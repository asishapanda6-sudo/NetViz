"""Traffic aggregation engine + rule-based threat detection.

Consumes packet dicts: {ts, src, dst, proto, sport, dport, len, flags?}
and maintains:
  * per-IP node aggregates (packets, bytes, protocols, ports, peers, rate)
  * per-connection edge aggregates
  * rule-based alerts:
      port scan, host sweep, SYN flood, C2 beaconing, known-malicious IP
      (blocklist), flagged infrastructure (proxy/hosting), traffic spike
  * optional IP geolocation enrichment (filled in by geo_service)
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from collections import Counter, defaultdict, deque
from statistics import median

# ----------------------------------------------------------------- tunables
SCAN_WINDOW = 10.0            # seconds of recent history to consider
SCAN_PORTS_THRESHOLD = 12     # distinct ports on one target => port scan
SCAN_COOLDOWN = 60.0          # don't re-alert for the same pair within this window

SWEEP_HOSTS_THRESHOLD = 15    # distinct destinations from one source => host sweep
SWEEP_WINDOW = 10.0
SWEEP_COOLDOWN = 60.0

SYN_FLOOD_THRESHOLD = 40      # SYN (no ACK) packets to one port => SYN flood
SYN_FLOOD_WINDOW = 10.0
SYN_FLOOD_COOLDOWN = 60.0

BEACON_MIN_SAMPLES = 12       # regular contacts => C2 beaconing
BEACON_MAX_CV = 0.30          # coefficient of variation (jitter ratio)
BEACON_MIN_MEAN = 1.0         # seconds between contacts
BEACON_MAX_MEAN = 120.0
BEACON_COOLDOWN = 300.0
BEACON_MIN_GAP = 1.0          # contacts closer than this count as one burst

BLOCKLIST_COOLDOWN = 600.0    # alert cadence per blocklisted IP
GEO_FLAG_COOLDOWN = 600.0     # alert cadence per proxy/hosting IP

SPIKE_BASELINE_SECS = 30      # rolling baseline window
SPIKE_FACTOR = 3.0            # current > 3x baseline ...
SPIKE_MIN_BPS = 250_000       # ... and > 250 KB/s absolute floor
SPIKE_COOLDOWN = 25.0

NODE_IDLE_PRUNE = 600.0       # drop nodes idle for 10 minutes
MAX_ALERTS = 200
MAX_NODES_IN_SNAPSHOT = 250
MAX_EDGES_IN_SNAPSHOT = 400
EPHEMERAL_MIN = 49152         # ports >= this are ephemeral; not counted as "service ports"

WELL_KNOWN = {
    53: "DNS", 80: "HTTP", 443: "HTTPS", 22: "SSH", 25: "SMTP", 587: "SMTP",
    465: "SMTP", 993: "IMAPS", 143: "IMAP", 110: "POP3", 21: "FTP", 23: "TELNET",
    873: "RSYNC", 3306: "MySQL", 5432: "Postgres", 6379: "Redis", 8080: "HTTP",
    123: "NTP", 67: "DHCP", 68: "DHCP", 161: "SNMP", 445: "SMB", 139: "NETBIOS",
    389: "LDAP", 636: "LDAPS", 5353: "mDNS", 1900: "SSDP",
}


def label_proto(proto: str, sport, dport) -> str:
    """Map a packet to an application label used for colour-coding."""
    if proto == "ICMP":
        return "ICMP"
    for p in (dport, sport):
        if p and int(p) in WELL_KNOWN:
            return WELL_KNOWN[int(p)]
    return proto or "OTHER"


def is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def human_bytes(n: float) -> str:
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"


def human_bps(bytes_per_sec: float) -> str:
    bits = float(bytes_per_sec) * 8
    for u in ("bps", "Kbps", "Mbps", "Gbps"):
        if bits < 1000 or u == "Gbps":
            return f"{bits:.0f} {u}" if u == "bps" else f"{bits:.1f} {u}"
        bits /= 1000
    return f"{bits:.1f} Gbps"


class Engine:
    """Thread-safe packet aggregator + detector. All public methods are safe
    to call from capture threads, SSE handlers and the HTTP handler."""

    def __init__(self, blocklist_path: str | None = None) -> None:
        self.lock = threading.RLock()
        self.nodes: dict[str, dict] = {}
        self.edges: dict[tuple[str, str], dict] = {}
        self.alerts: list[dict] = []

        self._alert_seq = 0
        self._scan_ports: dict[tuple[str, str], deque] = defaultdict(deque)
        self._scan_alerted: dict[tuple[str, str], float] = {}
        self._sweep_hosts: dict[str, deque] = defaultdict(deque)
        self._sweep_alerted: dict[str, float] = {}
        self._syn: dict[tuple[str, str, int], deque] = defaultdict(deque)
        self._syn_alerted: dict[tuple[str, str, int], float] = {}
        self._beacon: dict[tuple[str, str], deque] = defaultdict(deque)
        self._beacon_alerted: dict[tuple[str, str], float] = {}
        self._block_alerted: dict[str, float] = {}
        self._geo_alerted: dict[str, float] = {}
        self.risk_until: dict[str, tuple[float, str, str]] = {}  # ip -> (expiry, level, reason)

        # static blocklist (file: one IP/CIDR per line, '#' comments)
        self.blocklist_path = blocklist_path
        self.blocklist_nets: list[tuple[ipaddress._BaseNetwork, str]] = []
        self.blocklist_hits: set[str] = set()
        self._blocklist_mtime = 0.0
        self._ip_cache: dict[str, object] = {}
        self.load_blocklist()

        # geolocation enrichment (filled by geo_service.GeoService)
        self.geo: dict[str, dict] = {}
        self.geo_flagged: set[str] = set()
        self.geo_enabled = True

        self.history: deque[tuple[float, float, int]] = deque(maxlen=120)  # (t, bytes/sec, pkts/sec)
        self._sec_bucket: int | None = None
        self._sec_bytes = 0
        self._sec_pkts = 0
        self._spike_last = 0.0

        self.total_pkts = 0
        self.total_bytes = 0
        self.started = time.time()

    # ------------------------------------------------------------ blocklist
    def load_blocklist(self, path: str | None = None) -> int:
        """(Re)load the blocklist file. Returns number of entries."""
        path = path or self.blocklist_path
        if not path:
            return 0
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return len(self.blocklist_nets)
        if mtime == self._blocklist_mtime and self.blocklist_nets is not None and path == self.blocklist_path:
            return len(self.blocklist_nets)
        nets = []
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    entry = line.split("#", 1)[0].strip()
                    if not entry:
                        continue
                    try:
                        nets.append((ipaddress.ip_network(entry, strict=False), entry))
                    except ValueError:
                        continue
        except OSError:
            return len(self.blocklist_nets)
        with self.lock:
            self.blocklist_path = path
            self._blocklist_mtime = mtime
            self.blocklist_nets = nets
            # re-check hits against the new list
            self.blocklist_hits = {ip for ip in self.blocklist_hits if self._in_blocklist_nets(ip)}
        return len(nets)

    def _in_blocklist_nets(self, ip: str) -> str | None:
        addr = self._ip_cache.get(ip)
        if addr is None:
            if len(self._ip_cache) > 8192:
                self._ip_cache.clear()
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                addr = False
            self._ip_cache[ip] = addr
        if addr is False:
            return None
        for net, entry in self.blocklist_nets:
            if addr in net:
                return entry
        return None

    def _check_blocklist(self, ts: float, ip: str) -> None:
        hit = self._in_blocklist_nets(ip)
        if hit is None:
            return
        self.blocklist_hits.add(ip)
        self.risk_until[ip] = (ts + 10**9, "suspicious", f"Listed in blocklist ({hit})")
        if ts - self._block_alerted.get(ip, -1e9) > BLOCKLIST_COOLDOWN:
            self._block_alerted[ip] = ts
            self.add_alert(
                "blocklist", "high", f"Known malicious IP: {ip}",
                f"Traffic involves {ip} which is on the local blocklist ({hit}).",
                src=ip,
            )

    # ------------------------------------------------------------ geo
    def set_geo(self, ip: str, data: dict) -> None:
        with self.lock:
            self.geo[ip] = data
            if data.get("proxy") or data.get("hosting"):
                self.geo_flagged.add(ip)

    def uncached_external_ips(self, limit: int = 64) -> list[str]:
        with self.lock:
            cand = [nd["ip"] for nd in self.nodes.values()
                    if not nd["internal"] and nd["ip"] not in self.geo and ":" not in nd["ip"]]
            cand.sort(key=lambda ip: -self.nodes[ip]["bytes"])
            return cand[:limit]

    def _check_geo_flag(self, ts: float, ip: str) -> None:
        if ip not in self.geo_flagged:
            return
        if ts - self._geo_alerted.get(ip, -1e9) > GEO_FLAG_COOLDOWN:
            self._geo_alerted[ip] = ts
            g = self.geo.get(ip, {})
            is_proxy = bool(g.get("proxy"))
            kinds = []
            if is_proxy:
                kinds.append("proxy")
            if g.get("hosting"):
                kinds.append("hosting/datacenter")
            # proxies/anonymizers are genuinely unusual; plain hosting (every CDN)
            # is informational only — keeps alert noise down
            sev = "medium" if is_proxy else "info"
            title = f"Unusual destination: {ip}" if is_proxy else f"Datacenter destination: {ip}"
            self.add_alert(
                "geo_flag", sev, title,
                f"{ip} is flagged as {'/'.join(kinds)} infrastructure"
                + (f" — {g.get('isp', '?')} ({g.get('country', '?')})" if g else ""),
                src=ip,
            )
            if is_proxy:
                self.risk_until[ip] = (ts + 300, "watch", f"Flagged infrastructure ({'/'.join(kinds)})")

    # ------------------------------------------------------------ ingestion
    def process(self, pkt: dict) -> None:
        ts = float(pkt.get("ts") or time.time())
        src, dst = pkt["src"], pkt["dst"]
        proto = pkt.get("proto") or "OTHER"
        sp, dp = pkt.get("sport"), pkt.get("dport")
        flags = pkt.get("flags") or ""
        n = int(pkt.get("len") or 0)
        label = pkt.get("label") or label_proto(proto, sp, dp)

        with self.lock:
            self.total_pkts += 1
            self.total_bytes += n

            for ip, direction in ((src, "out"), (dst, "in")):
                nd = self.nodes.get(ip)
                if nd is None:
                    nd = {
                        "ip": ip, "internal": is_internal(ip), "pkts": 0, "bytes": 0,
                        "in_pkts": 0, "out_pkts": 0, "in_bytes": 0, "out_bytes": 0,
                        "first": ts, "last": ts, "protos": Counter(), "ports": Counter(),
                        "peers": set(), "_win": deque(),
                    }
                    self.nodes[ip] = nd
                nd["pkts"] += 1
                nd["bytes"] += n
                nd["last"] = max(nd["last"], ts)
                nd[direction + "_pkts"] += 1
                nd[direction + "_bytes"] += n
                nd["protos"][label] += 1
                nd["_win"].append((ts, n))

            self.nodes[src]["peers"].add(dst)
            self.nodes[dst]["peers"].add(src)
            port = dp if dp else sp
            if port and int(port) < EPHEMERAL_MIN:
                self.nodes[src]["ports"][int(port)] += 1
                self.nodes[dst]["ports"][int(port)] += 1

            key = (src, dst)
            e = self.edges.get(key)
            if e is None:
                e = self.edges[key] = {
                    "src": src, "dst": dst, "pkts": 0, "bytes": 0,
                    "protos": Counter(), "first": ts, "last": ts,
                }
            e["pkts"] += 1
            e["bytes"] += n
            e["last"] = max(e["last"], ts)
            e["protos"][label] += 1

            # per-second throughput bucketing
            b = int(ts)
            if self._sec_bucket is None:
                self._sec_bucket = b
            if b > self._sec_bucket:
                self.history.append((self._sec_bucket + 1, self._sec_bytes, self._sec_pkts))
                self._sec_bucket, self._sec_bytes, self._sec_pkts = b, 0, 0
            self._sec_bytes += n
            self._sec_pkts += 1

            # detection on every packet (cheap, deques are small)
            if self.blocklist_nets:
                self._check_blocklist(ts, src)
                self._check_blocklist(ts, dst)
            if self.geo_flagged:
                self._check_geo_flag(ts, src)
                self._check_geo_flag(ts, dst)
            if dp:
                self._check_scan(ts, src, dst, int(dp))
            self._check_sweep(ts, src, dst)
            if proto == "TCP" and "S" in flags and "A" not in flags and dp:
                self._check_syn_flood(ts, src, dst, int(dp))
            self._check_beacon(ts, src, dst, dp, e)

    # ------------------------------------------------------------ detection
    def _check_scan(self, ts: float, src: str, dst: str, dport: int) -> None:
        key = (src, dst)
        dq = self._scan_ports[key]
        dq.append((ts, dport))
        cutoff = ts - SCAN_WINDOW
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        ports = {p for _, p in dq}
        if len(ports) >= SCAN_PORTS_THRESHOLD and ts - self._scan_alerted.get(key, -1e9) > SCAN_COOLDOWN:
            self._scan_alerted[key] = ts
            span = max(ts - dq[0][0], 0.001)
            self.add_alert(
                "port_scan", "high",
                f"Possible port scan: {src} → {dst}",
                f"{len(ports)} distinct ports probed on {dst} within {span:.1f}s "
                f"({len(dq)} probes from {src})",
                src=src, dst=dst,
            )
            self.risk_until[src] = (ts + 120, "suspicious", "Source of port-scan alert")
            self.risk_until[dst] = (ts + 120, "watch", "Target of port-scan alert")

    def _check_sweep(self, ts: float, src: str, dst: str) -> None:
        dq = self._sweep_hosts[src]
        dq.append((ts, dst))
        cutoff = ts - SWEEP_WINDOW
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        hosts = {d for _, d in dq}
        if len(hosts) >= SWEEP_HOSTS_THRESHOLD and ts - self._sweep_alerted.get(src, -1e9) > SWEEP_COOLDOWN:
            self._sweep_alerted[src] = ts
            span = max(ts - dq[0][0], 0.001)
            self.add_alert(
                "host_sweep", "medium",
                f"Possible host sweep from {src}",
                f"{len(hosts)} distinct destinations contacted within {span:.1f}s",
                src=src,
            )
            self.risk_until[src] = (ts + 120, "suspicious", "Source of host-sweep alert")

    def _check_syn_flood(self, ts: float, src: str, dst: str, dport: int) -> None:
        key = (src, dst, dport)
        dq = self._syn[key]
        dq.append(ts)
        cutoff = ts - SYN_FLOOD_WINDOW
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= SYN_FLOOD_THRESHOLD and ts - self._syn_alerted.get(key, -1e9) > SYN_FLOOD_COOLDOWN:
            self._syn_alerted[key] = ts
            self.add_alert(
                "syn_flood", "high",
                f"Possible SYN flood: {src} → {dst}:{dport}",
                f"{len(dq)} half-open SYNs to port {dport} within "
                f"{max(ts - cutoff, 0):.0f}s (threshold {SYN_FLOOD_THRESHOLD})",
                src=src, dst=dst,
            )
            self.risk_until[src] = (ts + 120, "suspicious", "Source of SYN-flood alert")
            self.risk_until[dst] = (ts + 120, "watch", "Target of SYN-flood alert")

    # benign periodic services that check-in regularly by design — not C2 beacons
    BENIGN_BEACON_PORTS = {53, 123, 137, 161, 5353, 1900, 67, 68}

    def _check_beacon(self, ts: float, src: str, dst: str, dp, e: dict) -> None:
        key = (src, dst)
        dq = self._beacon[key]
        if dq and ts - dq[-1][0] < BEACON_MIN_GAP:
            return  # part of the same burst as the previous contact
        dq.append((ts, int(dp or 0), e["pkts"]))
        while len(dq) > BEACON_MIN_SAMPLES + 2:
            dq.popleft()
        if len(dq) < BEACON_MIN_SAMPLES:
            return
        # a beacon is an ISOLATED packet; a bulk flow moves many packets between contacts
        deltas = [dq[i][2] - dq[i - 1][2] for i in range(1, len(dq))]
        if deltas and max(deltas) > 3:
            return
        # NTP / DNS / mDNS etc. are periodic by design — not beacons
        if any(dq[i][1] in self.BENIGN_BEACON_PORTS for i in range(len(dq))):
            return
        diffs = [dq[i + 1][0] - dq[i][0] for i in range(len(dq) - 1)]
        m = sum(diffs) / len(diffs)
        if not (BEACON_MIN_MEAN <= m <= BEACON_MAX_MEAN):
            return
        var = sum((d - m) ** 2 for d in diffs) / len(diffs)
        cv = (var ** 0.5) / m if m > 0 else 1.0
        if cv <= BEACON_MAX_CV and ts - self._beacon_alerted.get(key, -1e9) > BEACON_COOLDOWN:
            self._beacon_alerted[key] = ts
            self.add_alert(
                "beaconing", "high",
                f"Possible C2 beaconing: {src} → {dst}",
                f"{len(dq)} contacts at regular ~{m:.1f}s intervals "
                f"(jitter {cv * 100:.0f}%) — periodic check-in pattern",
                src=src, dst=dst,
            )
            self.risk_until[src] = (ts + 300, "suspicious", "Periodic beaconing pattern detected")
            self.risk_until[dst] = (ts + 300, "watch", "Beaconing destination")

    def _check_spike(self, now: float) -> None:
        if len(self.history) < 15:
            return
        cur = [b for t, b, _ in self.history if t > now - 3]
        base = [b for t, b, _ in self.history if now - 3 - SPIKE_BASELINE_SECS < t <= now - 3]
        if len(cur) < 2 or len(base) < 8:
            return
        cb = sum(cur) / len(cur)
        bb = median(base)
        if cb > SPIKE_MIN_BPS and cb > SPIKE_FACTOR * max(bb, 1) and now - self._spike_last > SPIKE_COOLDOWN:
            self._spike_last = now
            top = self._top_talker(now)
            extra = f" Top talker: {top[0]} ({human_bps(top[1])})." if top else ""
            self.add_alert(
                "traffic_spike", "high",
                "Traffic spike detected",
                f"Throughput {human_bps(cb)} vs baseline {human_bps(bb)} "
                f"({cb / max(bb, 1):.1f}× the last {SPIKE_BASELINE_SECS}s).{extra}",
                src=top[0] if top else None,
            )
            if top:
                self.risk_until[top[0]] = (now + 120, "watch", "Dominant talker during traffic spike")

    def _top_talker(self, now: float):
        best_ip, best = None, 0.0
        for nd in self.nodes.values():
            r = self._rate(nd, now)
            if r > best:
                best_ip, best = nd["ip"], r
        return (best_ip, best) if best_ip else None

    # ------------------------------------------------------------ housekeeping
    def tick(self, now: float | None = None) -> None:
        """Roll per-second buckets, evaluate spike detection, prune stale nodes."""
        now = time.time() if now is None else now
        with self.lock:
            if self._sec_bucket is not None:
                while now >= self._sec_bucket + 1:
                    self.history.append((self._sec_bucket + 1, self._sec_bytes, self._sec_pkts))
                    self._sec_bucket += 1
                    self._sec_bytes, self._sec_pkts = 0, 0
            self._check_spike(now)
            self._prune(now)
        # hot-reload blocklist if the file changed (checked ~every 5s)
        if int(now) % 5 == 0 and self.blocklist_path:
            self.load_blocklist()

    def _prune(self, now: float) -> None:
        stale = [ip for ip, nd in self.nodes.items() if nd["last"] < now - NODE_IDLE_PRUNE]
        if stale:
            st = set(stale)
            for ip in stale:
                del self.nodes[ip]
            for key in [k for k in self.edges if k[0] in st or k[1] in st]:
                del self.edges[key]
        for ip in [ip for ip, exp in self.risk_until.items() if exp[0] <= now]:
            if ip not in self.blocklist_hits:  # blocklisted IPs stay flagged
                del self.risk_until[ip]

    def _rate(self, nd: dict, now: float) -> float:
        w = nd["_win"]
        while w and w[0][0] < now - 5:
            w.popleft()
        return sum(b for _, b in w) / 5.0

    # ------------------------------------------------------------ alerts
    def add_alert(self, kind: str, severity: str, title: str, detail: str,
                  src: str | None = None, dst: str | None = None) -> dict:
        with self.lock:
            self._alert_seq += 1
            a = {
                "id": self._alert_seq, "ts": time.time(), "kind": kind,
                "severity": severity, "title": title, "detail": detail,
                "src": src, "dst": dst,
            }
            self.alerts.insert(0, a)
            self.alerts = self.alerts[:MAX_ALERTS]
            return a

    def clear_alerts(self) -> None:
        with self.lock:
            self.alerts = []

    # ------------------------------------------------------------ snapshots
    def _node_row(self, nd: dict, now: float) -> dict:
        ip = nd["ip"]
        r = self.risk_until.get(ip)
        level, reasons = "normal", []
        if ip in self.blocklist_hits:
            level, reasons = "suspicious", [f"On blocklist ({self._in_blocklist_nets(ip)})"]
        elif r and r[0] > now:
            level, reasons = r[1], [r[2]]
        extra = []
        if len(nd["peers"]) > 25:
            extra.append(f"{len(nd['peers'])} distinct peers")
        if len(nd["ports"]) > 60:
            extra.append(f"{len(nd['ports'])} distinct service ports")
        if extra and level == "normal":
            level = "watch"
        return {
            "ip": ip, "internal": nd["internal"],
            "pkts": nd["pkts"], "bytes": nd["bytes"],
            "in_pkts": nd["in_pkts"], "out_pkts": nd["out_pkts"],
            "in_bytes": nd["in_bytes"], "out_bytes": nd["out_bytes"],
            "first": nd["first"], "last": nd["last"],
            "peers": len(nd["peers"]),
            "ports": [{"port": p, "count": c} for p, c in nd["ports"].most_common(8)],
            "protos": [{"proto": p, "count": c} for p, c in nd["protos"].most_common(5)],
            "risk": {"level": level, "reasons": reasons + extra},
            "rate": round(self._rate(nd, now), 1),
            "geo": self.geo.get(ip),
        }

    def snapshot(self, meta: dict | None = None) -> dict:
        now = time.time()
        with self.lock:
            ordered = sorted(self.nodes.values(), key=lambda d: d["bytes"], reverse=True)
            kept = ordered[:MAX_NODES_IN_SNAPSHOT]
            keep_ips = {nd["ip"] for nd in kept}
            nodes = [self._node_row(nd, now) for nd in kept]

            edges = sorted(self.edges.values(), key=lambda e: e["last"], reverse=True)
            edge_rows = []
            for e in edges:
                if e["src"] not in keep_ips or e["dst"] not in keep_ips:
                    continue
                edge_rows.append({
                    "src": e["src"], "dst": e["dst"], "pkts": e["pkts"], "bytes": e["bytes"],
                    "proto": e["protos"].most_common(1)[0][0], "last": e["last"],
                })
                if len(edge_rows) >= MAX_EDGES_IN_SNAPSHOT:
                    break

            top = sorted(((self._rate(nd, now), nd["ip"]) for nd in kept), reverse=True)[:5]
            hist = [(t, b, p) for t, b, p in self.history][-90:]

            d = {
                "t": now,
                "stats": {
                    "total_pkts": self.total_pkts,
                    "total_bytes": self.total_bytes,
                    "nodes": len(self.nodes),
                    "edges": len(self.edges),
                    "pps": hist[-1][2] if hist else self._sec_pkts,
                    "bps": hist[-1][1] if hist else self._sec_bytes,
                    "history": hist,
                    "started": self.started,
                    "top": [{"ip": ip, "rate": round(r, 1)} for r, ip in top],
                    "blocklist": len(self.blocklist_nets),
                    "geo_ok": bool(self.geo) or not self.geo_enabled,
                },
                "nodes": nodes,
                "edges": edge_rows,
                "alerts": self.alerts[:60],
            }
        if meta:
            d.update(meta)
        return d

    def node_detail(self, ip: str) -> dict | None:
        now = time.time()
        with self.lock:
            nd = self.nodes.get(ip)
            if nd is None:
                return None
            row = self._node_row(nd, now)
            peers = {}
            for e in self.edges.values():
                if e["src"] == ip or e["dst"] == ip:
                    other = e["dst"] if e["src"] == ip else e["src"]
                    a = peers.setdefault(other, {"ip": other, "pkts": 0, "bytes": 0})
                    a["pkts"] += e["pkts"]
                    a["bytes"] += e["bytes"]
            row["peer_list"] = sorted(peers.values(), key=lambda p: p["bytes"], reverse=True)[:12]
            row["ports_full"] = [{"port": p, "count": c} for p, c in nd["ports"].most_common(15)]
            row["alerts"] = [a for a in self.alerts if a.get("src") == ip or a.get("dst") == ip][:20]
            return row

    def clear(self) -> None:
        with self.lock:
            self.nodes.clear()
            self.edges.clear()
            self.alerts = []
            self.risk_until.clear()
            self._scan_ports.clear()
            self._scan_alerted.clear()
            self._sweep_hosts.clear()
            self._sweep_alerted.clear()
            self._syn.clear()
            self._syn_alerted.clear()
            self._beacon.clear()
            self._beacon_alerted.clear()
            self._block_alerted.clear()
            self._geo_alerted.clear()
            self.history.clear()
            self._sec_bucket = None
            self._sec_bytes = 0
            self._sec_pkts = 0
            self._spike_last = 0.0
            self.total_pkts = 0
            self.total_bytes = 0
            self.started = time.time()
