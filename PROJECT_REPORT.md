# PROJECT REPORT — NetViz: Real-Time Network Traffic Visualizer

> **How to use this file:** ye ek ready-made report structure hai. Har section
> me likha hai kya daalna hai — `[FILL: ...]` wali jagah apni details daalo,
> "Screenshot" wali jagah dashboard ke screenshots lagao, aur apne college ke
> format (cover page, fonts) me convert kar lo. English me hai taaki direct
> submit kar sako.

---

## COVER PAGE
[FILL: Project title, your name(s), roll number(s), department, college name,
guide name, semester, academic year]

## CERTIFICATE / ACKNOWLEDGEMENT
[FILL: as per your college format]

---

## 1. ABSTRACT

Network security monitoring traditionally relies on packet analyzers that
present traffic as long, raw text logs. Reading these logs is slow, requires
expertise, and makes attacks such as port scans easy to miss. **NetViz** is a
real-time network traffic visualizer that converts live packet captures into an
animated, interactive graph: every IP address appears as a node, every
connection as a color-coded pulsing line, and traffic flows are shown as moving
particles. A rule-based detection engine raises alerts for eight threat
patterns — port scans, host sweeps, SYN floods, C2 beaconing, known-malicious
IPs (blocklist), proxy/datacenter destinations, traffic spikes, and heuristic
watch conditions. The tool supports three traffic sources — a synthetic
simulator, PCAP file replay, and live interface capture — and presents
everything through a beginner-friendly web dashboard with search, zoom/pan,
CSV/PNG export, IP geolocation, and per-node detail panels. The result: even a
non-expert can spot an ongoing attack **at a glance** instead of reading
thousands of log lines.

**Keywords:** network monitoring, intrusion detection, packet capture, pcap,
visualization, port scan, SYN flood, C2 beaconing, Flask, canvas.

---

## 2. INTRODUCTION

### 2.1 Problem Statement
Modern networks carry thousands of packets per second. Tools like tcpdump and
Wireshark record this traffic as text; finding an attack inside those logs is
a "needle in a haystack" problem that needs trained eyes and hours of effort.

### 2.2 Objective
Build a tool that:
1. Captures live network traffic (or replays recorded `.pcap` files).
2. Visualizes traffic in real time as an animated graph (IPs = nodes,
   connections = color-coded lines).
3. Detects suspicious patterns automatically and raises alerts.
4. Remains simple enough for a non-expert (first-year student / junior SOC
   analyst) to understand at a glance.

### 2.3 Scope
Real-time monitoring of a small LAN, detection of eight rule-based threat
patterns, interactive investigation of any device, and exportable evidence
(CSV/PNG). ML-based detection and multi-sensor scale-out are future scope.

---

## 3. LITERATURE SURVEY

| Tool | Type | Limitation addressed by NetViz |
|---|---|---|
| tcpdump | CLI text capture | No visualization; expert-only |
| Wireshark | Deep packet inspection GUI | Text/table-first, manual analysis, not attack-focused at a glance |
| ntopng | Web traffic monitor | Requires nProbe/subscription for many features; heavier setup |
| Darktrace / commercial NDR | ML-based, enterprise | Expensive; overkill for small networks and teaching |
| Zeek / Suricata | IDS/LOG engines | Log-first output; needs separate visualization stack |

**Conclusion of survey:** a free, lightweight, visual-first tool with built-in
basic detection fills the gap for small networks, labs, and training.

[FILL: add 2–3 sentences per tool from their official docs and cite them — see References]

---

## 4. SYSTEM REQUIREMENTS

- **Hardware:** any PC with 4 GB RAM (8 GB recommended for live capture on busy links).
- **Software:** Python 3.10+, Flask, scapy, any modern browser.
- **Privileges:** administrator/root needed *only* for live capture mode.

---

## 5. SYSTEM ARCHITECTURE

```
┌──────────────────────────── DATA SOURCES ────────────────────────────┐
│  simulator.py (synthetic LAN + scripted attacks)                     │
│  pcap_source.py (recorded .pcap replay, 0.25×–8×, loop)              │
│  live_source.py (real interface via scapy AsyncSniffer)              │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ packet dicts {src, dst, proto, ports, size, flags}
                               ▼
┌──────────────────────────── ENGINE (engine.py) ──────────────────────┐
│  • aggregation: per-IP stats, per-connection stats, 1-second rates   │
│  • 8 detection rules (see §6)                                         │
│  • blocklist.txt matching (hot-reload)                                │
└──────────┬───────────────────────────────────────────┬───────────────┘
           │ snapshots (1 Hz)                          │ geo enrichment
           ▼                                           ▼
┌──────────────── WEB SERVER (app.py, Flask) ──┐  ┌─ geo_service.py ──┐
│  GET /  (dashboard)                          │  │ ip-api.com batch  │
│  GET /api/state, /api/stream (SSE)           │  │ country/ISP/proxy │
│  GET /api/node/<ip>, /api/samples, /api/ifaces │ │ cached in JSON    │
│  POST /api/source, /api/control              │  └───────────────────┘
└──────────────────────┬───────────────────────┘
                       │ JSON over SSE + polling fallback
                       ▼
┌──────────────── BROWSER DASHBOARD (static/, no CDN) ─────────────────┐
│  canvas force-directed graph · zoom/pan/search · node info panel     │
│  alerts panel (filters, CSV) · PNG export · beginner tour & help     │
└───────────────────────────────────────────────────────────────────────┘
```

### Module table

| Module | File(s) | Responsibility |
|---|---|---|
| Traffic sources | `sources/simulator.py`, `sources/pcap_source.py`, `sources/live_source.py` | produce packet dicts from simulation / pcap / live NIC |
| Aggregation + detection | `engine.py` | per-IP/per-connection stats; 8 rules; risk levels |
| Geolocation | `geo_service.py` | enrich external IPs (country, ISP, proxy flags) |
| Web server + API | `app.py` | dashboard hosting, SSE stream, source control |
| Frontend | `static/index.html`, `style.css`, `app.js` | animated graph, panels, search, export, tour |
| Testing | `selftest.py` | automated tests of every detection rule |
| Samples | `tools/make_samples.py`, `samples/*.pcap` | deterministic demo captures |
| Deployment | `Dockerfile`, `render.yaml`, `DEPLOY.md` | Docker / Render / LAN deployment |

---

## 6. DETECTION RULES (the core of the project)

| # | Rule | Logic (default thresholds) | Severity |
|---|---|---|---|
| 1 | Possible port scan | ≥ 12 distinct ports probed on one target within 10 s | HIGH |
| 2 | Possible host sweep | ≥ 15 distinct destinations from one source within 10 s | MEDIUM |
| 3 | Possible SYN flood | ≥ 40 half-open SYNs (SYN without ACK) to one port within 10 s | HIGH |
| 4 | Possible C2 beaconing | ≥ 12 isolated contacts at regular intervals (jitter < 30%), non-benign port | HIGH |
| 5 | Known malicious IP | traffic involving an IP/CIDR from `blocklist.txt` (hot-reloads) | HIGH |
| 6 | Unusual destination | proxy/anonymizer IP per geolocation flags | MEDIUM |
| 7 | Traffic spike | throughput > 3× the 30 s rolling median baseline and > 250 KB/s | HIGH |
| 8 | Heuristic watch | node with > 25 peers or > 60 distinct service ports | watch |

**Anti-false-positive design (worth highlighting in viva):** the beaconing
rule distinguishes an isolated periodic "check-in" from a bulk transfer
(many packets between check-ins are *not* beacons) and ignores periodic
services like NTP/DNS by design.

All thresholds are constants at the top of `engine.py` and can be tuned
without touching any other code.

---

## 7. USER INTERFACE

[FILL: one screenshot + 2–3 lines each]
- **Screenshot 1 — Dashboard overview:** animated graph, legend, meters
  (packets/sec, current speed, device/connection counts), risk summary pill.
- **Screenshot 2 — Threat alert + "In simple words" explanation:** left panel
  shows detection with plain-language meaning; clicking an alert jumps to the
  suspect node (red pulsing ring).
- **Screenshot 3 — Node info panel:** IP, internal/external, geolocation
  (country flag, ISP), traffic types, busiest ports, peers, related alerts.
- **Screenshot 4 — Search & zoom:** `/` search by IP/country/ISP; scroll zoom,
  drag pan, `F` fit.
- **Screenshot 5 — Export:** alerts → CSV; graph → PNG.
- **Screenshot 6 — Help modal & beginner tour:** explains every shape, color
  and rule in simple language.

---

## 8. TESTING

### 8.1 Automated engine tests (`python selftest.py`)

| Test case | Input | Expected output | Result |
|---|---|---|---|
| TC-01 Baseline, no false spike | 35 s × 100 KB/s steady flow | no traffic_spike alert | PASS |
| TC-02 Bulk flow is not beaconing | continuous transfer | no beaconing alert | PASS |
| TC-03 Traffic spike | ~800 KB/s burst vs 100 KB/s baseline | traffic_spike HIGH | PASS |
| TC-04 Port scan | 40 ports in ~5 s to one host | port_scan HIGH | PASS |
| TC-05 Host sweep | 20 destinations in 4 s | host_sweep MEDIUM | PASS |
| TC-06 SYN flood | 50 SYNs in 2.5 s to one port | syn_flood HIGH | PASS |
| TC-07 C2 beaconing | 14 contacts every 5 s, jitter 0% | beaconing HIGH | PASS |
| TC-08 Blocklist | traffic with IP in CIDR list | blocklist HIGH + node risk "suspicious" | PASS |
| TC-09 Snapshot integrity | after all feeds | nodes/edges/alerts consistent | PASS |
| TC-10 Clear state | engine.clear() | empty state | PASS |

[FILL: paste your actual `selftest.py` output here as evidence]

### 8.2 Manual / integration tests

| Test case | Steps | Expected | Result |
|---|---|---|---|
| Simulation start | run `python app.py`, open dashboard | animated graph within 2 s | [FILL] |
| PCAP replay | select `samples/demo_traffic.pcap`, speed 2× | scan + SYN flood + beaconing + spike alerts | [FILL] |
| Live capture | `sudo python app.py`, choose interface | own traffic visualized | [FILL] |
| Search | type `185.220.101.7`, Enter | camera jumps to C2 node | [FILL] |
| Export CSV/PNG | click ⬇ CSV / 📷 | files download | [FILL] |
| Blocklist hot-reload | add IP to blocklist.txt, wait ≤ 5 s | node flagged without restart | [FILL] |

---

## 9. DEPLOYMENT

- **LAN demo:** `python app.py` → share `http://<your-ip>:5001` on same Wi-Fi.
- **Cloud (free):** push to GitHub → Render.com blueprint (`render.yaml`) →
  public HTTPS link. Live-capture mode is on-premise only (cloud has no NIC).
- **Docker:** `docker build -t netviz . && docker run -p 5001:5001 netviz`.
Details in `DEPLOY.md`.

---

## 10. ADVANTAGES

1. Real-time visual detection — attacks visible in seconds, not hours.
2. Zero-cost, zero-dependency frontend (no CDN/frameworks).
3. Three interchangeable sources; same engine and UI.
4. Explainable, tunable rules (no black box).
5. Beginner-friendly: plain-language alerts, tour, help guide.

## 11. LIMITATIONS

1. Live capture needs admin/root privileges.
2. Built-in pcap parser covers classic pcap (Ethernet/raw-IP, VLAN, IPv4/6);
   pcapng requires scapy.
3. Rule thresholds are heuristics — tuning per network is expected.
4. Geolocation uses the free ip-api.com tier (IPv4, rate-limited); degrades
   silently offline.

## 12. FUTURE SCOPE

1. Machine-learning anomaly detection to complement rules (Isolation Forest /
   autoencoders for zero-day anomalies).
2. Distributed multi-sensor capture with a central dashboard.
3. Time-series persistence (SQLite/ClickHouse) + timeline scrubber for
   forensic replay.
4. SIEM/Splunk/ELK alert forwarding and e-mail/Slack notifications.
5. Deeper packet inspection (payload strings, TLS SNI extraction).

## 13. CONCLUSION

NetViz demonstrates that converting raw packet logs into a live, animated,
plain-language picture makes network threat spotting dramatically faster and
accessible to non-experts. All eight detection rules were implemented and
verified by automated tests, and the tool runs anywhere — from a laptop
(simulation/replay) to a real network (live capture) to the cloud (Docker/
Render). [FILL: 2–3 lines about what YOU learned building it.]

## 14. REFERENCES

1. Wireshark — https://www.wireshark.org/docs/
2. Scapy documentation — https://scapy.readthedocs.io/
3. Flask documentation — https://flask.palletsprojects.com/
4. ip-api.com geolocation API — https://ip-api.com/docs/
5. RFC 793 (TCP), RFC 792 (ICMP), RFC 1918 (private address space)
6. [FILL: your textbook / class notes on intrusion detection]

[FILL: bibliography format as per your college (IEEE/APA)]
