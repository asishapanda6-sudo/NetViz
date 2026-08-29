"""PCAP replay support.

Includes a dependency-free classic-pcap reader (Ethernet / raw-IP link types,
IPv4 + IPv6, VLAN tags). If scapy is installed it is used automatically for
pcapng files and exotic link types.
"""
from __future__ import annotations

import os
import socket
import struct
import threading
import time

from sources.common import paced_wait

MAX_PACKETS = 200_000

LINKTYPE_ETH = 1
LINKTYPE_RAW = 101


class PcapError(Exception):
    pass


# --------------------------------------------------------------------- reader
def _iter_classic(path: str):
    """Yield (ts, frame_bytes, linktype) from a classic pcap file."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise PcapError("truncated pcap header")
        magic = gh[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        elif magic == b"\x4d\x3c\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\x3c\x4d":
            endian = ">"
        else:
            raise PcapError("not a classic pcap file")
        _, _, _, _, snaplen, linktype = struct.unpack(endian + "HHiIII", gh[4:24])
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_s, ts_us, caplen, _ = struct.unpack(endian + "IIII", ph)
            data = f.read(caplen)
            if len(data) < caplen:
                break
            yield ts_s + ts_us / 1e6, data, linktype


def _iter_scapy(path: str):
    try:
        from scapy.utils import PcapReader
    except ImportError:
        raise PcapError("scapy is required for this capture file (pip install scapy)")
    from engine import label_proto  # local import to avoid cycles
    with PcapReader(path) as rdr:
        for pkt in rdr:
            ts = float(pkt.time) if pkt.time is not None else time.time()
            yield ts, bytes(pkt), LINKTYPE_ETH, pkt


# --------------------------------------------------------------------- parsing
TCP_FLAG_NAMES = ["F", "S", "R", "P", "A", "U", "E", "C"]


def tcp_flags_str(flags_byte: int) -> str:
    return "".join(name for bit, name in enumerate(TCP_FLAG_NAMES) if flags_byte & (1 << bit))


def _ip4(ts, b):
    if len(b) < 20:
        return None
    ihl = (b[0] & 0x0F) * 4
    if ihl < 20 or len(b) < ihl:
        return None
    proto = b[9]
    src = socket.inet_ntoa(b[12:16])
    dst = socket.inet_ntoa(b[16:20])
    total = struct.unpack("!H", b[2:4])[0]
    if 20 <= total <= len(b):
        b = b[:total]
    flags = None
    if proto == 6 and len(b) >= ihl + 4:
        sp, dp = struct.unpack("!HH", b[ihl:ihl + 4])
        pr = "TCP"
        if len(b) >= ihl + 14:
            flags = tcp_flags_str(b[ihl + 13])
    elif proto == 17 and len(b) >= ihl + 4:
        sp, dp = struct.unpack("!HH", b[ihl:ihl + 4])
        pr = "UDP"
    elif proto == 1:
        sp = dp = None
        pr = "ICMP"
    else:
        return None
    return {"ts": ts, "src": src, "dst": dst, "proto": pr,
            "sport": sp, "dport": dp, "len": max(len(b), 20), "flags": flags}


def _ip6(ts, b):
    if len(b) < 40:
        return None
    nxt = b[6]
    src = socket.inet_ntop(socket.AF_INET6, b[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, b[24:40])
    off = 40
    # skip common extension headers
    while nxt in (0, 43, 44, 51, 60) and len(b) >= off + 8:
        nxt = b[off]
        off += (b[off + 1] + 1) * 8 if nxt == 0 else 8
    flags = None
    if nxt == 6 and len(b) >= off + 4:
        sp, dp = struct.unpack("!HH", b[off:off + 4])
        pr = "TCP"
        if len(b) >= off + 14:
            flags = tcp_flags_str(b[off + 13])
    elif nxt == 17 and len(b) >= off + 4:
        sp, dp = struct.unpack("!HH", b[off:off + 4])
        pr = "UDP"
    elif nxt == 58:
        sp = dp = None
        pr = "ICMP"
    else:
        return None
    return {"ts": ts, "src": src, "dst": dst, "proto": pr,
            "sport": sp, "dport": dp, "len": len(b), "flags": flags}


def _parse_frame(ts, data, linktype):
    if linktype == LINKTYPE_ETH:
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        if etype == 0x8100:  # VLAN
            if len(data) < 18:
                return None
            etype = struct.unpack("!H", data[16:18])[0]
            off = 18
        if etype == 0x0800:
            return _ip4(ts, data[off:])
        if etype == 0x86DD:
            return _ip6(ts, data[off:])
        return None
    if linktype in (LINKTYPE_RAW, 12, 14):
        if not data:
            return None
        v = data[0] >> 4
        if v == 4:
            return _ip4(ts, data)
        if v == 6:
            return _ip6(ts, data)
    return None


def _parse_scapy(ts, raw, pkt):
    try:
        from scapy.layers.inet import IP, IPv6, TCP, UDP
        from scapy.layers.inet6 import ICMPv6EchoRequest  # noqa: F401 (availability check)
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            return None
        sp = dp = None
        pr = None
        t = pkt.getlayer(TCP)
        u = pkt.getlayer(UDP)
        flags = None
        if t is not None:
            sp, dp, pr = int(t.sport), int(t.dport), "TCP"
            flags = str(t.flags)
        elif u is not None:
            sp, dp, pr = int(u.sport), int(u.dport), "UDP"
        elif pkt.getlayer("ICMP") is not None:
            pr = "ICMP"
        else:
            return None
        return {"ts": ts, "src": ip.src, "dst": ip.dst, "proto": pr,
                "sport": sp, "dport": dp, "len": len(pkt), "flags": flags}
    except ImportError:
        return None


def load_packets(path: str):
    """Load a capture file into a list of packet dicts (capped)."""
    pkts = []
    truncated = False
    it = None
    use_scapy = False
    try:
        it = _iter_classic(path)
    except PcapError:
        use_scapy = True
    if it is not None:
        for ts, data, linktype in it:
            if len(pkts) >= MAX_PACKETS:
                truncated = True
                break
            p = _parse_frame(ts, data, linktype)
            if p:
                pkts.append(p)
    elif use_scapy:
        for item in _iter_scapy(path):
            if len(pkts) >= MAX_PACKETS:
                truncated = True
                break
            ts, raw, _lt, pkt = item
            p = _parse_scapy(ts, raw, pkt)
            if p:
                pkts.append(p)
    if truncated:
        pkts.append(None)  # marker handled by caller
    return pkts, truncated


# --------------------------------------------------------------------- replayer
class Replayer(threading.Thread):
    """Replays a capture file onto the engine at an adjustable speed."""

    def __init__(self, engine, path: str, speed_fn, stop_event: threading.Event, loop: bool = True):
        super().__init__(daemon=True, name="pcap-replayer")
        self.engine = engine
        self.path = path
        self.speed_fn = speed_fn
        self.stop_event = stop_event
        self.loop = loop

    def run(self):
        name = os.path.basename(self.path)
        try:
            pkts, truncated = load_packets(self.path)
        except Exception as e:  # noqa: BLE001
            self.engine.add_alert("error", "high", "Replay failed",
                                  f"Could not read {name}: {e}")
            return
        pkts = [p for p in pkts if p]
        if not pkts:
            self.engine.add_alert("error", "high", "Replay failed",
                                  f"No IP packets found in {name}")
            return
        note = f" ({MAX_PACKETS:,} packet cap reached)" if truncated else ""
        self.engine.add_alert("replay", "info", f"Replaying {name}",
                              f"{len(pkts):,} packets{note}")

        while not self.stop_event.is_set():
            prev_ts = pkts[0]["ts"]
            for p in pkts:
                if self.stop_event.is_set():
                    return
                gap = max(0.0, p["ts"] - prev_ts)
                prev_ts = p["ts"]
                paced_wait(min(gap, 1.5), self.speed_fn, self.stop_event)
                if self.stop_event.is_set():
                    return
                q = dict(p)
                q["ts"] = time.time()
                self.engine.process(q)
            if not self.loop:
                self.engine.add_alert("replay", "info", "Replay finished", name)
                return
            paced_wait(1.5, self.speed_fn, self.stop_event)
