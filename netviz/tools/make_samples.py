"""Generate bundled sample capture files (classic pcap, Ethernet/IPv4/TCP/UDP/ICMP).

Usage: python tools/make_samples.py
Creates:
  samples/demo_traffic.pcap — browsing + DNS + a port scan + a bulk-transfer spike
  samples/quiet.pcap        — gentle background traffic only
"""
from __future__ import annotations

import os
import random
import socket
import struct

random.seed(42)

BASE = 1750000000  # fixed epoch for reproducibility


def ip_checksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_hdr(sport, dport, flags=0x18, payload_len=0, seq=1000, ack=200):
    off = 5 << 12
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, off | flags, 8192, 0, 0) + b"\x00" * payload_len


def udp_hdr(sport, dport, payload_len):
    return struct.pack("!HHHH", sport, dport, 8 + payload_len, 0) + b"\x00" * payload_len


def ip4(src, dst, proto, payload):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    ck = ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", ck) + hdr[12:]
    return hdr + payload


def frame(pkt):
    return b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800) + pkt


def t_pkt(ts_list, ts, src, dst, proto, sport, dport, size):
    """size = total IP length we want."""
    body_len = max(0, size - 40 if proto == 6 else size - 28 if proto == 17 else size - 28)
    payload = bytes(random.getrandbits(8) for _ in range(min(body_len, 64))) + b"\x00" * max(0, body_len - 64)
    if proto == 6:
        body = tcp_hdr(sport, dport, 0x18 if size > 60 else 0x02, len(payload))
    elif proto == 17:
        body = udp_hdr(sport, dport, len(payload))
    else:  # ICMP echo
        body = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + payload
    ts_list.append((ts, frame(ip4(src, dst, proto, body))))


def write_pcap(path, ts_list):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in ts_list:
            s = int(ts)
            us = int(round((ts - s) * 1e6))
            f.write(struct.pack("<IIII", s, us, len(data), len(data)))
            f.write(data)
    print(f"wrote {path}: {len(ts_list)} packets, {os.path.getsize(path):,} bytes")


CLIENTS = ["192.168.1.10", "192.168.1.14", "192.168.1.18", "192.168.1.23", "192.168.1.20"]
WEB = ["142.250.185.78", "104.18.32.7", "151.101.1.69", "13.107.42.14"]
GATEWAY = "192.168.1.1"
NAS = "192.168.1.5"


def background(pkts, t, until, intensity=1.0):
    """Gentle browsing traffic between t and until (epoch seconds)."""
    while t < until:
        r = random.random()
        c = random.choice(CLIENTS)
        if r < 0.45:  # https burst
            w = random.choice(WEB)
            sport = random.randint(49152, 65535)
            t_pkt(pkts, t, c, w, 6, sport, 443, 60); t += 0.01
            for i in range(random.randint(3, 8)):
                t_pkt(pkts, t, c if i % 2 == 0 else w, w if i % 2 == 0 else c,
                      6, sport if i % 2 == 0 else 443, 443 if i % 2 == 0 else sport,
                      random.randint(200, 1400))
                t += random.uniform(0.02, 0.1)
        elif r < 0.65:  # dns
            sport = random.randint(49152, 65535)
            t_pkt(pkts, t, c, GATEWAY, 17, sport, 53, random.randint(70, 90)); t += 0.02
            t_pkt(pkts, t, GATEWAY, c, 17, 53, sport, random.randint(110, 170))
            t += random.uniform(0.1, 0.5)
        elif r < 0.78:  # http
            w = random.choice(WEB)
            sport = random.randint(49152, 65535)
            t_pkt(pkts, t, c, w, 6, sport, 80, 320); t += 0.03
            t_pkt(pkts, t, w, c, 6, 80, sport, 900)
            t += random.uniform(0.1, 0.4)
        elif r < 0.88:  # icmp ping to gateway
            t_pkt(pkts, t, c, GATEWAY, 1, 0, 0, 98); t += 0.02
            t_pkt(pkts, t, GATEWAY, c, 1, 0, 0, 98)
            t += random.uniform(0.2, 0.8)
        else:  # ntp
            sport = random.randint(49152, 65535)
            t_pkt(pkts, t, c, "162.159.200.1", 17, sport, 123, 90); t += 0.02
            t_pkt(pkts, t, "162.159.200.1", c, 17, 123, sport, 90)
            t += random.uniform(0.1, 0.6)
        t += random.uniform(0.05, 0.3) / intensity
    return t


def make_demo():
    pkts = []
    t = BASE + 0.0
    # 1) background browsing, 0-12s
    t = background(pkts, t, BASE + 12)
    # 2) SYN port scan 192.168.1.77 -> 10.0.0.15 at t=12..15
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465,
                  587, 993, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
    for i, port in enumerate(scan_ports):
        t_pkt(pkts, t, "192.168.1.77", "10.0.0.15", 6, 44440, port, 58)
        t += 0.12
        if i % 3 == 0:  # RST reply for closed port
            t_pkt(pkts, t, "10.0.0.15", "192.168.1.77", 6, port, 44440, 60)
            t += 0.01
    # 3) background again, 15-30s
    t = background(pkts, BASE + 15, BASE + 30)
    # 4) bulk rsync transfer (traffic spike) 192.168.1.20 -> NAS:873, ~350 KB/s for 6s
    sport = 51432
    spike_end = BASE + 36
    while t < spike_end:
        t_pkt(pkts, t, "192.168.1.20", NAS, 6, sport, 873, random.randint(1300, 1440))
        if random.random() < 0.12:
            t_pkt(pkts, t, NAS, "192.168.1.20", 6, 873, sport, 60)
        t += 0.004
    # 5) SYN flood 192.168.1.66 -> NAS:8080 at 36..40 (60+ half-open SYNs, one port)
    for i in range(70):
        t_pkt(pkts, t, "192.168.1.66", NAS, 6, 55555 + (i % 4), 8080, 58)
        t += 0.05
    # 6) tail traffic
    background(pkts, BASE + 40, BASE + 65)
    # 7) C2 beaconing: 192.168.1.31 -> 185.220.101.7:443 every 5s (blocklisted IP!)
    for i in range(13):
        t_pkt(pkts, BASE + 2 + i * 5, "192.168.1.31", "185.220.101.7", 6, 49231, 443,
              random.randint(64, 84))
    pkts.sort(key=lambda x: x[0])  # beacons were generated out of order
    write_pcap("samples/demo_traffic.pcap", pkts)


def make_quiet():
    pkts = []
    t = BASE + 0.0
    background(pkts, t, BASE + 30, intensity=0.5)
    write_pcap("samples/quiet.pcap", pkts)


if __name__ == "__main__":
    os.makedirs("samples", exist_ok=True)
    make_demo()
    make_quiet()
