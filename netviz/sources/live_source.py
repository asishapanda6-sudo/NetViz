"""Live interface capture using scapy (requires root/administrator)."""
from __future__ import annotations

import time


def list_ifaces():
    ifaces = []
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name = line.split(":", 1)[0].strip()
                if name:
                    ifaces.append(name)
    except OSError:
        pass
    if not ifaces:
        try:
            from scapy.config import conf
            ifaces = [str(i) for i in conf.ifaces]
        except Exception:  # noqa: BLE001
            pass
    return ifaces


def start_live(engine, iface=None, bpf=""):
    try:
        from scapy.all import AsyncSniffer
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
    except ImportError:
        engine.add_alert("error", "high", "Live capture unavailable",
                         "scapy is not installed. Run: pip install scapy")
        raise RuntimeError("scapy is not installed")

    def cb(pkt):
        try:
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            if ip is None:
                return
            sp = dp = None
            pr = None
            flags = None
            t = pkt.getlayer(TCP)
            u = pkt.getlayer(UDP)
            if t is not None:
                sp, dp, pr = int(t.sport), int(t.dport), "TCP"
                flags = str(t.flags)
            elif u is not None:
                sp, dp, pr = int(u.sport), int(u.dport), "UDP"
            elif pkt.getlayer("ICMP") is not None:
                pr = "ICMP"
            else:
                return
            engine.process({
                "ts": time.time(), "src": ip.src, "dst": ip.dst, "proto": pr,
                "sport": sp, "dport": dp, "len": len(pkt), "flags": flags,
            })
        except Exception:  # noqa: BLE001
            pass

    try:
        sniffer = AsyncSniffer(iface=iface or None, filter=bpf or None, prn=cb, store=False)
        sniffer.start()
    except Exception as e:  # noqa: BLE001
        engine.add_alert(
            "error", "high", "Live capture failed",
            f"{type(e).__name__}: {e} — live sniffing usually needs root/admin "
            f"privileges (try: sudo python app.py).")
        raise
    return sniffer
