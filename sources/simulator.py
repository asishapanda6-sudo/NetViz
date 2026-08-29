"""Synthetic traffic generator.

Produces a realistic mix of LAN background traffic (DNS, HTTPS, HTTP, SSH,
ICMP, NTP, mDNS) plus periodic scripted "incidents":
  * a port scan from a dodgy host          -> port-scan rule
  * a large rsync backup transfer          -> traffic-spike rule
  * a SYN flood against the NAS web server -> SYN-flood rule
  * a regular beacon to a known-bad C2 IP  -> beaconing + blocklist rules
"""
from __future__ import annotations

import random
import threading
import time

from sources.common import paced_wait

GATEWAY = "192.168.1.1"
NAS = "192.168.1.5"
ATTACKER = "192.168.1.66"
PRINTER = "192.168.1.90"
WORKSTATION = "192.168.1.20"
VICTIM_HOST = "192.168.1.99"
C2 = "185.220.101.7"          # listed in blocklist.txt
CLIENTS = ["192.168.1.2", "192.168.1.7", "192.168.1.9", "192.168.1.10",
           "192.168.1.12", "192.168.1.14", "192.168.1.18", "192.168.1.20",
           "192.168.1.23", "192.168.1.27", "192.168.1.31"]
WEB = ["142.250.185.78", "104.18.32.7", "151.101.1.69", "13.107.42.14",
       "204.79.197.203", "185.199.108.153", "5.9.11.24"]
NTP = "162.159.200.1"


class Simulator(threading.Thread):
    def __init__(self, engine, speed_fn, stop_event: threading.Event):
        super().__init__(daemon=True, name="simulator")
        self.engine = engine
        self.speed_fn = speed_fn
        self.stop_event = stop_event
        now = time.time()
        self._next_scan = now + 8.0
        self._next_spike = now + 20.0
        self._next_flood = now + 45.0
        self._next_beacon = now + 10.0
        self._beacon_seq = 0

    # ------------------------------------------------------------------ emit
    def emit(self, src, dst, proto, sport, dport, size, flags=None):
        pkt = {
            "ts": time.time(), "src": src, "dst": dst, "proto": proto,
            "sport": sport, "dport": dport, "len": size,
        }
        if flags:
            pkt["flags"] = flags
        self.engine.process(pkt)

    def wait(self, seconds):
        paced_wait(seconds, self.speed_fn, self.stop_event)

    # ------------------------------------------------------------------ flows
    def _dns(self):
        c = random.choice(CLIENTS)
        self.emit(c, GATEWAY, "UDP", random.randint(49152, 65535), 53, random.randint(74, 96))
        self.wait(random.uniform(0.01, 0.04))
        self.emit(GATEWAY, c, "UDP", 53, random.randint(49152, 65535), random.randint(110, 180))

    def _https_session(self):
        c = random.choice(CLIENTS)
        w = random.choice(WEB)
        sport = random.randint(49152, 65535)
        n = random.randint(3, 9)
        self.emit(c, w, "TCP", sport, 443, 60, flags="S")       # SYN
        for i in range(n):
            self.wait(random.uniform(0.01, 0.08))
            if i % 2 == 0:
                self.emit(c, w, "TCP", sport, 443, random.randint(120, 1400), flags="PA")
            else:
                self.emit(w, c, "TCP", 443, sport, random.randint(200, 1400), flags="PA")

    def _http(self):
        c = random.choice(CLIENTS)
        w = random.choice(WEB)
        sport = random.randint(49152, 65535)
        self.emit(c, w, "TCP", sport, 80, random.randint(200, 400), flags="PA")
        self.wait(0.03)
        self.emit(w, c, "TCP", 80, sport, random.randint(500, 1400), flags="PA")

    def _ssh(self):
        self.emit("192.168.1.10", NAS, "TCP", random.randint(49152, 65535), 22, random.randint(80, 300), flags="PA")
        self.wait(0.04)
        self.emit(NAS, "192.168.1.10", "TCP", 22, random.randint(49152, 65535), random.randint(80, 300), flags="PA")

    def _ping(self):
        a, b = random.sample(CLIENTS, 2) if len(CLIENTS) > 1 else (CLIENTS[0], GATEWAY)
        self.emit(a, b, "ICMP", None, None, 98)
        self.wait(0.02)
        self.emit(b, a, "ICMP", None, None, 98)

    def _ntp(self):
        c = random.choice(CLIENTS)
        self.emit(c, NTP, "UDP", random.randint(49152, 65535), 123, 90)
        self.wait(0.02)
        self.emit(NTP, c, "UDP", 123, random.randint(49152, 65535), 90)

    def _mdns(self):
        c = random.choice(CLIENTS)
        self.emit(c, "224.0.0.251", "UDP", 5353, 5353, random.randint(80, 240))

    def _background_once(self):
        r = random.random()
        if r < 0.44:
            self._https_session()
        elif r < 0.60:
            self._dns()
        elif r < 0.72:
            self._http()
        elif r < 0.80:
            self._ssh()
        elif r < 0.88:
            self._ping()
        elif r < 0.95:
            self._ntp()
        else:
            self._mdns()

    # ------------------------------------------------------------------ incidents
    def _do_scan(self):
        target = random.choice([NAS, PRINTER, random.choice(WEB), "10.0.0.15"])
        base_port = random.choice([20, 21, 22, 80, 443, 1000, 3000, 8000])
        n = random.randint(16, 32)
        src = ATTACKER if random.random() < 0.75 else random.choice(CLIENTS)
        for i in range(n):
            if self.stop_event.is_set():
                return
            self.emit(src, target, "TCP", 44440 + (i % 6), base_port + i * random.randint(1, 7),
                      random.randint(58, 74), flags="S")
            self.wait(random.uniform(0.07, 0.13))
        # a few reset responses for closed ports
        for i in range(0, min(n, 6)):
            self.emit(target, src, "TCP", base_port + i, 44440, 60, flags="RA")
            self.wait(0.02)

    def _do_spike(self):
        dur = random.uniform(5.0, 7.0)
        pps = 250
        step = 1.0 / pps
        end = time.time() + dur / max(self.speed_fn() or 1.0, 0.001)
        sport = random.randint(49152, 65535)
        while not self.stop_event.is_set() and time.time() < end:
            self.emit(WORKSTATION, NAS, "TCP", sport, 873, random.randint(1300, 1440), flags="PA")
            if random.random() < 0.12:
                self.emit(NAS, WORKSTATION, "TCP", 873, sport, 60, flags="A")
            self.wait(step)

    def _do_syn_flood(self):
        # 60-90 half-open SYNs against the NAS web-app port
        n = random.randint(60, 90)
        sport = 55555
        for i in range(n):
            if self.stop_event.is_set():
                return
            self.emit(ATTACKER, NAS, "TCP", sport + (i % 4), 8080, 60, flags="S")
            self.wait(random.uniform(0.03, 0.06))

    def _beacon_once(self):
        # compromised host checks in with the C2 every ~5s (low jitter)
        c = "192.168.1.31"
        self._beacon_seq += 1
        self.emit(c, C2, "TCP", 49231, 443, random.randint(60, 90), flags="PA")

    # ------------------------------------------------------------------ main
    def run(self):
        self.engine.add_alert("info", "info", "Simulation started",
                              "Synthetic LAN traffic with port scans, SYN floods, "
                              "C2 beaconing and bulk transfers.")
        while not self.stop_event.is_set():
            now = time.time()
            if now >= self._next_beacon:
                self._beacon_once()
                self._next_beacon = now + random.uniform(4.8, 5.4)
            if now >= self._next_scan:
                self._next_scan = now + random.uniform(25, 45)
                self._do_scan()
                continue
            if now >= self._next_spike:
                self._next_spike = now + random.uniform(45, 90)
                self._do_spike()
                continue
            if now >= self._next_flood:
                self._next_flood = now + random.uniform(70, 110)
                self._do_syn_flood()
                continue
            self._background_once()
            self.wait(random.uniform(0.05, 0.18))
