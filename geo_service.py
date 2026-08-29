"""IP geolocation enrichment service (optional, degrades gracefully offline).

Uses the free ip-api.com batch endpoint (no API key, 45 req/min limit) to add
country / city / ISP / ASN / proxy / hosting info to external IPs. Results are
cached in geo_cache.json so restarts don't re-query.

If the network is unavailable the service backs off and posts one info alert.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.request

API = "http://ip-api.com/batch?fields=status,message,query,country,countryCode,city,isp,as,proxy,hosting"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_PATH = os.path.join(BASE_DIR, "geo_cache.json")


class GeoService(threading.Thread):
    def __init__(self, engine, interval: float = 12.0):
        super().__init__(daemon=True, name="geo-service")
        self.engine = engine
        self.interval = interval
        self._failures = 0
        self._warned = False
        self._load_cache()

    # ------------------------------------------------------------------ cache
    def _load_cache(self):
        try:
            with open(CACHE_PATH, encoding="utf-8") as f:
                data = json.load(f)
            for ip, d in data.items():
                self.engine.set_geo(ip, d)
        except (OSError, ValueError):
            pass

    def _save_cache(self):
        try:
            with self.engine.lock:
                snap = dict(self.engine.geo)
            tmp = CACHE_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snap, f)
            os.replace(tmp, CACHE_PATH)
        except OSError:
            pass

    # ------------------------------------------------------------------ loop
    def run(self):
        while True:
            if not self.engine.geo_enabled:
                time.sleep(60)
                continue
            delay = self.interval if self._failures == 0 else min(120.0, 30.0 * self._failures)
            time.sleep(delay)
            ips = self.engine.uncached_external_ips(limit=60)  # stays under rate limit
            if not ips:
                continue
            try:
                body = json.dumps([{"query": ip} for ip in ips]).encode()
                req = urllib.request.Request(API, data=body,
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    results = json.loads(resp.read().decode())
            except Exception:  # noqa: BLE001 — offline / rate-limited
                self._failures += 1
                if self._failures == 2 and not self._warned:
                    self._warned = True
                    self.engine.add_alert(
                        "info", "info", "Geolocation unavailable",
                        "Could not reach ip-api.com (offline or blocked). "
                        "Country flags and ISP info are disabled; detection is unaffected.")
                continue
            self._failures = 0
            for r in results:
                if not isinstance(r, dict) or r.get("status") != "success":
                    continue
                ip = r.get("query")
                if not ip:
                    continue
                self.engine.set_geo(ip, {
                    "country": r.get("country"),
                    "code": r.get("countryCode"),
                    "city": r.get("city"),
                    "isp": r.get("isp"),
                    "as": r.get("as"),
                    "proxy": bool(r.get("proxy")),
                    "hosting": bool(r.get("hosting")),
                })
            self._save_cache()
