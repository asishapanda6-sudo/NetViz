"""NetViz — Real-Time Network Traffic Visualizer.

Serves the dashboard and a JSON API:
  GET  /                dashboard
  GET  /api/state       full snapshot (nodes, edges, alerts, stats)
  GET  /api/stream      server-sent events, 1 snapshot/sec
  GET  /api/node/<ip>   per-node detail
  GET  /api/samples     bundled pcap files
  GET  /api/ifaces      available capture interfaces
  POST /api/source      {type: sim|pcap|live, path?, iface?, bpf?, loop?, speed?}
  POST /api/control     {action: pause|resume|toggle|clear|clear_alerts|speed, ...}
"""
from __future__ import annotations

import json
import os
import threading
import time

from flask import Flask, Response, jsonify, request, send_from_directory

from engine import Engine
from sources.live_source import list_ifaces, start_live
from sources.pcap_source import Replayer
from sources.simulator import Simulator

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

app = Flask(__name__, static_folder=os.path.join(BASE_DIR, "static"), static_url_path="/static")
ENGINE = Engine(blocklist_path=os.path.join(BASE_DIR, "blocklist.txt"))


# ------------------------------------------------------------------ manager
class Manager:
    """Owns the currently active traffic source thread."""

    def __init__(self):
        self.lock = threading.Lock()
        self.engine = ENGINE
        self.kind = None
        self.label = "—"
        self.detail = ""
        self.speed = 1.0
        self.paused = False
        self._stop = None
        self.thread = None
        self.handle = None  # e.g. scapy sniffer

    def speed_fn(self):
        return 0.0 if self.paused else self.speed

    def stop_source(self):
        with self.lock:
            stop, th, handle = self._stop, self.thread, self.handle
            self._stop = self.thread = self.handle = None
            self.kind = None
            self.label = "—"
            self.detail = ""
        if stop:
            stop.set()
        if th:
            th.join(timeout=3.0)
        if handle:
            try:
                handle.stop()
            except Exception:  # noqa: BLE001
                pass

    def start(self, kind: str, **opts):
        self.stop_source()
        stop = threading.Event()
        with self.lock:
            self._stop = stop
        if kind == "sim":
            with self.lock:
                self.kind, self.label, self.detail = "sim", "Simulation", "synthetic LAN traffic"
            self.thread = Simulator(self.engine, self.speed_fn, stop)
            self.thread.start()
            return True, ""
        if kind == "pcap":
            path = opts.get("path", "")
            if not os.path.isfile(path):
                return False, f"file not found: {path}"
            with self.lock:
                self.kind = "pcap"
                self.label = "PCAP replay"
                self.detail = os.path.basename(path)
            self.thread = Replayer(self.engine, path, self.speed_fn, stop,
                                   loop=bool(opts.get("loop", True)))
            self.thread.start()
            return True, ""
        if kind == "live":
            iface = (opts.get("iface") or "").strip() or None
            try:
                self.handle = start_live(self.engine, iface, opts.get("bpf", ""))
            except Exception:  # noqa: BLE001
                with self.lock:
                    self.kind, self.label, self.detail = None, "—", ""
                return False, "live capture failed to start (see alerts panel)"
            with self.lock:
                self.kind = "live"
                self.label = "Live capture"
                self.detail = iface or "all interfaces"
            return True, ""
        return False, f"unknown source type: {kind}"

    def meta(self):
        with self.lock:
            return {
                "source": {"kind": self.kind, "label": self.label, "detail": self.detail},
                "running": self.kind is not None and not self.paused,
                "paused": self.paused,
                "speed": self.speed,
            }


MGR = Manager()


# ------------------------------------------------------------------ routes
@app.get("/")
def index():
    return send_from_directory(os.path.join(BASE_DIR, "static"), "index.html")


@app.get("/api/health")
def health():
    return jsonify({"ok": True})


@app.get("/api/state")
def api_state():
    return jsonify(ENGINE.snapshot(meta=MGR.meta()))


@app.get("/api/stream")
def api_stream():
    def gen():
        try:
            while True:
                data = ENGINE.snapshot(meta=MGR.meta())
                yield "event: state\ndata: " + json.dumps(data, separators=(",", ":")) + "\n\n"
                time.sleep(1.0)
        except GeneratorExit:
            pass

    resp = Response(gen(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


@app.get("/api/node/<ip>")
def api_node(ip):
    detail = ENGINE.node_detail(ip)
    if detail is None:
        return jsonify({"error": "unknown node"}), 404
    return jsonify(detail)


@app.get("/api/samples")
def api_samples():
    out = []
    if os.path.isdir(SAMPLES_DIR):
        for name in sorted(os.listdir(SAMPLES_DIR)):
            if name.lower().endswith((".pcap", ".pcapng", ".cap")):
                p = os.path.join(SAMPLES_DIR, name)
                out.append({"name": name, "path": p,
                            "size": os.path.getsize(p)})
    return jsonify(out)


@app.get("/api/ifaces")
def api_ifaces():
    return jsonify(list_ifaces())


@app.post("/api/source")
def api_source():
    body = request.get_json(force=True, silent=True) or {}
    kind = body.get("type")
    if "speed" in body:
        try:
            MGR.speed = float(body["speed"])
        except (TypeError, ValueError):
            pass
    ENGINE.clear()
    ok, err = MGR.start(kind, **{k: v for k, v in body.items() if k != "type"})
    if not ok:
        return jsonify({"ok": False, "error": err}), 400
    return jsonify({"ok": True, **MGR.meta()})


@app.post("/api/control")
def api_control():
    body = request.get_json(force=True, silent=True) or {}
    action = body.get("action")
    if action == "pause":
        MGR.paused = True
    elif action == "resume":
        MGR.paused = False
    elif action == "toggle":
        MGR.paused = not MGR.paused
    elif action == "clear":
        ENGINE.clear()
    elif action == "clear_alerts":
        ENGINE.clear_alerts()
    elif action == "speed":
        try:
            MGR.speed = max(0.1, min(16.0, float(body.get("speed", 1.0))))
        except (TypeError, ValueError):
            pass
    else:
        return jsonify({"ok": False, "error": "unknown action"}), 400
    return jsonify({"ok": True, **MGR.meta()})


# ------------------------------------------------------------------ main
def _ticker():
    while True:
        ENGINE.tick()
        time.sleep(1.0)


_started = False
_start_lock = threading.Lock()


def ensure_started():
    """Start background threads + the default traffic source exactly once.
    Works both with `python app.py` and gunicorn (app:app)."""
    global _started
    with _start_lock:
        if _started:
            return
        _started = True
        os.makedirs(SAMPLES_DIR, exist_ok=True)
        threading.Thread(target=_ticker, daemon=True, name="engine-ticker").start()
        from geo_service import GeoService
        GeoService(ENGINE).start()
        MGR.start("sim")  # start with the simulator so the dashboard is alive immediately


@app.before_request
def _lazy_start():
    ensure_started()


def main():
    ensure_started()
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
