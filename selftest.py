"""Engine self-test: feeds synthetic timelines (no sleeping) through the
engine and asserts that every detection rule fires.

Usage: python selftest.py
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, ".")

from engine import Engine  # noqa: E402

# Use a realistic wall-clock base so risk-expiry checks (which compare against
# time.time()) behave exactly as they do in production.
T0 = time.time()


def feed_baseline(e):
    # ~35 seconds at ~100 KB/s (continuous bulk flow — must NOT look like beaconing)
    for sec in range(35):
        for i in range(100):
            e.process({"ts": T0 + sec + i * 0.009, "src": "192.168.1.10",
                       "dst": "93.184.216.34", "proto": "TCP",
                       "sport": 51000, "dport": 443, "len": 1000, "flags": "PA"})
        e.tick(T0 + sec + 1)


def feed_spike(e):
    # ~3 seconds at ~800 KB/s
    for sec in range(35, 38):
        for i in range(570):
            e.process({"ts": T0 + sec + i * 0.00175, "src": "192.168.1.20",
                       "dst": "192.168.1.5", "proto": "TCP",
                       "sport": 51432, "dport": 873, "len": 1400, "flags": "PA"})
        e.tick(T0 + sec + 1)


def feed_scan(e):
    s = T0 + 40
    for j, port in enumerate(range(100, 140)):
        e.process({"ts": s + j * 0.12, "src": "203.0.113.7", "dst": "10.0.0.9",
                   "proto": "TCP", "sport": 40000, "dport": port, "len": 60, "flags": "S"})


def feed_sweep(e):
    s = T0 + 50
    for j in range(20):
        e.process({"ts": s + j * 0.2, "src": "198.51.100.9",
                   "dst": f"192.168.1.{j + 2}", "proto": "TCP",
                   "sport": 40001, "dport": 445, "len": 60, "flags": "S"})


def feed_syn_flood(e):
    s = T0 + 60
    for j in range(50):
        e.process({"ts": s + j * 0.05, "src": "192.168.1.66", "dst": "192.168.1.5",
                   "proto": "TCP", "sport": 55555, "dport": 8080, "len": 60, "flags": "S"})


def feed_beacon(e):
    s = T0 + 80
    for j in range(14):
        e.process({"ts": s + j * 5.0, "src": "192.168.1.31", "dst": "45.33.10.2",
                   "proto": "TCP", "sport": 49231, "dport": 443, "len": 74, "flags": "PA"})


def main():
    e = Engine()
    assert not e.blocklist_nets, "default engine should load without a blocklist"

    feed_baseline(e)
    assert not [a for a in e.alerts if a["kind"] == "traffic_spike"], "false spike during baseline"
    assert not [a for a in e.alerts if a["kind"] == "beaconing"], "false beacon during bulk baseline"

    feed_spike(e)
    assert [a for a in e.alerts if a["kind"] == "traffic_spike"], "spike not detected"
    print("  ✓ traffic_spike detected:", e.alerts[0]["title"])

    feed_scan(e)
    scan = [a for a in e.alerts if a["kind"] == "port_scan"]
    assert scan, "port scan not detected"
    print("  ✓ port_scan detected:", scan[0]["title"], "—", scan[0]["detail"])

    feed_sweep(e)
    sweep = [a for a in e.alerts if a["kind"] == "host_sweep"]
    assert sweep, "host sweep not detected"
    print("  ✓ host_sweep detected:", sweep[0]["title"])

    feed_syn_flood(e)
    flood = [a for a in e.alerts if a["kind"] == "syn_flood"]
    assert flood, "SYN flood not detected"
    print("  ✓ syn_flood detected:", flood[0]["title"])

    feed_beacon(e)
    beacon = [a for a in e.alerts if a["kind"] == "beaconing"]
    assert beacon, "C2 beaconing not detected"
    print("  ✓ beaconing detected:", beacon[0]["title"], "—", beacon[0]["detail"])

    # blocklist: temp file with a /24 that covers one endpoint
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("# test blocklist\n198.51.100.0/24\n")
        path = f.name
    try:
        eb = Engine(blocklist_path=path)
        assert eb.load_blocklist() == 1
        eb.process({"ts": time.time(), "src": "10.0.0.1", "dst": "198.51.100.50",
                    "proto": "TCP", "sport": 51000, "dport": 443, "len": 100})
        blocked = [a for a in eb.alerts if a["kind"] == "blocklist"]
        assert blocked, "blocklisted IP not flagged"
        detail = eb.node_detail("198.51.100.50")
        assert detail["risk"]["level"] == "suspicious"
        assert detail["risk"]["reasons"], "blocklist reason missing"
        print("  ✓ blocklist detected:", blocked[0]["title"], "| node risk = suspicious")
    finally:
        os.unlink(path)

    snap = e.snapshot()
    assert snap["nodes"] and snap["edges"] and snap["stats"]["total_pkts"] > 0
    ips = {n["ip"] for n in snap["nodes"]}
    assert "203.0.113.7" in ips and "45.33.10.2" in ips
    detail = e.node_detail("203.0.113.7")
    assert detail and detail["risk"]["level"] == "suspicious"
    assert detail["alerts"], "scanner node should reference its alert"
    print(f"  ✓ snapshot OK: {len(snap['nodes'])} nodes, {len(snap['edges'])} edges, "
          f"{len(snap['alerts'])} alerts; scanner risk = {detail['risk']['level']}")

    e.clear()
    assert not e.nodes and not e.alerts
    print("  ✓ clear() OK")
    print("SELFTEST PASSED")


if __name__ == "__main__":
    main()
