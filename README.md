# NetViz — Real-Time Network Traffic Visualizer

Captures network packets and turns them into a **live, moving visualization**
instead of raw text logs — making it easy to spot suspicious patterns like
port scans, SYN floods, C2 beaconing, or traffic spikes at a glance.

![stack](https://img.shields.io/badge/Python-Flask%20%2B%20scapy-3776ab) ![ui](https://img.shields.io/badge/UI-Canvas%2C%20zero--dependency-26c6da)

## Features

- **Packet capture** — three interchangeable sources:
  - 🧪 **Simulation** — synthetic LAN traffic (DNS, HTTPS, HTTP, SSH, ICMP, NTP)
    with periodic *scripted incidents* (port scans, SYN floods, C2 beaconing,
    bulk transfers), so the dashboard is alive with zero setup.
  - 📼 **PCAP replay** — replays `.pcap` captures at 0.25×–8× speed, looping
    optionally. Two samples are bundled in `samples/`. A dependency-free
    classic-pcap parser is built in; with `scapy` installed, `pcapng` and exotic
    link types work too.
  - 🔴 **Live capture** — sniffs a real interface via scapy (`sudo` required;
    a friendly alert appears in the UI if privileges are missing).
- **Live visualization** — animated force-directed graph:
  - **zoom / pan / fit**, draggable nodes
  - each **IP = a node** (internal hosts as rounded squares, external as circles,
    size ∝ traffic volume); 🌍 country flags when geolocation is available
  - each **connection = a color-coded, pulsing line** (color = protocol) with
    **travelling packet particles**
- **Node search** — search by IP, country or ISP; Enter jumps to the node.
- **IP information panel** — click any node: IP, internal/external, geo (country,
  city, ISP/AS), protocols, top ports, packet count, traffic volume, current
  rate, peers, related alerts, and a **risk status** (Normal / Watch / Suspicious).
- **Threat detection panel** — 8 rule-based detectors, clickable to locate the
  offending node, filterable by severity, exportable to **CSV**:

  | Rule | Logic (defaults) | Severity |
  |---|---|---|
  | 🎯 Possible port scan | ≥ 12 distinct ports on one target within 10 s | HIGH |
  | 📡 Possible host sweep | ≥ 15 distinct destinations from one source within 10 s | MEDIUM |
  | ⚡ Possible SYN flood | ≥ 40 half-open SYNs to one port within 10 s | HIGH |
  | 📶 Possible C2 beaconing | ≥ 12 regular isolated check-ins, jitter < 30%, non-benign port | HIGH |
  | ☠️ Known malicious IP | traffic with an IP from `blocklist.txt` | HIGH |
  | 🌍 Unusual destination | proxy/anonymizer IP (ip-api flag) | MEDIUM |
  | 📈 Traffic spike | throughput > 3× the 30 s rolling baseline **and** > 250 KB/s | HIGH |
  | 👁 Heuristic watch | node with > 25 peers or > 60 service ports | — |

  Thresholds are tunable constants at the top of `engine.py`.
- **Blocklist** — edit `blocklist.txt` (one IP/CIDR per line, `#` comments);
  it hot-reloads within ~5 s and flags matching nodes immediately.
- **Geolocation** — external IPs are enriched via the free ip-api.com batch API
  (no key; cached in `geo_cache.json`; degrades silently offline).
- **Export** — alerts → CSV, graph → PNG screenshot.
- **Beginner-friendly by design** — first-run tour, plain-language alerts
  ("💡 In simple words: …"), a live risk-summary pill on the graph
  ("🚨 2 suspicious devices"), and an in-app help guide (`?`).
- **Shortcuts** — `/` search · `F` fit view · `Space` pause · `Esc` close ·
  scroll = zoom · drag background = pan · drag node = reposition.

## Quick start

```bash
cd netviz
pip install -r requirements.txt
python app.py                 # → http://localhost:5001
```

The dashboard starts in **Simulation** mode immediately (press `?` in the top
bar for an in-app guide). Use the top bar to switch to a bundled pcap
(`demo_traffic.pcap` contains a scan, a SYN flood, beaconing to a blocklisted
C2 *and* a spike), replay your own capture, or go live:

```bash
sudo python app.py            # then pick "Live capture" (root needed to sniff)
```

Deployment (LAN demo / Render / Docker): see `DEPLOY.md`.
VS Code setup (Hinglish, step-by-step): see `SETUP_VSCODE.md`.
College submission: `PROJECT_REPORT.md` is a ready-made report skeleton
(abstract → architecture → test-case table → future scope) — fill in the
`[FILL: …]` markers and screenshots.

## Architecture

```
  simulator.py ─┐
  pcap_source.py├──▶ engine.py ──▶ app.py (Flask) ──▶ /api/stream (SSE, 1 Hz) ──▶ static/app.js
  live_source.py┘    aggregates      + /api/state        polling fallback         canvas graph,
                     + 8 detectors   + /api/node/<ip>                             panels, search
                                     │                                            zoom/pan, export
                                     └── geo_service.py ── ip-api.com (country/ISP/proxy flags)
```

- `engine.py` — thread-safe aggregation (nodes/edges/per-second throughput) and
  all detection rules. `selftest.py` feeds synthetic timelines through it and
  asserts every rule fires (and that bulk flows don't false-positive as
  beaconing): `python selftest.py`.
- `app.py` — HTTP + SSE API, source manager (start/stop/pause/speed).
- `geo_service.py` — optional IP geolocation enrichment, JSON-cached.
- `static/` — single-page dashboard, no external assets/CDNs.
- `tools/make_samples.py` — regenerates the bundled pcaps byte-by-byte
  (stdlib only, deterministic).

## API

| Endpoint | Description |
|---|---|
| `GET /api/state` | full snapshot: nodes (+geo), edges, alerts, stats |
| `GET /api/stream` | server-sent events, one snapshot per second |
| `GET /api/node/<ip>` | node detail: ports, peers, related alerts |
| `GET /api/samples` · `GET /api/ifaces` | bundled pcaps / capture interfaces |
| `POST /api/source` | `{type: sim\|pcap\|live, path?, iface?, loop?, speed?}` |
| `POST /api/control` | `{action: pause\|resume\|toggle\|clear\|clear_alerts\|speed, ...}` |

## Notes & limitations

- Live sniffing needs root/admin; the error is surfaced as an in-app alert.
- The built-in parser reads classic pcap (Ethernet/raw-IP, IPv4/IPv6, VLAN).
  Install scapy for pcapng or other link types.
- Geolocation uses the free ip-api.com tier (HTTP, 45 req/min, IPv4); it is
  optional and disabled silently when offline.
- Detection is heuristic by design — thresholds should be tuned to your
  baseline (constants at the top of `engine.py`).
