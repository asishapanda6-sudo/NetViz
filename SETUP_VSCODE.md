# NetViz — VS Code Setup Guide (Step by Step)

Is guide me se aap project ko apne laptop/PC par VS Code me chalane ke saare steps milenge.

---

## PART 1 — One-time installation (sirf ek baar)

### Step 1: Python install karo
1. https://www.python.org/downloads/ pe jao → **Download Python 3.1x**
2. Installer kholo → **Windows** pe ☑ "Add Python to PATH" **zaroor tick karo** (bahut important!)
3. Install → Finish
4. Check karo: `cmd` kholo (Windows key → type cmd → Enter) aur type:
   ```
   python --version
   ```
   Output kuch aisa aana chahiye: `Python 3.12.x`

### Step 2: VS Code install karo
1. https://code.visualstudio.com/ → **Download** → install karo
2. VS Code kholo → left sidebar me **Extensions** icon (4 boxes wala) → search **Python** → Microsoft wala → **Install**

### Step 3 (Windows only, LIVE capture ke liye baad me)
Live sniffing ke liye **Npcap** chahiye: https://npcap.com/#download → install (default options ok).
Simulation aur PCAP replay ke liye ye zaroori NAHI hai.

---

## PART 2 — Project ko VS Code me laao

### Step 4: Download + Extract
1. Chat se **`netviz.zip`** download karo
2. Right-click → **Extract All** (Windows) / double-click (Mac) → jaise `C:\Projects\netviz` ya `Desktop\netviz`

### Step 5: VS Code me folder kholo
1. VS Code → **File → Open Folder** → `netviz` folder select karo
2. "Do you trust the authors?" → **Yes, I trust the authors**

Left sidebar (Explorer) me aisa dikhega:
```
netviz/
├── app.py              ← main server (ise run karte hain)
├── engine.py           ← traffic aggregation + threat detection rules
├── selftest.py         ← engine ka automated test
├── requirements.txt    ← libraries list
├── sources/
│   ├── simulator.py    ← fake traffic generator
│   ├── pcap_source.py  ← .pcap file replay
│   └── live_source.py  ← real interface capture (scapy)
├── static/             ← dashboard (HTML/CSS/JS)
├── samples/            ← demo .pcap files
└── tools/make_samples.py
```

---

## PART 3 — Libraries install karo

### Step 6: VS Code ka terminal kholo
Menu: **Terminal → New Terminal** (ya shortcut: **Ctrl + `**)

### Step 7: Virtual environment banao (good practice)
Terminal me type karo:
```
python -m venv .venv
```
Phir activate:
- **Windows:**
  ```
  .venv\Scripts\activate
  ```
- **Mac/Linux:**
  ```
  source .venv/bin/activate
  ```
Terminal ke aage `(.venv)` likha dikh jayega = activated ✓

### Step 8: Libraries install karo
```
pip install -r requirements.txt
```
(Flask + scapy install honge, 1-2 minute lagenge)

---

## PART 4 — Project CHALAO 🚀

### Step 9: Server start karo
```
python app.py
```
Aisa output aayega:
```
 * Running on http://127.0.0.1:5001
```

### Step 10: Browser me kholo
Chrome/Edge me jao → **http://localhost:5001**

Done! Graph chalne lagega — nodes ghumte dikhaenge, connections pulse karenge. 🎉

### Step 11: Rokne ke liye
Terminal me **Ctrl + C**

---

## PART 5 — Sab kuch test karo (report/demo ke liye)

| Test | Kaise | Expected result |
|---|---|---|
| Engine self-test | `python selftest.py` | `SELFTEST PASSED` (all 3 rules ✓) |
| Simulation | Top bar me "Simulation" → Start | Moving graph, alerts aayenge (scan ~25-45s me) |
| PCAP replay | Dropdown me `demo_traffic.pcap` → Start, speed 2× | Port scan + traffic spike alerts |
| Apna pcap | Wireshark/tcpdump se capture → "custom path" me select | Apna real traffic dikhega |
| Node info | Kisi node pe **click** | Right side panel: IP, ports, volume, risk |
| Alerts | Left panel | Click alert → suspect node highlight |

---

## LIVE capture (real network) — optional

1. **Windows:** VS Code ko **"Run as administrator"** se kholo (aur Npcap installed ho)
   **Mac/Linux:** `sudo python app.py`
2. Dropdown me **"🔴 Live capture"** → apna interface type karo (`eth0` / `wlan0` / `Wi-Fi`) → Start
3. Permission error aaye to UI me alert dikhega — ise report me "limitation" bata sakte ho

---

## Common problems (Troubleshooting)

| Problem | Fix |
|---|---|
| `python is not recognized` | Python reinstall karo, ☑ "Add to PATH" tick karo, ya `py` try karo |
| `pip is not found` | `python -m pip install -r requirements.txt` |
| `Address already in use` / port busy | `set PORT=5002` (Windows) phir `python app.py` |
| Page blank / not opening | Terminal me error dekho; browser refresh; `http://localhost:5001` spelling check |
| Live capture failed | Admin/sudo me chalao + Npcap (Windows) |
| Scapy slow on Wi-Fi | BPF filter use karo, ya wired interface lo |

---

## Code me khelna (customize)

- **Detection thresholds badalna:** `engine.py` file kholo → top me constants:
  - `SCAN_PORTS_THRESHOLD = 12` → 20 kar do (kam false alarms)
  - `SPIKE_FACTOR = 3.0` → 5.0 kar do
- **Simulation ke attack hosts badalna:** `sources/simulator.py` → `ATTACKER`, `NAS`, etc.
- **Colors badalna:** `static/app.js` → `PROTO_COLORS`
- Save karo (**Ctrl+S**) → browser refresh → change dikhega

Run commands summary:
```
python -m venv .venv          # ek baar
.venv\Scripts\activate        # har baar VS Code terminal kholne par (Windows)
pip install -r requirements.txt   # ek baar (ya requirements badalne par)
python app.py                 # server start
```
