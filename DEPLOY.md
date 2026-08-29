# NetViz — Deployment Guide (3 options, easiest first)

Deploy = project ko localhost se bahar laana, taaki do log bhi khul sakein.
Aapke project me `Dockerfile`, `render.yaml` aur `gunicorn` support already ready hai. 👍

---

## Option A — Same WiFi / College Lab (LAN demo) ⭐ demo day ke liye best

Koi cloud nahi, 2 minute ka kaam:

1. Apne laptop pe project chalao:
   ```
   python app.py
   ```
2. Apna IP pata karo (naya cmd kholo):
   - **Windows:** `ipconfig` → "IPv4 Address" dekho (jaise `192.168.1.5`)
   - **Mac/Linux:** `ifconfig | grep inet` ya `ip addr`
3. Same WiFi wale kisi bhi device (phone/laptop) pe ye kholo:
   ```
   http://192.168.1.5:5001      ← apna IP daalo
   ```
4. Windows firewall poochhe to **Allow** (Private networks ✓) kar do.

✅ Teacher ke laptop, sabke phones — sab pe live graph chalega.
❌ Ghar se / mobile data se NAHI khulega (wo Option B me aata hai).

---

## Option B — Public link (Render.com FREE) ⭐ resume/link ke liye best

Internet par permanent link: `https://netviz-xxxx.onrender.com`

### Step 1: GitHub pe code daalo
GitHub.com → New repository (`netviz`, **Private** bhi chalega) → phir project folder me:
```
git init
git add .
git commit -m "NetViz - Real-Time Network Traffic Visualizer"
git branch -M main
git remote add origin https://github.com/TUMHARA_USERNAME/netviz.git
git push -u origin main
```
(Git na ho to git-scm.com se install karo)

### Step 2: Render pe deploy
1. https://render.com → **Get Started** (free sign-up, GitHub se login)
2. Dashboard → **New +** → **Blueprint** → apna `netviz` repo select karo
   → `render.yaml` auto-detect ho jayega → **Apply**
   (Ya manually: **New + → Web Service** → repo connect → settings:
   Runtime: **Python** · Build: `pip install -r requirements.txt` ·
   Start: `gunicorn -w 1 --threads 8 --timeout 0 -b 0.0.0.1:$PORT app:app` · Instance: **Free**)
3. 3-5 minute build → URL mil jayega 🎉 → link kahi bhi share karo

### Notes (important)
- **Free plan**: 15 min idle pe sleep ho jata hai → pehla open ~30s slow hota hai (refresh karo). Demo se pehle khol ke warm kar lo.
- HTTPS automatically milta hai (lock 🔒 wala) — lock lagta hai resume me.
- **Cloud pe "Live capture" mode NAHI chalega** (server ke paas aapka LAN interface nahi hota) — Simulation + PCAP replay fully work karte hain. Viva me bolo: *"live capture is designed for on-premise deployment"* 😎
- Railway.app pe bhi same commands se ho jata hai (alternative).

---

## Option C — Docker (VPS / college server / any cloud)

Server pe (ya jahan Docker installed ho):
```
docker build -t netviz .
docker run -d -p 5001:5001 --name netviz netviz
```
→ `http://SERVER_IP:5001`

Band karne: `docker stop netviz` · Update: dobara build+run

---

## Kaunsa choose karein?

| Situation | Option |
|---|---|
| College demo / viva (sab same WiFi pe) | **A — LAN** |
| Resume me link / kisi ko bhejna hai | **B — Render free** |
| Company-style deployment dikhana hai | **C — Docker** (viva me extra marks 😄) |

## Viva one-liner

> "It runs with Flask's dev server for development, **gunicorn** for production,
> ships as a **Docker** container, and has a one-click **Render blueprint** —
> so it deploys the same way on a laptop, a lab server, or the cloud."
