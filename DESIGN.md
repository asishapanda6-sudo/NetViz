# NetViz — Design System ("Neon HUD")

Design goal: a **sci-fi movie operations console** — the "target acquired"
interface from a cyberpunk film. Void black, neon cyan/magenta/lime, CRT
scanlines, a rotating radar sweep, angular cut-corner panels, HUD corner
brackets, a glitching wordmark. Here, glow *is* the language: threats light
up the screen like a movie hacking scene.

## Palette

| Token | Hex | Use |
|---|---|---|
| `--bg` | `#04060b` | void black (page + graph) |
| `--panel` | `rgba(7,12,20,.92)` | console panels |
| `--rim` | `#12384a` | panel borders (dark cyan steel) |
| `--ink` | `#dff6ff` | ice-white text |
| `--ink-dim` | `#8fb3c6` | secondary text |
| `--cyan` | `#00f0ff` | **primary neon** — brand, meters, rings, sweep |
| `--magenta` | `#ff2ec4` | external/internet nodes, DNS |
| `--lime` | `#b6ff00` | "normal" status, UDP |
| `--danger` | `#ff3860` | HIGH severity, target-lock rings |
| `--warn` | `#ffb800` | MEDIUM severity, watch rings |

## Signature effects

- **CRT scanlines** — `body::after` repeating-linear-gradient over the whole
  app (pointer-events: none). The screen feels physical.
- **Radar sweep** — a fading cyan beam rotates from the graph center
  (26 fanned lines, alpha falloff) — drawn in canvas each frame.
- **Neon orbs** — nodes are void-black cores with a glowing protocol-colored
  ring (`shadowBlur`) and a hot center dot; internal hosts are **hexagons**,
  external are circles.
- **Target lock** — suspicious nodes get a **rotating dashed red ring** plus a
  pulsing outer ring, like a missile lock in a movie.
- **Neon beams** — edges drawn twice: wide translucent glow pass + thin bright
  core pass; packet particles glow as they travel.
- **Glitch wordmark** — the NETVIZ title occasionally splits into cyan and
  magenta offset layers (pure CSS, `clip-path` slices + steps() animation).
- **HUD chrome** — cut-corner buttons (`clip-path`), corner brackets on the
  info card and help modal (`::before/::after` L-borders), glow-on-hover.

## Performance guards

Node glow (`shadowBlur`) auto-disables above 180 nodes; the radar sweep is 26
cheap lines; edges use two-pass strokes instead of per-edge shadows.

## Data colors (neon, high-saturation on void)

`DNS #ff2ec4 · HTTPS #00f0ff · HTTP #ffb800 · SSH #ff3860 · TCP #4d7cff ·
UDP #b6ff00 · ICMP #ff6ec7 · RSYNC #ffd166 · NTP #00ffd0 · mDNS #c77dff ·
mail-family #ff9e7a · DB #d08bff · OTHER #5f7d95`

## Where what lives

- Tokens + effects: `static/style.css` (`body::before/::after`, glitch keyframes)
- Protocol colors: `PROTO_COLORS` in `static/app.js`
- Radar sweep / neon orbs / target lock / beam edges: `render()` in
  `static/app.js`
