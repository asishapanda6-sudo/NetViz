# NetViz — Design System ("Ember NOC")

Design goal: a **network operations terminal** look — warm charcoal surfaces,
one amber instrument accent, flat panels with hairline borders, mono-caps
labels. Deliberately avoids the generic "dark blue + purple/cyan glow" combo.

## Palette

| Token | Hex | Use |
|---|---|---|
| `--bg` | `#14110d` | page / graph background (warm near-black) |
| `--panel` | `#1a1611` | panels (alerts, top bar) |
| `--panel-2` | `#201b14` | cards, inputs, alert rows |
| `--field` | `#241f17` | form fields |
| `--line` | `#322c22` | borders |
| `--ink` | `#e8e2d4` | primary text (warm off-white) |
| `--ink-dim` | `#a89f8d` | secondary text |
| `--ink-faint` | `#6e685a` | captions, hints |
| `--accent` | `#e0a33e` | **amber** — brand, primary buttons, IP headings, sparkline |
| `--accent-ink` | `#211809` | text on amber |
| `--ok` | `#7fb069` | sage green — "normal" status |
| `--danger` | `#e05252` | HIGH severity, suspicious rings |
| `--warn` | `#d9822b` | MEDIUM severity, watch rings |
| `--info` | `#6d9bc9` | steel blue — info alerts |
| `--sage` | `#57b8a0` | internal-network nodes & chips |
| `--sand` | `#d9b36a` | external/internet nodes & chips |

## Data colors (protocol lines on the graph)

Harmonized, medium-saturation, warm-leaning:

`DNS #a890c8 · HTTPS #57b8a0 · HTTP #e0a33e · SSH #e05252 · TCP #6d9bc9 ·
UDP #9cb85e · ICMP #d475a8 · RSYNC #d4bd6e · NTP #7ec4c9 · mDNS #c98fc4 ·
mail-family #d98a5f · DB #a876c9 · OTHER #8d8778`

## Typography rules

- Section headers / captions / severities: **ui-monospace, UPPERCASE, tracked
  out** (`letter-spacing ≈ 1px`) — gives the "instrument" feel.
- IPs, ports, numbers: monospace, tabular numerals.
- Body copy: system sans, warm off-white.

## Surface rules

- Flat fills only — **no gradients, no glass blur, no neon glow**.
- 6–10 px radii, 1 px hairline borders (`--line`), shadows only for floating
  layers (tooltip, modals, info panel).
- One accent color (amber) used sparingly: brand, primary action, IP address,
  throughput sparkline. Everything else stays neutral so *alert colors pop*.

## Where what lives

- All tokens: `:root` at the top of `static/style.css`
- Protocol/data colors: `PROTO_COLORS` in `static/app.js`
- Canvas (graph) colors: `render()` in `static/app.js` (background vignette,
  grid dots, rings) — kept in sync with the CSS tokens above.
