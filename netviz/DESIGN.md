# NetViz — Design System ("Ledger")

Design goal: the opposite of the typical "AI dashboard." A **printed
instrument sheet** come alive — paper white, ink black, one signal red.
Serif headings, mono data labels, hairline rules, sharp corners. Everything
crisp and flat, like a Swiss technical drawing or a quality broadsheet
graphic. The graph is a **technical diagram**: white plate nodes with
protocol-colored rings and ink core dots — no glow, no glass, no gradients.

## Palette

| Token | Hex | Use |
|---|---|---|
| `--paper` | `#f6f5f1` | page + graph background (warm paper) |
| `--panel` | `#ffffff` | panels, cards, buttons |
| `--panel-2` | `#f1efe9` | inset surfaces (kv tiles, alert hovers) |
| `--line` | `#dcd8cd` | hairline rules |
| `--line-strong` | `#1c1e22` | structural rules (top bar, panel heads, inputs) |
| `--ink` | `#1c1e22` | primary text |
| `--ink-dim` | `#575c63` | secondary text |
| `--ink-faint` | `#8b9097` | captions, hints |
| `--accent` | `#d7263d` | **signal red** — live dot, brand mark, HIGH severity, suspicious rings |
| `--ok` | `#2e7d4f` | normal status |
| `--warn` | `#b0730a` | MEDIUM severity, watch rings |
| `--info` | `#2f639f` | info alerts, internal-network chips |

Only one loud color exists (signal red), and it means *threat* — so alerts
are impossible to miss on the quiet paper surface.

## Typography

- **Headings** (brand, panel titles, modal titles): Georgia serif — the
  editorial signature no AI dashboard uses.
- **Data + labels + buttons**: ui-monospace, uppercase, letter-spaced —
  instrument readout feel.
- Body: system sans, ink gray.

## The graph (canvas)

- Nodes are drawn like diagram symbols: **white plate + 2px protocol-color
  ring + solid core dot** (internal hosts = rounded squares, external =
  circles). Hover/selection thickens the ring in ink.
- Edges: protocol-colored ink lines; active ones pulse, particles travel as
  colored dots.
- Background: paper with a fine dot grid (like graph paper); no vignette.
- Risk rings: signal red (suspicious) / amber (watch).

## Data colors (light-bg safe, print-like)

`DNS #7c5cb0 · HTTPS #0e7c9c · HTTP #c2810a · SSH #c0392b · TCP #2f639f ·
UDP #557c2f · ICMP #ad4a86 · RSYNC #8a6d3b · NTP #2d7d78 · mDNS #8d5aa8 ·
mail-family #b25b3f · DB #6f4fa0 · OTHER #6e7681`

## Surface rules

- Flat white panels, 1px ink/hairline borders, 2–4px corner radius.
- Shadows only on floating layers (tooltip inverted ink, modals, info card).
- Buttons: mono uppercase; primary = ink fill → red on hover.
- No gradients, no blur, no glow, no neon.

## Where what lives

- Tokens + typography: `:root` in `static/style.css`
- Protocol colors: `PROTO_COLORS` in `static/app.js`
- Node diagram rendering: the "technical node" block in `render()` in
  `static/app.js`
