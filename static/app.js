/* NetViz dashboard — live animated network graph.
 * Data: snapshots from /api/stream (SSE) + polling heartbeat fallback.
 * Rendering: canvas 2D, custom force-directed layout in WORLD coordinates
 * with pan/zoom, protocol-coloured pulsing links and travelling particles.
 * Extras: node search, CSV/PNG export, geo flags, help modal, shortcuts.
 */
'use strict';

/* ---------------------------------------------------------------- helpers */
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

function humanBytes(n) {
  if (n == null || isNaN(n)) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
}
function humanBps(b) {
  let v = (b || 0) * 8;
  const u = ['bps', 'Kbps', 'Mbps', 'Gbps'];
  let i = 0;
  while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
  return (i ? v.toFixed(1) : Math.round(v)) + ' ' + u[i];
}
function fmtTime(ts) { return new Date(ts * 1000).toLocaleTimeString([], { hour12: false }); }
function hashStr(s) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0) / 4294967295;
}
function flagOf(code) {
  if (!code || code.length !== 2) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65));
}
function downloadBlob(blob, name) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

const PROTO_COLORS = {
  DNS: '#a890c8', HTTPS: '#57b8a0', HTTP: '#e0a33e', SSH: '#e05252',
  ICMP: '#d475a8', TCP: '#6d9bc9', UDP: '#9cb85e', RSYNC: '#d4bd6e',
  SMB: '#d4bd6e', NTP: '#7ec4c9', mDNS: '#c98fc4', MySQL: '#a876c9',
  Postgres: '#a876c9', Redis: '#a876c9', SMTP: '#d98a5f', IMAP: '#d98a5f',
  IMAPS: '#d98a5f', POP3: '#d98a5f', FTP: '#d98a5f', TELNET: '#d98a5f',
  DHCP: '#a5c47f', SNMP: '#a5c47f', LDAP: '#d98a5f', LDAPS: '#d98a5f',
  NETBIOS: '#d98a5f', OTHER: '#8d8778',
};
const protoColor = (p) => PROTO_COLORS[p] || PROTO_COLORS.OTHER;
const SEV_COLORS = { high: '#e05252', medium: '#d9822b', info: '#6d9bc9' };
const KIND_ICONS = {
  port_scan: '🎯', host_sweep: '📡', traffic_spike: '📈', syn_flood: '⚡',
  beaconing: '📶', blocklist: '☠️', geo_flag: '🌍', replay: '▶', error: '⛔', info: 'ℹ',
};
/* plain-language "why it matters" line per alert kind — for beginners */
const ALERT_WHY = {
  port_scan: 'Someone is trying every "door" (port) on one device — that is how attackers find a way in.',
  host_sweep: 'One device is rapidly touching many others — mapping out the whole network.',
  syn_flood: 'A device is being flooded with fake requests, trying to knock it offline (DoS attack).',
  beaconing: 'A device is secretly "phoning home" to the same server at fixed intervals — a classic malware pattern.',
  blocklist: 'This IP is on a known-attackers list — like a criminal-records database for the internet.',
  geo_flag: 'Traffic is heading to an anonymizer/proxy server — an unusual place for normal traffic.',
  traffic_spike: 'Traffic suddenly jumped several times above normal — like a traffic jam appearing from nowhere.',
};

/* ---------------------------------------------------------------- state */
const nodes = new Map();   // ip -> view node (world coords)
const edges = new Map();   // "src|dst" -> view edge
let pulses = [];
let selected = null;
let hovered = null;
let dragging = null;
let dragStart = null;
let dragMoved = false;
let panning = null;
let serverNow = Math.floor(Date.now() / 1000);
let latest = { stats: {}, alerts: [], source: null, running: false, paused: false, speed: 1 };
let maxAlertId = 0;
let labelSet = new Set();
let detailsCache = {};     // ip -> /api/node detail

/* ---------------------------------------------------------------- canvas + view */
const wrap = $('#netWrap');
const canvas = $('#net');
const ctx = canvas.getContext('2d');
let W = 0, H = 0, DPR = 1;
const view = { scale: 1, ox: 0, oy: 0, userMoved: false };

function resize() {
  DPR = window.devicePixelRatio || 1;
  W = wrap.clientWidth;
  H = wrap.clientHeight;
  canvas.width = Math.max(1, Math.floor(W * DPR));
  canvas.height = Math.max(1, Math.floor(H * DPR));
}
window.addEventListener('resize', resize);

const s2w = (x, y) => ({ x: (x - view.ox) / view.scale, y: (y - view.oy) / view.scale });

function fitView(force) {
  if (view.userMoved && !force) return;
  const arr = [...nodes.values()];
  if (arr.length === 0) { view.scale = 1; view.ox = W / 2; view.oy = H / 2; return; }
  let minX = 1e9, maxX = -1e9, minY = 1e9, maxY = -1e9;
  for (const n of arr) {
    minX = Math.min(minX, n.x - n.r); maxX = Math.max(maxX, n.x + n.r);
    minY = Math.min(minY, n.y - n.r); maxY = Math.max(maxY, n.y + n.r);
  }
  const bw = maxX - minX + 140, bh = maxY - minY + 160;
  view.scale = Math.max(0.1, Math.min(W / bw, H / bh, 1.8));
  view.ox = W / 2 - ((minX + maxX) / 2) * view.scale;
  view.oy = H / 2 - ((minY + maxY) / 2) * view.scale;
}

function centerOn(n) {
  view.scale = Math.max(view.scale, 0.9);
  view.ox = W / 2 - n.x * view.scale;
  view.oy = H / 2 - n.y * view.scale;
  view.userMoved = true;
}

/* ---------------------------------------------------------------- data transport */
function applyState(s) {
  serverNow = s.t || serverNow;
  latest = s;

  const seen = new Set();
  for (const n of s.nodes || []) {
    seen.add(n.ip);
    let g = nodes.get(n.ip);
    if (!g) {
      g = {
        ip: n.ip,
        x: (Math.random() - 0.5) * 320,
        y: (Math.random() - 0.5) * 260,
        vx: 0, vy: 0, r: 8, flashUntil: 0,
      };
      nodes.set(n.ip, g);
    }
    Object.assign(g, {
      internal: n.internal, pkts: n.pkts, bytes: n.bytes,
      in_pkts: n.in_pkts, out_pkts: n.out_pkts,
      in_bytes: n.in_bytes, out_bytes: n.out_bytes,
      first: n.first, last: n.last, peers: n.peers,
      ports: n.ports, protos: n.protos, risk: n.risk, rate: n.rate, geo: n.geo,
    });
  }
  for (const ip of [...nodes.keys()]) if (!seen.has(ip)) nodes.delete(ip);

  const eSeen = new Set();
  for (const e of s.edges || []) {
    const key = e.src + '|' + e.dst;
    eSeen.add(key);
    let g = edges.get(key);
    if (!g) {
      g = { key, src: e.src, dst: e.dst, pkts: 0, bytes: 0, hash: hashStr(key) };
      edges.set(key, g);
    }
    const delta = Math.max(0, e.pkts - g.pkts);
    Object.assign(g, { pkts: e.pkts, bytes: e.bytes, proto: e.proto, last: e.last });
    if (delta > 0 && nodes.has(e.src) && nodes.has(e.dst)) spawnPulses(g, Math.min(delta, 6));
  }
  for (const k of [...edges.keys()]) if (!eSeen.has(k)) edges.delete(k);

  labelSet = new Set(
    [...nodes.values()].sort((a, b) => (b.bytes || 0) - (a.bytes || 0)).slice(0, 16).map((n) => n.ip),
  );

  fitView(false);
  renderAlerts(latest.alerts || []);
  renderMeters();
  syncControls();
  if (selected && nodes.has(selected.ip)) renderInfo(selected.ip, false);
  else if (selected) { selected = null; hideInfo(); }
}

function spawnPulses(edge, k) {
  const color = protoColor(edge.proto);
  for (let i = 0; i < k; i++) {
    if (pulses.length > 700) pulses.shift();
    pulses.push({ e: edge, t: Math.random(), sp: 0.35 + Math.random() * 0.5, color });
  }
}

/* SSE primary + polling heartbeat (snapshots are idempotent) */
function fetchState() {
  fetch('/api/state').then((r) => r.json()).then(applyState).catch(() => {});
}

function connect() {
  const es = new EventSource('/api/stream');
  es.addEventListener('state', (ev) => {
    try { applyState(JSON.parse(ev.data)); } catch (e) { /* ignore */ }
  });
  es.onerror = () => { /* heartbeat polling keeps data flowing if SSE dies */ };
  setInterval(fetchState, 2500);
}

/* ---------------------------------------------------------------- physics */
const REP = 9000;
const REST = 150;
const K = 0.028;
const GRAV = 0.018;
const DAMP = 0.86;
const WORLD_LIMIT = 2600;

function physics() {
  const arr = [...nodes.values()];
  for (const a of arr) { a.fx = 0; a.fy = 0; }

  for (let i = 0; i < arr.length; i++) {
    for (let j = i + 1; j < arr.length; j++) {
      const a = arr[i], b = arr[j];
      const dx = a.x - b.x, dy = a.y - b.y;
      const d2 = dx * dx + dy * dy + 90;
      const d = Math.sqrt(d2);
      let f = REP / d2;
      if (f > 6) f = 6;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      a.fx += fx; a.fy += fy; b.fx -= fx; b.fy -= fy;
    }
  }
  for (const e of edges.values()) {
    const a = nodes.get(e.src), b = nodes.get(e.dst);
    if (!a || !b) continue;
    const dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.hypot(dx, dy) || 1;
    const f = K * (d - REST);
    const fx = (dx / d) * f, fy = (dy / d) * f;
    a.fx += fx; a.fy += fy; b.fx -= fx; b.fy -= fy;
  }
  for (const a of arr) {
    a.fx += -a.x * GRAV;   // gravity toward world origin
    a.fy += -a.y * GRAV;
    if (a === dragging) { a.vx = 0; a.vy = 0; continue; }
    a.vx = (a.vx + a.fx) * DAMP;
    a.vy = (a.vy + a.fy) * DAMP;
    const sp = Math.hypot(a.vx, a.vy);
    if (sp > 9) { a.vx = (a.vx / sp) * 9; a.vy = (a.vy / sp) * 9; }
    a.x = Math.min(WORLD_LIMIT, Math.max(-WORLD_LIMIT, a.x + a.vx));
    a.y = Math.min(WORLD_LIMIT, Math.max(-WORLD_LIMIT, a.y + a.vy));
    const bytes = a.bytes || 0;
    a.r = Math.max(7, Math.min(26, 6 + 3.2 * Math.log10(1 + bytes / 1500)));
  }
}

/* ---------------------------------------------------------------- rendering */
function edgeGeom(e) {
  const a = nodes.get(e.src), b = nodes.get(e.dst);
  if (!a || !b) return null;
  const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
  const dx = b.x - a.x, dy = b.y - a.y;
  const len = Math.hypot(dx, dy) || 1;
  const off = len * 0.14 * (e.hash - 0.5) * 2;
  return { a, b, cx: mx - (dy / len) * off, cy: my + (dx / len) * off };
}

function qPoint(g, t) {
  const u = 1 - t;
  return {
    x: u * u * g.a.x + 2 * u * t * g.cx + t * t * g.b.x,
    y: u * u * g.a.y + 2 * u * t * g.cy + t * t * g.b.y,
  };
}

function render(nowMs, dt) {
  // ---- screen space: background
  ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  ctx.clearRect(0, 0, W, H);
  const grad = ctx.createRadialGradient(W / 2, H / 2, 40, W / 2, H / 2, Math.max(W, H) * 0.75);
  grad.addColorStop(0, 'rgba(110, 86, 46, 0.16)');
  grad.addColorStop(1, 'rgba(20, 17, 13, 0)');
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, W, H);

  // world-space dot grid
  const gs = 60 * view.scale;
  if (gs >= 16) {
    ctx.fillStyle = 'rgba(205, 175, 125, 0.07)';
    const ox = ((view.ox % gs) + gs) % gs;
    const oy = ((view.oy % gs) + gs) % gs;
    for (let x = ox; x < W; x += gs) {
      for (let y = oy; y < H; y += gs) {
        ctx.fillRect(x - 1, y - 1, 2, 2);
      }
    }
  }

  // ---- world space: graph
  ctx.setTransform(DPR * view.scale, 0, 0, DPR * view.scale, DPR * view.ox, DPR * view.oy);

  for (const e of edges.values()) {
    const g = edgeGeom(e);
    if (!g) continue;
    const age = serverNow - e.last;
    let alpha = age < 2 ? 1 : Math.max(0.06, 1 - age / 30);
    if (age < 3) alpha *= 0.72 + 0.28 * Math.sin(nowMs * 0.006 + e.hash * 6.28); // pulsing line
    ctx.strokeStyle = protoColor(e.proto);
    ctx.globalAlpha = alpha * 0.85;
    ctx.lineWidth = (0.6 + Math.min(3, Math.log2(1 + (e.bytes || 0) / 2500) / 2)) / Math.max(0.4, view.scale * 0.9);
    ctx.beginPath();
    ctx.moveTo(g.a.x, g.a.y);
    ctx.quadraticCurveTo(g.cx, g.cy, g.b.x, g.b.y);
    ctx.stroke();
  }
  ctx.globalAlpha = 1;

  for (let i = pulses.length - 1; i >= 0; i--) {
    const p = pulses[i];
    const g = edgeGeom(p.e);
    if (!g) { pulses.splice(i, 1); continue; }
    p.t += p.sp * dt * 0.7;
    if (p.t >= 1) { pulses.splice(i, 1); continue; }
    const pt = qPoint(g, p.t);
    ctx.fillStyle = p.color;
    ctx.globalAlpha = 0.22;
    ctx.beginPath(); ctx.arc(pt.x, pt.y, 5, 0, 6.283); ctx.fill();
    ctx.globalAlpha = 0.95;
    ctx.beginPath(); ctx.arc(pt.x, pt.y, 2, 0, 6.283); ctx.fill();
  }
  ctx.globalAlpha = 1;

  ctx.font = '11px ui-monospace, Menlo, Consolas, monospace';
  ctx.textAlign = 'center';
  for (const n of nodes.values()) {
    const top = n.protos && n.protos[0] ? n.protos[0].proto : 'OTHER';
    const col = protoColor(top);
    const flash = n.flashUntil > nowMs;

    if (n.risk && n.risk.level === 'suspicious') {
      ctx.strokeStyle = '#e05252';
      ctx.globalAlpha = 0.5 + 0.5 * Math.sin(nowMs * 0.008);
      ctx.lineWidth = 2 / view.scale;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 6 + 2 * Math.sin(nowMs * 0.008), 0, 6.283); ctx.stroke();
      ctx.globalAlpha = 1;
    } else if (n.risk && n.risk.level === 'watch') {
      ctx.strokeStyle = '#d9822b';
      ctx.globalAlpha = 0.75;
      ctx.lineWidth = 1.6 / view.scale;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 5, 0, 6.283); ctx.stroke();
      ctx.globalAlpha = 1;
    }
    if (flash) {
      ctx.strokeStyle = '#fff';
      ctx.globalAlpha = 0.6 + 0.4 * Math.sin(nowMs * 0.02);
      ctx.lineWidth = 2 / view.scale;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 10, 0, 6.283); ctx.stroke();
      ctx.globalAlpha = 1;
    }
    if (n === selected) {
      ctx.strokeStyle = '#f2ecdf';
      ctx.setLineDash([4 / view.scale, 3 / view.scale]);
      ctx.lineWidth = 1.4 / view.scale;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 8, 0, 6.283); ctx.stroke();
      ctx.setLineDash([]);
    }

    ctx.globalAlpha = 0.3;
    ctx.fillStyle = col;
    if (n.internal) {
      const s = n.r * 1.7, x = n.x - s / 2, y = n.y - s / 2, rr = 4;
      ctx.beginPath();
      ctx.moveTo(x + rr, y);
      ctx.arcTo(x + s, y, x + s, y + s, rr);
      ctx.arcTo(x + s, y + s, x, y + s, rr);
      ctx.arcTo(x, y + s, x, y, rr);
      ctx.arcTo(x, y, x + s, y, rr);
      ctx.closePath(); ctx.fill();
    } else {
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, 6.283); ctx.fill();
    }
    ctx.globalAlpha = 1;
    ctx.lineWidth = 1.6 / view.scale;
    ctx.strokeStyle = n === hovered ? '#f2ecdf' : col;
    if (n.internal) {
      const s = n.r * 1.7, x = n.x - s / 2, y = n.y - s / 2, rr = 4;
      ctx.beginPath();
      ctx.moveTo(x + rr, y);
      ctx.arcTo(x + s, y, x + s, y + s, rr);
      ctx.arcTo(x + s, y + s, x, y + s, rr);
      ctx.arcTo(x, y + s, x, y, rr);
      ctx.arcTo(x, y, x + s, y, rr);
      ctx.closePath(); ctx.stroke();
    } else {
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, 6.283); ctx.stroke();
    }

    if (n === hovered || n === selected || n.r > 15 || labelSet.has(n.ip)) {
      ctx.fillStyle = 'rgba(232, 226, 214, 0.9)';
      const flag = n.geo && n.geo.code ? ' ' + flagOf(n.geo.code) : '';
      ctx.fillText(n.ip + flag, n.x, n.y + n.r + 13);
    }
  }
}

let lastFrame = performance.now();
function loop(nowMs) {
  const dt = Math.min(0.1, (nowMs - lastFrame) / 1000);
  lastFrame = nowMs;
  physics();
  render(nowMs, dt);
  requestAnimationFrame(loop);
}

/* ---------------------------------------------------------------- interaction */
function nodeAt(sx, sy) {
  const w = s2w(sx, sy);
  let best = null, bd = 1e9;
  for (const n of nodes.values()) {
    const d = Math.hypot(n.x - w.x, n.y - w.y);
    if (d < (n.r + 7 / view.scale) && d < bd) { bd = d; best = n; }
  }
  return best;
}

canvas.addEventListener('pointerdown', (ev) => {
  const r = canvas.getBoundingClientRect();
  const sx = ev.clientX - r.left, sy = ev.clientY - r.top;
  const n = nodeAt(sx, sy);
  if (n) {
    dragging = n;
    dragStart = { x: ev.clientX, y: ev.clientY };
    dragMoved = false;
    canvas.setPointerCapture(ev.pointerId);
  } else {
    panning = { sx: ev.clientX, sy: ev.clientY, ox: view.ox, oy: view.oy, moved: false };
    canvas.setPointerCapture(ev.pointerId);
  }
});
canvas.addEventListener('pointermove', (ev) => {
  const r = canvas.getBoundingClientRect();
  const sx = ev.clientX - r.left, sy = ev.clientY - r.top;
  if (dragging) {
    if (dragStart && Math.hypot(ev.clientX - dragStart.x, ev.clientY - dragStart.y) > 4) dragMoved = true;
    if (dragMoved) {
      const w = s2w(sx, sy);
      dragging.x = w.x; dragging.y = w.y;
      view.userMoved = true;
    }
  } else if (panning) {
    const dx = ev.clientX - panning.sx, dy = ev.clientY - panning.sy;
    if (Math.hypot(dx, dy) > 4) panning.moved = true;
    if (panning.moved) {
      view.ox = panning.ox + dx;
      view.oy = panning.oy + dy;
      view.userMoved = true;
    }
  } else {
    hovered = nodeAt(sx, sy);
    canvas.style.cursor = hovered ? 'pointer' : 'crosshair';
    const tip = $('#tooltip');
    if (hovered) {
      tip.classList.remove('hidden');
      tip.style.left = Math.min(W - 190, sx + 14) + 'px';
      tip.style.top = Math.max(8, sy - 52) + 'px';
      const sev = hovered.risk && hovered.risk.level !== 'normal' ? hovered.risk.level : 'normal';
      const geoLine = hovered.geo && hovered.geo.country
        ? `<div class="ttGeo">${flagOf(hovered.geo.code)} ${esc(hovered.geo.country)}${hovered.geo.city ? ' · ' + esc(hovered.geo.city) : ''}</div>` : '';
      tip.innerHTML = `<b>${esc(hovered.ip)}</b>${geoLine}` +
        `${hovered.pkts || 0} pkts · ${humanBytes(hovered.bytes)}<br>risk: ${sev}`;
    } else {
      tip.classList.add('hidden');
    }
  }
});
canvas.addEventListener('pointerup', () => {
  if (dragging && !dragMoved) selectNode(dragging.ip);
  else if (panning && !panning.moved) { selected = null; hideInfo(); }
  dragging = null;
  panning = null;
});
canvas.addEventListener('pointerleave', () => {
  hovered = null;
  $('#tooltip').classList.add('hidden');
});

canvas.addEventListener('wheel', (ev) => {
  ev.preventDefault();
  const r = canvas.getBoundingClientRect();
  const mx = ev.clientX - r.left, my = ev.clientY - r.top;
  const f = Math.exp(-ev.deltaY * 0.0012);
  const ns = Math.min(4, Math.max(0.15, view.scale * f));
  const w = s2w(mx, my);
  view.scale = ns;
  view.ox = mx - w.x * ns;
  view.oy = my - w.y * ns;
  view.userMoved = true;
}, { passive: false });

function selectNode(ip, focus) {
  const n = nodes.get(ip);
  if (!n) return;
  selected = n;
  n.flashUntil = performance.now() + 1800;
  if (focus) centerOn(n);
  renderInfo(ip, true);
}

/* ---------------------------------------------------------------- search */
const searchInput = $('#nodeSearch');
const searchSug = $('#searchSug');
let sugItems = [];
let sugActive = -1;

function searchMatches(q) {
  q = q.toLowerCase();
  const out = [];
  for (const n of nodes.values()) {
    const geo = n.geo || {};
    const hay = (n.ip + ' ' + (geo.country || '') + ' ' + (geo.city || '') + ' ' + (geo.isp || '')).toLowerCase();
    if (hay.includes(q)) out.push(n);
    if (out.length >= 8) break;
  }
  return out;
}

function renderSuggestions() {
  const q = searchInput.value.trim();
  sugActive = -1;
  if (!q) { searchSug.classList.add('hidden'); return; }
  sugItems = searchMatches(q);
  if (!sugItems.length) {
    searchSug.innerHTML = '<div class="sugItem" style="color:#7d8db4;cursor:default">no match</div>';
    searchSug.classList.remove('hidden');
    return;
  }
  searchSug.innerHTML = '';
  sugItems.forEach((n, i) => {
    const div = document.createElement('div');
    div.className = 'sugItem';
    const risk = n.risk ? n.risk.level : 'normal';
    const rc = risk === 'suspicious' ? '#e05252' : risk === 'watch' ? '#d9822b' : '#7fb069';
    const geo = n.geo || {};
    const meta = (geo.country ? flagOf(geo.code) + ' ' + geo.country + ' · ' : '') + humanBytes(n.bytes);
    div.innerHTML = `<span class="riskDot" style="background:${rc}"></span>` +
      `<span class="sugIp">${esc(n.ip)}</span><span class="sugMeta">${esc(meta)}</span>`;
    div.addEventListener('mousedown', (ev) => { ev.preventDefault(); pickSuggestion(i); });
    searchSug.appendChild(div);
  });
  searchSug.classList.remove('hidden');
}

function pickSuggestion(i) {
  const n = sugItems[i];
  if (!n) return;
  searchSug.classList.add('hidden');
  searchInput.blur();
  selectNode(n.ip, true);
}

searchInput.addEventListener('input', renderSuggestions);
searchInput.addEventListener('focus', renderSuggestions);
searchInput.addEventListener('blur', () => setTimeout(() => searchSug.classList.add('hidden'), 150));
searchInput.addEventListener('keydown', (ev) => {
  if (ev.key === 'Enter') { ev.preventDefault(); if (sugItems.length) pickSuggestion(Math.max(0, sugActive)); }
  else if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') {
    ev.preventDefault();
    const dir = ev.key === 'ArrowDown' ? 1 : -1;
    sugActive = (sugActive + dir + sugItems.length) % sugItems.length;
    [...searchSug.children].forEach((c, i) => c.classList.toggle('active', i === sugActive));
  } else if (ev.key === 'Escape') {
    searchInput.value = '';
    searchSug.classList.add('hidden');
    searchInput.blur();
  }
});

/* ---------------------------------------------------------------- info panel */
function hideInfo() { $('#infoPanel').classList.add('hidden'); }

function renderInfo(ip, fetchDetail) {
  const n = nodes.get(ip);
  if (!n) { hideInfo(); return; }
  const panel = $('#infoPanel');
  const risk = n.risk || { level: 'normal', reasons: [] };
  const protoTotal = (n.protos || []).reduce((a, p) => a + p.count, 0) || 1;
  let html = `
    <div class="ipRow"><h3>${esc(ip)}</h3><button class="close" title="close">✕</button></div>
    <div class="chips">
      <span class="chip ${n.internal ? 'internal' : 'external'}" title="${n.internal ? 'This device is part of the local network being monitored' : 'This is an outside server somewhere on the internet'}">${n.internal ? '🏠 internal · your network' : '🌐 external · internet'}</span>
      <span class="chip risk-${risk.level}" title="Risk level decided by the automatic detection rules">${risk.level === 'suspicious' ? '🚨 suspicious' : risk.level === 'watch' ? '👁 watch' : '✅ normal'}</span>
      <span class="chip" title="Current data transfer rate">${humanBps(n.rate || 0)} right now</span>
    </div>`;

  if (risk.level === 'suspicious') {
    html += `<div class="miniAlert" style="--sev:#ef5350"><span class="t">💡 In simple words: this device broke a detection rule — worth investigating.</span></div>`;
  } else if (risk.level === 'watch') {
    html += `<div class="miniAlert" style="--sev:#ffb74d"><span class="t">💡 In simple words: unusual behaviour noticed — keep an eye on it.</span></div>`;
  }

  if (n.geo && n.geo.country) {
    const badges = [
      n.geo.proxy ? '<span class="chip badgeProxy">PROXY</span>' : '',
      n.geo.hosting ? '<span class="chip badgeProxy">HOSTING/DC</span>' : '',
    ].join('');
    html += `<div class="geoCard"><span class="gFlag">${flagOf(n.geo.code)}</span>` +
      `<b>${esc(n.geo.country)}</b>${n.geo.city ? ' · ' + esc(n.geo.city) : ''}${badges}` +
      `<small>${esc(n.geo.isp || '')}${n.geo.as ? ' · ' + esc(n.geo.as) : ''}</small></div>`;
  }

  if (risk.reasons && risk.reasons.length) {
    html += `<div class="miniAlert" style="--sev:${risk.level === 'suspicious' ? '#e05252' : '#d9822b'}"><span class="t">${esc(risk.reasons.join(' · '))}</span></div>`;
  }
  html += `
    <div class="grid">
      <div class="kv"><div class="k">packets</div><div class="v">${(n.pkts || 0).toLocaleString()}</div></div>
      <div class="kv"><div class="k">volume</div><div class="v">${humanBytes(n.bytes)}</div></div>
      <div class="kv"><div class="k">sent / received</div><div class="v">${humanBytes(n.out_bytes)} / ${humanBytes(n.in_bytes)}</div></div>
      <div class="kv"><div class="k">talks with</div><div class="v">${n.peers || 0} devices</div></div>
      <div class="kv"><div class="k">first seen</div><div class="v">${fmtTime(n.first)}</div></div>
      <div class="kv"><div class="k">last seen</div><div class="v">${fmtTime(n.last)}</div></div>
    </div>
    <div class="section">Traffic types seen</div>
    ${(n.protos || []).map((p) => `
      <div class="protoBar">
        <span class="name">${esc(p.proto)}</span>
        <span class="barBg"><span class="bar" style="width:${Math.round(100 * p.count / protoTotal)}%;background:${protoColor(p.proto)}"></span></span>
        <span class="cnt">${p.count.toLocaleString()}</span>
      </div>`).join('') || '<div class="empty">—</div>'}
    <div class="section">Busiest ports (the “doors” it uses)</div>
    <div class="portChips">${(n.ports || []).map((p) => `<span class="portChip"><b>:${p.port}</b> ×${p.count.toLocaleString()}</span>`).join('') || '<span class="empty">—</span>'}</div>`;

  const d = detailsCache[ip];
  if (d) {
    if (d.peer_list && d.peer_list.length) {
      html += `<div class="section">Talks most with</div>` + d.peer_list.slice(0, 8).map((p) =>
        `<div class="peerRow"><b>${esc(p.ip)}</b><span>${humanBytes(p.bytes)} · ${p.pkts.toLocaleString()} pkts</span></div>`).join('');
    }
    if (d.alerts && d.alerts.length) {
      html += `<div class="section">Alerts for this device</div>` + d.alerts.slice(0, 5).map((a) =>
        `<div class="miniAlert" style="--sev:${SEV_COLORS[a.severity] || '#42a5f5'}">
           <span class="t">${KIND_ICONS[a.kind] || '⚠'} ${esc(a.title)}</span>
           <div style="color:#7d8db4">${fmtTime(a.ts)}</div>
         </div>`).join('');
    }
  }
  panel.innerHTML = html;
  panel.classList.remove('hidden');
  panel.querySelector('.close').onclick = () => { selected = null; hideInfo(); };

  if (fetchDetail) {
    fetch('/api/node/' + encodeURIComponent(ip))
      .then((r) => r.json())
      .then((d) => {
        detailsCache[ip] = d;
        if (selected && selected.ip === ip) renderInfo(ip, false);
      })
      .catch(() => {});
  }
}

/* ---------------------------------------------------------------- alerts UI */
let lastAlertSig = '';
let lastAckedId = 0;

function alertVisible(a) {
  const f = $('#alertFilter').value;
  if (f === 'high') return a.severity === 'high';
  if (f === 'med') return a.severity === 'high' || a.severity === 'medium';
  return true;
}

function renderAlerts(alerts) {
  const list = $('#alertList');
  const badge = $('#alertBadge');

  for (const a of alerts) {
    if (a.id > maxAlertId) {
      maxAlertId = a.id;
      if (a.severity === 'high') document.body.animate(
        [{ boxShadow: 'inset 0 0 120px rgba(224,82,82,.5)' }, { boxShadow: 'inset 0 0 120px rgba(224,82,82,0)' }],
        { duration: 1400 });
    }
  }
  const shown = alerts.filter(alertVisible);
  const sig = $('#alertFilter').value + '|' + shown.map((a) => a.id).join(',');
  if (sig !== lastAlertSig) {
    lastAlertSig = sig;
    if (!shown.length) {
      list.innerHTML = '<div class="empty">✅ All clear' +
        (alerts.length ? ' for this filter.' : ' — no threats detected yet.<br><small>8 automatic detectors are watching…</small>') + '</div>';
    } else {
      list.innerHTML = '';
      for (const a of shown) {
        const div = document.createElement('div');
        div.className = 'alert';
        div.style.setProperty('--sev', SEV_COLORS[a.severity] || '#42a5f5');
        const why = ALERT_WHY[a.kind];
        div.innerHTML = `
          <div class="aTitle"><span>${KIND_ICONS[a.kind] || '⚠'}</span><span>${esc(a.title)}</span><span class="aTime">${fmtTime(a.ts)}</span></div>
          <div class="aDetail"><span class="aSev">${esc(a.severity).toUpperCase()}</span> ${esc(a.detail)}</div>
          ${why ? `<div class="aWhy">💡 ${esc(why)}</div>` : ''}`;
        div.title = 'Click to jump to this device on the graph';
        div.onclick = () => {
          const target = (a.src && nodes.has(a.src)) ? a.src : (a.dst && nodes.has(a.dst) ? a.dst : null);
          if (target) selectNode(target, true);
        };
        list.appendChild(div);
      }
    }
  }
  const unread = alerts.filter((a) => a.id > lastAckedId).length;
  if (unread > 0) { badge.textContent = unread; badge.classList.remove('hidden'); }
  else badge.classList.add('hidden');
}

$('#alertFilter').addEventListener('change', () => { lastAlertSig = '?'; renderAlerts(latest.alerts || []); });

$('#clearAlerts').onclick = () => {
  fetch('/api/control', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ action: 'clear_alerts' }),
  }).then(() => { lastAlertSig = '?'; }).catch(() => {});
  lastAckedId = maxAlertId;
};
$('#alertsPanel').addEventListener('mouseenter', () => {
  lastAckedId = maxAlertId;
  $('#alertBadge').classList.add('hidden');
});

/* ---------------------------------------------------------------- exports */
function exportCSV() {
  const alerts = latest.alerts || [];
  if (!alerts.length) { alert('No alerts to export yet.'); return; }
  const rows = [['id', 'time', 'kind', 'severity', 'source', 'target', 'title', 'detail']];
  for (const a of alerts) {
    rows.push([a.id, new Date(a.ts * 1000).toLocaleString(), a.kind, a.severity,
      a.src || '', a.dst || '', a.title, a.detail]);
  }
  const csv = rows.map((r) => r.map((c) => '"' + String(c).replace(/"/g, '""') + '"').join(',')).join('\r\n');
  downloadBlob(new Blob([csv], { type: 'text/csv' }),
    `netviz_alerts_${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`);
}
$('#csvBtn').onclick = exportCSV;

function exportPNG() {
  // draw caption then grab the canvas
  ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  ctx.fillStyle = 'rgba(20,17,13,.75)';
  ctx.fillRect(W - 330, H - 34, 322, 22);
  ctx.fillStyle = 'rgba(232,226,214,.9)';
  ctx.font = '11px system-ui, sans-serif';
  ctx.textAlign = 'right';
  ctx.fillText(`NetViz · ${nodes.size} nodes · ${(latest.stats && latest.stats.total_pkts || 0).toLocaleString()} pkts · ${new Date().toLocaleString()}`, W - 14, H - 19);
  canvas.toBlob((b) => downloadBlob(b, `netviz_graph_${Date.now()}.png`), 'image/png');
}
$('#shotBtn').onclick = exportPNG;

/* ---------------------------------------------------------------- meters */
function renderMeters() {
  const st = latest.stats || {};
  $('#pps').textContent = (st.pps || 0).toLocaleString();
  $('#bps').textContent = humanBps(st.bps || 0);
  $('#counts').textContent = `${st.nodes || 0} devices · ${st.edges || 0} connections`;
  const bl = st.blocklist ? ` · 🛡${st.blocklist} blocked-list IPs` : '';
  $('#totals').textContent = `${(st.total_pkts || 0).toLocaleString()} packets seen · ${humanBytes(st.total_bytes || 0)}${bl}`;

  // live risk summary pill on the graph
  let bad = 0, watch = 0;
  for (const n of nodes.values()) {
    if (!n.risk) continue;
    if (n.risk.level === 'suspicious') bad++;
    else if (n.risk.level === 'watch') watch++;
  }
  const pill = $('#statusPill');
  if (nodes.size === 0) {
    pill.innerHTML = '<span>⏳ waiting for traffic…</span>';
  } else if (bad > 0) {
    pill.innerHTML = `<span class="spBad">🚨 ${bad} suspicious device${bad > 1 ? 's' : ''}</span>` +
      (watch ? `<span class="spWatch">👁 ${watch} worth watching</span>` : '') +
      `<span>${nodes.size} devices total</span>`;
  } else if (watch > 0) {
    pill.innerHTML = `<span class="spWatch">👁 ${watch} worth watching</span><span class="spOk">✅ nothing suspicious</span><span>${nodes.size} devices</span>`;
  } else {
    pill.innerHTML = `<span class="spOk">✅ everything looks normal</span><span>${nodes.size} devices</span>`;
  }

  const c = $('#spark');
  const g = c.getContext('2d');
  g.clearRect(0, 0, c.width, c.height);
  const hist = st.history || [];
  if (hist.length > 1) {
    const maxB = Math.max(...hist.map((h) => h[1]), 1);
    g.beginPath();
    hist.forEach((h, i) => {
      const x = (i / (hist.length - 1)) * (c.width - 4) + 2;
      const y = c.height - 3 - (h[1] / maxB) * (c.height - 6);
      i ? g.lineTo(x, y) : g.moveTo(x, y);
    });
    g.strokeStyle = '#e0a33e';
    g.lineWidth = 1.4;
    g.stroke();
    g.lineTo(c.width - 2, c.height); g.lineTo(2, c.height); g.closePath();
    g.fillStyle = 'rgba(224,163,62,0.14)';
    g.fill();
  }
}

/* ---------------------------------------------------------------- controls */
function syncControls() {
  const src = latest.source;
  if (src) {
    const dot = latest.paused ? '⏸' : '●';
    $('#srcStatus').textContent = `${dot} ${src.label}${src.detail ? ' · ' + src.detail : ''} · ${latest.speed || 1}×`;
  }
  $('#pauseBtn').textContent = latest.paused ? '▶ Resume' : '⏸ Pause';
  $('#pausedOverlay').classList.toggle('hidden', !latest.paused);
  if (document.activeElement !== $('#speed')) {
    $('#speed').value = latest.speed || 1;
    $('#speedVal').textContent = (latest.speed || 1) + '×';
  }
}

const srcSelect = $('#srcSelect');
function refreshSourceInputs() {
  const v = srcSelect.value;
  $('#pathInput').classList.toggle('hidden', v !== 'pcap_custom');
  $('#ifaceInput').classList.toggle('hidden', v !== 'live');
  $('#loopWrap').classList.toggle('hidden', !(v === 'pcap_custom' || v.startsWith('/')));
}
srcSelect.addEventListener('change', refreshSourceInputs);

$('#applySrc').onclick = () => {
  const v = srcSelect.value;
  let body;
  if (v === 'sim') body = { type: 'sim' };
  else if (v === 'live') body = { type: 'live', iface: $('#ifaceInput').value.trim() };
  else if (v === 'pcap_custom') body = { type: 'pcap', path: $('#pathInput').value.trim(), loop: $('#loopChk').checked };
  else body = { type: 'pcap', path: v, loop: $('#loopChk').checked };
  fetch('/api/source', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...body, speed: parseFloat($('#speed').value) || 1 }),
  })
    .then((r) => r.json())
    .then((res) => {
      if (!res.ok) alert('Could not start source: ' + (res.error || 'unknown error'));
      else localReset();
    })
    .catch((e) => alert('Request failed: ' + e));
};

function localReset() {
  nodes.clear(); edges.clear(); pulses = [];
  selected = null; hovered = null;
  maxAlertId = 0; lastAckedId = 0; lastAlertSig = '?'; detailsCache = {};
  view.userMoved = false;
  hideInfo();
  fetchState();
}

function togglePause() {
  fetch('/api/control', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ action: 'toggle' }),
  }).catch(() => {});
}
$('#pauseBtn').onclick = togglePause;

$('#clearBtn').onclick = () => {
  fetch('/api/control', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ action: 'clear' }),
  }).then(localReset).catch(() => {});
};
$('#speed').addEventListener('input', () => {
  $('#speedVal').textContent = $('#speed').value + '×';
});
$('#speed').addEventListener('change', () => {
  fetch('/api/control', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ action: 'speed', speed: parseFloat($('#speed').value) }),
  }).catch(() => {});
});

$('#zoomIn').onclick = () => { zoomAt(W / 2, H / 2, 1.3); };
$('#zoomOut').onclick = () => { zoomAt(W / 2, H / 2, 1 / 1.3); };
$('#fitBtn').onclick = () => fitView(true);

function zoomAt(mx, my, f) {
  const ns = Math.min(4, Math.max(0.15, view.scale * f));
  const w = s2w(mx, my);
  view.scale = ns;
  view.ox = mx - w.x * ns;
  view.oy = my - w.y * ns;
  view.userMoved = true;
}

/* ---------------------------------------------------------------- help modal + beginner tour */
$('#helpBtn').onclick = () => $('#helpModal').classList.remove('hidden');
$('#helpClose').onclick = () => $('#helpModal').classList.add('hidden');
$('#helpModal').addEventListener('click', (ev) => {
  if (ev.target === $('#helpModal')) $('#helpModal').classList.add('hidden');
});

function store(k, v) {
  try {
    if (v === undefined) return window.localStorage.getItem(k);
    window.localStorage.setItem(k, v);
  } catch (e) { return null; }  // sandboxed preview — just show the tour each load
}
function showWelcome() { $('#welcome').classList.remove('hidden'); }
function hideWelcome() {
  $('#welcome').classList.add('hidden');
  store('netviz_tour_done', '1');
  setTimeout(() => $('#hint').classList.add('faded'), 15000);
}
$('#welcomeGo').onclick = hideWelcome;
$('#tourBtn').onclick = () => { $('#helpModal').classList.add('hidden'); showWelcome(); };
if (!store('netviz_tour_done')) showWelcome();
setTimeout(() => $('#hint').classList.add('faded'), 25000);

/* ---------------------------------------------------------------- keyboard */
document.addEventListener('keydown', (ev) => {
  const tag = (ev.target.tagName || '').toUpperCase();
  if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
  if (ev.key === '/') { ev.preventDefault(); searchInput.focus(); }
  else if (ev.key === 'f' || ev.key === 'F') fitView(true);
  else if (ev.key === ' ') { ev.preventDefault(); togglePause(); }
  else if (ev.key === 'Escape') {
    $('#helpModal').classList.add('hidden');
    selected = null;
    hideInfo();
  }
});

/* ---------------------------------------------------------------- legend */
const LEGEND = ['DNS', 'HTTPS', 'HTTP', 'SSH', 'TCP', 'UDP', 'ICMP', 'RSYNC', 'other'];
function buildLegend() {
  const el = $('#legend');
  el.innerHTML = LEGEND.map((p) => {
    const col = p === 'other' ? PROTO_COLORS.OTHER : protoColor(p);
    return `<span class="legendItem"><span class="legendBar" style="background:${col}"></span>${p}</span>`;
  }).join('')
    + '<span class="legendItem"><span style="width:9px;height:9px;border:1.5px solid #57b8a0;border-radius:2px;display:inline-block"></span>inside network</span>'
    + '<span class="legendItem"><span style="width:9px;height:9px;border:1.5px solid #d9b36a;border-radius:50%;display:inline-block"></span>internet server</span>'
    + '<span class="legendItem"><span class="ringRed"></span>suspicious</span>'
    + '<span class="legendItem"><span class="ringAmber"></span>worth watching</span>';
}

/* ---------------------------------------------------------------- boot */
function loadSamples() {
  fetch('/api/samples').then((r) => r.json()).then((files) => {
    const group = $('#pcapGroup');
    for (const f of files) {
      const opt = document.createElement('option');
      opt.value = f.path;
      opt.textContent = `📼 ${f.name} (${humanBytes(f.size)})`;
      group.appendChild(opt);
    }
  }).catch(() => {});
  fetch('/api/ifaces').then((r) => r.json()).then((list) => {
    $('#ifaceList').innerHTML = (list || []).map((i) => `<option value="${esc(i)}">`).join('');
  }).catch(() => {});
}

buildLegend();
resize();
loadSamples();
fetchState();
connect();
requestAnimationFrame(loop);
