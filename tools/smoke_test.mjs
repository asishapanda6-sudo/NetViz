/* Headless smoke test for static/app.js — catches runtime errors that a
 * syntax check misses (e.g. a broken render loop). Run: node tools/smoke_test.mjs */
import { readFileSync } from 'node:fs';

const ctxStub = new Proxy({}, {
  get(t, k) {
    if (k === 'createRadialGradient' || k === 'createLinearGradient') {
      return () => ({ addColorStop() {} });
    }
    if (k === 'measureText') return () => ({ width: 0 });
    return typeof t[k] !== 'undefined' ? t[k] : () => {};
  },
  set() { return true; },
});

const elStub = () => new Proxy({
  classList: { add() {}, remove() {}, toggle() {} },
  style: { setProperty() {}, removeProperty() {} },
  dataset: {},
  value: '',
  textContent: '',
  innerHTML: '',
  getContext: () => ctxStub,
  getBoundingClientRect: () => ({ left: 0, top: 0 }),
  setPointerCapture() {},
  addEventListener() {},
  appendChild() {},
  remove() {},
  toBlob() {},
  focus() {}, blur() {},
  querySelector: () => elStub(),
  animate() {},
}, {
  get(t, k) { if (k in t) return t[k]; return undefined; },
  set() { return true; },
});

const els = {};
globalThis.window = {
  devicePixelRatio: 1,
  addEventListener() {},
  localStorage: { getItem: () => null, setItem() {} },
};
globalThis.document = {
  querySelector: (s) => (els[s] ||= elStub()),
  addEventListener() {},
  createElement: () => elStub(),
  body: { animate() {}, appendChild() {} },
  activeElement: null,
};
globalThis.EventSource = class { addEventListener() {} close() {} };
globalThis.fetch = () => Promise.resolve({ json: () => Promise.resolve({}) });
globalThis.requestAnimationFrame = () => 0;

const src = readFileSync(new URL('../static/app.js', import.meta.url), 'utf8');
const { applyState, physics, render } = new Function(src + '\nreturn { applyState, physics, render };')();

// fake snapshot -> applyState -> physics -> render (one frame)
const fake = {
  t: Date.now() / 1000,
  stats: { total_pkts: 10, total_bytes: 5000, nodes: 3, edges: 2, pps: 1, bps: 900,
           history: [[1, 10, 1], [2, 12, 1]], top: [], blocklist: 2 },
  nodes: [
    { ip: '192.168.1.5', internal: true, pkts: 5, bytes: 3000, in_pkts: 2, out_pkts: 3,
      in_bytes: 1000, out_bytes: 2000, first: 1, last: 2, peers: 2, rate: 10,
      ports: [{ port: 443, count: 4 }], protos: [{ proto: 'HTTPS', count: 5 }],
      risk: { level: 'suspicious', reasons: ['test'] }, geo: { country: 'x', code: 'US' } },
    { ip: '1.1.1.1', internal: false, pkts: 3, bytes: 1500, in_pkts: 1, out_pkts: 2,
      in_bytes: 500, out_bytes: 1000, first: 1, last: 2, peers: 1, rate: 5,
      ports: [], protos: [{ proto: 'DNS', count: 3 }],
      risk: { level: 'watch', reasons: [] }, geo: null },
    { ip: '2.2.2.2', internal: false, pkts: 2, bytes: 500, in_pkts: 2, out_pkts: 0,
      in_bytes: 500, out_bytes: 0, first: 1, last: 2, peers: 1, rate: 1,
      ports: [], protos: [{ proto: 'TCP', count: 2 }],
      risk: { level: 'normal', reasons: [] }, geo: null },
  ],
  edges: [
    { src: '192.168.1.5', dst: '1.1.1.1', pkts: 3, bytes: 1500, proto: 'DNS', last: Date.now() / 1000 },
    { src: '192.168.1.5', dst: '2.2.2.2', pkts: 2, bytes: 500, proto: 'TCP', last: Date.now() / 1000 },
  ],
  alerts: [{ id: 1, ts: Date.now() / 1000, kind: 'port_scan', severity: 'high',
             title: 't', detail: 'd', src: '192.168.1.5', dst: null }],
};

applyState(fake);
physics();
render(1000, 0.016);
physics();
render(1016, 0.016);
console.log('SMOKE TEST PASSED — applyState/physics/render run clean (nodes:', fake.nodes.length + ', edges:', fake.edges.length + ')');
process.exit(0);
