// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Tests of the pure rules of the live visualization page (crates/varsto-cli/ui/viz.js): particle speed
// and the stability of flow labels. Plain node, no packages:
//
//     node scripts/test/viz-rules.test.js
//
// The page script is run in a sandbox without a page; it then only exposes `varstoVizRules`.
"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const src = fs.readFileSync(path.join(__dirname, "..", "..", "crates", "varsto-cli", "ui", "viz.js"), "utf8");
const sandbox = { window: {}, document: { querySelector: () => null } };
vm.runInNewContext(src, sandbox);
const R = sandbox.window.varstoVizRules;
assert(R, "viz.js exposes its rules");

// ---- particle speed: independent of the pixel ratio and refresh rate (it takes neither), bounded, slower on small boards
const gap = (k) => Math.max(26, k * 0.5);
for (const bps of [0, 10, 1e3, 1e5, 3e6, 1e8, 1e10]) {
  for (const [w, k] of [[390, 55], [800, 90], [1280, 130], [1920, 200], [3840, 420]]) {
    const v = R.particleSpeed(bps, w, gap(k), false);
    assert(v >= 6 && v <= 240, `speed ${v} within bounds (bps ${bps}, board ${w})`);
    assert(v <= 2 * gap(k) + 1e-9, `no particle passes a point more than twice a second (bps ${bps}, board ${w}): ${v}`);
  }
}
// A phone shows a busy flow far slower than the old rule did (about 140 px/s at 3 MB/s on a 390 px board).
const phone = R.particleSpeed(3e6, 390, gap(55), false);
assert(phone < 60, `phone speed ${phone}`);
assert(R.particleSpeed(3e6, 390, gap(55), false) < R.particleSpeed(3e6, 1920, gap(200), false), "small boards are slower");
assert(R.particleSpeed(1e9, 1920, gap(200), false) >= R.particleSpeed(1e4, 1920, gap(200), false), "busier is not slower");
// Reduced motion: almost still.
assert(R.particleSpeed(1e9, 1920, gap(200), true) <= 5);
// A crossing of a phone board never takes less than 6 seconds at the busiest rate.
assert(390 / R.particleSpeed(1e10, 390, gap(55), false) >= 6);

// ---- labels: a stable key, hysteresis for the place, a width that does not breathe
const f = { from: "d:a", to: "s:b", kind: "p2p", folder: "Photos", bps: 1 };
assert.strictEqual(R.flowKey(f), R.flowKey(Object.assign({}, f, { bps: 99, eta_utc: 5 })), "the key ignores rates and estimates");
assert.notStrictEqual(R.flowKey(f), R.flowKey(Object.assign({}, f, { to: "s:c" })));
assert(R.labelRank(100, true) > R.labelRank(100, false), "a shown label is kept against an equal newcomer");
assert(R.labelRank(100, true) < R.labelRank(200, false), "but not against a much busier one");

const st = { slot: null, bad: 0 };
assert.strictEqual(R.labelNeedsMove(st, false, 0.03), true, "no place yet: pick one");
st.slot = [0, 0];
assert.strictEqual(R.labelNeedsMove(st, false, 0.03), false, "free place: stay");
let t = 0, moved = false;
for (let i = 0; i < 120 && !moved; i++) { moved = R.labelNeedsMove(st, true, 0.033); t += 0.033; }  // just over 3 s at 30 fps
assert(moved && t >= R.LABEL_PATIENCE - 0.05, `moves only after ${R.LABEL_PATIENCE} s of overlap (moved after ${t.toFixed(2)} s)`);
st.slot = [1, 0]; st.bad = 0;
for (let i = 0; i < 60; i++) { assert.strictEqual(R.labelNeedsMove(st, true, 0.033), false); }  // 2 s overlapping
assert.strictEqual(R.labelNeedsMove(st, false, 0.033), false);
assert.strictEqual(st.bad, 0, "a free moment resets the count");
for (let i = 0; i < 60; i++) { assert.strictEqual(R.labelNeedsMove(st, true, 0.033), false); }  // overlap must be consecutive

const w = { w: 0, wT: 0 };
assert.strictEqual(R.stickyWidth(w, 100, 0), 100);
assert.strictEqual(R.stickyWidth(w, 120, 1), 120, "grows at once");
assert.strictEqual(R.stickyWidth(w, 90, 2), 120, "does not shrink for a number of changing width");
assert.strictEqual(R.stickyWidth(w, 110, 5), 120);
assert.strictEqual(R.stickyWidth(w, 90, 12), 90, "shrinks after ten seconds of being narrower");

console.log("viz rules: ok");
