// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Live visualization page: where the data is, what flows where right now, whether it is safe and
// what it costs, on one isometric board drawn on a single <canvas> with the 3D sprites of
// /viz/*.webp (rendered like the website illustrations). Plain JavaScript, no libraries.
// Data: GET /api/viz once a second while the page is shown (spec section 63).
(function () {
  "use strict";
  var page = document.querySelector('.page[data-page="viz"]');
  if (!page) { return; }

  // ---------------------------------------------------------------- helpers
  var tcache = {}, tlang = "";
  function T(s) {
    var L = window.varstoLang;
    if (!L) { return s; }
    var cur = L.get();
    if (cur !== tlang) { tcache = {}; tlang = cur; }
    var v = tcache[s];
    if (v === undefined) { try { v = L.t(s); } catch (e) { v = s; } tcache[s] = v; }
    return v;
  }
  if (window.varstoLang && window.varstoLang.ready) { window.varstoLang.ready(function () { tcache = {}; dirty = true; renderPanels(); }); }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined && text !== null) { e.textContent = text; } return e; }
  function clamp(v, a, b) { return Math.max(a, Math.min(b, v)); }
  function nf(n, d) { return n.toLocaleString(undefined, { maximumFractionDigits: d === undefined ? 1 : d, minimumFractionDigits: 0 }); }
  var UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];
  function bytes(n) {
    if (n === null || n === undefined || isNaN(n)) { return "—"; }
    var i = 0; n = Math.max(0, n);
    while (n >= 1024 && i < UNITS.length - 1) { n /= 1024; i++; }
    return nf(n, n >= 100 || i === 0 ? 0 : n >= 10 ? 1 : 2) + " " + UNITS[i];
  }
  function rate(n) { return n > 0 ? bytes(n) + "/s" : "—"; }
  function money(v, cur) { if (v === null || v === undefined) { return "—"; } var s = v >= 100 ? nf(v, 0) : nf(v, 2); return (cur === "EUR" ? "€" : cur === "USD" ? "$" : "") + s + (cur && cur !== "EUR" && cur !== "USD" ? " " + cur : ""); }
  function nowSec() { return Date.now() / 1000 + skew; }
  function dur(secs) {
    if (secs === null || secs === undefined || !isFinite(secs)) { return "—"; }
    secs = Math.max(0, Math.round(secs));
    if (secs < 45) { return "< 1 " + T("min"); }
    var m = Math.round(secs / 60);
    if (m < 60) { return m + " " + T("min"); }
    var h = Math.floor(m / 60); m = m % 60;
    if (h < 24) { return h + " " + T("h") + (m ? " " + m + " " + T("min") : ""); }
    var d = Math.floor(h / 24); h = h % 24;
    return d + " " + T("d") + (h ? " " + h + " " + T("h") : "");
  }
  function etaText(eta) { return eta ? dur(eta - nowSec()) : "—"; }
  function ago(utc) {
    if (!utc) { return T("never"); }
    var s = nowSec() - utc;
    if (s < 90) { return T("just now"); }
    return dur(s) + " " + T("ago");
  }
  function pctText(p) { return p === null || p === undefined ? "" : Math.round(p) + " %"; }
  var KINDS = {
    upload: "Uploading", download: "Downloading", disk_check: "Verifying disk", disk_fill: "Filling disk", disk_fsck: "Checking disk",
    disk_insert: "Tidying disk", disk_fetch: "Fetching from disk", disk_init: "Preparing disk", disk_unmount: "Ejecting disk",
    repair: "Repairing", verify: "Verifying", scrub: "Bit-rot check", fsck: "Checking storage", data_move: "Moving data", drain: "Draining",
    backup_snapshot: "Backup", restore: "Restoring", sync_scan: "Scanning", restic: "Backup", storage_removal: "Removing storage",
    ledger_rebuild: "Rebuilding ledger", import: "Importing", trash_restore: "Restoring from trash", trash_purge: "Emptying trash", trash_move: "Moving trash",
    folder_purge: "Deleting folder data", strongroom_convert: "Encrypting folder", history_restore: "Restoring version", forward: "Forwarding", move: "Moving data", p2p: "Peer traffic", relay: "Relay", disk_fill_: "Filling disk"
  };
  function kindText(k) { return T(KINDS[k] || k.replace(/_/g, " ")); }

  // ---------------------------------------------------------------- state
  var skew = 0;                 // server clock minus ours, seconds
  var snap = null, demo = false, status = "wait", lastOk = 0, errCount = 0;
  var active = false, dirty = true, raf = 0, timer = 0, pollTimer = 0, abort = null;
  var mode = "auto";
  try { var m0 = localStorage.getItem("varsto-viz-bg"); if (m0 === "light" || m0 === "black" || m0 === "auto") { mode = m0; } } catch (e) { /* not kept */ }
  var root, canvas, ctx, stage, side, bar, panels = {}, chipsBox, resEl, statusEl, dotEl, demoTag, fsBtn;
  var W = 1, H = 1, dpr = 1, cssW = 1, cssH = 1;
  // The part of the canvas the board may use: all of it, or in the full-screen view of a wide screen the canvas minus the bar, the chips and the side panel drawn over it.
  var area = { x: 0, y: 0, w: 1, h: 1 };
  var layout = null, layoutKey = "";
  var lastDraw = 0;
  var reduced = false;
  try { reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) { reduced = false; }
  var token = function () { try { return sessionStorage.getItem("varsto-token") || ""; } catch (e) { return ""; } };

  // ---------------------------------------------------------------- demo data (nothing real)
  function demoSnap() {
    var t = Date.now() / 1000;
    return {
      v: 1, utc: t, unlocked: true, demo: true, this_device: "d1", key_epoch: 1, total_bytes: 412e9,
      devices: [
        { id: "d1", name: "Laptop", role: "this", platform: "linux", online: true, rx_bps: 2.4e6, tx_bps: 0 },
        { id: "d2", name: "Phone", role: "peer", platform: "android", online: true, rx_bps: 0, tx_bps: 3.1e6 },
        { id: "d3", name: "Desktop", role: "peer", platform: "windows", online: false }
      ],
      storages: [
        { id: "s:Home NAS", name: "Home NAS", kind: "directory", place: "home", configured: true, data_bytes: 380e9, used_bytes: 380e9, quota_bytes: 2e12, percent: 19, state: "ok", verified_bytes: 300e9 },
        { id: "s:Pool", name: "Pool", kind: "pool", place: "home", configured: true, data_bytes: 160e9, used_bytes: 160e9, quota_bytes: null, state: "none", verified_bytes: 90e9 },
        { id: "s:S3 bucket", name: "S3 bucket", kind: "s3", place: "cloud", configured: true, data_bytes: 290e9, used_bytes: 290e9, quota_bytes: 500e9, percent: 58, state: "ok", verified_bytes: 120e9, price: { currency: "EUR" }, monthly_cost: 1.9, read_all_cost: 22.5 },
        { id: "s:Archive", name: "Archive", kind: "s3", cold: true, place: "cloud", configured: true, data_bytes: 150e9, used_bytes: 150e9, quota_bytes: 200e9, percent: 92, state: "warning", verified_bytes: 0, price: { currency: "EUR" }, monthly_cost: 0.6, read_all_cost: 14 }
      ],
      disks: { count: 4, docked: ["B"], working_on: "B", list: [
        { pool: "Pool", label: "A", docked: false, phase: "away", capacity_bytes: 4e12, used_bytes: 3.1e12, last_verified_utc: t - 86400 * 12, overdue_share: 0 },
        { pool: "Pool", label: "B", docked: true, phase: "verify", progress: 42, eta_utc: t + 1320, capacity_bytes: 4e12, used_bytes: 2.2e12, last_verified_utc: t - 86400 * 40, overdue_share: 0.3 },
        { pool: "Pool", label: "C", docked: false, phase: "wanted", capacity_bytes: 2e12, used_bytes: 1.9e12, last_verified_utc: t - 86400 * 3, overdue_share: 0, wanted_by: "m1" },
        { pool: "Pool", label: "D", docked: false, phase: "away", capacity_bytes: 2e12, used_bytes: 0.4e12, last_verified_utc: 0, overdue_share: 1 }
      ] },
      folders: [
        { name: "Photos", bytes: 210e9, files: 41000, blocks: 90000, policy: "at least 2 copies", policy_state: "ok", verified_blocks: 70000, unverified_blocks: 19000, local_only_blocks: 1000, missing_blocks: 0, oldest_verification_days: 9, storages: { "Home NAS": 190e9, "S3 bucket": 205e9 }, targets: ["Home NAS", "S3 bucket"] },
        { name: "Documents", bytes: 38e9, files: 12000, blocks: 20000, policy: "at least 3 copies", policy_state: "at_risk", verified_blocks: 9000, unverified_blocks: 10000, local_only_blocks: 1000, missing_blocks: 0, oldest_verification_days: 27, storages: { "Home NAS": 38e9 }, targets: ["Home NAS", "S3 bucket", "Archive"] },
        { name: "Videos", bytes: 164e9, files: 900, blocks: 60000, policy: "at least 1 copy", policy_state: "ok", verified_blocks: 12000, unverified_blocks: 48000, local_only_blocks: 0, missing_blocks: 0, storages: { "S3 bucket": 85e9, "Archive": 150e9 }, targets: ["S3 bucket", "Archive"] }
      ],
      copies: { blocks: [0, 24000, 61000, 85000], bytes: [0, 40e9, 120e9, 252e9], average: 2.5 },
      flows: [
        { id: "a", kind: "upload", from: "d:d2", to: "s:S3 bucket", folder: "Photos", bps: 3.1e6, rate: 3.1e6, done: 2.1e9, total: 5.2e9, eta_utc: t + 1000, unit: "bytes" },
        { id: "b", kind: "p2p", from: "d:d2", to: "d:d1", folder: "", bps: 2.4e6, path: "direct-lan" },
        { id: "c", kind: "upload", from: "d:d1", to: "s:Home NAS", folder: "Documents", bps: 9e5, rate: 9e5, done: 3e8, total: 2.2e9, eta_utc: t + 2100, unit: "bytes" },
        { id: "d", kind: "disk_fill", from: "d:d1", to: "p:B", folder: "Videos", bps: 4.2e7, rate: 4.2e7, done: 8e10, total: 2.1e11, eta_utc: t + 3100, unit: "bytes" }
      ],
      jobs: [
        { id: "j1", kind: "upload", subject: "Photos", device_name: "Phone", device: "d2", done: 2.1e9, total: 5.2e9, unit: "bytes", percent: 40, rate: 3.1e6, eta_utc: t + 1000 },
        { id: "j2", kind: "disk_check", subject: "B", device_name: "Laptop", device: "d1", done: 42, total: 100, unit: "items", percent: 42, rate: 0, eta_utc: t + 1320, phase: "verify" },
        { id: "j3", kind: "disk_fill", subject: "B", device_name: "Laptop", device: "d1", done: 8e10, total: 2.1e11, unit: "bytes", percent: 38, rate: 4.2e7, eta_utc: t + 3100 }
      ],
      moves: [{ id: "m1", folder: "Videos", from: "S3 bucket", to: "Pool", state: "open", bytes_total: 164e9, bytes_done: 90e9, bytes_remaining: 74e9, waiting: "disk", waiting_text: "Attach disk C", waiting_disk: "C" }],
      drains: [], backups: [{ name: "Laptop backup", snapshots: 14, latest_utc: t - 7200, next_due_utc: t + 3600, stopped: false }],
      alerts: [{ level: "warn", code: "quota", subject: "Archive", text: "Archive is almost full" }, { level: "warn", code: "policy", subject: "Documents", text: "Documents: a verification is about to age out" }],
      health: { overall: "warn", ledger: "ok", verify: { enabled: true, last_run_utc: t - 5400, next_run_utc: t + 1800 }, scrub: { enabled: true, last_run_utc: t - 86400 * 2, next_run_utc: t + 86400 }, repair: { queued: 0, losses: 0 } },
      traffic: { rx_bps: 2.4e6, tx_bps: 0 },
      cost: { estimate: true, month: { EUR: 2.5 }, read_all_once: { EUR: 36.5 }, unpriced: [] }
    };
  }

  // ---------------------------------------------------------------- DOM
  function buildDom() {
    root = el("div", "viz");
    root.setAttribute("data-bg", mode);
    bar = el("div", "viz-bar");
    var seg = el("div", "viz-seg"); seg.setAttribute("role", "group"); seg.setAttribute("aria-label", T("Background"));
    [["auto", "Auto"], ["light", "Light"], ["black", "Black"]].forEach(function (o) {
      var b = el("button", "", T(o[1])); b.type = "button"; b.dataset.mode = o[0]; b.title = T(o[0] === "auto" ? "Follow the theme" : o[0] === "light" ? "Light background" : "Pure black background (OLED)");
      b.setAttribute("aria-pressed", String(mode === o[0]));
      b.onclick = function () { setMode(o[0]); };
      seg.appendChild(b);
    });
    fsBtn = el("button", "viz-btn", T("Full screen")); fsBtn.type = "button"; fsBtn.title = T("Full screen") + " (F)";
    fsBtn.onclick = toggleFull;
    statusEl = el("span", "viz-status"); dotEl = el("span", "viz-dot"); dotEl.dataset.s = "wait";
    var stTxt = el("span", "", ""); statusEl.appendChild(dotEl); statusEl.appendChild(stTxt); statusEl.txt = stTxt;
    resEl = el("span", "viz-status", "");
    bar.appendChild(seg); bar.appendChild(fsBtn); bar.appendChild(el("span", "grow")); bar.appendChild(statusEl); bar.appendChild(resEl);
    chipsBox = el("div", "viz-chips");
    var main = el("div", "viz-main");
    stage = el("div", "viz-stage");
    canvas = el("canvas"); canvas.setAttribute("role", "img"); canvas.setAttribute("aria-label", T("Live picture of where Varsto keeps your data and what moves now"));
    demoTag = el("div", "viz-demo hidden", T("Demo data"));
    stage.appendChild(canvas); stage.appendChild(demoTag);
    side = el("aside", "viz-side");
    ["jobs", "disks", "protect", "health", "cost"].forEach(function (k) { panels[k] = el("section", "viz-card"); side.appendChild(panels[k]); });
    main.appendChild(stage); main.appendChild(side);
    root.appendChild(bar); root.appendChild(chipsBox); root.appendChild(main);
    page.appendChild(root);
    ctx = canvas.getContext("2d");
    bindDisplayEvents();
    root.addEventListener("pointermove", wake);
    root.addEventListener("pointerdown", wake);
  }

  function setMode(m) {
    mode = m; root.setAttribute("data-bg", m);
    try { localStorage.setItem("varsto-viz-bg", m); } catch (e) { /* not kept */ }
    bar.querySelectorAll(".viz-seg button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.mode === m)); });
    dirty = true; schedule(0);
  }
  function isDark() {
    if (mode === "black") { return true; }
    if (mode === "light") { return false; }
    var th = document.documentElement.dataset.theme;
    if (th) { return th === "dark"; }
    try { return !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches); } catch (e) { return false; }
  }

  // ---------------------------------------------------------------- full screen and display detection
  var pseudoFull = false, idleTimer = 0;
  function fullEl() { return document.fullscreenElement || document.webkitFullscreenElement || null; }
  function canFull() { return !!(root && (root.requestFullscreen || root.webkitRequestFullscreen)); }
  function toggleFull() {
    if (fullEl()) { (document.exitFullscreen || document.webkitExitFullscreen).call(document); return; }
    if (pseudoFull) { setPseudo(false); return; }
    if (canFull()) {
      var p = (root.requestFullscreen || root.webkitRequestFullscreen).call(root);
      if (p && p.catch) { p.catch(function () { setPseudo(true); }); }
    } else { setPseudo(true); }
  }
  function setPseudo(on) { pseudoFull = on; root.classList.toggle("pseudo-full", on); onFullChange(); }
  function onFullChange() {
    var full = !!fullEl() || pseudoFull;
    root.classList.toggle("is-full", !!fullEl());
    fsBtn.textContent = T(full ? "Exit full screen" : "Full screen");
    if (full) { wake(); } else { clearTimeout(idleTimer); root.classList.remove("viz-idle"); }
    detectDisplay(); dirty = true; schedule(0);
  }
  function wake() {
    root.classList.remove("viz-idle");
    clearTimeout(idleTimer);
    if (fullEl() || pseudoFull) { idleTimer = setTimeout(function () { root.classList.add("viz-idle"); }, 4000); }
  }
  var dprQuery = null;
  function bindDisplayEvents() {
    document.addEventListener("fullscreenchange", onFullChange);
    document.addEventListener("webkitfullscreenchange", onFullChange);
    window.addEventListener("resize", function () { detectDisplay(); });
    try { if (screen.orientation && screen.orientation.addEventListener) { screen.orientation.addEventListener("change", detectDisplay); } } catch (e) { /* none */ }
    // A monitor or TV attached or moved to: the Window Management API fires "change" on the screen.
    try { if (screen.addEventListener) { screen.addEventListener("change", detectDisplay); } } catch (e) { /* none */ }
    if (window.ResizeObserver) { var ro = new ResizeObserver(function () { detectDisplay(); }); ro.observe(stage); ro.observe(side); ro.observe(chipsBox); }
    watchDpr();
    document.addEventListener("keydown", function (ev) {
      if (!active || ev.ctrlKey || ev.metaKey || ev.altKey) { return; }
      var t = ev.target, tag = t && t.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (t && t.isContentEditable)) { return; }
      if (ev.key === "f" || ev.key === "F") { ev.preventDefault(); toggleFull(); }
      else if (ev.key === "Escape" && pseudoFull) { setPseudo(false); }
    });
    var th = document.documentElement;
    new MutationObserver(function () { dirty = true; schedule(0); }).observe(th, { attributes: true, attributeFilter: ["data-theme"] });
    try { window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () { dirty = true; schedule(0); }); } catch (e) { /* none */ }
  }
  // devicePixelRatio changes (zoom, another monitor) are only announced through a media query for the current value.
  function watchDpr() {
    try {
      if (dprQuery && dprQuery.removeEventListener) { dprQuery.removeEventListener("change", onDpr); }
      dprQuery = window.matchMedia("(resolution: " + (window.devicePixelRatio || 1) + "dppx)");
      if (dprQuery.addEventListener) { dprQuery.addEventListener("change", onDpr); }
    } catch (e) { /* none */ }
  }
  function onDpr() { watchDpr(); detectDisplay(); }
  // Wide full-screen view: the canvas is the whole window and the bar, chips and side panel sit on it.
  function overlayFull() { return (!!fullEl() || pseudoFull) && window.innerWidth > 1100; }
  // The side panel never scrolls: the cards that do not fit are left out, the least important first.
  function fitSide(over) {
    var order = ["cost", "disks", "protect", "health", "jobs"];
    order.forEach(function (k) { panels[k].style.display = ""; });
    if (!over) { return; }
    for (var i = 0; i < order.length - 1 && side.scrollHeight > side.clientHeight + 1; i++) { panels[order[i]].style.display = "none"; }
  }
  function detectDisplay() {
    if (!canvas) { return; }
    var r = stage.getBoundingClientRect();
    cssW = Math.max(1, Math.round(r.width)); cssH = Math.max(1, Math.round(r.height));
    dpr = window.devicePixelRatio || 1;
    var bw = Math.round(cssW * dpr), bh = Math.round(cssH * dpr);
    // Never ask for a bigger bitmap than browsers allow.
    var lim = 8192, cap = 36e6, sc = Math.min(1, lim / Math.max(bw, bh), Math.sqrt(cap / (bw * bh)));
    bw = Math.max(1, Math.floor(bw * sc)); bh = Math.max(1, Math.floor(bh * sc));
    if (canvas.width !== bw || canvas.height !== bh) { canvas.width = bw; canvas.height = bh; }
    W = bw; H = bh; layoutKey = "";
    var sw = Math.round((screen.width || cssW) * dpr), sh = Math.round((screen.height || cssH) * dpr);
    resEl.textContent = T("Display") + " " + Math.max(sw, sh) + "×" + Math.min(sw, sh) + " · ×" + nf(dpr, 2) + " · " + T("canvas") + " " + bw + "×" + bh;
    var over = overlayFull();
    root.classList.toggle("viz-over", over);
    // Bigger text on big screens: the page's root size follows the CSS size of the canvas, or of the window when the canvas is the whole window.
    var sc = over ? Math.min(window.innerWidth / 1280, window.innerHeight / 720) : Math.min(cssW, cssH * 1.6) / 900;
    root.style.setProperty("--vz-scale", String(clamp(sc, 1, 3.2)));
    area = { x: 0, y: 0, w: cssW, h: cssH };
    if (over) {
      var cr = chipsBox.getBoundingClientRect(), sr = side.getBoundingClientRect(), g = 14 * clamp(sc, 1, 3.2);
      area = { x: g, y: Math.max(0, cr.bottom - r.top) + g * 0.5, w: Math.max(1, sr.left - r.left - 2 * g), h: 1 };
      area.h = Math.max(1, cssH - area.y - g);
    }
    fitSide(over);
    dirty = true; schedule(0);
  }

  // ---------------------------------------------------------------- sprites
  var MAN = null, manLoading = false;
  var imgs = {};
  function loadManifest() {
    if (MAN || manLoading) { return; }
    manLoading = true;
    fetch("/viz/manifest.json").then(function (r) { return r.json(); }).then(function (j) { MAN = j; dirty = true; schedule(0); }).catch(function () { MAN = {}; });
  }
  function sprite(name, px) {
    var dark = isDark(), big = px > 440;
    var key = name + (dark ? "-dark" : "") + (big ? "@2x" : "");
    var im = imgs[key];
    if (!im) {
      im = new Image(); im.decoding = "async";
      im.onload = function () { im.ok = true; dirty = true; schedule(0); };
      im.onerror = function () { im.bad = true; };
      im.src = "/viz/" + key + ".webp";
      imgs[key] = im;
    }
    if (im.ok) { return im; }
    // The other size of the same sprite while this one loads.
    var alt = imgs[name + (dark ? "-dark" : "") + (big ? "" : "@2x")];
    return alt && alt.ok ? alt : null;
  }

  // ---------------------------------------------------------------- projection (the sprites' camera: 33 deg elevation, 32 deg azimuth)
  var A = 32 * Math.PI / 180, E = 33 * Math.PI / 180, cA = Math.cos(A), sA = Math.sin(A), sE = Math.sin(E), cE = Math.cos(E);
  function P(x, y, z) { return [x * cA + y * sA, -((-x * sA + y * cA) * sE) - (z || 0) * cE]; }

  // ---------------------------------------------------------------- scene model
  var FOLDER_COLORS = ["#2b57d6", "#14a98e", "#e9962b", "#8e6cf0", "#e0535a", "#2f9bd6", "#d9609f", "#7aa83a"];
  var NODE_BASE = {
    laptop: "laptop", phone: "phone", tablet: "tablet", monitor: "monitor", nas: "nas", shelf: "shelf", bucket: "bucket", cloud: "cloud", archive: "archive", usb: "usb", dock: "dock"
  };
  function deviceSprite(d) {
    var n = (d.name || "").toLowerCase();
    if (d.platform === "android" || d.platform === "ios") { return /ipad|tablet|tab\b/.test(n) ? "tablet" : "phone"; }
    if (/ipad|tablet/.test(n)) { return "tablet"; }
    if (/desktop|tower|workstation|\bpc\b|imac|mini/.test(n)) { return "monitor"; }
    return "laptop";
  }
  function storageSprite(s) {
    if (s.kind === "pool") { return "shelf"; }
    if (s.kind === "transferrer" || s.carrier) { return "usb"; }
    if (s.kind === "s3") { return s.cold ? "archive" : "bucket"; }
    if (s.kind === "rclone") { return s.cold ? "archive" : "cloud"; }
    if (s.kind === "replica") { return "nas"; }
    if (s.kind === "unknown") { return "cloud"; }
    return s.state === "full" || s.state === "warning" ? "nas-warn" : "nas";
  }
  function tierOf(s) {
    if (s.kind === "pool" || s.kind === "directory" || s.kind === "transferrer") { return 1; }
    if (s.place && s.place !== "cloud" && s.kind !== "s3" && s.kind !== "rclone") { return 1; }
    return 2;
  }

  function buildModel(sn) {
    var nodes = [], byId = {}, folders = {}, order = (sn.folders || []).map(function (f) { return f.name; }).sort();
    order.forEach(function (n, i) { folders[n] = FOLDER_COLORS[i % FOLDER_COLORS.length]; });
    (sn.devices || []).forEach(function (d) {
      var n = { id: "d:" + d.id, kind: "device", tier: 0, sprite: deviceSprite(d), title: d.name, d: d, online: d.online !== false, key: "0" + d.name };
      nodes.push(n); byId[n.id] = n;
    });
    var disksByPool = {};
    ((sn.disks && sn.disks.list) || []).forEach(function (d) { (disksByPool[d.pool] = disksByPool[d.pool] || []).push(d); });
    (sn.storages || []).forEach(function (s) {
      var n = { id: "s:" + s.name, kind: "storage", tier: s.kind === "replica" ? 2 : tierOf(s), sprite: storageSprite(s), title: s.name, s: s, online: true, key: "1" + s.kind + s.name };
      nodes.push(n); byId[n.id] = n;
      if (s.kind === "pool") {
        var dk = disksByPool[s.name] || [];
        var cur = dk.filter(function (d) { return d.docked; })[0] || dk.filter(function (d) { return d.phase !== "away" && d.phase !== "wanted"; })[0];
        var dn = { id: "dock:" + s.name, kind: "dock", tier: 1, sprite: "dock", title: T("Disk dock"), pool: s.name, disks: dk, cur: cur || null, online: true, key: "1pool" + s.name + "~" };
        nodes.push(dn); byId[dn.id] = dn;
        dk.forEach(function (d) { byId["p:" + d.label] = dn; });
      }
    });
    return { nodes: nodes, byId: byId, folderColor: folders };
  }

  function doLayout(model) {
    var tiers = [[], [], []];
    model.nodes.forEach(function (n) { tiers[n.tier].push(n); });
    tiers.forEach(function (t) { t.sort(function (a, b) { return a.key < b.key ? -1 : 1; }); });
    var biggest = Math.max(tiers[0].length, tiers[1].length, tiers[2].length, 1), best = null;
    // Try the number of nodes per row and keep the one that makes the board largest on this canvas.
    for (var perRow = 1; perRow <= Math.min(6, biggest); perRow++) {
      var r = layoutRows(model, tiers, perRow);
      if (!best || r.k > best.k * 1.02) { best = r; }
    }
    model.k = best.k; model.zones = best.zones; model.dy = best.dy; model.ox = best.ox; model.oy = best.oy;
    best.pos.forEach(function (p) { p[0].x = p[1]; p[0].y = p[2]; });
  }
  function layoutRows(model, tiers, perRow) {
    var dx = 2.5, dy = 3.9, y = 0, zones = [], grow = 0, pos = [];
    var names = [T("Devices"), T("Home"), T("Cloud")];
    tiers.forEach(function (t, ti) {
      if (!t.length) { return; }
      var rows = Math.ceil(t.length / perRow), cols = Math.ceil(t.length / rows), y0 = y, zw = cols * dx;
      for (var r = 0; r < rows; r++) {
        // Alternate rows sit half a step aside, so a straight line along the board's depth axis passes between the nodes of the row in between.
        var inRow = Math.min(cols, t.length - r * cols), shift = (grow + r) % 2 ? dx / 2 : 0;
        for (var c = 0; c < inRow; c++) { pos.push([t[r * cols + c], (c - (inRow - 1) / 2) * dx + shift, y0 + r * dy]); }
      }
      grow += rows;
      zones.push({ name: names[ti], tier: ti, x0: -zw / 2 - 0.9, x1: zw / 2 + 0.9 + dx / 2, y0: y0 - 1.5, y1: y0 + (rows - 1) * dy + 1.5 });
      y = y0 + rows * dy + 0.9;
    });
    // Screen extent at scale 1 (metres), with margins for sprites and labels.
    var minX = 1e9, maxX = -1e9, minY = 1e9, maxY = -1e9;
    function ext(p) { minX = Math.min(minX, p[0]); maxX = Math.max(maxX, p[0]); minY = Math.min(minY, p[1]); maxY = Math.max(maxY, p[1]); }
    zones.forEach(function (z) { [[z.x0, z.y0], [z.x1, z.y0], [z.x1, z.y1], [z.x0, z.y1]].forEach(function (c) { ext(P(c[0], c[1], 0)); }); });
    pos.forEach(function (q) { var p = P(q[1], q[2], 0); ext([p[0] - 1.3, p[1] - 1.9]); ext([p[0] + 1.3, p[1] + 1.3]); });
    var pad = area.w < area.h * 0.8 ? 0.01 : 0.03, k = Math.min(area.w * (1 - 2 * pad) / (maxX - minX), area.h * (1 - 2 * pad) / (maxY - minY));
    return { k: k, zones: zones, dy: dy, pos: pos, ox: area.x + (area.w - (maxX + minX) * k) / 2, oy: area.y + (area.h - (maxY + minY) * k) / 2 };
  }
  function S(x, y, z) { var p = P(x, y, z); return [layout.ox + p[0] * layout.k, layout.oy + p[1] * layout.k]; }

  // ---------------------------------------------------------------- drawing
  function rr(c, x, y, w, h, r) {
    r = Math.min(r, w / 2, h / 2);
    c.beginPath(); c.moveTo(x + r, y); c.arcTo(x + w, y, x + w, y + h, r); c.arcTo(x + w, y + h, x, y + h, r); c.arcTo(x, y + h, x, y, r); c.arcTo(x, y, x + w, y, r); c.closePath();
  }
  function palette(dark) {
    return dark ? { text: "#eef1f6", muted: "#98a3b3", pill: mode === "black" ? "#0d0f13" : "#1d2431", pillB: "rgba(255,255,255,.12)", zone: "rgba(138,169,255,.06)", zoneB: "rgba(138,169,255,.16)", track: "rgba(255,255,255,.14)", ok: "#3ecf8e", warn: "#f0a53a", bad: "#f0646b", blue: "#8aa9ff" }
      : { text: "#1c2a3a", muted: "#5f6f84", pill: "rgba(255,255,255,.94)", pillB: "rgba(43,87,214,.14)", zone: "rgba(43,87,214,.045)", zoneB: "rgba(43,87,214,.14)", track: "rgba(43,87,214,.13)", ok: "#1fa971", warn: "#d98a14", bad: "#d6433a", blue: "#2b57d6" };
  }
  var FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, Roboto, "Helvetica Neue", Arial, sans-serif';
  function fs(px, w) { return (w || 500) + " " + px + "px " + FONT; }
  function pill(c, x, y, text, o) {
    o = o || {};
    var size = o.size, padX = size * 0.62, h = size * 1.7;
    c.font = fs(size, o.weight || 600);
    var tw = c.measureText(text).width, w = tw + padX * 2 + (o.dot ? size * 1 : 0);
    var left = o.anchor === "l" ? x : o.anchor === "r" ? x - w : x - w / 2, top = y - h / 2;
    rr(c, left, top, w, h, h / 2);
    c.fillStyle = o.bg; c.fill();
    if (o.border) { c.lineWidth = 1; c.strokeStyle = o.border; c.stroke(); }
    var tx = left + padX;
    if (o.dot) { c.fillStyle = o.dot; c.beginPath(); c.arc(tx + size * 0.32, y, size * 0.3, 0, 6.2832); c.fill(); tx += size * 1; }
    c.fillStyle = o.fg; c.textBaseline = "middle"; c.textAlign = "left"; c.fillText(text, tx, y + size * 0.04);
    var rect = { x: left, y: top, w: w, h: h };
    if (!o.free) { placed.push(rect); }
    return rect;
  }
  function flowPath(a, b, lane) {
    // On the floor, along the board's axes: out of the sender along the depth axis into the aisle between two rows, across to the receiver's
    // column, then in. Parallel flows between the same nodes use lanes beside each other.
    var off = (lane || 0) * 0.3, z = 0.12, dir = b.y >= a.y ? 1 : -1;
    var ay = a.y + dir * layout.dy / 2 + off * dir;
    var pts;
    if (Math.abs(a.x - b.x) < 0.01 && Math.abs(a.y - b.y) > 0.01) { pts = [[a.x + off, a.y], [b.x + off, b.y]]; }
    else { pts = [[a.x + off, a.y], [a.x + off, ay], [b.x + off, ay], [b.x + off, b.y]]; }
    var out = pts.map(function (p) { return S(p[0], p[1], z); });
    return trim(out, layout.k * 0.62);
  }
  function trim(pts, d) {
    if (pts.length < 2) { return pts; }
    function cut(p, q, d2) { var dx = q[0] - p[0], dy = q[1] - p[1], L = Math.hypot(dx, dy) || 1; if (L <= d2) { return p; } return [p[0] + dx / L * d2, p[1] + dy / L * d2]; }
    var r = pts.slice();
    r[0] = cut(pts[0], pts[1], d);
    r[r.length - 1] = cut(pts[pts.length - 1], pts[pts.length - 2], d);
    return r;
  }
  function polyLen(pts) { var L = 0; for (var i = 1; i < pts.length; i++) { L += Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]); } return L; }
  function along(pts, s) {
    for (var i = 1; i < pts.length; i++) {
      var d = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]);
      if (s <= d || i === pts.length - 1) { var f = d ? clamp(s / d, 0, 1) : 0; return [pts[i - 1][0] + (pts[i][0] - pts[i - 1][0]) * f, pts[i - 1][1] + (pts[i][1] - pts[i - 1][1]) * f]; }
      s -= d;
    }
    return pts[pts.length - 1];
  }

  var anyMotion = false, curSn = null, placed = [];
  function hits(r) { for (var i = 0; i < placed.length; i++) { var q = placed[i]; if (r.x < q.x + q.w + 4 && r.x + r.w + 4 > q.x && r.y < q.y + q.h + 2 && r.y + r.h + 2 > q.y) { return true; } } return false; }
  function draw(t) {
    if (!ctx) { return; }
    var sn = snap || demoSnap(); curSn = sn;
    var dark = isDark(), pal = palette(dark);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.setTransform(canvas.width / cssW, 0, 0, canvas.height / cssH, 0, 0);
    // Layout in CSS pixels.
    var key = JSON.stringify([sn.devices.map(function (d) { return d.id; }), sn.storages.map(function (s) { return s.name + s.kind; }), (sn.disks && sn.disks.list || []).map(function (d) { return d.pool + d.label; }), cssW, cssH, T("Home"), area.x, area.y, area.w, area.h]);
    if (!layout || key !== layoutKey) {
      var model = buildModel(sn); doLayout(model); layout = model; layoutKey = key;
    } else {
      // Keep positions, refresh node data.
      var fresh = buildModel(sn);
      fresh.nodes.forEach(function (n) { var o = layout.byId[n.id]; if (o && o.kind === n.kind) { n.x = o.x; n.y = o.y; } });
      fresh.k = layout.k; fresh.ox = layout.ox; fresh.oy = layout.oy; fresh.zones = layout.zones; fresh.dy = layout.dy; layout = fresh;
      layout.nodes.forEach(function (n) { if (n.x === undefined) { layoutKey = ""; } });
    }
    var m = layout, k = m.k;
    placed = [];
    var fontS = clamp(k * 0.2, cssW < 520 ? 9 : 11, 90);
    // Zones (platforms).
    m.zones.forEach(function (z) {
      var c = [S(z.x0, z.y0, 0), S(z.x1, z.y0, 0), S(z.x1, z.y1, 0), S(z.x0, z.y1, 0)];
      ctx.beginPath(); ctx.moveTo(c[0][0], c[0][1]); for (var i = 1; i < 4; i++) { ctx.lineTo(c[i][0], c[i][1]); } ctx.closePath();
      ctx.fillStyle = pal.zone; ctx.fill(); ctx.lineWidth = 1.2; ctx.strokeStyle = pal.zoneB; ctx.stroke();
      ctx.font = fs(fontS * 0.8, 700); ctx.fillStyle = pal.muted; ctx.textAlign = "left"; ctx.textBaseline = "middle";
      var lp = S(z.x0 + 0.3, z.y0 + 0.1, 0); ctx.save(); ctx.translate(lp[0], lp[1]); ctx.fillText(z.name.toUpperCase(), 4, -fontS * 0.4); ctx.restore();
    });
    // Flows under the nodes.
    var flows = (sn.flows || []).filter(function (f) { return f.from && f.to; });
    var lanes = {};
    var drawn = [];
    flows.forEach(function (f) {
      var a = m.byId[f.from], b = m.byId[f.to];
      if (!a || !b || a === b || a.x === undefined || b.x === undefined) { return; }
      var pk = [a.id, b.id].sort().join("|"), lane = lanes[pk] || 0; lanes[pk] = lane + 1;
      var path = flowPath(a, b, lane - 0);
      if (path.length < 2) { return; }
      drawn.push({ f: f, a: a, b: b, path: path });
    });
    anyMotion = drawn.length > 0;
    var labelBoxes = [];
    drawn.forEach(function (d) {
      var f = d.f, col = f.folder && m.folderColor[f.folder] ? m.folderColor[f.folder] : (f.kind === "p2p" || f.kind === "relay" ? pal.blue : "#14a98e");
      var bps = f.bps || 0, w = clamp(2.2 + Math.log10(Math.max(bps, 1)) * 0.7, 2.5, 8) * clamp(k / 90, 0.8, 2.2);
      ctx.lineCap = "round"; ctx.lineJoin = "round";
      ctx.beginPath(); d.path.forEach(function (p, i) { if (i) { ctx.lineTo(p[0], p[1]); } else { ctx.moveTo(p[0], p[1]); } });
      ctx.globalAlpha = dark ? 0.2 : 0.16; ctx.strokeStyle = col; ctx.lineWidth = w * 2.4; ctx.stroke();
      ctx.globalAlpha = dark ? 0.5 : 0.42; ctx.lineWidth = w; ctx.stroke(); ctx.globalAlpha = 1;
      // Particles run from the sender to the receiver; the speed follows bytes per second.
      var L = polyLen(d.path), gap = Math.max(26, k * 0.5), speed = clamp(30 + Math.log10(Math.max(bps, 10)) * 22, 30, 210) * clamp(k / 90, 0.8, 2.2);
      var n = Math.max(1, Math.floor(L / gap)), off = reduced ? 0 : (t * speed) % gap;
      for (var i = 0; i <= n; i++) {
        var s = i * gap + off; if (s > L) { continue; }
        var p = along(d.path, s), r = w * 0.95;
        ctx.globalAlpha = 0.28; ctx.fillStyle = col; ctx.beginPath(); ctx.arc(p[0], p[1], r * 2.1, 0, 6.2832); ctx.fill();
        ctx.globalAlpha = 1; ctx.fillStyle = dark ? "#ffffff" : col; ctx.beginPath(); ctx.arc(p[0], p[1], r, 0, 6.2832); ctx.fill();
      }
      // Arrow head at the receiving end.
      var e = d.path[d.path.length - 1], q = d.path[d.path.length - 2], ang = Math.atan2(e[1] - q[1], e[0] - q[0]), ah = w * 2.2;
      ctx.fillStyle = col; ctx.beginPath(); ctx.moveTo(e[0] + Math.cos(ang) * ah, e[1] + Math.sin(ang) * ah);
      ctx.lineTo(e[0] + Math.cos(ang + 2.5) * ah, e[1] + Math.sin(ang + 2.5) * ah); ctx.lineTo(e[0] + Math.cos(ang - 2.5) * ah, e[1] + Math.sin(ang - 2.5) * ah); ctx.closePath(); ctx.fill();
      d.col = col;
    });
    // Nodes, far to near.
    var sorted = m.nodes.filter(function (n) { return n.x !== undefined; }).sort(function (a, b) { return S(a.x, a.y, 0)[1] - S(b.x, b.y, 0)[1]; });
    var rings = ringTargets(sn);
    sorted.forEach(function (n) { drawNode(n, t, pal, dark, fontS, rings); });
    // Flow labels on top.
    var top = drawn.slice().sort(function (a, b) { return (b.f.bps || 0) - (a.f.bps || 0); }).slice(0, layout.k < 62 ? 3 : 12);
    top.forEach(function (d) {
      var f = d.f, L = polyLen(d.path);
      var parts = [];
      if (f.folder) { parts.push(f.folder); } else if (f.kind === "p2p") { parts.push(T("Peer-to-peer")); } else if (f.kind === "relay") { parts.push(T("Relay")); }
      if (f.bps > 0) { parts.push(rate(f.bps)); }
      var eta = f.eta_utc ? etaText(f.eta_utc) : "";
      if (eta && eta !== "\u2014") { parts.push("\u23f1 " + eta); }
      if (f.kind === "disk_fill" && !f.folder) { parts.unshift(kindText("disk_fill")); }
      if (!parts.length) { return; }
      var sz = fontS * 0.86, tx = parts.join(" \u00b7 ");
      ctx.font = fs(sz, 600);
      var w = ctx.measureText(tx).width + sz * 2.2, h = sz * 1.7;
      // First free place along the path, middle first.
      var cand = [0.5, 0.4, 0.6, 0.3, 0.7, 0.2, 0.8, 0.1, 0.9], dys = [0, -1.1, 1.1, -2.2, 2.2], done = false;
      for (var di = 0; di < dys.length && !done; di++) {
        for (var ci = 0; ci < cand.length; ci++) {
          var mid = along(d.path, L * cand[ci]), my = mid[1] + dys[di] * h, r = { x: mid[0] - w / 2, y: my - h / 2, w: w, h: h };
          if (!hits(r)) { pill(ctx, mid[0], my, tx, { size: sz, bg: pal.pill, fg: pal.text, border: d.col, dot: d.col }); done = true; break; }
        }
      }
    });
    if (!sn.devices.length && !sn.storages.length) { emptyHint(pal); }
  }
  function emptyHint(pal) {
    ctx.font = fs(18, 600); ctx.fillStyle = pal.muted; ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText(T("Nothing to show yet"), cssW / 2, cssH / 2);
  }

  function ringTargets(sn) {
    var r = {};
    (sn.jobs || []).forEach(function (j) {
      var kind = j.kind;
      if (!/^(verify|scrub|repair|fsck|disk_check|disk_fsck|drain|disk_insert|storage_removal)$/.test(kind)) { return; }
      var id = null;
      if (/^disk_/.test(kind)) { id = "p:" + j.subject; } else if (j.subject) { id = "s:" + j.subject; }
      if (!id) { return; }
      var col = kind === "repair" ? "#e0535a" : kind === "drain" ? "#e9962b" : kind === "scrub" ? "#8e6cf0" : "#2f9bd6";
      r[id] = { color: col, kind: kind, percent: j.percent };
    });
    return r;
  }

  function drawNode(n, t, pal, dark, fontS, rings) {
    var k = layout.k, foot = S(n.x, n.y, 0);
    var name = n.sprite, scaleBoost = n.kind === "dock" ? 1 : 1;
    // Docked disk on its dock: the disk sprite lifted a little, in its state.
    var alpha = n.online ? 1 : 0.5;
    var man = MAN && MAN[name];
    var span = man ? man.span_m : 1.7;
    var w = span * k * scaleBoost;
    var ring = rings[n.id] || (n.kind === "dock" && n.cur && rings["p:" + n.cur.label]) || null;
    if (ring) {
      var pulse = reduced ? 0.5 : (Math.sin(t * 3.2) + 1) / 2, rx = k * (0.95 + pulse * 0.25), ry = rx * sE * 1.15;
      ctx.save(); ctx.translate(foot[0], foot[1] + k * 0.1); ctx.scale(1, ry / rx);
      ctx.lineWidth = Math.max(2, k * 0.06); ctx.strokeStyle = ring.color; ctx.globalAlpha = 0.85 - pulse * 0.45;
      ctx.beginPath(); ctx.arc(0, 0, rx, 0, 6.2832); ctx.stroke();
      ctx.globalAlpha = 0.14; ctx.fillStyle = ring.color; ctx.fill(); ctx.restore(); ctx.globalAlpha = 1;
      anyMotion = anyMotion || !reduced;
    }
    var im = MAN ? sprite(name, w * dpr) : null;
    ctx.globalAlpha = alpha;
    if (im && man) { ctx.drawImage(im, foot[0] - man.ax * w, foot[1] - man.ay * w, w, w); }
    else { rr(ctx, foot[0] - k * 0.5, foot[1] - k * 0.7, k, k * 0.7, k * 0.12); ctx.fillStyle = pal.zoneB; ctx.fill(); }
    ctx.globalAlpha = 1;
    placed.push({ x: foot[0] - w * 0.25, y: foot[1] - w * 0.58, w: w * 0.5, h: w * 0.56 });
    // Docked disk on the dock.
    if (n.kind === "dock") { drawDockDisk(n, foot, k, t, pal, dark, fontS); }
    // Labels under the node.
    var y = foot[1] + k * 0.42, sz = fontS;
    var title = n.title, subs = [];
    var dotCol = n.kind === "device" ? (n.online ? pal.ok : pal.muted) : null;
    if (n.kind === "device") {
      var d = n.d;
      var up = d.tx_bps > 0 ? "↑ " + rate(d.tx_bps) : "", dn = d.rx_bps > 0 ? "↓ " + rate(d.rx_bps) : "";
      subs.push(d.online === false ? T("offline") : [up, dn].filter(Boolean).join("  ") || (d.role === "this" ? T("this device") : T("online")));
    } else if (n.kind === "storage") {
      var s = n.s, bits = [];
      bits.push(bytes(s.used_bytes) + (s.quota_bytes ? " / " + bytes(s.quota_bytes) : ""));
      subs.push(bits.join(" "));
      if (s.state === "full" || s.state === "warning") { dotCol = s.state === "full" ? pal.bad : pal.warn; }
      else if (s.state !== "none") { dotCol = pal.ok; }
      if (s.drain) { subs.push(T("Draining") + " " + s.drain.percent + " %" + (s.drain.eta_utc ? " · " + etaText(s.drain.eta_utc) : "")); }
    } else if (n.kind === "dock") {
      var dc = n.cur;
      subs.push(dc ? (T("Disk") + " " + dc.label + " · " + phaseText(dc)) : T("no disk docked"));
    }
    var compact = k < 62;
    if (compact && n.kind !== "dock") { subs = []; }
    var ly = y + sz * 0.9;
    var bgp = pal.pill;
    var shown = n.kind === "storage" && n.s.kind === "pool" ? [] : [];
    var tbox = pill(ctx, foot[0], ly, title, { size: sz, bg: bgp, fg: pal.text, border: pal.pillB, dot: dotCol });
    var yy = ly + sz * 1.5;
    subs.forEach(function (tx) { ctx.font = fs(sz * 0.86, 500); ctx.fillStyle = pal.muted; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText(tx, foot[0], yy); var tw = ctx.measureText(tx).width; placed.push({ x: foot[0] - tw / 2, y: yy - sz * 0.55, w: tw, h: sz * 1.1 }); yy += sz * 1.15; });
    // Fullness bar and cost badge of a storage.
    if (n.kind === "storage") {
      var s2 = n.s, bw = Math.max(k * 1.6, 70), bh = Math.max(4, sz * 0.32), bx = foot[0] - bw / 2;
      var frac = s2.quota_bytes ? clamp(s2.used_bytes / s2.quota_bytes, 0, 1) : null;
      if (frac !== null) {
        rr(ctx, bx, yy - bh / 2 + 2, bw, bh, bh / 2); ctx.fillStyle = pal.track; ctx.fill();
        rr(ctx, bx, yy - bh / 2 + 2, Math.max(bh, bw * frac), bh, bh / 2); ctx.fillStyle = frac >= 0.9 ? pal.bad : frac >= 0.7 ? pal.warn : pal.ok; ctx.fill();
        yy += bh + sz * 0.5;
      }
      var chips = [];
      if (s2.monthly_cost !== null && s2.monthly_cost !== undefined && s2.price) { chips.push("≈ " + money(s2.monthly_cost, s2.price.currency) + "/" + T("mo")); }
      if (s2.verified_bytes > 0 && s2.data_bytes > 0) { chips.push("✔ " + Math.round(s2.verified_bytes / s2.data_bytes * 100) + " %"); }
      if (compact) { chips = []; }
      if (chips.length) { var cim = MAN ? sprite("coins", 60) : null; pill(ctx, foot[0], yy + sz * 0.6, chips.join("  ·  "), { size: sz * 0.82, bg: pal.pill, fg: pal.text, border: pal.pillB, weight: 500 }); }
      if (s2.kind === "pool" && !compact) {
        var dsk = curSn.disks;
        var wait = (curSn.moves || []).filter(function (mv) { return mv.waiting === "disk" && mv.to === s2.name; })[0];
        var txt = dsk.count + " " + T(dsk.count === 1 ? "disk" : "disks") + (dsk.docked && dsk.docked.length ? " · " + dsk.docked.length + " " + T("docked") : "");
        pill(ctx, foot[0], yy + sz * (chips.length ? 2.2 : 0.6), txt, { size: sz * 0.82, bg: pal.pill, fg: pal.text, border: pal.pillB, weight: 500 });
        if (wait) { pill(ctx, foot[0], yy + sz * (chips.length ? 3.9 : 2.3), T("Waiting for a disk") + (wait.waiting_disk ? ": " + wait.waiting_disk : ""), { size: sz * 0.82, bg: dark ? "#3a2c0f" : "#fff3d6", fg: dark ? "#f5c86a" : "#8a5a00", border: pal.warn, weight: 600 }); }
      }
    }
  }
  function phaseText(d) {
    var p = d.phase, label = { verify: "Verifying", fill: "Filling", tidy: "Tidying", fsck: "Checking", fetch: "Fetching", init: "Preparing", unmount: "Ejecting", idle: "Idle", away: "Away", wanted: "Wanted" }[p] || p;
    var s = T(label);
    if (d.progress !== null && d.progress !== undefined) { s += " " + Math.round(d.progress) + " %"; }
    if (d.eta_utc) { s += " · " + etaText(d.eta_utc); }
    return s;
  }
  function drawDockDisk(n, foot, k, t, pal, dark, fontS) {
    var d = n.cur; if (!d) { return; }
    var name = d.failing ? "disk-bad" : d.phase === "idle" ? "disk" : "disk-busy";
    var man = MAN && MAN[name]; if (!man) { return; }
    var w = man.span_m * k * 0.72, bob = reduced || d.phase === "idle" ? 0 : Math.sin(t * 2.2) * k * 0.03;
    var im = sprite(name, w * dpr);
    if (im) { ctx.drawImage(im, foot[0] - man.ax * w, foot[1] - k * 0.42 - man.ay * w + bob, w, w); }
    if (d.progress !== null && d.progress !== undefined) {
      var bw = k * 1.1, bh = Math.max(4, fontS * 0.3), bx = foot[0] - bw / 2, by = foot[1] - k * 1.0;
      rr(ctx, bx, by, bw, bh, bh / 2); ctx.fillStyle = pal.track; ctx.fill();
      rr(ctx, bx, by, Math.max(bh, bw * d.progress / 100), bh, bh / 2); ctx.fillStyle = pal.blue; ctx.fill();
    }
  }

  // ---------------------------------------------------------------- panels (DOM)
  function card(key, title, count) {
    var p = panels[key]; p.textContent = "";
    var h = el("h3"); h.appendChild(el("span", "", T(title)));
    if (count !== undefined && count !== null && count !== "") { h.appendChild(el("span", "n", String(count))); }
    p.appendChild(h); return p;
  }
  function bar2(parts, total) {
    var tr = el("div", "viz-bar-track");
    parts.forEach(function (pt) { if (pt.v > 0 && total > 0) { var i = el("i"); i.style.width = (pt.v / total * 100) + "%"; i.style.background = pt.c; i.title = pt.t || ""; tr.appendChild(i); } });
    return tr;
  }
  function row(title, right, sub, frac, color) {
    var r = el("div", "viz-row"), l1 = el("div", "l1");
    l1.appendChild(el("span", "t", title)); l1.appendChild(el("span", "r", right || ""));
    r.appendChild(l1);
    if (sub) { r.appendChild(el("div", "l2", sub)); }
    if (frac !== null && frac !== undefined) { r.appendChild(bar2([{ v: clamp(frac, 0, 1) * 100, c: color || "var(--vz-info)" }], 100)); }
    return r;
  }
  function tag(text, level) { var t = el("span", "viz-tag", text); if (level) { t.dataset.level = level; } return t; }

  function renderPanels() {
    if (!root) { return; }
    var sn = snap || demoSnap();
    // Chips.
    chipsBox.textContent = "";
    var rx = 0, tx = 0;
    (sn.flows || []).forEach(function (f) { if (f.kind === "upload") { tx += f.bps || 0; } else if (f.kind === "download") { rx += f.bps || 0; } });
    var jobs = sn.jobs || [], alerts = sn.alerts || [], worst = sn.health ? sn.health.overall : "ok";
    var ver = 0, tot = 0; (sn.folders || []).forEach(function (f) { ver += f.verified_blocks || 0; tot += f.blocks || 0; });
    var cost = sn.cost && sn.cost.month || {}, cur = Object.keys(cost);
    function chip(k, v, s, level) { var c = el("div", "viz-chip"); if (level) { c.dataset.level = level; } c.appendChild(el("div", "k", T(k))); c.appendChild(el("div", "v", v)); c.appendChild(el("div", "s", s || " ")); chipsBox.appendChild(c); }
    chip("Health", T(worst === "ok" ? "All good" : worst === "warn" ? "Attention" : "Problem"), alerts.length ? alerts.length + " " + T(alerts.length === 1 ? "alert" : "alerts") : T("no alerts"), worst);
    chip("Running now", String(jobs.length), jobs.length ? T("tasks on all devices") : T("idle"));
    chip("Network", "\u2191 " + rate(tx), "\u2193 " + rate(rx) + " \u00b7 " + T("peer traffic") + " " + rate((sn.traffic && (sn.traffic.rx_bps + sn.traffic.tx_bps)) || 0));
    chip("Copies", sn.copies && sn.copies.average ? nf(sn.copies.average, 1) : "—", T("average copies per block"), sn.copies && sn.copies.blocks && sn.copies.blocks[0] > 0 ? "bad" : null);
    chip("Verified", tot ? Math.round(ver / tot * 100) + " %" : "—", T("blocks checked by another device"));
    chip("Cloud cost", cur.length ? "≈ " + cur.map(function (c) { return money(cost[c], c); }).join(" + ") + "/" + T("mo") : "—", T("estimate"));
    chip("Offline disks", String(sn.disks ? sn.disks.count : 0), sn.disks && sn.disks.docked && sn.disks.docked.length ? T("docked") + ": " + sn.disks.docked.join(", ") : T("none docked"));
    // Running now.
    var p = card("jobs", "Running now", jobs.length || "");
    if (!jobs.length && !(sn.moves || []).length) { p.appendChild(el("p", "viz-empty", T("Nothing is running."))); }
    jobs.slice(0, 12).forEach(function (j) {
      var right = j.percent !== null && j.percent !== undefined ? pctText(j.percent) : "";
      var sub = [j.device_name, j.rate > 0 && j.unit === "bytes" ? rate(j.rate) : "", j.total && j.unit === "bytes" ? bytes(j.done) + " / " + bytes(j.total) : ""].filter(Boolean).join(" · ");
      var r = row(kindText(j.kind) + (j.subject ? " · " + j.subject : ""), right, sub, j.percent !== null && j.percent !== undefined ? j.percent / 100 : null);
      var e = el("div", "l2"); e.appendChild(document.createTextNode(T("Done in") + " ")); e.appendChild(el("span", "eta", etaText(j.eta_utc))); r.appendChild(e);
      p.appendChild(r);
    });
    (sn.moves || []).forEach(function (mv) {
      var frac = mv.bytes_total ? mv.bytes_done / mv.bytes_total : null;
      var r = row(T("Move") + " · " + mv.folder, frac !== null ? pctText(frac * 100) : "", mv.from + " → " + mv.to + " · " + bytes(mv.bytes_remaining) + " " + T("left"), frac, "var(--vz-accent)");
      if (mv.waiting) { var t = tag(T(mv.waiting === "disk" ? "waiting for a disk" : "waiting for room"), "warn"); r.firstChild.firstChild.appendChild(t); }
      p.appendChild(r);
    });
    (sn.drains || []).forEach(function (d) { p.appendChild(row(T("Drain") + " · " + d.storage, pctText(d.percent), bytes(d.bytes_left) + " " + T("left") + " · " + T("Done in") + " " + etaText(d.eta_utc), d.percent / 100, "var(--vz-warn)")); });
    // Offline disks.
    var dl = (sn.disks && sn.disks.list) || [];
    p = card("disks", "Offline disks", dl.length || "");
    if (!dl.length) { p.appendChild(el("p", "viz-empty", T("No disk pool configured."))); }
    dl.forEach(function (d) {
      var lvl = d.failing ? "bad" : d.docked ? "info" : d.phase === "wanted" ? "warn" : "";
      var r = row(T("Disk") + " " + d.label, d.capacity_bytes ? bytes(d.used_bytes) + " / " + bytes(d.capacity_bytes) : "", "", d.capacity_bytes ? d.used_bytes / d.capacity_bytes : null);
      r.firstChild.firstChild.appendChild(tag(d.docked ? (phaseText(d)) : T(d.phase === "wanted" ? "wanted by a move" : d.retired ? "retired" : "away"), lvl));
      var chk = d.last_verified_utc ? T("verified") + " " + ago(d.last_verified_utc) : T("never verified");
      r.insertBefore(el("div", "l2", chk + (d.overdue_share > 0 ? " · " + Math.round(d.overdue_share * 100) + " % " + T("overdue") : "") + (d.failing ? " · " + d.failing : "")), r.lastChild);
      p.appendChild(r);
    });
    // Protection.
    p = card("protect", "Is it safe?", (sn.folders || []).length || "");
    if (!(sn.folders || []).length) { p.appendChild(el("p", "viz-empty", T("No folders yet."))); }
    (sn.folders || []).forEach(function (f) {
      var lvl = f.policy_state === "violated" ? "bad" : f.policy_state === "at_risk" ? "warn" : f.policy_state === "ok" ? "ok" : "";
      var total = f.verified_blocks + f.unverified_blocks + f.local_only_blocks + f.missing_blocks;
      var r = row(f.name, bytes(f.bytes), "", null);
      if (lvl) { r.firstChild.firstChild.appendChild(tag(T(f.policy_state === "ok" ? "policy met" : f.policy_state === "at_risk" ? "at risk" : "violated"), lvl)); }
      r.appendChild(bar2([{ v: f.verified_blocks, c: "var(--vz-ok)", t: T("verified") }, { v: f.unverified_blocks, c: "var(--vz-info)", t: T("stored, not yet verified") }, { v: f.local_only_blocks, c: "#9aa7b6", t: T("only on this device") }, { v: f.missing_blocks, c: "var(--vz-bad)", t: T("missing") }], total));
      var sub = [f.policy || T("no policy"), f.oldest_verification_days !== null && f.oldest_verification_days !== undefined ? T("oldest check") + " " + f.oldest_verification_days + " " + T("d") : ""].filter(Boolean).join(" · ");
      r.appendChild(el("div", "l2", sub));
      p.appendChild(r);
    });
    var lg = el("div", "viz-legend");
    [["verified", "#1fa971"], ["stored, not yet verified", "#3466dc"], ["only on this device", "#9aa7b6"], ["missing", "#de4a3b"]].forEach(function (x) { var s = el("span", "", T(x[0])); s.style.setProperty("--c", x[1]); lg.appendChild(s); });
    p.appendChild(lg);
    // Health.
    var h = sn.health || {};
    p = card("health", "Health and alerts", alerts.length || "");
    p.appendChild(row(T("Verification"), h.verify && h.verify.enabled ? T("on") : T("off"), T("last") + " " + ago(h.verify && h.verify.last_run_utc) + " · " + T("next") + " " + (h.verify && h.verify.next_run_utc ? dur(h.verify.next_run_utc - nowSec()) : "—")));
    p.appendChild(row(T("Bit-rot check"), h.scrub && h.scrub.enabled ? T("on") : T("off"), T("last") + " " + ago(h.scrub && h.scrub.last_run_utc) + " · " + T("next") + " " + (h.scrub && h.scrub.next_run_utc ? dur(h.scrub.next_run_utc - nowSec()) : "—")));
    p.appendChild(row(T("Repairs"), String(h.repair ? h.repair.queued : 0) + " " + T("queued"), (h.repair && h.repair.losses ? h.repair.losses + " " + T("lost") : T("nothing lost")) + " · " + T("Key epoch") + " " + (sn.key_epoch || 0)));
    (sn.backups || []).forEach(function (b) { p.appendChild(row(T("Backup") + " · " + b.name, b.stopped ? T("stopped") : "", T("last") + " " + ago(b.latest_utc) + " · " + (b.snapshots || 0) + " " + T("snapshots"))); });
    alerts.slice(0, 8).forEach(function (a) {
      var r = el("div", "viz-row"); var l1 = el("div", "l1"); l1.appendChild(el("span", "t", a.text)); l1.appendChild(tag(T(a.level === "bad" ? "problem" : a.level === "warn" ? "attention" : "note"), a.level === "bad" ? "bad" : a.level === "warn" ? "warn" : "info")); r.appendChild(l1); p.appendChild(r);
    });
    // Cost.
    p = card("cost", "Cloud costs (estimate)", "");
    var anyCost = false;
    (sn.storages || []).forEach(function (s) {
      if (s.monthly_cost === null || s.monthly_cost === undefined || !s.price) { return; }
      anyCost = true;
      p.appendChild(row(s.name, "≈ " + money(s.monthly_cost, s.price.currency) + "/" + T("mo"), bytes(s.data_bytes) + (s.read_all_cost ? " · " + T("reading it all back") + " ≈ " + money(s.read_all_cost, s.price.currency) : "")));
    });
    if (anyCost) { p.appendChild(row(T("Total"), cur.map(function (c) { return "≈ " + money(cost[c], c); }).join(" + ") + "/" + T("mo"), T("Prices are estimates; request fees and tax are not included."))); }
    else { p.appendChild(el("p", "viz-empty", T("No priced cloud storage."))); }
    if (sn.cost && sn.cost.unpriced && sn.cost.unpriced.length) { p.appendChild(el("p", "viz-empty", T("No price set for") + " " + sn.cost.unpriced.join(", "))); }
    updateStatus();
    if (side) { fitSide(overlayFull()); }
  }
  function updateStatus() {
    var s = demo ? "demo" : status;
    dotEl.dataset.s = s;
    statusEl.txt.textContent = s === "live" ? T("Live") : s === "stale" ? T("Service busy: showing the last data") : s === "demo" ? T("Demo data") : s === "error" ? T("No answer from the service") : T("Loading");
    demoTag.classList.toggle("hidden", !demo);
  }

  // ---------------------------------------------------------------- data
  function poll() {
    clearTimeout(pollTimer);
    if (!active) { return; }
    if (abort) { try { abort.abort(); } catch (e) { /* done */ } }
    abort = window.AbortController ? new AbortController() : null;
    var t0 = Date.now();
    fetch("/api/viz", { headers: { "X-Varsto-Token": token() }, signal: abort ? abort.signal : undefined, cache: "no-store" })
      .then(function (r) { if (!r.ok) { throw new Error("http " + r.status); } return r.json(); })
      .then(function (j) {
        errCount = 0; lastOk = Date.now();
        skew = j.utc ? j.utc - (t0 + Date.now()) / 2000 : 0;
        var has = j.unlocked && ((j.devices && j.devices.length) || (j.storages && j.storages.length));
        demo = !has; snap = has ? j : null;
        status = j.stale ? "stale" : "live";
        afterData();
      })
      .catch(function (e) {
        if (e && e.name === "AbortError") { return; }
        errCount++; status = "error";
        if (!snap) { demo = true; }
        afterData();
      })
      .then(function () { pollTimer = setTimeout(poll, errCount ? Math.min(8000, 1000 * (1 + errCount)) : (document.visibilityState === "hidden" ? 4000 : 1000)); });
  }
  function afterData() { dirty = true; renderPanels(); schedule(0); }

  // ---------------------------------------------------------------- frame loop (about 30 fps while something moves, otherwise once a second)
  function schedule(ms) {
    if (!active) { return; }
    if (raf || timer) { if (ms === 0 && timer) { clearTimeout(timer); timer = 0; } else { return; } }
    if (ms > 0) { timer = setTimeout(function () { timer = 0; schedule(0); }, ms); return; }
    raf = requestAnimationFrame(frame);
  }
  function frame(ts) {
    raf = 0;
    if (!active) { return; }
    var animated = anyMotion && !reduced;
    var gap = animated ? 33 : 1000;
    if (dirty || ts - lastDraw >= gap - 3) {
      lastDraw = ts; dirty = false;
      try { draw(ts / 1000); } catch (e) { if (window.console) { console.error("viz draw", e); } }
    }
    schedule(animated ? 12 : 250);
  }

  // ---------------------------------------------------------------- show and hide with the page
  function activate() {
    if (!root) { buildDom(); loadManifest(); }
    if (active) { return; }
    active = true; loadManifest(); detectDisplay(); renderPanels(); poll(); dirty = true; schedule(0);
  }
  function deactivate() {
    active = false; clearTimeout(pollTimer); clearTimeout(timer); timer = 0;
    if (abort) { try { abort.abort(); } catch (e) { /* done */ } }
    if (raf) { cancelAnimationFrame(raf); raf = 0; }
    if (fullEl()) { try { (document.exitFullscreen || document.webkitExitFullscreen).call(document); } catch (e) { /* none */ } }
    if (pseudoFull) { setPseudo(false); }
  }
  function sync() {
    var shown = !page.classList.contains("hidden") && document.body.dataset.view === "app";
    if (shown && !active) { activate(); } else if (!shown && active) { deactivate(); }
  }
  new MutationObserver(sync).observe(page, { attributes: true, attributeFilter: ["class"] });
  new MutationObserver(sync).observe(document.body, { attributes: true, attributeFilter: ["data-view"] });
  document.addEventListener("visibilitychange", function () { if (active && document.visibilityState === "visible") { dirty = true; poll(); schedule(0); } });
  sync();
  // Exposed for tests: the snapshot the page draws and a way to feed one in.
  window.varstoViz = { feed: function (j) { snap = j; demo = !j; status = "live"; afterData(); }, demo: demoSnap };
})();
