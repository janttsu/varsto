// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Folder overview, safety indicator and list density. Loaded after app.js,
// which hands over every /api/status through `window.varstoFolders.update`.
// The indicator is computed by the service from the ledger (`protection` of
// each folder in /api/status; spec section 63): this file only shows it.
(function () {
  "use strict";
  var DENSITY_KEY = "varsto-density", OPEN_KEY = "varsto-folders-open", SORT_KEY = "varsto-folders-sort";
  var NS = "http://www.w3.org/2000/svg";
  var status = null;

  function store(k, v) { try { if (v === undefined) { return localStorage.getItem(k); } localStorage.setItem(k, v); } catch (e) { /* storage blocked */ } return null; }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined) { e.textContent = text; } return e; }
  function byId(id) { return document.getElementById(id); }
  function fmtBytes(n) { var u = ["B", "KiB", "MiB", "GiB", "TiB"]; var i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + " " + u[i]; }
  function fmtDate(t) { return t ? new Date(t * 1000).toLocaleDateString() : "–"; }
  function whole(p) { return String(Math.floor(p || 0)); }

  // ----- Density: compact by default, kept in this browser -----
  function density() { return store(DENSITY_KEY) === "comfortable" ? "comfortable" : "compact"; }
  function applyDensity(d) {
    document.documentElement.dataset.density = d;
    var b = byId("density-toggle");
    if (b) {
      b.setAttribute("aria-pressed", d === "compact" ? "true" : "false");
      b.title = d === "compact" ? "Compact rows (click for comfortable rows)" : "Comfortable rows (click for compact rows)";
      b.querySelector(".sr-only").textContent = d === "compact" ? "Compact rows" : "Comfortable rows";
    }
  }
  applyDensity(density());
  function addDensityToggle() {
    var bar = document.querySelector(".files-toolbar");
    if (!bar || byId("density-toggle")) { return; }
    var b = el("button", "secondary icon-btn"); b.type = "button"; b.id = "density-toggle";
    var s = document.createElementNS(NS, "svg"); s.setAttribute("class", "icon"); s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("aria-hidden", "true");
    var p = document.createElementNS(NS, "path"); p.setAttribute("d", "M4 6h16M4 10h16M4 14h16M4 18h16"); s.appendChild(p);
    b.appendChild(s); b.appendChild(el("span", "sr-only", ""));
    b.onclick = function () { var next = density() === "compact" ? "comfortable" : "compact"; store(DENSITY_KEY, next); applyDensity(next); };
    var spacer = bar.querySelector(".toolbar-spacer");
    bar.insertBefore(b, spacer || null);
    applyDensity(density());
  }

  // ----- The safety indicator -----
  // Colours are Okabe-Ito based (safe for the common colour blindness types)
  // and every state has its own icon and words as well.
  var STATES = {
    cloud: { label: "100 % in external storage", short: "100 %", cls: "cloud" },
    disks: { label: "100 % on your own disks only (no cloud copy)", short: "Disks", cls: "disks" },
    mixed: { label: "100 % external, split between cloud and disks", short: "100 %", cls: "mixed" },
    device: { label: "Only on devices: no external copy", short: "None", cls: "device" },
    empty: { label: "No files yet", short: "–", cls: "empty" }
  };
  function stateOf(f) {
    var p = f && f.protection;
    if (!p) { return null; }
    if (p.state === "partial") { return { label: "Partly protected: " + whole(p.pct) + " %", short: whole(p.pct) + " %", cls: "partial" }; }
    return STATES[p.state] || STATES.empty;
  }
  function svg(parts, w) {
    var s = document.createElementNS(NS, "svg"); s.setAttribute("viewBox", "0 0 16 16"); s.setAttribute("class", "prot-ico"); s.setAttribute("aria-hidden", "true");
    parts.forEach(function (d) { var p = document.createElementNS(NS, d[0]); Object.keys(d[1]).forEach(function (k) { p.setAttribute(k, d[1][k]); }); s.appendChild(p); });
    return s;
  }
  var CLOUD = "M4.5 12.5a3 3 0 0 1-.4-5.97A4 4 0 0 1 11.8 5.6 3.5 3.5 0 0 1 11.5 12.5z";
  function iconFor(st, p) {
    switch (st.cls) {
      case "cloud": return svg([["path", { d: CLOUD }], ["path", { d: "m6.2 9 1.4 1.4L10 7.6" }]]);
      case "disks": return svg([["rect", { x: 2, y: 3.5, width: 12, height: 9, rx: 2 }], ["path", { d: "M2 9.5h12" }], ["circle", { cx: 11.5, cy: 11.2, r: .4 }]]);
      case "mixed": return svg([["path", { d: "M4.5 7.5a2.5 2.5 0 0 1 .3-4.98A3.4 3.4 0 0 1 11 3.6 3 3 0 0 1 11 9.5H4.5z" }], ["rect", { x: 2.5, y: 11, width: 11, height: 3, rx: 1 }]]);
      case "partial": {
        var c = 2 * Math.PI * 5.5, share = Math.max(0, Math.min(100, p ? p.pct : 0)) / 100;
        return svg([["circle", { cx: 8, cy: 8, r: 5.5, class: "ring-bg" }], ["circle", { cx: 8, cy: 8, r: 5.5, class: "ring-fg", "stroke-dasharray": (c * share).toFixed(2) + " " + c.toFixed(2), transform: "rotate(-90 8 8)" }]]);
      }
      case "device": return svg([["path", { d: "M8 2.2 14.3 13H1.7z" }], ["path", { d: "M8 6.6v3.2M8 11.4v.2" }]]);
      default: return svg([["circle", { cx: 8, cy: 8, r: 5.5, "stroke-dasharray": "2 2" }]]);
    }
  }
  function badge(f, long) {
    var st = stateOf(f); if (!st) { return null; }
    var b = el("span", "prot prot-" + st.cls + (long ? " prot-long" : " prot-short"));
    b.tabIndex = 0; b.setAttribute("role", "img"); b.setAttribute("aria-label", st.label); b.dataset.folder = f.name;
    b.appendChild(iconFor(st, f.protection));
    b.appendChild(el("span", "prot-text", long ? st.label : st.short));
    return b;
  }

  // The details, shown on hover or focus (and inline in the folder header).
  var POLICY = { ok: "Policy met", at_risk: "Policy at risk", violated: "Policy not met", unknown: "Policy not checked" };
  function classRow(name, c) {
    var r = el("div", "prot-row"); r.appendChild(el("span", "prot-k", name));
    var v = el("span", "prot-v"); v.appendChild(document.createTextNode(whole(c.pct) + " %"));
    if (c.pct > 0) { v.appendChild(document.createTextNode(" ")); v.appendChild(el("span", "prot-sub", "verified " + whole(c.verified_pct) + " %")); }
    r.appendChild(v); return r;
  }
  function details(f) {
    var p = f.protection, st = stateOf(f), box = el("div", "prot-details");
    if (!p || !st) { return box; }
    box.appendChild(el("div", "prot-head", st.label));
    if (p.total_bytes > 0) {
      box.appendChild(classRow("External storage (S3, rclone)", p.cloud));
      box.appendChild(classRow("Own disks (directories, disk pools)", p.disks));
      box.appendChild(classRow("Devices (this device, others, replicas)", p.devices));
      if (p.unprotected_bytes > 0) {
        var r = el("div", "prot-row prot-warn"); r.appendChild(el("span", "prot-k", "No copy outside devices"));
        r.appendChild(el("span", "prot-v", p.unprotected_blocks + " blocks · " + fmtBytes(p.unprotected_bytes)));
        box.appendChild(r);
        if (p.missing_bytes > 0) { var m = el("div", "prot-row prot-warn"); m.appendChild(el("span", "prot-k", "Not on any device either")); m.appendChild(el("span", "prot-v", fmtBytes(p.missing_bytes))); box.appendChild(m); }
      }
    }
    var pr = el("div", "prot-row"); pr.appendChild(el("span", "prot-k", p.policy_state ? POLICY[p.policy_state] || POLICY.unknown : "No policy")); box.appendChild(pr);
    box.appendChild(el("div", "prot-note", "Shares of the folder's bytes, from the ledger. Verified: another device has read the copy back."));
    return box;
  }
  var tip = null, tipFor = null;
  function showTip(target) {
    var f = folderNamed(target.dataset.folder); if (!f) { return; }
    if (!tip) { tip = el("div", "prot-tip"); tip.id = "prot-tip"; tip.setAttribute("role", "tooltip"); document.body.appendChild(tip); }
    tip.innerHTML = ""; tip.appendChild(details(f)); tip.style.display = "block"; tipFor = target;
    var r = target.getBoundingClientRect(), w = tip.offsetWidth, h = tip.offsetHeight;
    var x = Math.min(Math.max(8, r.left), window.innerWidth - w - 8), y = r.bottom + 6;
    if (y + h > window.innerHeight - 8) { y = Math.max(8, r.top - h - 6); }
    tip.style.left = x + "px"; tip.style.top = y + "px";
    target.setAttribute("aria-describedby", "prot-tip");
  }
  function hideTip() { if (tip) { tip.style.display = "none"; } if (tipFor) { tipFor.removeAttribute("aria-describedby"); tipFor = null; } }
  document.addEventListener("mouseover", function (e) { var t = e.target.closest && e.target.closest(".prot"); if (t && !t.closest(".prot-inline")) { showTip(t); } else if (tipFor && !(e.target.closest && e.target.closest(".prot-tip"))) { hideTip(); } });
  document.addEventListener("focusin", function (e) { var t = e.target.closest && e.target.closest(".prot"); if (t && !t.closest(".prot-inline")) { showTip(t); } });
  document.addEventListener("focusout", hideTip);
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") { hideTip(); } });
  window.addEventListener("scroll", hideTip, true);

  function folderNamed(n) { return status && status.folders.filter(function (f) { return f.name === n; })[0]; }

  // ----- Nav, phone cards and folder header -----
  function decorate() {
    if (!status) { return; }
    document.querySelectorAll("#foldertree .tree-item").forEach(function (b) {
      var old = b.querySelector(".prot"); if (old) { old.remove(); }
      var f = folderNamed(b.dataset.folder), bd = f && badge(f, false);
      if (bd) { bd.tabIndex = -1; b.appendChild(bd); }
    });
    document.querySelectorAll("#folderlist .folder-card").forEach(function (c) {
      var old = c.querySelector(".prot"); if (old) { old.remove(); }
      var f = folderNamed(c.dataset.folder), bd = f && badge(f, true);
      var title = c.querySelector(".fc-title");
      if (bd && title) { bd.tabIndex = -1; title.appendChild(bd); }
    });
  }
  function renderHead() {
    var sub = byId("files-sub"); if (!sub) { return; }
    var box = byId("files-safety");
    if (!box) { box = el("div", "files-safety prot-inline"); box.id = "files-safety"; sub.parentNode.insertBefore(box, sub.nextSibling); }
    box.innerHTML = "";
    var sel = byId("filesfolder"), f = status && sel && folderNamed(sel.value);
    var bd = f && badge(f, true);
    if (!bd) { box.classList.add("hidden"); return; }
    box.classList.remove("hidden");
    bd.tabIndex = -1; box.appendChild(bd);
    var p = f.protection;
    if (p.total_bytes > 0) {
      var line = el("span", "prot-line");
      [["Cloud", p.cloud], ["Disks", p.disks], ["Devices", p.devices]].forEach(function (x, i) {
        if (i) { line.appendChild(document.createTextNode(" · ")); }
        line.appendChild(el("span", "", x[0])); line.appendChild(document.createTextNode(" " + whole(x[1].pct) + " %"));
      });
      box.appendChild(line);
    }
    if (p.policy_state && p.policy_state !== "ok") { box.appendChild(el("span", "prot-policy", POLICY[p.policy_state] || POLICY.unknown)); }
  }

  // ----- The folder overview on the Files page (desktop) -----
  var COLS = [["safety", "Safety"], ["name", "Folder"], ["mode", "Mode"], ["bytes", "Size", "num"], ["files", "Files", "num"], ["last", "Last change"]];
  var RANK = { device: 0, partial: 1, mixed: 2, disks: 3, cloud: 4, empty: 5 };
  function sortState() { try { var s = JSON.parse(store(SORT_KEY) || "null"); if (s && COLS.some(function (c) { return c[0] === s.key; })) { return s; } } catch (e) { /* default */ } return { key: "name", dir: 1 }; }
  function sortKey(f, key) {
    switch (key) {
      case "safety": return f.protection ? RANK[f.protection.state] * 1000 + (f.protection.pct || 0) : 9999;
      case "mode": return f.mode || "normal";
      case "bytes": return f.bytes; case "files": return f.files; case "last": return f.last_change_utc || 0;
      default: return f.name.toLowerCase();
    }
  }
  var MODE = { "normal": "Normal", "send-only": "Send only", "receive-only": "Receive only" };
  function pill(cls, t) { return el("span", "pill " + cls, t); }
  function ensureOverview() {
    var o = byId("folderoverview"); if (o) { return o; }
    var main = byId("filesmain"), head = main && main.querySelector(".files-head");
    if (!head) { return null; }
    o = el("section", "folder-overview"); o.id = "folderoverview"; o.setAttribute("aria-label", "Folders");
    var bar = el("div", "fo-bar"); bar.appendChild(el("span", "card-title", "Folders"));
    bar.appendChild(el("span", "toolbar-spacer"));
    var t = el("button", "secondary fo-toggle", ""); t.type = "button"; t.id = "fo-toggle"; bar.appendChild(t);
    o.appendChild(bar);
    var wrap = el("div", "table-wrap fo-wrap"); var tb = el("table", "fo-table"); tb.id = "fo-table";
    tb.appendChild(el("thead")); tb.appendChild(el("tbody")); wrap.appendChild(tb); o.appendChild(wrap);
    o.appendChild(el("p", "muted small fo-hint", "Safety shows where the copies of a folder's files are, counted from the ledger: in external storage (S3, rclone), on your own disks, or only on devices."));
    main.insertBefore(o, head);
    t.onclick = function () { var open = o.classList.toggle("collapsed") === false; store(OPEN_KEY, open ? "1" : "0"); toggleLabel(); };
    if (store(OPEN_KEY) === "0") { o.classList.add("collapsed"); }
    return o;
  }
  function toggleLabel() { var o = byId("folderoverview"), t = byId("fo-toggle"); if (o && t) { var c = o.classList.contains("collapsed"); t.textContent = c ? "Show folders" : "Hide folders"; t.setAttribute("aria-expanded", c ? "false" : "true"); } }
  function renderOverview() {
    var o = ensureOverview(); if (!o || !status) { return; }
    var folders = status.folders.slice(), ss = sortState();
    o.classList.toggle("hidden", folders.length === 0);
    folders.sort(function (a, b) { var x = sortKey(a, ss.key), y = sortKey(b, ss.key); return (x < y ? -1 : x > y ? 1 : a.name.localeCompare(b.name)) * ss.dir; });
    var tb = byId("fo-table"), thead = tb.querySelector("thead"), body = tb.querySelector("tbody");
    thead.innerHTML = ""; body.innerHTML = "";
    var hr = el("tr");
    COLS.forEach(function (c) {
      var th = el("th", c[2] || ""); th.scope = "col";
      var b = el("button", "fo-sort"); b.type = "button"; b.appendChild(el("span", "", c[1]));
      var on = ss.key === c[0]; if (on) { b.appendChild(el("span", "fo-arrow", ss.dir > 0 ? " ▲" : " ▼")); th.setAttribute("aria-sort", ss.dir > 0 ? "ascending" : "descending"); }
      b.onclick = function () { store(SORT_KEY, JSON.stringify({ key: c[0], dir: on ? -ss.dir : 1 })); renderOverview(); };
      th.appendChild(b); hr.appendChild(th);
    });
    thead.appendChild(hr);
    var current = (byId("filesfolder") || {}).value;
    folders.forEach(function (f) {
      var tr = el("tr", "fo-row" + (f.path ? "" : " detached") + (f.name === current && f.path ? " current" : "")); tr.dataset.folder = f.name; tr.tabIndex = 0;
      var s = el("td"); var bd = badge(f, true); if (bd) { bd.tabIndex = 0; s.appendChild(bd); } tr.appendChild(s);
      var n = el("td", "fo-name"); var nm = el("span", "", f.name); nm.setAttribute("data-no-i18n", ""); n.appendChild(nm);
      if (f.shared) { n.appendChild(pill("accent", "shared")); }
      if (f.strongroom) { n.appendChild(pill("grey", "Strongroom")); }
      if (f.paused) { n.appendChild(pill("bad", "paused")); }
      if (!f.path) { n.appendChild(pill("grey", "not on this device")); }
      tr.appendChild(n);
      var m = el("td"); if (f.path) { m.appendChild(pill(f.mode && f.mode !== "normal" ? "accent" : "grey", MODE[f.mode || "normal"] || f.mode)); } else { m.textContent = "–"; } tr.appendChild(m);
      tr.appendChild(el("td", "num", fmtBytes(f.bytes)));
      tr.appendChild(el("td", "num", String(f.files)));
      tr.appendChild(el("td", "", fmtDate(f.last_change_utc)));
      function open() { var b = document.querySelector('#foldertree .tree-item[data-folder="' + (window.CSS && CSS.escape ? CSS.escape(f.name) : f.name.replace(/"/g, '\\"')) + '"]'); if (b) { b.click(); } }
      tr.onclick = function (ev) { if (ev.target.closest && ev.target.closest(".fo-sort")) { return; } open(); };
      tr.onkeydown = function (ev) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); } };
      body.appendChild(tr);
    });
    toggleLabel();
  }
  function markCurrent() {
    var cur = (byId("filesfolder") || {}).value;
    document.querySelectorAll("#fo-table tbody tr").forEach(function (r) { r.classList.toggle("current", r.dataset.folder === cur && !r.classList.contains("detached")); });
    renderHead();
  }

  function update(s) {
    status = s;
    addDensityToggle();
    renderOverview(); decorate(); renderHead();
  }
  window.varstoFolders = { update: update, density: density };

  function init() {
    addDensityToggle();
    var sel = byId("filesfolder"); if (sel) { sel.addEventListener("change", markCurrent); }
    var tree = byId("foldertree");
    if (tree) {
      // The tree marks the open folder and is rebuilt on every status.
      new MutationObserver(function (list) {
        var rebuilt = list.some(function (m) { return m.type === "childList" && m.target === tree; });
        if (rebuilt) { decorate(); }
        markCurrent();
      }).observe(tree, { childList: true, subtree: true, attributes: true, attributeFilter: ["aria-current"] });
    }
    var cards = byId("folderlist");
    if (cards) { new MutationObserver(function () { decorate(); }).observe(cards, { childList: true }); }
  }
  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", init); } else { init(); }
})();
