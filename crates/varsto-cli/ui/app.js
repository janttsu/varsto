// Varsto desktop and mobile UI. Talks to the local API with a per-session token.
(function () {
  "use strict";
  var token = (function () {
    var m = location.search.match(/[?&]token=([0-9a-f]+)/);
    if (m) { try { sessionStorage.setItem("varsto-token", m[1]); } catch (e) {} history.replaceState(null, "", location.pathname); return m[1]; }
    try { return sessionStorage.getItem("varsto-token") || ""; } catch (e) { return ""; }
  })();
  var $ = function (id) { return document.getElementById(id); };
  var logEl = $("log");
  // Activity: newest first, one row per event with its time and a mark for
  // how it went (failed, finished or under way); at most 200 rows are kept.
  function log(msg) {
    msg = String(msg);
    // The same message again (a poll failing while the service restarts):
    // one line with a count and the latest time.
    var top = logEl.firstChild;
    if (top && top.dataset.msg === msg) {
      var n = (+top.dataset.count || 1) + 1; top.dataset.count = n;
      var c = top.querySelector(".activity-count"); if (!c) { c = document.createElement("span"); c.className = "activity-count muted"; top.querySelector(".activity-text").appendChild(c); }
      c.textContent = " (×" + n + ")";
      var tm = top.querySelector("time"); var d = new Date(); tm.dateTime = d.toISOString(); tm.textContent = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      return;
    }
    var kind = /\b(error|failed|refused|could not|cannot|FORKED|corrupt)\b/i.test(msg) ? "bad" : /\b(started|checking|installing|restarting|waiting|shutting down)\b/i.test(msg) ? "run" : "ok";
    var li = document.createElement("li"); li.className = "activity-item " + kind; li.dataset.msg = msg;
    var dot = document.createElement("span"); dot.className = "activity-dot"; dot.setAttribute("aria-hidden", "true");
    var body = document.createElement("div"); body.className = "activity-body";
    var m = /^([^:]{1,40}): (.+)$/.exec(msg);
    var head = document.createElement("div"); head.className = "activity-text";
    if (m) { var b = document.createElement("strong"); b.textContent = m[1]; head.appendChild(b); head.appendChild(document.createTextNode(" " + m[2])); } else { head.textContent = msg; }
    var time = document.createElement("time"); time.className = "activity-time"; var now = new Date(); time.dateTime = now.toISOString(); time.textContent = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    body.appendChild(head); li.appendChild(dot); li.appendChild(body); li.appendChild(time);
    logEl.insertBefore(li, logEl.firstChild);
    while (logEl.children.length > 200) { logEl.removeChild(logEl.lastChild); }
  }
  // Feedback for every action: the button that started a request shows a
  // spinner until it settles (and "Still working…" after a while), and a
  // thin bar at the top shows that something runs. Background polls (GET
  // without a press) stay silent.
  var lastPress = null; var working = 0; var barTimer = null;
  // The progress bar at the top (taskbar*, below the live activity code).
  var TB_AFTER = 5, tbTimer = null, tbBusy = false, tbOn = false, tbHide = null, tbLastWhat = null;
  document.addEventListener("click", function (ev) { var b = ev.target.closest && ev.target.closest("button"); if (b) { lastPress = { el: b, t: Date.now() }; } }, true);
  document.addEventListener("submit", function (ev) { var b = ev.submitter || (ev.target.querySelector && ev.target.querySelector("button[type=submit], button:not([type])")); if (b) { lastPress = { el: b, t: Date.now() }; } }, true);
  function pressed() { var p = lastPress; if (!p || Date.now() - p.t > 600 || !document.contains(p.el)) { return null; } if (p.el.closest("#modal") || p.el.classList.contains("nav-item") || p.el.classList.contains("tree-item")) { return null; } return p.el; }
  function markBusy(b, on) {
    var n = (+b.dataset.busy || 0) + (on ? 1 : -1); b.dataset.busy = Math.max(0, n);
    if (n > 0 && on && n === 1) {
      b.classList.add("is-busy"); b.setAttribute("aria-busy", "true");
      b._busyNote = setTimeout(function () { if (+b.dataset.busy > 0 && !(b.nextElementSibling && b.nextElementSibling.classList.contains("busy-note"))) { var note = el("span", "busy-note muted small", "Still working\u2026"); b.after(note); } }, 2000);
    }
    if (n <= 0) { b.classList.remove("is-busy"); b.removeAttribute("aria-busy"); clearTimeout(b._busyNote); var nx = b.nextElementSibling; if (nx && nx.classList.contains("busy-note")) { nx.remove(); } }
  }
  function workBar(on) {
    working = Math.max(0, working + (on ? 1 : -1));
    if (working > 0 && !barTimer) { barTimer = setTimeout(function () { if (working > 0) { $("workbar").classList.add("on"); } }, 300); }
    if (on && working === 1 && typeof taskbarSoon === "function") { taskbarSoon(); }
    if (working === 0) { clearTimeout(barTimer); barTimer = null; $("workbar").classList.remove("on"); }
  }
  // While a pressed button downloads a file, the note under it shows how far.
  // With the event stream up, its `transfers` events say it; otherwise
  // /api/progress is asked every 400 ms.
  function followDownload(b) {
    var stop = false;
    function show(j) {
      var d = j && j.download;
      if (stop || !d || !(d.total > 0)) { return; }
      var note = b.nextElementSibling && b.nextElementSibling.classList.contains("busy-note") ? b.nextElementSibling : null;
      if (!note) { note = el("span", "busy-note muted small"); b.after(note); }
      note.textContent = "Downloading " + showName(d.path.split("/").pop()) + ": " + fmtBytes(d.done) + " of " + fmtBytes(d.total) + " (" + d.percent + " %" + (d.bytes_per_sec > 0 ? ", " + fmtBytes(d.bytes_per_sec) + "/s" : "") + ")";
    }
    transferFollowers.push(show);
    (function tick() {
      if (stop) { return; }
      if (evsOk) { setTimeout(tick, 1000); return; }
      fetch("/api/progress", { headers: { "X-Varsto-Token": token } }).then(function (r) { return r.json(); }).then(show).catch(function () {}).then(function () { if (!stop) { setTimeout(tick, 400); } });
    })();
    return function () { stop = true; transferFollowers = transferFollowers.filter(function (f) { return f !== show; }); };
  }
  var transferFollowers = [];
  function api(method, path, body) {
    var b = pressed(); var loud = !!b || method !== "GET";
    if (b) { markBusy(b, true); }
    if (loud) { workBar(true); }
    var unfollow = b && /^\/api\/(fetch|paths|sync|view)/.test(path) ? followDownload(b) : null;
    var done = function () { if (unfollow) { unfollow(); } if (b) { markBusy(b, false); } if (loud) { workBar(false); } };
    // Errors say which request failed: a browser only says "Load failed" or
    // "Failed to fetch" when the service did not answer at all.
    var what = method + " " + path.split("?")[0];
    return fetch(path, { method: method, headers: { "X-Varsto-Token": token, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined })
      .then(function (r) {
        return r.text().then(function (t) {
          var j = null; try { j = t ? JSON.parse(t) : {}; } catch (x) { j = null; }
          if (!r.ok) { throw new Error((j && j.error) || ("The Varsto service answered " + r.status + " to " + what)); }
          if (j === null) { throw new Error("The Varsto service sent an unreadable answer to " + what); }
          return j;
        });
      }, function (e) {
        throw new Error("Could not reach the Varsto service (" + what + "): " + e.message + ". It may be restarting or busy; try again in a moment.");
      })
      .then(function (j) { done(); return j; }, function (e) { done(); throw e; });
  }
  // Without a vault (first start, after a reset or a wipe) nothing of the
  // old one may stay on screen: the folder tree in the sidebar, the lists.
  function clearVaultViews() {
    ["foldertree", "devicelist", "settingsdevices", "sharedlist", "policylist", "attachlist", "storagelist", "org-users", "org-log"].forEach(function (id) { var e = $(id); if (e) { e.innerHTML = ""; } });
    var t = $("folders"); if (t && t.querySelector("tbody")) { t.querySelector("tbody").innerHTML = ""; }
    $("who").textContent = "";
    document.querySelectorAll("[data-org-only]").forEach(function (b) { b.classList.add("hidden"); });
    lastStatus = null;
  }
  function show(section) { if (section === "setup") { clearVaultViews(); } ["setup", "unlock", "app"].forEach(function (id) { $(id).classList.toggle("hidden", id !== section); }); $("lock").classList.toggle("hidden", section !== "app"); document.body.dataset.view = section; if (section !== "app") { $("pagetitle").textContent = section === "setup" ? "Welcome" : "Locked"; } else { $("pagetitle").textContent = pageTitle(currentPage); } trafficWatch(); activityWatch(); taskbarSchedule(section === "app" ? 0 : undefined); }
  function fmtBytes(n) { var u = ["B", "KiB", "MiB", "GiB", "TiB"]; var i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + " " + u[i]; }
  function fmtDate(t) { return t ? new Date(t * 1000).toLocaleDateString() : ""; }
  function formData(form) { var o = {}; new FormData(form).forEach(function (v, k) { o[k] = v; }); form.querySelectorAll("input[type=checkbox]").forEach(function (c) { o[c.name] = c.checked; }); return o; }
  // Help text on [data-help]: shown on hover, on keyboard focus and on a
  // tap (web views in the apps show no title tooltips, phones have no hover).
  var helpTip = null;
  function showHelp(t) {
    hideHelp(); if (!t.dataset.help) { return; }
    helpTip = document.createElement("div"); helpTip.className = "help-tip"; helpTip.setAttribute("role", "tooltip"); helpTip.textContent = t.dataset.help;
    document.body.appendChild(helpTip);
    var r = t.getBoundingClientRect(), w = helpTip.offsetWidth, h = helpTip.offsetHeight;
    var left = Math.max(8, Math.min(window.innerWidth - w - 8, r.left + r.width / 2 - w / 2));
    var top = r.bottom + 8; if (top + h > window.innerHeight - 8) { top = r.top - h - 8; }
    helpTip.style.left = left + "px"; helpTip.style.top = Math.max(8, top) + "px";
  }
  function hideHelp() { if (helpTip) { helpTip.remove(); helpTip = null; } }
  document.addEventListener("mouseover", function (e) { var t = e.target.closest && e.target.closest("[data-help]"); if (t) { showHelp(t); } });
  document.addEventListener("mouseout", function (e) { var t = e.target.closest && e.target.closest("[data-help]"); if (t && !t.contains(e.relatedTarget)) { hideHelp(); } });
  document.addEventListener("focusin", function (e) { if (e.target.dataset && e.target.dataset.help) { showHelp(e.target); } });
  document.addEventListener("focusout", hideHelp);
  document.addEventListener("click", function (e) { var t = e.target.closest && e.target.closest("[data-help]"); if (t) { showHelp(t); } else { hideHelp(); } });
  window.addEventListener("scroll", hideHelp, true);
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined) { e.textContent = text; } return e; }
  // A file name as it is (":" and backslash included), with control characters and
  // direction overrides shown as \u{..} so that a name cannot pass for another.
  function showName(s) { return String(s).replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, function (c) { return "\\u{" + c.charCodeAt(0).toString(16) + "}"; }); }
  function pill(cls, text) { return el("span", "pill " + cls, text); }
  function icon(name, cls) { var s = document.createElementNS("http://www.w3.org/2000/svg", "svg"); s.setAttribute("class", "icon" + (cls ? " " + cls : "")); var u = document.createElementNS("http://www.w3.org/2000/svg", "use"); u.setAttribute("href", "#i-" + name); s.appendChild(u); return s; }
  function enc(s) { return encodeURIComponent(s); }

  // App-level state from /api/state (platform, mobile shell, folder roots) and the last /api/status.
  var appState = { mobile: false, folder_root: "", platform: "", plain_root: "", plain_root_writable: true };
  var lastStatus = null;
  var selectedFile = null;
  var filesLoadedFor = null;
  // Load the file list of the chosen folder unless it is already shown.
  function ensureFiles() { var f = $("filesfolder").value; if (f && filesLoadedFor !== f) { loadFiles(); } }
  var phoneMq = window.matchMedia ? window.matchMedia("(max-width: 600px)") : null;
  function isMobile() { return appState.mobile || !!(phoneMq && phoneMq.matches); }
  function applyMobile() { document.body.dataset.mobile = isMobile() ? "1" : "0"; }
  if (phoneMq && phoneMq.addEventListener) { phoneMq.addEventListener("change", function () { applyMobile(); nav(currentPage); }); }
  applyMobile();

  // Android shell: a small bridge (apps/android MainActivity) for things a page cannot do itself.
  // iOS: the equivalent (UIDocumentInteractionController / UIActivityViewController) is not wired yet;
  // without a bridge the page falls back to the download link.
  var droid = window.VarstoAndroid || null;
  function hasAllFiles() { if (droid) { try { return !!droid.hasAllFilesAccess(); } catch (e) {} } return !!appState.plain_root_writable; }
  function phoneActions() { return isMobile() && !!droid; }

  // Dialog: the one modal the page uses for every question (WebViews return null for window.prompt).
  // dialog({title, text, code, fields: [{name, label, type, value, placeholder, hint, required}], ok, cancel, extra, danger})
  // resolves with {action: "ok"|"extra", values} or null when cancelled.
  var modalResolve = null, modalConfirm = null;
  function dialog(o) {
    return new Promise(function (resolve) {
      closeDialog("cancel");
      modalResolve = resolve;
      $("modal-title").textContent = o.title || "Varsto";
      var tx = $("modal-text"); tx.textContent = o.text || ""; tx.classList.toggle("hidden", !o.text);
      var code = $("modal-code"); code.textContent = o.code || ""; code.classList.toggle("hidden", !o.code);
      // facts: [label, value] pairs; the label is translated, the value shown as given.
      var facts = $("modal-facts"); facts.innerHTML = "";
      (o.facts || []).forEach(function (f) { facts.appendChild(el("dt", null, f[0])); var dd = el("dd", null, f[1]); dd.setAttribute("data-no-i18n", ""); facts.appendChild(dd); });
      facts.classList.toggle("hidden", !(o.facts || []).length);
      var fs = $("modal-fields"); fs.innerHTML = "";
      (o.fields || []).forEach(function (f) {
        // A group of checkboxes; its value is the ticked ones, comma-separated.
        if (f.checks) {
          var grp = el("div", "field-group"); grp.appendChild(el("span", "field-caption", f.label));
          f.checks.forEach(function (c) {
            var cl = el("label", "inline"); var cb = el("input"); cb.type = "checkbox"; cb.dataset.group = f.name; cb.value = c[0]; cb.checked = !!c[2];
            cl.appendChild(cb); var tx = el("span", null, c[1]); if (c[3]) { tx.setAttribute("data-no-i18n", ""); } cl.appendChild(tx);
            if (c[4]) { cl.appendChild(el("span", "muted", c[4])); }
            grp.appendChild(cl);
          });
          if (!f.checks.length && f.empty) { grp.appendChild(el("span", "hint muted", f.empty)); }
          if (f.hint) { grp.appendChild(el("span", "hint muted", f.hint)); }
          fs.appendChild(grp);
          return;
        }
        if (f.options) {
          var sl = el("label", "", f.label); var sel = el("select"); sel.name = f.name;
          f.options.forEach(function (op) { var x = el("option", null, op[1]); x.value = op[0]; sel.appendChild(x); });
          if (f.value !== undefined && f.value !== null) { sel.value = f.value; }
          sl.appendChild(sel); if (f.hint) { sl.appendChild(el("span", "hint muted", f.hint)); } fs.appendChild(sl);
          return;
        }
        // A text of several lines (user data: never translated).
        if (f.textarea) {
          var tl = el("label", "", f.label); var ta = el("textarea"); ta.name = f.name; ta.rows = f.rows || 8; ta.value = f.value || "";
          if (f.maxlength) { ta.maxLength = f.maxlength; }
          if (f.placeholder) { ta.placeholder = f.placeholder; }
          tl.appendChild(ta); if (f.hint) { tl.appendChild(el("span", "hint muted", f.hint)); } fs.appendChild(tl);
          return;
        }
        var lab = el("label", "", f.label); var inp = el("input"); inp.name = f.name; inp.type = f.type || "text"; inp.autocomplete = "off";
        if (f.type === "number") { inp.min = "0"; inp.step = "1"; inp.inputMode = "numeric"; }
        if (f.value !== undefined && f.value !== null) { inp.value = f.value; }
        if (f.placeholder) { inp.placeholder = f.placeholder; }
        if (f.required) { inp.required = true; }
        lab.appendChild(inp); if (f.hint) { lab.appendChild(el("span", "hint muted", f.hint)); } fs.appendChild(lab);
      });
      // confirmText: the buttons stay disabled until exactly this is typed.
      modalConfirm = o.confirmText || null;
      if (modalConfirm) {
        var cl = el("label", "", "Type " + modalConfirm + " to confirm"); var ci = el("input"); ci.name = "confirm_text"; ci.autocomplete = "off"; ci.spellcheck = false;
        ci.addEventListener("input", confirmTyped); cl.appendChild(ci); fs.appendChild(cl);
      }
      fs.classList.toggle("hidden", !(o.fields || []).length && !modalConfirm);
      var ok = $("modal-ok"); ok.textContent = o.ok || "OK"; ok.className = o.danger ? "danger-fill" : "";
      $("modal-cancel").textContent = o.cancel || "Cancel"; $("modal-cancel").classList.toggle("hidden", o.cancel === false);
      var ex = $("modal-extra"); ex.textContent = o.extra || ""; ex.classList.toggle("hidden", !o.extra);
      confirmTyped();
      $("modal").classList.remove("hidden"); document.body.classList.add("modal-open");
      var first = fs.querySelector("input, textarea") || ok;
      setTimeout(function () { first.focus(); if (first.select) { first.select(); } }, 30);
    });
  }
  function confirmMatches() {
    var ci = $("modal-fields").querySelector("input[name=confirm_text]");
    return !modalConfirm || (ci && ci.value.trim() === modalConfirm);
  }
  function confirmTyped() { var off = !confirmMatches(); $("modal-ok").disabled = off; $("modal-extra").disabled = off; }
  function dialogValues() {
    var v = {};
    $("modal-fields").querySelectorAll("input, select, textarea").forEach(function (i) {
      if (i.dataset.group) { var g = i.dataset.group; if (!(g in v)) { v[g] = ""; } if (i.checked) { v[g] = v[g] ? v[g] + "," + i.value : i.value; } return; }
      v[i.name] = i.value;
    });
    return v;
  }
  function closeDialog(action) {
    if (!modalResolve) { return; }
    var r = modalResolve; modalResolve = null;
    var vals = dialogValues();
    $("modal").classList.add("hidden"); document.body.classList.remove("modal-open");
    r(action === "cancel" ? null : { action: action, values: vals });
  }
  $("modalform").onsubmit = function (ev) {
    ev.preventDefault();
    var missing = null; $("modal-fields").querySelectorAll("input[required]").forEach(function (i) { if (!missing && !i.value.trim()) { missing = i; } });
    if (missing) { missing.focus(); return; }
    if (!confirmMatches()) { return; }
    closeDialog("ok");
  };
  $("modal-cancel").onclick = function () { closeDialog("cancel"); };
  $("modal-extra").onclick = function () { if (confirmMatches()) { closeDialog("extra"); } };
  $("modal-backdrop").onclick = function () { closeDialog("cancel"); };
  document.addEventListener("keydown", function (ev) {
    if (!modalResolve) { return; }
    if (ev.key === "Escape") { ev.preventDefault(); closeDialog("cancel"); return; }
    if (ev.key === "Tab") {
      var items = Array.prototype.filter.call($("modal").querySelectorAll("input, button"), function (x) { return !x.classList.contains("hidden") && !x.disabled && x.offsetParent !== null; });
      if (!items.length) { return; }
      var first = items[0], last = items[items.length - 1];
      if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
      else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
    }
  });
  function alertBox(msg, title) { return dialog({ title: title || "Varsto", text: msg, cancel: false }); }
  function confirmBox(msg, o) { o = o || {}; return dialog({ title: o.title || "Are you sure?", text: msg, ok: o.ok || "OK", danger: !!o.danger }).then(function (r) { return !!r; }); }

  // Block maps: one square per block of encrypted data. The colour says where
  // the block is kept (verified by another device, on a storage, only on this
  // device, nowhere reachable); a filled square is also on this device, an
  // outlined one is not. Exact counts come from /api/status (blocks).
  var BLOCK_STATES = ["verified_here", "verified_away", "stored_here", "stored_away", "local_only", "missing"];
  var BLOCK_CLASS = { verified_here: "s-verified", verified_away: "s-verified away", stored_here: "s-stored", stored_away: "s-stored away", local_only: "s-local", missing: "s-missing" };
  function folderBlocks(f) {
    var b = {}; var src = f.blocks || {};
    BLOCK_STATES.forEach(function (k) { b[k] = src[k] || 0; });
    return b;
  }
  function addBlocks(a, b) { BLOCK_STATES.forEach(function (k) { a[k] = (a[k] || 0) + (b[k] || 0); }); return a; }
  function blockTotal(b) { return BLOCK_STATES.reduce(function (n, k) { return n + (b[k] || 0); }, 0); }
  function drawBlocks(container, counts, perSquare) {
    container.innerHTML = "";
    var frag = document.createDocumentFragment();
    BLOCK_STATES.forEach(function (k) {
      var n = Math.round((counts[k] || 0) / perSquare);
      if (counts[k] > 0 && n === 0) { n = 1; }
      for (var i = 0; i < n; i++) { var sq = document.createElement("i"); sq.className = "blk " + BLOCK_CLASS[k]; frag.appendChild(sq); }
    });
    container.appendChild(frag);
    container.classList.remove("fade"); void container.offsetWidth; container.classList.add("fade");
  }
  // A row's less-used actions: a "More" menu on desktops, plain buttons on phones.
var openRowMenu = null;
function rowMenu(cell, key) {
  if (document.body.dataset.mobile === "1") { return { appendChild: function (b) { cell.appendChild(b); }, done: function () {} }; }
  var d = document.createElement("details"); d.className = "row-menu";
  var sm = document.createElement("summary"); sm.textContent = "More"; sm.setAttribute("aria-label", "More actions"); d.appendChild(sm);
  var list = document.createElement("div"); list.className = "row-menu-list"; d.appendChild(list);
  list.addEventListener("click", function (e) { if (e.target.closest("button")) { d.open = false; openRowMenu = null; } });
  // Fixed position under the button, so a scrolling table does not clip the menu.
  d.addEventListener("toggle", function () {
    if (!d.open) { if (openRowMenu === key) { openRowMenu = null; } return; }
    openRowMenu = key;
    var r = sm.getBoundingClientRect(); var w = Math.max(200, list.offsetWidth);
    list.style.left = Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8)) + "px";
    var below = r.bottom + 4, h = list.offsetHeight;
    list.style.top = (below + h > window.innerHeight - 8 ? Math.max(8, r.top - h - 4) : below) + "px";
  });
  return { appendChild: function (b) { list.appendChild(b); }, done: function () { if (list.children.length) { cell.appendChild(d); if (openRowMenu === key) { d.open = true; } } } };
}
window.addEventListener("scroll", function () { openRowMenu = null; document.querySelectorAll("details.row-menu[open]").forEach(function (d) { d.open = false; }); }, true);
document.addEventListener("click", function (e) {
  document.querySelectorAll("details.row-menu[open]").forEach(function (d) { if (!d.contains(e.target)) { d.open = false; openRowMenu = null; } });
});

function miniMap(f) { var m = el("span", "minimap"); var b = folderBlocks(f); var t = blockTotal(b); if (t === 0) { return m; } var per = Math.max(1, Math.ceil(t / 40)); drawBlocks(m, b, per); m.title = t + " block" + (t === 1 ? "" : "s") + (per > 1 ? ", 1 square ≈ " + per + " blocks" : ""); return m; }
  function fileStateKey(f) { return f.state === "awaiting_import" ? "missing" : f.state === "placeholder" ? "ph" : f.state === "missing" ? "missing" : f.pinned ? "verified" : "stored"; }
  function fileStateLabel(f) { return f.state === "awaiting_import" ? "Awaiting import" : f.state === "placeholder" ? "Not on this device" : f.state === "missing" ? "Unavailable" : f.pinned ? "Local, kept here" : "Local"; }
  function stateSquare(f) { var sq = el("i", "blk state-blk s-" + fileStateKey(f)); sq.title = fileStateLabel(f); return sq; }

  // Theme: the OS's until the user switches it (then persisted).
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  function storedTheme() { try { return localStorage.getItem("varsto-theme") || ""; } catch (e) { return ""; } }
  function applyTheme(t) { if (t === "dark" || t === "light") { document.documentElement.dataset.theme = t; } else { delete document.documentElement.dataset.theme; } var dark = t ? t === "dark" : !!(mq && mq.matches); document.querySelector("#themetoggle .theme-label").textContent = dark ? "Light mode" : "Dark mode"; $("themetoggle").setAttribute("aria-pressed", dark ? "true" : "false"); }
  applyTheme(storedTheme());
  if (mq && mq.addEventListener) { mq.addEventListener("change", function () { applyTheme(storedTheme()); }); }
  function toggleTheme() { var dark = document.documentElement.dataset.theme ? document.documentElement.dataset.theme === "dark" : !!(mq && mq.matches); var next = dark ? "light" : "dark"; try { localStorage.setItem("varsto-theme", next); } catch (e) {} applyTheme(next); }
  $("themetoggle").onclick = toggleTheme;
  $("themetoggle2").onclick = toggleTheme;

  // Navigation between the pages of the app section.
  var titles = { overview: "Overview", files: "Files", shared: "Shared", storages: "Storages", backups: "Backups", import: "Import", trash: "Trash", policies: "Policies", peers: "Peers", organization: "Organization", settings: "Settings", recovery: "Recovery package", help: "Help", more: "More" };
  var legacyPages = { folders: "files", sharing: "shared" };
  function pageTitle(p) { return titles[p] || "Overview"; }
  var currentPage = (function () { try { var p = sessionStorage.getItem("varsto-page"); p = legacyPages[p] || p; return titles[p] ? p : "overview"; } catch (e) { return "overview"; } })();
  function nav(page) {
    page = legacyPages[page] || page;
    if (!titles[page]) { page = "overview"; }
    // Without an open vault, Help is the panel above the setup or unlock screen.
    if (page === "help" && document.body.dataset.view !== "app" && document.body.dataset.view !== "loading") { preHelpOpen(true); $("prehelp").scrollIntoView({ block: "start", behavior: "smooth" }); return; }
    if (page === "more" && !isMobile()) { page = "settings"; }
    if (page !== "policies") { policyReturn = null; } else if (!policyEdited()) { policyReturn = null; policyButtons(); }
    currentPage = page;
    try { sessionStorage.setItem("varsto-page", page); } catch (e) {}
    document.querySelectorAll(".page").forEach(function (d) { d.classList.toggle("hidden", d.dataset.page !== page); });
    var tab = page === "help" || page === "shared" || page === "backups" || page === "import" || page === "trash" || page === "policies" || page === "peers" || page === "organization" || page === "settings" || page === "recovery" ? "more" : page;
    document.querySelectorAll(".sidebar .nav-item[data-nav]").forEach(function (b) { if (b.dataset.nav === page) { b.setAttribute("aria-current", "page"); } else { b.removeAttribute("aria-current"); } });
    document.querySelectorAll(".tabbar .nav-item[data-nav]").forEach(function (b) { if (b.dataset.nav === tab) { b.setAttribute("aria-current", "page"); } else { b.removeAttribute("aria-current"); } });
    if (document.body.dataset.view === "app") { $("pagetitle").textContent = pageTitle(page); }
    if (page === "peers") { loadP2p(); }
    if (page === "organization") { loadOrg(); }
    if (page === "backups") { loadBackups(); }
    if (page === "recovery") { loadGuide(); }
    if (page === "help") { setTimeout(loadHelp, 0); }
    if (page === "import") { loadImports(); }
    if (page === "trash") { loadTrash(); loadHistorySettings(); }
    if (page === "overview" && lastWhere) { renderWhere(lastWhere); }
    trafficWatch();
    activityWatch();
    if (page === "files") { ensureFiles(); }
    if (page === "settings" && droid && lastStatus) { refreshAllFiles(); }
    if (page === "settings") { loadLogs(); }
    window.scrollTo(0, 0);
  }
  // Buttons inside pages that lead to another page.
  document.querySelectorAll("button[data-nav]:not(.nav-item):not(.more-item)").forEach(function (b) { b.addEventListener("click", function () { nav(b.dataset.nav); }); });
  document.querySelectorAll(".nav-item[data-nav], .more-item[data-nav]").forEach(function (b) {
    b.onclick = function () {
      // Tapping the Files tab again on a phone returns to the folder list.
      if (b.dataset.nav === "files" && currentPage === "files" && isMobile() && b.closest(".tabbar")) { showFolderList(); }
      nav(b.dataset.nav);
    };
  });
  nav(currentPage);

  function refreshState() {
    return api("GET", "/api/state").then(function (st) {
      $("version").textContent = st.version; $("version2").textContent = st.version;
      appState.mobile = !!st.mobile; appState.folder_root = st.folder_root || ""; appState.platform = st.platform || ""; joinKindForDevice();
      appState.plain_root = st.plain_root || ""; appState.plain_root_writable = st.plain_root_writable !== false;
      applyMobile();
      refreshAllFiles();
      if (st.removal && !removalShown) {
        removalShown = true;
        alertBox("This device was removed from the vault by " + st.removal.by_name + " on " + fmtDate(st.removal.issued_utc) + (st.removal.wipe ? ". As ordered, its keys, sync state and folder contents were deleted." : ". It no longer syncs; reset it under Settings to start over."), "Device removed");
      }
      if (!st.has_vault) { show("setup"); showPreHelp(true); takeLink(); return; }
      if (!st.unlocked) { show("unlock"); showPreHelp(false); return; }
      show("app");
      if (currentPage === "settings") { loadLogs(); }
      return refreshStatus().then(takeLink);
    }).catch(function (e) { log("error: " + e.message); });
  }

  // Devices on the Peers page, each with "Remove device…" (revocation, optionally with a wipe order).
  var removalShown = false;
  function loadDevices(s) {
    var ul = $("devicelist");
    if (s.member) { ul.innerHTML = ""; return; }
    api("GET", "/api/devices").then(function (r) {
      ul.innerHTML = "";
      renderSettingsDevices(r);
      r.devices.forEach(function (d) {
        var li = el("li"); var ic = el("span", "li-icon"); ic.appendChild(icon("device")); li.appendChild(ic);
        var body = el("div", "li-body"); var title = el("div", "li-title", d.name);
        if (d.this_device) { title.appendChild(pill("grey", "This device")); }
        if (d.revoked) { title.appendChild(pill("risk", "Removed")); }
        if (d.user) { title.appendChild(pill(d.role === "admin" ? "accent" : "grey", d.user + (d.role === "admin" ? " · admin" : ""))); }
        body.appendChild(title);
        body.appendChild(el("div", "li-sub", d.revoked
          ? "Removed by " + d.revoked_by + " on " + fmtDate(d.revoked_utc) + (d.wipe_ordered ? ", wipe ordered" : "") + " · " + d.device_id.slice(0, 8)
          : [deviceSystem(d), "added " + fmtDate(d.enrolled_utc), d.device_id.slice(0, 8)].filter(Boolean).join(" · ")));
        if (!d.revoked) { var act = el("div", "li-activity"); act.dataset.device = d.device_id; body.appendChild(act); }
        li.appendChild(body);
        if (!d.this_device && !d.revoked) {
          var a = el("div", "li-actions"); var b = el("button", "secondary danger", "Remove device…"); b.type = "button";
          b.onclick = function () { removeDevice(d); }; a.appendChild(b); li.appendChild(a);
        }
        ul.appendChild(li);
      });
      if (lastActivity) { renderActivity(lastActivity); }
    }).catch(function (e) { log("error: " + e.message); });
  }
  function ago(t) {
    if (!t) { return ""; }
    var s = Math.max(0, Math.round(Date.now() / 1000 - t));
    return s < 90 ? "just now" : s < 5400 ? Math.round(s / 60) + " min ago" : s < 129600 ? Math.round(s / 3600) + " h ago" : Math.round(s / 86400) + " days ago";
  }
  // "Android 15 · Samsung SM-S926B · Varsto 0.0.1-alpha.8", or "" before the device published any.
  function deviceSystem(d) {
    var x = d.details; if (!x) { return ""; }
    var sys = !x.os_version ? x.os : x.os_version.indexOf(x.os) >= 0 ? x.os_version : x.os + " " + x.os_version;
    return [sys, x.model, "Varsto " + x.app_version].filter(Boolean).join(" · ");
  }
  // Settings: every device in one compact list, each removable from here too.
  function renderSettingsDevices(r) {
    var ul = $("settingsdevices"); ul.innerHTML = "";
    var mine = (r.devices.filter(function (d) { return d.this_device; })[0] || {}).details;
    r.devices.forEach(function (d) {
      var li = el("li"); var body = el("div", "li-body"); var title = el("div", "li-title", d.name);
      if (d.this_device) { title.appendChild(pill("grey", "This device")); }
      if (d.revoked) { title.appendChild(pill("risk", "Removed")); }
      if (!d.revoked && d.details && mine && d.details.app_version !== mine.app_version) { title.appendChild(pill("grey", "other version")); }
      body.appendChild(title);
      var seen = d.details ? (d.details.last_sync_utc ? "synced " + ago(d.details.last_sync_utc) : "seen " + ago(d.details.updated_utc)) : "";
      body.appendChild(el("div", "li-sub", d.revoked ? "Removed " + fmtDate(d.revoked_utc) : [deviceSystem(d) || "no details yet (they appear after its next sync with this version)", seen].filter(Boolean).join(" · ")));
      if (d.details) { body.title = d.details.arch + " · " + d.device_id; }
      li.appendChild(body);
      if (!d.this_device && !d.revoked) {
        var a = el("div", "li-actions"); var b = el("button", "secondary danger", "Remove…"); b.type = "button";
        b.onclick = function () { removeDevice(d); }; a.appendChild(b); li.appendChild(a);
      }
      ul.appendChild(li);
    });
  }
  function removeDevice(d) {
    dialog({
      title: "Remove " + d.name + "?",
      text: "Use this for a lost or stolen device. " + d.name + " is cut off at once: its ledger entries from now on are ignored, your other devices refuse its peer connections, and the vault gets new keys that only your remaining devices receive. " +
        "What is written from now on is unreadable to it, except in folders shared with other people and Strongroom folders, which keep their keys. " +
        "Everything it could read until now it can still read: keys cannot be recalled, and its storage credentials work until you change them at your storage provider. " +
        "Remove and wipe also orders it to delete its keys, sync state and the contents of its folders, unsynced changes included, the next time it reaches one of your storages. " +
        "Afterwards print a new recovery kit: the old one does not open new data. This cannot be undone.",
      fields: [{ name: "confirm", label: "Type the device name to confirm", placeholder: d.name, required: true }],
      ok: "Remove and wipe", extra: "Remove without wipe", danger: true
    }).then(function (r) {
      if (!r) { return; }
      if (r.values.confirm.trim() !== d.name) { return alertBox("The name does not match, so nothing was changed."); }
      var wipe = r.action === "ok";
      return api("POST", "/api/device/revoke", { device: d.device_id, wipe: wipe, confirm: d.name }).then(function (rep) {
        log("removed " + rep.name + (rep.wipe ? " with a wipe order" : "") + "; vault key epoch " + rep.key_epoch);
        var text = d.name + " was removed" + (rep.wipe ? " and will wipe itself when it next reaches a storage" : "") + ". New keys went to: " + (rep.keys_sent_to.join(", ") || "no other device") + ".";
        if (rep.keys_pending_for.length) { text += " Waiting for " + rep.keys_pending_for.join(", ") + ": they receive the new key after their next sync with this version."; }
        if (rep.folders_not_rekeyed.length) { text += " Kept their key (shared or Strongroom): " + rep.folders_not_rekeyed.join(", ") + "."; }
        text += " Print a new recovery kit now.";
        return alertBox(text, "Device removed").then(refreshStatus);
      });
    }).catch(function (e) { log("error: " + e.message); alertBox(e.message, "Could not remove the device"); });
  }

  // Policy editor: four minimums; zeros everywhere (or the Clear button) remove the policy.
  function editPolicy(f) {
    api("GET", "/api/policy").then(function (p) {
      var cur = null; (p.policies || []).forEach(function (x) { if (x.folder === f.name) { cur = x.policy; } });
      var places = (cur && cur.min_per_place) || {}; var names = policyPlaces(p);
      var fields = [{ name: "min_copies", label: "Copies on any storage", type: "number", value: cur ? cur.min_copies || 0 : 2 }];
      names.forEach(function (pl) { fields.push({ name: "place:" + pl, label: placeLabel(pl), type: "number", value: cur ? places[pl] || 0 : (pl === "cloud" || pl === "home" ? 1 : 0) }); });
      fields.push({ name: "days", label: "Every block verified by another device within (days)", type: "number", value: cur ? cur.verified_within_days || 0 : 30 });
      return dialog({
        title: (cur ? "Policy for " : "Set a policy for ") + f.name,
        text: "Minimums that Varsto checks against the ledger on every sync. 0 means no rule.",
        fields: fields,
        ok: cur ? "Save" : "Set policy", extra: cur ? "Clear policy" : null
      }).then(function (r) { return r && { r: r, names: names }; });
    }).then(function (res) {
      if (!res) { return; }
      var r = res.r; var v = r.values; var n = function (k) { return Math.max(0, Math.floor(+v[k]) || 0); };
      var pl = {}; var total = n("min_copies") + n("days");
      res.names.forEach(function (k) { pl[k] = n("place:" + k); total += pl[k]; });
      var clear = r.action === "extra" || total === 0;
      return api("POST", "/api/policy", { folder: f.name, clear: clear, min_copies: n("min_copies"), verified_within_days: n("days"), places: pl })
        .then(function () { log(clear ? "policy cleared for " + f.name : "policy set for " + f.name); return refreshStatus(); });
    }).catch(function (e) { alertBox(e.message); });
  }
  // Column and field labels for places: the two defaults by what they are.
  function placeLabel(pl) { return pl === "home" ? "Copies on own devices and disks" : pl === "cloud" ? "Copies in external storage (S3 etc.)" : "Copies in place '" + pl + "'"; }
  // A place as a short tag beside a storage: "at home", "external", or its own name.
  function placeShort(pl) { return pl === "home" ? "at home" : pl === "cloud" ? "external" : pl; }
  // Places a policy can name: those of the storages, those already in use, and the two defaults.
  function policyPlaces(p) {
    var set = { home: 1, cloud: 1 };
    ((lastStatus && lastStatus.storages) || []).forEach(function (st) { if (!st.carrier) { set[st.place || "home"] = 1; } });
    ((p && p.policies) || []).forEach(function (x) { if (x.policy) { Object.keys(x.policy.min_per_place || {}).forEach(function (k) { set[k] = 1; }); } });
    return Object.keys(set).sort();
  }
  // Where the Policy button was pressed, so Back and Cancel return there.
  var policyReturn = null; var lastPolicy = null;
  function policyEdited() { return !!document.querySelector("#policygrid tbody tr.changed"); }
  function policyButtons() {
    var edited = policyEdited();
    $("policysave").disabled = !edited;
    $("policycancel").disabled = !edited && !policyReturn;
    $("policyback").classList.toggle("hidden", !policyReturn);
    if (policyReturn) { $("policyback").textContent = "\u2190 Back to " + (titles[policyReturn] || policyReturn); }
  }
  function leavePolicies() { var to = policyReturn; policyReturn = null; nav(to || "overview"); }
  function discardPolicyEdits() {
    document.querySelectorAll("#policygrid tbody tr.changed").forEach(function (tr) { tr.classList.remove("changed"); });
    if (lastPolicy) { renderPolicyGrid(lastPolicy); }
    policyButtons();
  }
  $("policycancel").onclick = function () { discardPolicyEdits(); if (policyReturn) { leavePolicies(); } };
  $("policyback").onclick = function () {
    if (!policyEdited()) { leavePolicies(); return; }
    dialog({ title: "Discard changes?", text: "The edited policies have not been saved.", ok: "Discard", extra: null }).then(function (r) { if (r) { discardPolicyEdits(); leavePolicies(); } });
  };
  function openPolicy(f) {
    if (isMobile()) { editPolicy(f); return; }
    var from = currentPage;
    nav("policies");
    policyReturn = from === "policies" ? null : from; policyButtons();
    var row = document.querySelector('#policygrid tr[data-folder="' + (window.CSS && CSS.escape ? CSS.escape(f.name) : f.name) + '"]');
    window.scrollTo(0, 0);
    if (row) { var i = row.querySelector("input"); if (i) { i.focus({ preventScroll: true }); i.select(); } if (row.getBoundingClientRect().bottom > window.innerHeight) { row.scrollIntoView({ block: "nearest" }); } }
  }
  // Desktop: every folder's rules in one table, saved together.
  function renderPolicyGrid(p) {
    lastPolicy = p;
    if (policyEdited()) { return; }
    var places = policyPlaces(p); var reports = {}; (p.reports || []).forEach(function (r) { reports[r.folder] = r; });
    var head = document.querySelector("#policygrid thead tr"); head.innerHTML = "";
    ["Folder", "Status", "Written to", "Copies on any storage"].concat(places.map(placeLabel)).concat(["Verified by another device within (days)"]).forEach(function (h) { head.appendChild(el("th", null, h)); });
    var body = document.querySelector("#policygrid tbody"); body.innerHTML = "";
    var member = !!(lastStatus && lastStatus.member);
    (p.policies || []).forEach(function (x) {
      var pol = x.policy || {}; var per = pol.min_per_place || {}; var r = reports[x.folder];
      var tr = el("tr"); tr.dataset.folder = x.folder;
      tr.appendChild(el("td", "policy-folder", x.folder));
      var stc = el("td", "policy-state"); stc.appendChild(r ? pill(stateClass(r.state), stateLabel(r.state)) : pill("grey", x.policy ? "Unchecked" : "No policy"));
      stc.appendChild(el("div", "muted small", x.text || "No rule set."));
      (r ? r.reasons.concat(r.warnings) : []).forEach(function (w) { stc.appendChild(el("div", "small", w)); });
      tr.appendChild(stc);
      var wc = el("td", "policy-placement"); wc.dataset.placementFor = x.folder; wc.appendChild(el("div", "small", "every storage"));
      if (!member) { var wb = el("button", "secondary small", "Change"); wb.type = "button"; wb.onclick = function () { editPlacement(x.folder); }; wc.appendChild(wb); }
      tr.appendChild(wc);
      var num = function (key, val, label) {
        var c = el("td", "num"); var i = document.createElement("input"); i.type = "number"; i.min = "0"; i.step = "1"; i.value = val || 0; i.dataset.key = key; i.disabled = member; i.setAttribute("aria-label", x.folder + ": " + label);
        i.oninput = function () { tr.classList.add("changed"); policyButtons(); };
        c.appendChild(i); tr.appendChild(c);
      };
      num("min_copies", pol.min_copies, "copies on any storage");
      places.forEach(function (pl) { num("place:" + pl, per[pl], placeLabel(pl).toLowerCase()); });
      num("days", pol.verified_within_days, "verified within days");
      body.appendChild(tr);
    });
    policyButtons();
    api("GET", "/api/placement").then(function (pp) {
      (pp.folders || []).forEach(function (x) {
        var c = document.querySelector('#policygrid td[data-placement-for="' + (window.CSS && CSS.escape ? CSS.escape(x.folder) : x.folder) + '"] div');
        if (!c) { return; }
        c.textContent = x.placement ? x.description + " (here: " + x.targets.join(", ") + ")" : "every storage";
        c.title = (x.warnings || []).join(" ");
      });
    }).catch(function () {});
  }
  // Folder placement: which storages a folder's blocks are written to (all
  // by default). Published like the policy, so every device writes it the same way.
  function editPlacement(folder) {
    var names = [];
    api("GET", "/api/placement").then(function (p) {
      var cur = null; (p.folders || []).forEach(function (x) { if (x.folder === folder) { cur = x; } });
      var places = {}; var storages = [];
      var pl = cur && cur.placement;
      var on = function (list, x) { return !!(pl && list.indexOf(x) >= 0); };
      (p.storages || []).filter(function (s) { return !s.carrier; }).forEach(function (s) {
        places[s.place] = 1;
        storages.push([s.name, s.name, on(pl ? pl.storages : [], s.name), true, placeShort(s.place) + (s.cold ? ", cold" : "")]);
      });
      names = Object.keys(places);
      return dialog({
        title: "Where " + folder + " is written",
        text: "By default every block goes to every storage. Tick storages or places to write this folder only there; a place means every storage in it, now and later. Blocks already stored stay where they are until you move them; policies still count every copy." + (cur && cur.warnings.length ? " Note: " + cur.warnings.join(" ") : ""),
        fields: [
          { name: "storages", label: "Storages", checks: storages, empty: "No storage yet" },
          { name: "places", label: "Places", checks: names.map(function (n) { return [n, placeLabel(n), on(pl ? pl.places : [], n)]; }) }
        ],
        ok: "Save", extra: pl ? "Every storage" : null
      });
    }).then(function (r) {
      if (!r) { return; }
      var v = r.values; var every = r.action === "extra" || (!(v.storages || "").trim() && !(v.places || "").trim());
      return api("POST", "/api/placement", { folder: folder, storages: v.storages, places: v.places, every: every }).then(function (info) {
        log(folder + ": new blocks go to " + info.targets.join(", ") + (info.placement ? " (" + info.description + ")" : ""));
        return refreshStatus();
      });
    }).catch(function (e) { alertBox(e.message); });
  }
  $("policysave").onclick = function () {
    var rows = Array.prototype.slice.call(document.querySelectorAll("#policygrid tbody tr.changed"));
    if (!rows.length) { return; }
    busy(true);
    rows.reduce(function (chain, tr) {
      return chain.then(function () {
        var body = { folder: tr.dataset.folder, places: {} }; var total = 0;
        tr.querySelectorAll("input").forEach(function (i) { var n = Math.max(0, Math.floor(+i.value) || 0); total += n; var k = i.dataset.key; if (k === "min_copies") { body.min_copies = n; } else if (k === "days") { body.verified_within_days = n; } else { body.places[k.slice(6)] = n; } });
        body.clear = total === 0;
        return api("POST", "/api/policy", body).then(function () { tr.classList.remove("changed"); log((body.clear ? "policy cleared for " : "policy saved for ") + body.folder); });
      });
    }, Promise.resolve()).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); return refreshStatus(); });
  };
  // Transferrers: which devices one travels to. It then carries what those
  // devices lack and is emptied as they receive it.
  function otherDeviceNames() {
    var me = lastStatus ? lastStatus.device_name : "";
    return Object.keys((lastStatus && lastStatus.devices) || {}).map(function (k) { return lastStatus.devices[k]; }).filter(function (n, i, all) { return n !== me && all.indexOf(n) === i; });
  }
  function fillCarrierFor() {
    var sel = $("carrierfor"); var keep = sel.value; sel.innerHTML = "";
    var any = document.createElement("option"); any.value = ""; any.textContent = "any device that lacks the blocks"; sel.appendChild(any);
    otherDeviceNames().forEach(function (n) { var o = document.createElement("option"); o.value = n; o.textContent = n; sel.appendChild(o); });
    sel.value = keep;
  }
  function carrierDestination(name, current) {
    var names = otherDeviceNames();
    // Devices named before that are not known any more stay offered, ticked.
    current.forEach(function (n) { if (names.indexOf(n) < 0) { names.push(n); } });
    dialog({ title: "Where does " + name + " travel?", text: "Tick the device (or devices) this transferrer is taken to. It then carries the blocks they still lack and is emptied as they receive them. Tick none to carry what any device lacks.", fields: [{ name: "devices", label: "Destination devices", checks: names.map(function (n) { return [n, n, current.indexOf(n) >= 0, true]; }), empty: "No other device yet" }], ok: "Save" }).then(function (r) {
      if (!r) { return; }
      return api("POST", "/api/storage/carrier-for", { name: name, devices: r.values.devices || "" }).then(function (x) { log(x.devices.length ? name + " now carries what " + x.devices.join(", ") + " lacks" : name + " carries what any device lacks"); return refreshStatus(); });
    }).catch(function (e) { alertBox(e.message); });
  }
  (function () {
    var form = $("addstorage"); var carrier = form.querySelector("input[name=carrier]"); var cold = form.querySelector("input[name=cold]");
    // A transferrer is read whenever it is plugged in; cold storage is never read without asking: one or the other.
    function sync() {
      cold.disabled = carrier.checked && !carrier.closest("[data-kind]").classList.contains("hidden");
      if (cold.disabled) { cold.checked = false; }
      carrier.disabled = cold.checked; if (carrier.disabled) { carrier.checked = false; }
      $("carrierforrow").classList.toggle("hidden", !carrier.checked);
      if (carrier.checked) { fillCarrierFor(); }
    }
    carrier.addEventListener("change", sync); cold.addEventListener("change", sync);
    form.addEventListener("reset", function () { setTimeout(sync, 0); });
    $("storagekind").addEventListener("change", sync);
  })();
  // S3 providers from the built-in price data: picking one fills in the
  // endpoint, region and URL style and shows its headline prices with their
  // source and date; "Compare providers" lists them side by side. Numbers and
  // provider names are not translated; an unknown price says so.
  (function () {
    var form = $("addstorage"), sel = $("s3provider"), regionSel = $("s3region"), card = $("s3price");
    var providers = [], loaded = false;
    function raw(text) { var s = el("span", null, text); s.setAttribute("data-no-i18n", ""); return s; }
    function money(f, cur, suffix) {
      if (!f || f.value === null || f.value === undefined) { var u = el("span", "muted", "unknown"); if (f && f.note) { u.title = f.note; } return u; }
      var s = raw(f.value + (cur ? " " + cur : "") + (suffix || "")); if (f.note) { s.title = f.note; } return s;
    }
    function current() { var id = sel.value; return providers.filter(function (p) { return p.id === id; })[0] || null; }
    function endpointOf(p) { return p ? p.endpoints[+regionSel.value] || p.endpoints[0] : null; }
    function row(dl, label, node) { dl.appendChild(el("dt", null, label)); var dd = el("dd"); dd.appendChild(node); dl.appendChild(dd); }
    function pair(a, sep, b) { var s = el("span"); s.appendChild(a); s.appendChild(raw(sep)); s.appendChild(b); return s; }
    function warn(text) { return el("div", "notice warn", text); }
    function renderCard() {
      var p = current(), e = endpointOf(p); card.innerHTML = "";
      if (p && e && e.region_prices) { p = Object.assign({}, p, e.region_prices); }
      card.classList.toggle("hidden", !p);
      if (!p) { return; }
      var head = el("p", "price-head"); head.appendChild(raw(p.name + (p.class ? " · " + p.class.name : ""))); card.appendChild(head);
      if (p.kind === "self_hosted") {
        card.appendChild(el("p", "muted small", "Self-hosted: there is no provider price. Replace the endpoint with your own server's address."));
      } else {
        var cur = p.currency || "", dl = el("dl");
        if (p.plan) { row(dl, "Plan per month", raw((p.plan.capacity_gb && p.plan.capacity_gb.value !== null ? p.plan.capacity_gb.value + " GB: " : "") + (p.plan.monthly_price && p.plan.monthly_price.value !== null ? p.plan.monthly_price.value + " " + cur : "?"))); }
        else { var st = money(p.storage_per_gb_month, cur); if (p.storage_tiered) { st = pair(st, " ", el("span", "muted", "(first volume band)")); } row(dl, "Storage per GB-month", st); }
        row(dl, "Free egress per month", money(p.egress_free_gb_per_month, "", " GB"));
        row(dl, "Egress per GB after that", money(p.egress_per_gb, cur));
        if (p.egress_fair_use && p.egress_fair_use.value) { row(dl, "Egress rules", raw(p.egress_fair_use.value)); }
        row(dl, "PUT / GET per 1000 requests", pair(money(p.put_per_1000, cur), " / ", money(p.get_per_1000, cur)));
        row(dl, "Minimum storage duration (days)", money(p.minimum_storage_days, ""));
        row(dl, "Minimum billable object size (KB)", money(p.minimum_object_kb, ""));
        row(dl, "Free tier", p.free_tier && p.free_tier.value ? raw(p.free_tier.value) : money(p.free_tier, ""));
        row(dl, "Tax", p.tax_note ? raw(p.tax_note) : el("span", null, p.prices_include_tax === true ? "included" : p.prices_include_tax === false ? "not included" : "unknown"));
        card.appendChild(dl);
        var foot = el("p", "muted small");
        if (p.last_verified) { foot.appendChild(el("span", null, "verified")); foot.appendChild(raw(" " + p.last_verified + " · ")); }
        var src = p.source_url || p.pricing_url;
        if (src) { var a = el("a", null, "price source"); a.href = src; a.target = "_blank"; a.rel = "noopener"; foot.appendChild(a); }
        if (p.signup_url) { foot.appendChild(raw(" · ")); var s = el("a", null, "sign up"); s.href = p.signup_url; s.target = "_blank"; s.rel = "noopener"; foot.appendChild(s); }
        card.appendChild(foot);
        if (p.stale) { card.appendChild(warn("These prices were verified more than 90 days ago and may have changed; check the source.")); }
        if (e && !e.prices_verified) { card.appendChild(warn("The prices were not verified for this region; it may be priced differently.")); }
      }
      if (e && e.has_placeholder) { card.appendChild(el("p", "muted small", "Replace the part in braces in the endpoint with your own value, for example your account id.")); }
      if (e && e.note) { var n = el("p", "muted small"); n.appendChild(raw(e.note)); card.appendChild(n); }
    }
    function fill() {
      var e = endpointOf(current()); if (!e) { return; }
      form.querySelector("input[name=endpoint]").value = e.endpoint;
      form.querySelector("input[name=region]").value = e.region;
      form.querySelector("input[name=virtual_host]").checked = !e.path_style;
    }
    function pickProvider() {
      var p = current(); regionSel.innerHTML = "";
      $("s3regionrow").classList.toggle("hidden", !p || p.endpoints.length < 2);
      if (p) {
        p.endpoints.forEach(function (e, i) {
          var o = el("option", null, e.label + (e.label !== e.region ? " (" + e.region + ")" : "") + (e.country ? ", " + e.country : "")); o.value = String(i); o.setAttribute("data-no-i18n", ""); regionSel.appendChild(o);
        });
        fill();
      }
      renderCard();
    }
    function renderCompare() {
      var tb = $("s3comparetable").querySelector("tbody"); tb.innerHTML = "";
      providers.forEach(function (p) {
        if (p.kind === "self_hosted") { return; }
        var tr = el("tr"), cur = p.currency || "";
        var name = el("td"); var a = el("a", null, p.name); a.href = "#"; a.setAttribute("data-no-i18n", "");
        a.onclick = function (ev) { ev.preventDefault(); sel.value = p.id; pickProvider(); sel.scrollIntoView({ block: "nearest" }); };
        name.appendChild(a); tr.appendChild(name);
        function cell(label, node) { var td = el("td", "num"); td.setAttribute("data-label", label); td.appendChild(node); tr.appendChild(td); }
        cell("Storage /GB-month", p.plan && !p.storage_per_gb_month.value ? el("span", "muted", "plan") : money(p.storage_per_gb_month, cur));
        cell("Egress /GB", money(p.egress_per_gb, cur));
        cell("Free egress", money(p.egress_free_gb_per_month, "", " GB"));
        cell("PUT /1000", money(p.put_per_1000, cur));
        cell("GET /1000", money(p.get_per_1000, cur));
        cell("Minimum days", money(p.minimum_storage_days, ""));
        var v = el("td"); v.setAttribute("data-label", "Verified"); v.appendChild(raw(p.last_verified || "")); if (p.stale) { v.appendChild(raw(" ")); v.appendChild(el("span", "muted", "(old)")); }
        tr.appendChild(v); tb.appendChild(tr);
      });
    }
    function load() {
      if (loaded) { return; }
      loaded = true;
      api("GET", "/api/providers").then(function (r) {
        providers = r.providers || [];
        providers.forEach(function (p) { var o = el("option", null, p.name); o.value = p.id; o.setAttribute("data-no-i18n", ""); sel.appendChild(o); });
        renderCompare();
      }).catch(function () { loaded = false; });
    }
    sel.addEventListener("change", pickProvider);
    regionSel.addEventListener("change", function () { fill(); renderCard(); });
    $("storagekind").addEventListener("change", function () { if (this.value === "s3") { load(); } });
    form.addEventListener("reset", function () { setTimeout(pickProvider, 0); });
  })();
  // Removing a storage: first show what has to be copied elsewhere to keep
  // every block's copies (one, or the folder policy's minimum), then do it.
  function removeStorage(name) {
    api("GET", "/api/storage/remove-plan?name=" + enc(name)).then(function (p) {
      if (p.blocked) { alertBox("Cannot remove " + name + ": " + p.blocked); return null; }
      var text = name + " holds " + p.blocks + " block" + (p.blocks === 1 ? "" : "s") + " of your files. ";
      text += p.copies.length ? p.blocks_ok + " already have enough copies elsewhere; " + p.copies.length + " cop" + (p.copies.length === 1 ? "y" : "ies") + " (" + fmtBytes(p.bytes_to_copy) + ") will first be made on " + p.targets.join(", ") + ". " : "Every block already has enough copies on your other storages. ";
      text += "Then no device counts " + name + " as a copy any more. Remove leaves its data in place; you can also delete it.";
      return dialog({ title: "Remove storage " + name + "?", text: text, ok: "Remove", extra: "Remove and delete data", danger: true, confirmText: name }).then(function (r) {
        if (!r) { return null; }
        busy(true); log((p.copies.length ? "copying " + p.copies.length + " blocks, then " : "") + "removing storage " + name);
        return api("POST", "/api/storage/remove", { name: name, delete_data: r.action === "extra" }).then(function (x) {
          log("storage " + name + " removed" + (x.blocks_copied ? ": " + x.blocks_copied + " blocks copied (" + fmtBytes(x.bytes_copied) + ")" : "") + (x.objects_deleted ? ", " + x.objects_deleted + " objects deleted from it" : ""));
        });
      });
    }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); return refreshStatus(); });
  }
  // Removing a folder: stop syncing it here, or remove it from the vault on
  // every device (optionally with its data on the storages). Files stay.
  function removeFolder(f) {
    var vaultWide = function () {
      return dialog({ title: "Remove " + f.name + " from the vault?", text: "Every device stops syncing " + f.name + " and it disappears from the folder lists. Files already on your devices stay where they are. You can also delete its encrypted data from your storages; then it cannot be brought back.", ok: "Remove from the vault", extra: "Remove and delete its data" }).then(function (r) {
        if (!r) { return null; }
        var purge = r.action === "extra"; busy(true);
        return api("POST", "/api/folder/remove", { name: f.name, purge: purge }).then(function (x) { log(f.name + " removed from the vault" + (purge ? "; " + x.objects_deleted + " objects deleted from the storages" : "")); });
      });
    };
    var first = f.path
      ? dialog({ title: "Remove " + f.name + "?", text: "Stop syncing it on this device only (the files stay in " + f.path + "), or remove it from the vault on every device.", ok: "Stop syncing here", extra: "Remove from the vault\u2026" }).then(function (r) {
          if (!r) { return null; }
          if (r.action === "extra") { return vaultWide(); }
          busy(true);
          return api("POST", "/api/folder/detach", { name: f.name }).then(function () { log(f.name + " is no longer synced on this device"); });
        })
      : vaultWide();
    first.catch(function (e) { alertBox(e.message); }).then(function () { busy(false); return refreshStatus(); });
  }
  function shareFolder(f) {
    dialog({
      title: (f.shared ? "New token for " : "Share ") + f.name,
      text: (f.shared ? "" : "An editor reads and writes this folder; a viewer only reads it: nothing a viewer changes is accepted by your devices or the editors. ") + "Paste the recipient's request code or scan its QR code to seal the token to their device, or leave it empty for a plain token that carries the folder key itself (editors only).",
      fields: [
        { name: "to", label: "Recipient's request code (optional)", placeholder: "vsr1…" },
        { name: "role", label: "Role", options: [["editor", "Editor: read and write"], ["viewer", "Viewer: read only"]], value: "editor", hint: "A viewer can still copy what it reads; a key cannot prevent that." }
      ],
      ok: f.shared ? "Create token" : "Share",
      extra: "Scan QR code…"
    }).then(function (r) {
      if (!r) { return; }
      var role = r.values.role || "editor";
      if (r.action === "extra") { return scanQr("request").then(function (info) { if (info) { return sealTo(f, info.text, role); } }); }
      var code = (r.values.to || "").trim();
      if (!code && role === "viewer") { return alertBox("A viewer's token must be sealed to their request code: paste it or scan it. A plain token cannot say what its holder may do."); }
      if (!code) { return createToken(f, "", "", role); }
      return sealTo(f, code, role);
    }).catch(function (e) { alertBox(e.message); });
  }
  // Confirm who asked: both sides see the same six words for the code.
  function sealTo(f, code, role) {
      return api("POST", "/api/share/fingerprint", { code: code }).then(function (fp) {
        var who = fp.name || "the requester";
        return dialog({
          title: "Is this " + who + "'s request?",
          text: "Ask " + who + " to read the fingerprint their device shows for the request code (under Accept a shared folder, or `varsto share request`), over a call or in person, not in the same message as the code. Share only if all six words match: different words mean the code was changed on its way.",
          code: fp.fingerprint, ok: "The words match", danger: false
        }).then(function (c) { if (c) { return createToken(f, code, fp.fingerprint, role); } });
      });
  }
  function createToken(f, code, fingerprint, role) {
    return api("POST", "/api/share/create", { folder: f.name, to: code, fingerprint: fingerprint, role: role || "editor" }).then(function (t) {
      $("sharetoken").textContent = (t.sealed ? (t.role === "viewer" ? "Sealed share token for a viewer of " : "Sealed share token for an editor of ") + t.folder + " (only the requesting device can open it; fingerprint " + t.fingerprint + "): " : "Share token for " + t.folder + " (contains the folder key; send over a secure channel): ") + t.token;
      $("sharetoken").classList.remove("hidden"); nav("shared"); refreshStatus();
      // A sealed token is safe to show: only the requesting device opens it. A plain one never becomes a QR code.
      return renderQr($("sharetokenqr"), t.sealed ? t.token : "");
    });
  }

  // ----- QR invitations (spec section 51) -----
  // Codes: POST /api/qr gives the SVG of one code or of a sequence of smaller ones (shown in turn).
  var qrTimers = {};
  function renderQr(box, text, parts) {
    if (box.dataset.text === (text || "") && !!parts === (box.dataset.parts === "1")) { return Promise.resolve(); }
    box.dataset.text = text || ""; box.dataset.parts = parts ? "1" : "";
    if (qrTimers[box.id]) { clearInterval(qrTimers[box.id]); delete qrTimers[box.id]; }
    box.innerHTML = ""; box.classList.add("hidden");
    if (!text) { return Promise.resolve(); }
    return api("POST", "/api/qr", { text: text, parts: !!parts }).then(function (r) {
      if (box.dataset.text !== text) { return; }
      var frames = r.codes.map(function (c) { return "data:image/svg+xml;base64," + btoa(c.svg); });
      var img = el("img", "qr-img"); img.alt = "QR code"; img.src = frames[0]; box.appendChild(img);
      if (r.fingerprint) {
        box.appendChild(el("span", "muted small", "Fingerprint"));
        var w = el("span", "qr-words", r.fingerprint); w.setAttribute("data-no-i18n", ""); box.appendChild(w);
      }
      if (frames.length > 1) {
        var n = el("span", "muted small", "Part 1 of " + frames.length); box.appendChild(n); var i = 0;
        qrTimers[box.id] = setInterval(function () {
          if (!document.body.contains(box) || box.classList.contains("hidden")) { return; }
          i = (i + 1) % frames.length; img.src = frames[i]; n.textContent = "Part " + (i + 1) + " of " + frames.length;
        }, 900);
      }
      if (r.kind !== "pair") {
        var t = el("button", "linklike", frames.length > 1 ? "Show one code" : "Camera cannot read it? Show smaller codes"); t.type = "button";
        t.onclick = function () { renderQr(box, text, !parts).catch(function (e) { alertBox(e.message); }); };
        box.appendChild(t);
      }
      box.classList.remove("hidden");
    });
  }
  // Scanning: the camera through getUserMedia; frames are read by BarcodeDetector where the browser has it,
  // else by the service (POST /api/qr/scan, nothing kept). Parts of a split code are collected until complete.
  var scan = null, scanCanvas = null;
  var NOT_KIND = { request: "This is not a share request code.", token: "This is not a sealed share token.", pair: "This is not a pairing code." };
  function rawPost(path, body, type) {
    return fetch(path, { method: "POST", headers: { "X-Varsto-Token": token, "Content-Type": type || "application/octet-stream" }, body: body }).then(function (r) {
      return r.json().then(function (j) { if (!r.ok) { throw new Error(j.error || ("The Varsto service answered " + r.status)); } return j; });
    });
  }
  function scanQr(want) {
    return new Promise(function (resolve) {
      closeScanner(null);
      scan = { resolve: resolve, want: want || "", texts: [], stream: null, timer: null, busy: false, detector: null };
      var v = $("scanner-video"), st = $("scanner-status");
      $("scanner-text").value = ""; st.textContent = "Point the camera at the QR code.";
      $("scanner").classList.remove("hidden"); document.body.classList.add("modal-open");
      var md = navigator.mediaDevices;
      if (!md || !md.getUserMedia) { v.classList.add("hidden"); st.textContent = "No camera is available here. Open a screenshot of the code or paste the code."; return; }
      v.classList.remove("hidden");
      var s = scan;
      md.getUserMedia({ video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } }, audio: false }).then(function (stream) {
        if (scan !== s) { stream.getTracks().forEach(function (t) { t.stop(); }); return; }
        s.stream = stream; v.srcObject = stream; v.play().catch(function () {});
        if (window.BarcodeDetector) { try { s.detector = new window.BarcodeDetector({ formats: ["qr_code"] }); } catch (e) { s.detector = null; } }
        s.timer = setInterval(scanFrame, 300);
      }).catch(function (e) { if (scan === s) { v.classList.add("hidden"); st.textContent = "The camera could not be opened (" + e.message + "). Open a screenshot of the code or paste the code."; } });
    });
  }
  function closeScanner(result) {
    if (!scan) { return; }
    var s = scan; scan = null;
    if (s.timer) { clearInterval(s.timer); }
    if (s.stream) { s.stream.getTracks().forEach(function (t) { t.stop(); }); }
    var v = $("scanner-video"); v.pause(); v.srcObject = null;
    $("scanner").classList.add("hidden"); document.body.classList.remove("modal-open");
    s.resolve(result);
  }
  function frameTexts(v) {
    var k = Math.min(1, 1280 / Math.max(v.videoWidth, v.videoHeight));
    var w = Math.round(v.videoWidth * k), h = Math.round(v.videoHeight * k);
    var c = scanCanvas || (scanCanvas = document.createElement("canvas")); c.width = w; c.height = h;
    var g = c.getContext("2d", { willReadFrequently: true }); g.drawImage(v, 0, 0, w, h);
    var d = g.getImageData(0, 0, w, h).data, luma = new Uint8Array(w * h);
    for (var i = 0, j = 0; j < luma.length; i += 4, j++) { luma[j] = (d[i] * 77 + d[i + 1] * 150 + d[i + 2] * 29) >> 8; }
    return rawPost("/api/qr/scan?w=" + w + "&h=" + h, luma).then(function (r) { return r.texts || []; });
  }
  function scanFrame() {
    var s = scan, v = $("scanner-video");
    if (!s || s.busy || !v.videoWidth) { return; }
    s.busy = true;
    var found = s.detector
      ? s.detector.detect(v).then(function (codes) { return codes.map(function (c) { return c.rawValue; }); }, function () { s.detector = null; return []; })
      : frameTexts(v);
    found.then(function (texts) {
      texts = texts.filter(function (t) { return /^varsto:\/\//i.test(t); });
      if (texts.length) { return scanned(texts); }
    }).catch(function (e) { if (scan === s) { $("scanner-status").textContent = e.message; } }).then(function () { s.busy = false; });
  }
  function scanned(texts) {
    var s = scan; if (!s) { return Promise.resolve(); }
    texts.forEach(function (t) { if (s.texts.indexOf(t) < 0) { s.texts.push(t); } });
    s.texts = s.texts.slice(-64);
    return rawPost("/api/link/parse", JSON.stringify({ texts: s.texts }), "application/json").then(function (r) {
      if (scan !== s) { return; }
      if (r.part) { $("scanner-status").textContent = "Scanned " + r.have.length + " of " + r.count + " parts. Keep the camera on the changing code."; return; }
      if (s.want && r.kind !== s.want) { s.texts = []; $("scanner-status").textContent = NOT_KIND[s.want]; return; }
      closeScanner(r);
    }, function (e) { if (scan === s) { s.texts = []; $("scanner-status").textContent = e.message; } });
  }
  $("scanner-cancel").onclick = function () { closeScanner(null); };
  $("scanner-backdrop").onclick = function () { closeScanner(null); };
  $("scanner-use").onclick = function () { var t = $("scanner-text").value.trim(); if (t) { scanned([t]); } };
  $("scanner-upload").onclick = function () { $("scanner-file").click(); };
  $("scanner-file").onchange = function (ev) {
    var f = ev.target.files && ev.target.files[0]; ev.target.value = ""; if (!f || !scan) { return; }
    $("scanner-status").textContent = "Reading the image…";
    rawPost("/api/qr/scan?image=1", f).then(function (r) {
      var texts = (r.texts || []).filter(function (t) { return /^varsto:\/\//i.test(t); });
      if (!texts.length) { $("scanner-status").textContent = "No Varsto QR code was found in the image."; return; }
      return scanned(texts);
    }).catch(function (e) { $("scanner-status").textContent = e.message; });
  };
  document.addEventListener("keydown", function (ev) { if (scan && ev.key === "Escape") { ev.preventDefault(); closeScanner(null); } });

  // varsto:// links opened from outside (a QR code scanned with the system camera, a clicked link):
  // the service keeps the link (`varsto open-link`), phone shells call varstoOpenLink or pass #link=.
  var pendingLink = null;
  try { var hl = /^#link=(.+)$/.exec(location.hash); if (hl) { pendingLink = decodeURIComponent(hl[1]); history.replaceState(null, "", location.pathname + location.search); } } catch (e) { /* no history API */ }
  window.varstoOpenLink = function (uri) { pendingLink = uri; routeLink(); };
  function takeLink() {
    api("GET", "/api/link").then(function (r) { if (r.uri) { pendingLink = r.uri; } routeLink(); }).catch(function () {});
  }
  function routeLink() {
    var view = document.body.dataset.view;
    if (!pendingLink || !view || view === "unlock") { return; }
    var uri = pendingLink; pendingLink = null;
    api("POST", "/api/link/parse", { text: uri }).then(function (info) { return applyLink(info, view); }).catch(function (e) { alertBox(e.message); });
  }
  function fillPair(info) {
    var form = $("pair"); form.querySelector("input[name=code]").value = info.code;
    if (info.addresses && info.addresses.length) { form.querySelector("input[name=address]").value = info.addresses[0]; }
    var n = form.querySelector("input[name=name]"); if (n) { n.focus(); }
  }
  function applyLink(info, view) {
    if (info.kind === "pair") {
      if (view !== "setup") { return alertBox("This device already uses a vault. A pairing code is for the device you are adding: scan it there."); }
      fillPair(info); log("pairing code filled in from the QR code; give this device a name and a passphrase, then Pair");
      return;
    }
    if (info.kind === "token") {
      if (view !== "setup") { return alertBox("This device already has a vault of its own. Open the sealed token on the device that made the request code."); }
      $("acceptshare").querySelector("input[name=token]").value = info.text;
      return alertBox("The sealed share token for " + info.folder + " is filled in under Accept a shared folder. Fill in the rest and choose Accept.");
    }
    var folders = lastStatus && !lastStatus.member ? lastStatus.folders.filter(function (f) { return !f.member; }) : [];
    if (view !== "app" || !folders.length) { return alertBox("This is a share request. Open it on the device of the folder's owner."); }
    return dialog({
      title: "Share a folder with " + (info.name || "the requester") + "?",
      text: "Choose the folder. Next you compare the six-word fingerprint with them.",
      fields: [
        { name: "folder", label: "Folder", options: folders.map(function (f) { return [f.name, f.name]; }) },
        { name: "role", label: "Role", options: [["editor", "Editor: read and write"], ["viewer", "Viewer: read only"]], value: "editor", hint: "A viewer can still copy what it reads; a key cannot prevent that." }
      ],
      ok: "Continue"
    }).then(function (r) { if (r) { return sealTo(folderByName(r.values.folder), info.text, r.values.role || "editor"); } });
  }
  // Who has access to a shared folder, under its row on the Shared page.
  function showMembers(f, box, owner) {
    api("GET", "/api/share/members?folder=" + encodeURIComponent(f.name)).then(function (l) {
      box.innerHTML = "";
      if (l.access_lost) { box.appendChild(el("li", "notice warn", "This device no longer receives new content of " + f.name + ": the owner removed it, or has not sent it the new key yet.")); }
      if (l.this_role === "viewer") { box.appendChild(el("li", "notice", "This device may only read " + f.name + ": changes made here are not published. Files you change are moved aside and the shared version comes back.")); }
      l.members.forEach(function (m) {
        var li = el("li"); var body = el("div", "li-body"); var title = el("div", "li-title", m.name);
        var kind = m.kind === "owner-device" ? ["grey", "Owner's device"] : m.kind === "invite" ? (m.status === "pending" ? ["accent", "Token not accepted yet"] : ["grey", "Token revoked"]) : m.status === "removed" ? ["risk", "Removed"] : ["accent", "Member"];
        title.appendChild(pill(kind[0], kind[1]));
        if (m.kind !== "owner-device" && m.status !== "removed" && m.status !== "revoked") { title.appendChild(m.role === "viewer" ? pill("grey", "Viewer") : pill("ok", "Editor")); }
        if (m.this_device) { title.appendChild(pill("grey", "This device")); }
        body.appendChild(title);
        var sub = [];
        if (m.fingerprint) { sub.push("fingerprint " + m.fingerprint); }
        if (m.status === "removed") { sub.push("removed" + (m.removed_by ? " by " + m.removed_by : "") + (m.removed_utc ? " " + fmtDate(m.removed_utc) : "")); }
        else if (m.since_utc) { sub.push((m.kind === "invite" ? "issued " : "since ") + fmtDate(m.since_utc)); }
        if (sub.length) { body.appendChild(el("div", "li-sub", sub.join(" · "))); }
        li.appendChild(body);
        var removable = owner && ((m.kind === "member" && m.status === "active") || (m.kind === "invite" && m.status === "pending"));
        if (removable) {
          var a = el("div", "li-actions");
          if (m.kind === "member") {
            // The role: only the owner's devices sign a change of it.
            var rs = el("select"); rs.setAttribute("aria-label", "Role");
            [["editor", "Editor"], ["viewer", "Viewer"]].forEach(function (o) { var x = el("option", null, o[1]); x.value = o[0]; rs.appendChild(x); });
            rs.value = m.role === "viewer" ? "viewer" : "editor";
            rs.onchange = function () { setMemberRole(f, m, rs.value, box); };
            a.appendChild(rs);
          }
          var b = el("button", "secondary danger", m.kind === "invite" ? "Revoke…" : "Remove…"); b.type = "button";
          b.onclick = function () { removeMember(f, m, box); }; a.appendChild(b); li.appendChild(a);
        }
        box.appendChild(li);
      });
      if (owner && l.members.some(function (m) { return (m.kind === "member" && m.status === "active") || (m.kind === "invite" && m.status === "pending"); })) {
        var li = el("li"); var a = el("div", "li-actions"); var b = el("button", "secondary danger", "Remove everyone…"); b.type = "button";
        b.onclick = function () { removeMember(f, { id: "all", name: "everyone", kind: "all" }, box); }; a.appendChild(b); li.appendChild(a); box.appendChild(li);
      }
    }).catch(function (e) { alertBox(e.message); });
  }
  function setMemberRole(f, m, role, box) {
    var viewer = role === "viewer";
    dialog({
      title: (viewer ? "Make " + m.name + " a viewer?" : "Let " + m.name + " write?"),
      text: viewer ? m.name + " keeps reading " + f.name + ", and what it wrote until now stays. What it changes from now on is not accepted by your devices or the editors. It can still copy what it reads: a key cannot prevent that." : m.name + " can change, add and delete files in " + f.name + " again; your devices and the other members accept its changes.",
      ok: viewer ? "Make viewer" : "Make editor", danger: viewer
    }).then(function (r) {
      if (!r) { return showMembers(f, box, true); }
      busy(true);
      return api("POST", "/api/share/role", { folder: f.name, member: m.id, role: role }).then(function (rep) {
        log(f.name + ": " + rep.member + " is now " + (rep.role === "viewer" ? "a viewer" : "an editor"));
        showMembers(f, box, true);
      });
    }).catch(function (e) { alertBox(e.message, "Nothing was changed"); showMembers(f, box, true); }).then(function () { busy(false); });
  }
  function removeMember(f, m, box) {
    var invite = m.kind === "invite";
    dialog({
      title: (invite ? "Revoke the token for " : "Remove ") + m.name + (invite ? "?" : " from " + f.name + "?"),
      text: (invite ? "The token was not accepted yet. " : "") + f.name + " gets a new key: your devices and the members who stay receive it, and everything written from now on is unreadable to " + (m.kind === "all" ? "the people removed" : m.name) + ". Their changes from now on are ignored. " +
        "Everything they already received stays readable to them: a key cannot be recalled, and they can still reach the storage you shared until you change its access. " + (invite ? "If the token is accepted later, it brings nothing written from now on. " : "") + "This cannot be undone; share again with a new token.",
      fields: [{ name: "confirm", label: "Type " + (m.kind === "all" ? "the folder name" : "the name") + " to confirm", placeholder: m.kind === "all" ? f.name : m.name, required: true }],
      ok: invite ? "Revoke" : "Remove", danger: true
    }).then(function (r) {
      if (!r) { return; }
      if (r.values.confirm.trim() !== (m.kind === "all" ? f.name : m.name)) { return alertBox("The name does not match, so nothing was changed."); }
      busy(true);
      return api("POST", "/api/share/revoke", { folder: f.name, member: m.id, confirm: true }).then(function (rep) {
        log(f.name + ": new key (share epoch " + rep.share_epoch + ")" + (rep.removed.length ? ", removed " + rep.removed.join(", ") : "") + (rep.invites_revoked.length ? ", " + rep.invites_revoked.length + " token(s) revoked" : ""));
        var text = f.name + " has a new key." + (rep.removed.length ? " Removed: " + rep.removed.join(", ") + "." : "") + (rep.invites_revoked.length ? " Tokens revoked: " + rep.invites_revoked.length + "." : "");
        if (rep.grants_pending.length) { text += " Waiting for " + rep.grants_pending.join(", ") + ": they receive the new key once they run this version."; }
        return alertBox(text, "Access changed").then(function () { showMembers(f, box, true); });
      });
    }).catch(function (e) { alertBox(e.message, "Nothing was changed"); }).then(function () { busy(false); });
  }
  // Strongroom: the security key is touched on the command line (libfido2 tools), so the page shows the command.
  function shArg(n) { return /^[A-Za-z0-9._\/-]+$/.test(n) ? n : "'" + n.replace(/'/g, "'\\''") + "'"; }
  function convertStrongroom(f) {
    api("GET", "/api/strongroom").then(function (r) {
      var resume = (r.conversions || []).some(function (c) { return c.folder === f.name && !c.cleanup_only; });
      return dialog({
        title: (resume ? "Resume converting " : "Convert ") + f.name + " to a Strongroom",
        text: (resume ? "A conversion of this folder was interrupted; nothing old was deleted. Run the same command again and touch the key it was started with. " : "The folder gets a new key that only your FIDO2 security key opens. Everything is re-encrypted and uploaded again, then the old copies are deleted from your storages. Other devices replace their plain copies with placeholders and need the security key to open the folder; a device that already had the old key could have kept it. ") + "Run this in a terminal on this computer with the security key plugged in:",
        code: "varsto strongroom convert " + shArg(f.name), ok: "Close", cancel: false
      });
    }).then(function () { return refreshStatus(); }).catch(function (e) { alertBox(e.message); });
  }
  function strongroomKeys(f) {
    api("GET", "/api/strongroom").then(function (r) {
      var sr = (r.strongrooms || []).filter(function (x) { return x.folder === f.name; })[0];
      var keys = sr ? sr.keys : [];
      var lines = keys.map(function (k) { return k.number + ". " + (k.label || "no label") + " (" + k.method + (k.added_utc ? ", added " + fmtDate(k.added_utc) : "") + "): " + k.name; });
      return dialog({
        title: "Security keys of " + f.name,
        text: (keys.length === 1 ? "One key opens this Strongroom; if it is lost, so is the folder. Enrol a backup key and keep it somewhere safe." : keys.length + " keys open this Strongroom; any one of them is enough.") + " To add a backup key, run the command with an enrolled key plugged in; it asks you to swap to the new key. " +
          "Removing a key does not change the folder key. After removing a key someone may have kept, or if you suspect the key leaked, re-key the folder: it gets a new key wrapped for every enrolled key (touch each one), everything is re-encrypted and the old copies are deleted.",
        code: lines.join("\n") + "\n\nvarsto strongroom add-key " + shArg(f.name) + " --label safe\nvarsto strongroom rekey " + shArg(f.name),
        ok: "Close", cancel: false, extra: keys.length > 1 ? "Remove a key…" : ""
      }).then(function (d) {
        if (!d || d.action !== "extra") { return; }
        return dialog({ title: "Remove a key from " + f.name, text: "The key stops opening the folder and its wrap is deleted from the storages. The folder key itself does not change, so a removed key that was kept could still open an older copy of the records. The last key always stays.", fields: [{ name: "key", label: "Key number or label", required: true }], ok: "Remove", danger: true }).then(function (x) {
          if (!x) { return; }
          return api("POST", "/api/strongroom/remove-key", { folder: f.name, key: x.values.key.trim() }).then(function (res) { log("removed key " + res.removed + " from " + f.name); });
        });
      });
    }).catch(function (e) { alertBox(e.message); });
  }
  function stateLabel(state) { return state === "ok" ? "OK" : state === "at_risk" ? "At risk" : state === "violated" ? "Violated" : "Unknown"; }
  function stateClass(state) { return state === "ok" ? "ok" : state === "at_risk" ? "risk" : state === "violated" ? "bad" : "grey"; }
  function folderByName(name) { if (!lastStatus) { return null; } for (var i = 0; i < lastStatus.folders.length; i++) { if (lastStatus.folders[i].name === name) { return lastStatus.folders[i]; } } return null; }

  // The ledger banner: shown only when something is wrong with this
  // device's ledger or it is being repaired. The service restores a lost
  // ledger by itself; a copy restored from an older backup continues from
  // the storages when the user asks (the button), and only when they hold
  // this device's own later history.
  var LEDGER_TEXT = {
    "rebuild_needed": "This device's ledger was lost or damaged. It is being restored from the storages before anything else is synced.",
    "repairing": "Restoring this device's ledger from the storages…",
    "fenced": "The storages hold newer ledger entries of this device than it has: it was probably restored from an older copy. It records nothing until it continues from them.",
    "forked": "Another copy of this device has written a different ledger history. This device records nothing more: remove it from the vault on another device and pair this computer again as a new device.",
    "no_ledger": "No storage holds the record of where the blocks are any more. It is being rebuilt from the folders' file lists and the stored blocks."
  };
  var LEDGER_BUTTON = { "rebuild_needed": "Restore now", "fenced": "Continue from the storages", "no_ledger": "Rebuild now" };
  function renderLedger(h) {
    var b = $("ledgerbanner"); if (!b) { return; }
    var show = !!(h && h.state && h.state !== "ok");
    b.classList.toggle("hidden", !show);
    if (!show) { return; }
    var text = $("ledgerbanner-text");
    text.textContent = LEDGER_TEXT[h.state] || (h.problems || []).map(function (p) { return p.detail; }).join("; ");
    var btn = $("ledgerbanner-btn"); var label = LEDGER_BUTTON[h.state];
    btn.classList.toggle("hidden", !label);
    if (!label) { return; }
    btn.textContent = label; btn.disabled = false;
    btn.onclick = function () {
      btn.disabled = true; text.textContent = LEDGER_TEXT.repairing;
      api("POST", "/api/ledger/rebuild", { from_storage: h.state === "no_ledger" }).then(function (r) {
        renderLedger(r.health); refreshStatus();
      }).catch(function (e) {
        log("error: " + e.message); btn.disabled = false; refreshStatus();
      });
    };
  }

  // Folder safety: a banner per folder that is paused on this device (its
  // marker is missing or names another folder; deletions are held) or has
  // changes waiting in send-only / receive-only mode, with the actions.
  function folderAction(f, action, extra) {
    var body = Object.assign({ folder: f.name, action: action }, extra || {});
    return api("POST", "/api/folder/safety", body);
  }
  function safetyButton(label, cls, onclick) { var b = el("button", cls || "secondary", label); b.type = "button"; b.onclick = onclick; return b; }
  function showFolderChanges(f) {
    folderAction(f, "pending").then(function (c) {
      var lines = [];
      (c.held_paths || []).slice(0, 200).forEach(function (p) { lines.push("deleted  " + p); });
      (c.local_changes || []).concat(c.remote_not_applied || []).slice(0, 200).forEach(function (x) { lines.push(x.kind + "  " + x.path); });
      return dialog({ title: f.name, text: lines.length ? "The files waiting for your decision:" : "Nothing waits for a decision.", code: lines.join("\n"), cancel: false });
    }).catch(function (e) { alertBox(e.message); });
  }
  function runFolderAction(f, action, done) {
    busy(true);
    return folderAction(f, action).then(function (r) { log(f.name + ": " + done(r)); return refreshStatus(); })
      .catch(function (e) { alertBox(e.message); }).then(function () { busy(false); });
  }
  function renderFolderSafety(s) {
    var box = $("foldersafety"); if (!box) { return; }
    box.innerHTML = "";
    (s.folders || []).forEach(function (f) {
      if (!f.path) { return; }
      var p = f.paused, h = f.held_deletions, text = null, buttons = [];
      if (p && p.kind === "marker-missing") {
        text = "Folder " + f.name + " is paused: the marker .varsto-folder is missing at " + p.path + ". Is the disk mounted? Nothing is synced until it is back.";
        buttons.push(safetyButton("The directory is right", null, function () {
          confirmBox("Write the marker into " + p.path + " and sync this directory as " + f.name + "? Only do this if the directory holds the folder's files: if it is an empty mount point, its files would be read as deleted (the deletion guard would still ask first).", { ok: "Write the marker" }).then(function (yes) { if (yes) { runFolderAction(f, "repair-marker", function () { return "marker written"; }); } });
        }));
      } else if (p && p.kind === "marker-other") {
        text = "Folder " + f.name + " is paused: the directory " + p.path + " holds another folder's marker. Is the right disk mounted? Nothing is synced until it is fixed.";
        buttons.push(safetyButton("The directory is right", null, function () {
          confirmBox("Mark " + p.path + " as folder " + f.name + "? Only do this if the directory really holds this folder's files.", { ok: "Write the marker", danger: true }).then(function (yes) { if (yes) { runFolderAction(f, "repair-marker", function () { return "marker written"; }); } });
        }));
      } else if (h && h.origin === "local") {
        text = "Folder " + f.name + " is paused: " + h.files + " of " + h.of_files + " files were deleted at once on this device. Nothing is synced until you decide.";
        buttons.push(safetyButton("Restore them", null, function () { runFolderAction(f, "discard-deletions", function (r) { return r.restored + " files restored" + (r.unavailable.length ? ", " + r.unavailable.length + " not available now" : ""); }); }));
        buttons.push(safetyButton("Delete them everywhere", "secondary danger", function () {
          confirmBox("Delete these " + h.files + " files on every device? Other devices move them to their trash.", { ok: "Delete everywhere", danger: true }).then(function (yes) { if (yes) { runFolderAction(f, "confirm-deletions", function (r) { return r.deleted + " deletions confirmed"; }); } });
        }));
      } else if (h) {
        text = "Folder " + f.name + " is paused: " + (h.device || "another device") + " deleted " + h.files + " of " + h.of_files + " files at once. Nothing is deleted here until you decide.";
        buttons.push(safetyButton("Keep them and restore them everywhere", null, function () { runFolderAction(f, "discard-deletions", function (r) { return r.restored + " files kept"; }); }));
        buttons.push(safetyButton("Delete them here too", "secondary danger", function () {
          confirmBox("Delete these " + h.files + " files on this device too? They go to this device's trash.", { ok: "Delete here", danger: true }).then(function (yes) { if (yes) { runFolderAction(f, "confirm-deletions", function (r) { return r.deleted + " files moved to the trash"; }); } });
        }));
      } else if (f.remote_not_applied > 0) {
        text = "Folder " + f.name + " is send-only on this device: " + f.remote_not_applied + " remote changes are not applied here.";
        buttons.push(safetyButton("Override: make everyone match this device", null, function () {
          confirmBox("Publish this device's state of these " + f.remote_not_applied + " files as the newest version? The other devices then match this one.", { ok: "Override", danger: true }).then(function (yes) { if (yes) { runFolderAction(f, "override", function (r) { return r.files + " files now follow this device"; }); } });
        }));
      } else if (f.local_changes > 0) {
        text = "Folder " + f.name + " is receive-only on this device: " + f.local_changes + " local changes are not published.";
        buttons.push(safetyButton("Revert: restore the vault version", null, function () {
          confirmBox("Replace the " + f.local_changes + " locally changed files with the vault's versions? The local copies go to this device's trash.", { ok: "Revert" }).then(function (yes) { if (yes) { runFolderAction(f, "revert", function (r) { return r.reverted + " local changes reverted"; }); } });
        }));
      }
      if (!text) { return; }
      var n = el("div", "notice warn banner-action"); n.dataset.folderSafety = f.name;
      n.appendChild(el("span", null, text));
      if (h || f.remote_not_applied > 0 || f.local_changes > 0) { buttons.unshift(safetyButton("Show files", null, function () { showFolderChanges(f); })); }
      buttons.forEach(function (b) { n.appendChild(b); });
      box.appendChild(n);
    });
  }
  // Sync settings of a folder on this device: its mode and the deletion guard.
  var MODE_HINT = {
    "normal": "This device publishes its changes and applies everyone else's.",
    "send-only": "This device publishes its changes but never applies other devices' changes to its files (for a camera phone, say). Differences are listed; an override makes everyone match this device.",
    "receive-only": "This device applies other devices' changes but never publishes its own. Local changes are listed; a revert restores the vault's versions."
  };
  function folderSettings(f) {
    folderAction(f, "pending").then(function (c) {
      var g = c.deletion_guard || {};
      return dialog({
        title: "Sync settings of " + f.name,
        text: "These settings apply to this device only.",
        fields: [
          { name: "mode", label: "Mode on this device", options: [["normal", "Normal (send and receive)"], ["send-only", "Send only"], ["receive-only", "Receive only"]], value: c.mode || "normal", hint: MODE_HINT[c.mode || "normal"] },
          { name: "guard", label: "Hold mass deletions for confirmation", options: [["on", "Yes"], ["off", "No"]], value: g.enabled === false ? "off" : "on", hint: "Deletions are held when more than the share and more than the files below are deleted at once, or more than the limit." },
          { name: "percent", label: "Share of the folder's files (%)", type: "number", value: g.percent },
          { name: "min_files", label: "and more than this many files", type: "number", value: g.min_files },
          { name: "max_files", label: "or more than this many files (0: no limit)", type: "number", value: g.max_files }
        ],
        ok: "Save"
      }).then(function (r) {
        if (!r) { return; }
        var v = r.values;
        var guard = { enabled: v.guard !== "off", percent: Math.max(0, Math.floor(+v.percent) || 0), min_files: Math.max(0, Math.floor(+v.min_files) || 0), max_files: Math.max(0, Math.floor(+v.max_files) || 0) };
        var chain = Promise.resolve();
        if (v.mode !== (c.mode || "normal")) { chain = chain.then(function () { return folderAction(f, "mode", { mode: v.mode }); }).then(function () { log(f.name + ": mode " + v.mode); }); }
        if (guard.enabled !== (g.enabled !== false) || guard.percent !== g.percent || guard.min_files !== g.min_files || guard.max_files !== g.max_files) {
          chain = chain.then(function () { return folderAction(f, "deletion-guard", { guard: guard }); }).then(function (x) { log(f.name + ": deletions are held when " + x.text); });
        }
        return chain.then(function () { return refreshStatus(); });
      });
    }).catch(function (e) { alertBox(e.message); });
  }

  // `known`: a status the last request already returned (no second round trip,
  // which would wait while the service syncs).
  function refreshStatus(known) {
    return (known && known.folders ? Promise.resolve(known) : api("GET", "/api/status")).then(function (s) {
      lastStatus = s;
      setTimeout(function () { helpAfterStatus(s); }, 0);
      renderLedger(s.ledger_health);
      renderFolderSafety(s);
      $("who").textContent = s.device_name + " · vault " + s.vault_id.slice(0, 8) + " · " + s.ledger_batches + " ledger batches";
      var tb = $("folders").querySelector("tbody"); tb.innerHTML = "";
      var sel = $("dupefolder"); sel.innerHTML = "";
      var fsel = $("filesfolder"); var prev = fsel.value; fsel.innerHTML = "";
      var tree = $("foldertree"); tree.innerHTML = "";
      var pl = $("policylist"); pl.innerHTML = "";
      var shl = $("sharedlist"); shl.innerHTML = "";
      var al = $("attachlist"); al.innerHTML = "";
      var totalFiles = 0, totalBytes = 0; var totalBlocks = {}; var shared = 0, detached = 0;
      s.folders.forEach(function (f) {
        totalFiles += f.files; totalBytes += f.bytes;
        var tr = document.createElement("tr");
        function td(text, cls, label) { var d = document.createElement("td"); d.textContent = text; if (cls) { d.className = cls; } if (label) { d.dataset.label = label; } tr.appendChild(d); }
        var nameCell = document.createElement("td"); nameCell.appendChild(document.createTextNode(f.name));
        if (f.strongroom) { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill(f.strongroom === "locked" ? "grey" : "accent", f.strongroom === "locked" ? "Strongroom locked" : "Strongroom open")); }
        if (f.selective) { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill("grey", "selective")); }
        if (f.shared) { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill("accent", "shared")); }
        if (f.read_only) { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill("grey", "read only")); }
        if (f.path && f.plain === false) { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill("grey", "encrypted here")); }
        if (f.path && f.mode && f.mode !== "normal") { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill("grey", f.mode)); }
        if (f.path && f.paused) { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill("bad", "paused")); }
        var sub = el("span", "sub", f.path || "Not attached on this device"); if (f.path) { sub.title = f.path; } nameCell.appendChild(sub);
        nameCell.appendChild(miniMap(f));
        tr.appendChild(nameCell);
        totalBlocks = addBlocks(totalBlocks, folderBlocks(f));
        td(f.files, "num", "Files"); td(fmtBytes(f.bytes), "num", "Size"); td(f.chunks, "num", "Chunks");
        td(f.chunks_without_storage_copy, "num" + (f.chunks_without_storage_copy > 0 ? " bad" : ""), "Without storage copy"); td(f.chunks_verified_elsewhere, "num", "Verified elsewhere");
        var pc = document.createElement("td"); pc.dataset.policyFor = f.name; pc.appendChild(pill("grey", f.policy ? "Unchecked" : "No policy")); if (f.policy) { var pt = el("span", "policy-text", f.policy); pt.title = f.policy; pc.appendChild(pt); } tr.appendChild(pc);
        var act = document.createElement("td");
        var menu = rowMenu(act, "folder:" + f.name);
        if (!s.member) { var sh = document.createElement("button"); sh.className = "secondary"; sh.textContent = f.shared ? "Token" : "Share"; sh.onclick = function () { shareFolder(f); }; menu.appendChild(sh); }
        if (!s.member) { var pb = document.createElement("button"); pb.className = "secondary"; pb.textContent = "Policy"; pb.onclick = function () { openPolicy(f); }; act.appendChild(pb); }
        if (f.path) { var ssb = document.createElement("button"); ssb.className = "secondary"; ssb.textContent = "Sync settings…"; ssb.title = "Mode on this device and the deletion guard"; ssb.onclick = function () { folderSettings(f); }; menu.appendChild(ssb); }
        if (!s.member) { var rmb = document.createElement("button"); rmb.className = "secondary"; rmb.textContent = "Remove"; rmb.onclick = function () { removeFolder(f); }; menu.appendChild(rmb); }
        if (f.strongroom && f.strongroom !== "locked") { var lk = document.createElement("button"); lk.className = "secondary"; lk.textContent = "Lock"; lk.onclick = function () { api("POST", "/api/strongroom/lock", { folder: f.name }).then(function () { log("locked " + f.name); return refreshStatus(); }).catch(function (e) { alertBox(e.message); }); }; menu.appendChild(lk); }
        if (!s.member && f.path && !f.strongroom && !f.shared) { var cv = document.createElement("button"); cv.className = "secondary"; cv.textContent = "Convert to Strongroom…"; cv.onclick = function () { convertStrongroom(f); }; menu.appendChild(cv); }
        if (f.path) { var mf = document.createElement("button"); mf.className = "secondary"; mf.textContent = "Free space\u2026"; mf.title = "Free space kept on this folder's disk: " + (f.min_free_text || "5 %"); mf.onclick = function () { editMinFree("folder", f.name, f.min_free); }; menu.appendChild(mf); }
        if (f.strongroom) { var ks = document.createElement("button"); ks.className = "secondary"; ks.textContent = "Security keys…"; ks.title = "Enrolled security keys; add a backup key"; ks.onclick = function () { strongroomKeys(f); }; menu.appendChild(ks); }
        if (f.strongroom === "locked") { var note = document.createElement("span"); note.className = "muted"; note.textContent = "unlock with: varsto strongroom unlock " + f.name; act.appendChild(note); }
        menu.done();
        tr.appendChild(act); tb.appendChild(tr);
        var o = document.createElement("option"); o.value = f.name; o.textContent = f.name; sel.appendChild(o);
        if (f.path) { var o2 = document.createElement("option"); o2.value = f.name; o2.textContent = f.name; o2.dataset.selective = f.selective ? "1" : "0"; fsel.appendChild(o2); }

        // Sidebar tree under Files.
        var li = el("li"); var tbtn = el("button", "tree-item" + (f.path ? "" : " detached")); tbtn.type = "button"; tbtn.dataset.folder = f.name; tbtn.title = f.path || "Not attached on this device";
        tbtn.appendChild(icon("folders")); tbtn.appendChild(el("span", "tree-name", f.name));
        if (!f.path) { var dot = el("i", "tree-dot"); dot.title = "Not attached on this device"; tbtn.appendChild(dot); }
        tbtn.onclick = function () { if (f.path) { openFolder(f.name); } else { offerAttach(f); } };
        li.appendChild(tbtn); tree.appendChild(li);

        // Attach list (mobile): folders of the vault not attached here.
        if (!f.path) {
          detached++;
          var ali = el("li"); var aic = el("span", "li-icon"); aic.appendChild(icon("folders")); ali.appendChild(aic);
          var abody = el("div", "li-body"); abody.appendChild(el("div", "li-title", f.name)); abody.appendChild(el("div", "li-sub", f.files + " files · " + fmtBytes(f.bytes))); ali.appendChild(abody);
          var aa = el("div", "li-actions"); var ab = el("button", "", "Attach"); ab.type = "button"; ab.onclick = function () { attachFolder(f.name, ""); }; aa.appendChild(ab); ali.appendChild(aa);
          al.appendChild(ali);
        }

        // Shared page: folders shared with other users.
        if (f.shared) {
          shared++;
          var sli = el("li"); var sic = el("span", "li-icon"); sic.appendChild(icon("sharing")); sli.appendChild(sic);
          var sbody = el("div", "li-body"); var stitle = el("div", "li-title", f.name); stitle.appendChild(pill("accent", "shared")); if (f.read_only) { stitle.appendChild(pill("grey", "read only")); } sbody.appendChild(stitle);
          sbody.appendChild(el("div", "li-sub", f.files + " files · " + fmtBytes(f.bytes) + (f.path ? " · " + f.path : ""))); sli.appendChild(sbody);
          var sa = el("div", "li-actions");
          var smw = el("li", "sub-row hidden"); var sm = el("ul", "list sub-list"); smw.appendChild(sm);
          var smb = el("button", "secondary", "Members"); smb.type = "button";
          smb.onclick = function () { var hidden = smw.classList.toggle("hidden"); if (!hidden) { showMembers(f, sm, !s.member); } };
          sa.appendChild(smb);
          if (!s.member) { var sb = el("button", "secondary", "New token"); sb.type = "button"; sb.onclick = function () { shareFolder(f); }; sa.appendChild(sb); }
          sli.appendChild(sa);
          shl.appendChild(sli); shl.appendChild(smw);
        }

        // Policies page: one row per folder, filled in once the reports arrive.
        var pli = el("li"); pli.dataset.policyRow = f.name;
        var pic = el("span", "li-icon"); pic.appendChild(icon("policies")); pli.appendChild(pic);
        var pbody = el("div", "li-body"); var ptitle = el("div", "li-title", f.name); ptitle.appendChild(pill("grey", f.policy ? "Unchecked" : "No policy")); pbody.appendChild(ptitle);
        pbody.appendChild(el("div", "li-sub", f.policy || "No rule set. Files are still written to every storage; a policy adds a minimum that Varsto watches for you."));
        pli.appendChild(pbody);
        if (!s.member) { var pa = el("div", "li-actions"); var pe = el("button", "secondary", f.policy ? "Edit policy" : "Set policy"); pe.type = "button"; pe.onclick = function () { editPolicy(f); }; pa.appendChild(pe); var pw = el("button", "secondary", "Placement"); pw.type = "button"; pw.title = "Which storages this folder is written to"; pw.onclick = function () { editPlacement(f.name); }; pa.appendChild(pw); pli.appendChild(pa); }
        pl.appendChild(pli);
      });
      renderFolderList(s);
      $("folders-empty").classList.toggle("hidden", s.folders.length > 0);
      $("policylist-empty").classList.toggle("hidden", s.folders.length > 0);
      $("sharedlist-empty").classList.toggle("hidden", shared > 0);
      $("attachlist-empty").classList.toggle("hidden", detached > 0);
      $("addfolder-hint").classList.toggle("hidden", detached === 0);
      $("stat-folders").textContent = s.folders.length;
      $("stat-files").textContent = totalFiles;
      $("stat-bytes").textContent = fmtBytes(totalBytes);
      $("stat-devices").textContent = Object.keys(s.devices).length;
      $("stat-storages").textContent = s.storages.length;
      (function () {
        var t = blockTotal(totalBlocks); var per = Math.max(1, Math.ceil(t / 600));
        drawBlocks($("datamap"), totalBlocks, per);
        var tb = totalBlocks; var n = function (k) { return tb[k] || 0; };
        $("leg-verified").textContent = n("verified_here") + n("verified_away");
        $("leg-stored").textContent = n("stored_here") + n("stored_away");
        $("leg-local").textContent = n("local_only");
        $("leg-missing").textContent = n("missing");
        $("leg-here").textContent = n("verified_here") + n("stored_here") + n("local_only");
        $("leg-away").textContent = n("verified_away") + n("stored_away");
        $("datamap-total").textContent = t + " block" + (t === 1 ? "" : "s") + " in " + s.folders.length + " folder" + (s.folders.length === 1 ? "" : "s");
        $("datamap-note").textContent = per > 1 ? "1 square ≈ " + per + " blocks" : (t ? "1 square = 1 block" : "");
      })();
      loadWhere();
      if (prev && folderByName(prev) && folderByName(prev).path) { fsel.value = prev; }
      else if (!fsel.value && fsel.options.length) { fsel.selectedIndex = 0; }
      markTree(fsel.value);
      if (currentPage === "files") { ensureFiles(); }
      updateFilesHead();
      if (fsel.options.length === 0) { showFolderForms(true); } else if (s.folders.length > 0 && $("folderforms").dataset.user !== "1") { showFolderForms(false); }
      api("GET", "/api/policy").then(function (p) {
        renderPolicyGrid(p);
        var lines = [];
        (p.reports || []).forEach(function (r) {
          var label = stateLabel(r.state); var cls = stateClass(r.state);
          var cell = document.querySelector('[data-policy-for="' + r.folder + '"]');
          if (cell) { var old = cell.querySelector(".pill"); if (old) { old.replaceWith(pill(cls, label)); } }
          var row = document.querySelector('[data-policy-row="' + r.folder + '"]');
          if (row) { var rp = row.querySelector(".pill"); if (rp) { rp.replaceWith(pill(cls, label)); } var sub = row.querySelector(".li-sub"); var extra = r.reasons.concat(r.warnings).join("; "); if (sub && extra) { sub.textContent = sub.textContent + " — " + extra; } }
          if (r.state !== "ok") { lines.push(r.folder + ": " + label + ". " + r.reasons.concat(r.warnings).join("; ") + "."); }
        });
        $("policybanner").textContent = lines.join(" ");
        $("policybanner").classList.toggle("hidden", lines.length === 0);
      }).catch(function () {});
      loadAdvice(); loadAutoVerify(); loadRepair(); loadScrub();
      updateFilesHead();
      var ul = $("storages"); ul.innerHTML = "";
      s.storages.forEach(function (st) {
        var where = st.kind === "s3" ? st.endpoint + " bucket " + st.bucket + (st.prefix ? "/" + st.prefix : "") + (st.storage_class ? ", class " + st.storage_class : "") : (st.kind === "rclone" ? st.remote : st.kind === "pool" ? (st.disks || []).length + " disk" + ((st.disks || []).length === 1 ? "" : "s") + ", " + (st.reserve_percent || 5) + " % kept free" : st.path);
        var li = el("li"); li.dataset.storage = st.name; var ic = el("span", "li-icon"); ic.appendChild(icon("storages")); li.appendChild(ic);
        var body = el("div", "li-body"); var title = el("div", "li-title", st.name);
        title.appendChild(pill("grey", st.kind === "s3" ? "S3" : st.kind === "rclone" ? "rclone" : st.kind === "pool" ? "disk pool" : "directory"));
        var dest = (s.carrier_for || {})[st.name] || [];
        if (st.cold) { title.appendChild(pill("grey", "cold")); } if (st.carrier) { title.appendChild(pill("grey", dest.length ? "transferrer for " + dest.join(", ") : "transferrer")); }
        if (st.place) { title.appendChild(pill("grey", st.place)); }
        if (st.kind === "local-dir") { where = (where || "") + " \u00b7 keeps " + (st.min_free ? (/%$/.test(st.min_free) ? st.min_free.replace("%", " %") : fmtBytes(+st.min_free)) : "5 %") + " free"; }
        body.appendChild(title); body.appendChild(el("div", "li-sub", where || "")); li.appendChild(body);
        if (!s.member) {
          var ra = el("div", "li-actions");
          if (st.kind === "local-dir") { var mb = el("button", "secondary", "Free space\u2026"); mb.type = "button"; mb.title = "Free space kept on this storage's disk"; mb.onclick = function () { editMinFree("storage", st.name, st.min_free); }; ra.appendChild(mb); }
          if (st.carrier) { var cb = el("button", "secondary", "Destination\u2026"); cb.type = "button"; cb.onclick = function () { carrierDestination(st.name, dest); }; ra.appendChild(cb); }
          if (!st.carrier) { var db = el("button", "secondary drain-btn", "Drain\u2026"); db.type = "button"; db.title = "Empty this storage onto the others, without weakening any policy"; db.onclick = function () { drainStorage(st.name); }; ra.appendChild(db); }
          var rb = el("button", "secondary", "Remove"); rb.type = "button"; rb.onclick = function () { removeStorage(st.name); }; ra.appendChild(rb); li.appendChild(ra);
        }
        ul.appendChild(li);
      });
      $("storages-empty").classList.toggle("hidden", s.storages.length > 0);
      loadStorageCosts();
      loadStorageUsage();
      renderPools(s.storages);
      var names = Object.keys(s.devices).map(function (k) { return s.devices[k] + " (" + k.slice(0, 8) + ")"; });
      var reps = Object.keys(s.replicas || {}).map(function (k) { return s.replicas[k]; });
      var mems = Object.keys(s.members || {}).map(function (k) { return s.members[k]; });
      $("devices").textContent = (s.member ? "This device is a member of a shared folder. " : "") + "Devices: " + (names.join(", ") || "none yet") + (reps.length ? " · replicas: " + reps.join(", ") : "") + (mems.length ? " · members: " + mems.join(", ") : "") + (s.forked_devices.length ? " · FORKED: " + s.forked_devices.join(", ") : "");
      $("members").textContent = mems.length ? "Members with access to shared folders: " + mems.join(", ") : "";
      loadDevices(s);
      var org = s.org || null;
      // Locked out by the organization's platform policy.
      $("orgblockbanner").textContent = org && org.blocked ? orgBlockedText(org.blocked) : "";
      $("orgblockbanner").classList.toggle("hidden", !(org && org.blocked));
      document.querySelectorAll("[data-org-only]").forEach(function (b) { b.classList.toggle("hidden", !org); });
      $("teamcard").classList.toggle("hidden", !!org || !!s.member);
      if (!org && currentPage === "organization") { nav("settings"); }
      $("replicatoken").classList.toggle("hidden", !!s.member);
      $("replicacard").classList.toggle("hidden", !!s.member);
      if (currentPage === "backups") { fillBackupStorages(); }
      return api("GET", "/api/service").then(function (sv) { renderService(sv); return api("GET", "/api/ledger"); }).then(function (l) {
        $("ledger").textContent = l.map(function (e) { return e.device.slice(0, 8) + " #" + e.seq + " lamport " + e.lamport + " events " + e.events; }).join("\n") || "(empty)";
      });
    }).catch(function (e) { log("error: " + e.message); });
  }

  // Phone: the Files tab opens with one card per folder of the vault.
  function renderFolderList(s) {
    var list = $("folderlist"); list.innerHTML = "";
    s.folders.forEach(function (f) {
      var b = el("button", "folder-card" + (f.path ? "" : " detached")); b.type = "button"; b.dataset.folder = f.name;
      var ic = el("span", "li-icon"); ic.appendChild(icon("folders")); b.appendChild(ic);
      var body = el("span", "fc-body"); var title = el("span", "fc-title"); title.appendChild(el("span", "fc-name", f.name));
      if (f.selective) { title.appendChild(pill("grey", "selective")); }
      if (f.shared) { title.appendChild(pill("accent", "shared")); }
      if (f.path && f.plain === false) { title.appendChild(pill("grey", "encrypted here")); }
      if (f.path && f.mode && f.mode !== "normal") { title.appendChild(pill("grey", f.mode)); }
      if (f.path && f.paused) { title.appendChild(pill("bad", "paused")); }
      if (!f.path) { title.appendChild(pill("grey", "not on this device")); }
      body.appendChild(title);
      body.appendChild(el("span", "fc-sub", f.files + " file" + (f.files === 1 ? "" : "s") + " · " + fmtBytes(f.bytes)));
      body.appendChild(miniMap(f)); b.appendChild(body);
      b.appendChild(icon("chevron", "fc-chev"));
      b.onclick = function () { if (f.path) { openFolder(f.name); } else { offerAttach(f); } };
      list.appendChild(b);
    });
    $("folderlist-empty").classList.toggle("hidden", s.folders.length > 0);
  }

  // Suggestions: Varsto's own placement estimate for files idle for 90 days.
  function money(n, cur) { return (n < 0.01 ? "under 0.01" : n < 10 ? n.toFixed(2) : n < 100 ? n.toFixed(1) : Math.round(n).toString()) + " " + cur; }
  function className(e) { var prov = e.provider || ""; var cls = e.class || ""; var last = prov.split(" ").pop(); if (last && cls.indexOf(last + " ") === 0) { prov = prov.split(" ").slice(0, -1).join(" "); } return (prov ? prov + " " : "") + cls; }
  function loadAdvice() {
    api("GET", "/api/advice?idle_days=90").then(function (a) {
      var files = (a.idle_files || []).length;
      renderSuggestions(a);
      if (!files || !(a.estimates || []).length) { $("advice").classList.add("hidden"); return; }
      var best = a.estimates[0];
      var gb = a.idle_gb >= 0.1 ? a.idle_gb.toFixed(1) + " GB" : fmtBytes(a.idle_bytes);
      var main = $("advice-main"); main.innerHTML = "";
      main.appendChild(document.createTextNode(files + " file" + (files === 1 ? "" : "s") + " (" + gb + ") " + (files === 1 ? "has" : "have") + " not been used in " + (a.idle_days_threshold || 90) + " days; in "));
      main.appendChild(el("b", "", className(best)));
      main.appendChild(document.createTextNode(" they would cost about "));
      main.appendChild(el("b", "", money(best.monthly_cost, best.currency) + " a month"));
      main.appendChild(document.createTextNode((best.last_verified ? " (source verified " + best.last_verified + ")" : "") + "."));
      var hot = null;
      for (var i = 0; i < a.estimates.length; i++) { var e = a.estimates[i]; if (e !== best && e.kind === "hot") { hot = e; break; } }
      var alt = $("advice-alt");
      var tail = " The figures are estimates from Varsto's price table and the prices set on the Storages page.";
      if (hot) { alt.textContent = "Cheapest option that stays instantly readable: " + className(hot) + " at about " + money(hot.monthly_cost, hot.currency) + " a month" + (hot.last_verified ? " (verified " + hot.last_verified + ")" : "") + "." + tail; }
      else { var second = a.estimates[1]; alt.textContent = (second ? "Next: " + className(second) + " at about " + money(second.monthly_cost, second.currency) + " a month" + (second.retrieval_cost_once ? ", " + money(second.retrieval_cost_once, second.currency) + " to retrieve once" : "") + "." : "") + tail; }
      $("advice").classList.remove("hidden");
    }).catch(function () { $("advice").classList.add("hidden"); });
  }

  // Placement: per-folder monthly cost and suggestions that can be carried out
  // after a confirmation that says what happens and what it saves.
  var ADVICE_IDLE_DAYS = 90;
  function approx(n, cur) { return n < 0.01 ? "less than 0.01 " + cur : "about " + money(n, cur); }
  function costText(c) { return Object.keys(c || {}).map(function (cur) { return approx(c[cur], cur); }).join(" + "); }
  function renderSuggestions(a) {
    var box = $("advice-suggestions"); box.innerHTML = "";
    (a.folders || []).forEach(function (f) {
      if (!f.idle_bytes || !Object.keys(f.idle_monthly || {}).length) { return; }
      box.appendChild(el("p", "muted small", "Folder " + f.folder + ": its idle files cost " + costText(f.idle_monthly) + " a month on its storages, the whole folder " + costText(f.monthly) + (f.unpriced_storages.length ? " (no price set for " + f.unpriced_storages.join(", ") + ")" : "") + "."));
    });
    (a.suggestions || []).forEach(function (s) {
      var row = el("div", "suggestion"); var b;
      if (s.kind === "cold-idle") {
        row.appendChild(el("span", "", s.folder + ": the blocks of " + s.files + " idle file" + (s.files === 1 ? "" : "s") + " (" + fmtBytes(s.bytes) + ") can move from " + s.move_from + " to cold storage " + s.move_to + ", saving " + costText(s.monthly_saving) + " a month."));
        b = el("button", "secondary", "Move to " + s.move_to);
      } else {
        row.appendChild(el("span", "", s.folder + ": " + s.files + " idle file" + (s.files === 1 ? "" : "s") + " (" + fmtBytes(s.bytes) + ") can be freed on this device; they stay on " + s.keep_on.join(", ") + "."));
        b = el("button", "secondary", "Free " + s.files + " file" + (s.files === 1 ? "" : "s"));
      }
      b.type = "button";
      b.onclick = function () { applySuggestion(s); };
      row.appendChild(b); box.appendChild(row);
    });
  }
  function applySuggestion(s) {
    if (s.kind === "cold-idle") { return applyMove(s); }
    var text = s.summary + (s.warnings.length ? " " + s.warnings.join(" ") : "");
    confirmBox(text, { title: "Free idle files of " + s.folder + "?", ok: "Free " + fmtBytes(s.bytes) }).then(function (yes) {
      if (!yes) { return; }
      busy(true); log("freeing idle files of " + s.folder);
      return api("POST", "/api/advice/apply", { id: s.id, idle_days: ADVICE_IDLE_DAYS }).then(function (r) {
        log(r.folder + ": " + r.files_freed + " file" + (r.files_freed === 1 ? "" : "s") + " freed (" + fmtBytes(r.bytes_freed) + ")" + (r.blocks_verified ? ", " + r.blocks_verified + " blocks verified first" : "") + (r.skipped.length ? "; " + r.skipped.length + " kept: " + r.skipped[0][1] : ""));
        busy(false); refreshStatus();
      });
    }).catch(function (e) { log("error: " + e.message); busy(false); });
  }

  // Moving idle files to cold storage: the confirmation states the copies
  // left, the change in the bill and what reading them back needs.
  function applyMove(s) {
    confirmBox(s.summary, { title: "Move idle files of " + s.folder + " to " + s.move_to + "?", ok: "Move " + fmtBytes(s.bytes) }).then(function (yes) {
      if (!yes) { return; }
      busy(true); log("moving idle files of " + s.folder + " to " + s.move_to);
      return api("POST", "/api/advice/apply", { id: s.id, idle_days: ADVICE_IDLE_DAYS }).then(function (r) {
        var m = r.moved || {};
        log(r.folder + ": " + (m.blocks_dropped || 0) + " block" + (m.blocks_dropped === 1 ? "" : "s") + " (" + fmtBytes(m.bytes_dropped || 0) + ") moved from " + m.from + " to " + m.to + (m.blocks_kept ? "; " + m.blocks_kept + " kept: " + m.kept[0][1] : ""));
        busy(false); refreshStatus();
      });
    }).catch(function (e) { log("error: " + e.message); busy(false); });
  }

  // Storage prices: one line per storage with its price and monthly cost, and a dialog to set them.
  function priceText(p) {
    var cur = p.currency ? " " + p.currency : "";
    var parts = [p.storage_per_gb_month != null ? p.storage_per_gb_month + cur + "/GB-month" : "storage price unknown"];
    if (p.egress_per_gb != null) { parts.push("egress " + p.egress_per_gb + cur + "/GB"); }
    if (p.retrieval_per_gb != null) { parts.push("retrieval " + p.retrieval_per_gb + cur + "/GB"); }
    if (p.minimum_storage_days != null) { parts.push("minimum " + p.minimum_storage_days + " days"); }
    return parts.join(", ") + (p.source ? " (" + p.source + ")" : "");
  }
  function loadStorageCosts() {
    api("GET", "/api/storage/costs").then(function (list) {
      list.forEach(function (e) {
        var li = null; $("storages").querySelectorAll("li").forEach(function (x) { if (x.dataset.storage === e.name) { li = x; } });
        if (!li || li.querySelector(".li-price")) { return; }
        li.querySelector(".li-body").appendChild(el("div", "li-sub li-price", (e.price ? priceText(e.price) : "No price set") + " · " + fmtBytes(e.bytes) + " stored" + (e.monthly_cost != null ? " · " + approx(e.monthly_cost, e.currency) + " a month" : "")));
        var acts = el("div", "li-actions"); var pb = el("button", "secondary", "Price and quota"); pb.type = "button"; pb.onclick = function () { editPrice(e); }; acts.appendChild(pb); li.appendChild(acts);
      });
    }).catch(function () {});
  }
  function editPrice(e) {
    var p = e.price || {};
    var v = function (x) { return x == null ? "" : String(x); };
    var q = storageQuotas[e.name] || {};
    var pool = e.kind === "pool" || e.carrier;
    var fields = [
      { name: "gb_month", label: "Storage per GB-month", value: v(p.storage_per_gb_month), placeholder: "0.006" },
      { name: "egress", label: "Egress per GB", value: v(p.egress_per_gb), placeholder: "0.01" },
      { name: "retrieval", label: "Retrieval per GB (cold classes)", value: v(p.retrieval_per_gb) },
      { name: "min_days", label: "Minimum storage days (cold classes)", value: v(p.minimum_storage_days) },
      { name: "currency", label: "Currency", value: p.currency || "", placeholder: "EUR" }
    ];
    if (!pool) {
      fields.push({ name: "quota", label: "Quota (most data Varsto keeps here)", value: q.quota_bytes != null ? String(q.quota_bytes / 1e9) + "GB" : "", placeholder: "1TB", hint: "Every device respects it and keeps 1 % free; blocks then go to your other storages or wait. Empty: no quota." });
      fields.push({ name: "quota_objects", label: "Most objects (optional)", type: "number", value: v(q.quota_objects) });
    }
    dialog({ title: "Prices and quota of " + e.name, text: "Prices are used for the monthly cost and the placement suggestions. Empty means unknown, not free." + (p.source ? " Now: " + p.source + "." : ""), fields: fields, ok: "Save", extra: "Clear my prices" }).then(function (r) {
      if (!r) { return; }
      var body = r.action === "extra" ? { name: e.name, clear: true } : { name: e.name, gb_month: r.values.gb_month, egress: r.values.egress, retrieval: r.values.retrieval, min_days: r.values.min_days, currency: r.values.currency };
      return api("POST", "/api/storage/price", body).then(function () {
        log("prices of " + e.name + " saved");
        if (pool || r.action === "extra") { return null; }
        var oldQ = q.quota_bytes != null ? String(q.quota_bytes / 1e9) + "GB" : "";
        if ((r.values.quota || "").trim() === oldQ && (r.values.quota_objects || "") === v(q.quota_objects)) { return null; }
        return api("POST", "/api/storage/quota", { name: e.name, bytes: (r.values.quota || "").trim(), objects: (r.values.quota_objects || "").trim() }).then(function () { log("quota of " + e.name + " saved"); });
      }).then(function () { refreshStatus(); });
    }).catch(function (err) { alertBox(err.message); });
  }

  // Quotas and drains on the storage rows: use against the quota, and a
  // drain's progress with its Stop button (/api/storage/quotas, /drains).
  var storageQuotas = {};
  function usageBar(percent, cls) { var b = el("div", "usage-bar" + (cls ? " " + cls : "")); var f = el("span"); f.style.width = Math.max(0, Math.min(100, percent || 0)) + "%"; b.appendChild(f); return b; }
  function rawSpan(text, cls) { var x = el("span", cls || null, text); x.setAttribute("data-no-i18n", ""); return x; }
  function loadStorageUsage() {
    Promise.all([api("GET", "/api/storage/quotas"), api("GET", "/api/storage/drains")]).then(function (r) {
      var drains = r[1]; storageQuotas = {};
      r[0].forEach(function (q) { storageQuotas[q.storage] = q; });
      $("storages").querySelectorAll("li").forEach(function (li) {
        var name = li.dataset.storage; var body = li.querySelector(".li-body"); if (!body) { return; }
        body.querySelectorAll(".li-usage").forEach(function (x) { x.remove(); });
        var q = storageQuotas[name];
        if (q && q.state !== "none") {
          var u = el("div", "li-sub li-usage");
          u.appendChild(usageBar(q.percent, q.state === "full" ? "bad" : q.state === "warning" ? "risk" : ""));
          u.appendChild(el("span", null, "Quota"));
          u.appendChild(rawSpan(fmtBytes(q.used_bytes) + " / " + (q.quota_bytes != null ? fmtBytes(q.quota_bytes) : q.used_objects + " / " + q.quota_objects) + " (" + (q.percent || 0) + " %)"));
          if (q.message) { u.appendChild(rawSpan(actTr(q.message), "usage-note " + (q.state === "full" ? "bad" : "risk"))); }
          body.appendChild(u);
        }
        var d = drains.filter(function (x) { return x.storage === name; })[0];
        var btn = li.querySelector("button.drain-btn");
        if (!d) { return; }
        var title = li.querySelector(".li-title");
        if (title && !title.querySelector(".drain-pill")) { var dp = pill(d.phase === "drained" ? "grey" : d.phase === "blocked" ? "bad" : "risk", d.phase === "drained" ? "drained" : d.phase === "blocked" ? "drain waiting" : "draining"); dp.classList.add("drain-pill"); title.appendChild(dp); }
        var w = el("div", "li-sub li-usage");
        w.appendChild(usageBar(d.percent, d.phase === "blocked" ? "risk" : ""));
        if (d.phase === "drained") { w.appendChild(el("span", null, "Drained: it holds nothing Varsto needs.")); } else {
          w.appendChild(el("span", null, "Drained so far"));
          w.appendChild(rawSpan(d.percent + " % · " + fmtBytes(d.bytes_left) + (d.eta_utc ? " · \u2248 " + new Date(d.eta_utc * 1000).toLocaleString() : "")));
          if (d.remove_when_empty) { w.appendChild(el("span", "muted", "removed when empty")); }
        }
        (d.phase === "drained" ? [] : d.blocked).forEach(function (b) { w.appendChild(rawSpan(actTr(b), "usage-note risk")); });
        if (d.last_error) { w.appendChild(rawSpan(d.last_error, "usage-note bad")); }
        body.appendChild(w);
        if (btn) { btn.textContent = d.phase === "drained" ? "Use again" : "Stop draining"; btn.title = ""; btn.onclick = function () { stopDrain(name, d.phase === "drained"); }; }
      });
    }).catch(function () {});
  }
  // Draining: show what it takes (bytes to move and where, egress, time at
  // the budget, whether every policy holds), then start it in the service.
  function drainStorage(name) {
    busy(true);
    api("GET", "/api/storage/drain-plan?name=" + enc(name)).then(function (p) {
      busy(false);
      if (p.records_blocked) { alertBox(actTr(p.records_blocked)); return null; }
      var money = function (c) { return Object.keys(c || {}).map(function (k) { return c[k].toFixed(2) + " " + k; }).join(" + "); };
      var facts = [
        ["Blocks on this storage", p.blocks + " · " + fmtBytes(p.bytes)],
        ["Only deleted (enough copies elsewhere)", String(p.blocks_drop_only)],
        ["Copied first, read back before deleting", p.blocks_to_copy + " · " + fmtBytes(p.bytes_to_copy) + (Object.keys(p.targets).length ? " \u2192 " + Object.keys(p.targets).map(function (t) { return t + " " + fmtBytes(p.targets[t]); }).join(", ") : "")],
        ["Read from this storage", fmtBytes(p.bytes_read_here) + (money(p.egress_cost) ? " · \u2248 " + money(p.egress_cost) : "")]
      ];
      if (money(p.early_deletion_cost)) { facts.push(["Minimum storage duration still billed", "\u2248 " + money(p.early_deletion_cost)]); }
      facts.push(["Policies", p.policy === "ok" ? actTr("Every folder's policy holds without it.") : p.blocks_blocked + " \u00d7 " + p.blocked.map(actTr).join("; ")]);
      (p.notes || []).forEach(function (n) { facts.push(["Note", actTr(n)]); });
      var checks = [["remove", "Remove the storage when it is empty", false]];
      if (p.cold) { checks.push(["cold", "Read from this cold storage (retrieval fees and restore delays apply)", false]); }
      return dialog({ title: "Drain storage " + name + "?", text: "Draining empties the storage onto your other storages in the background, without ever weakening a folder's policy: each block is copied and read back before its copy here is deleted, and blocks that cannot keep their policy elsewhere stay. Nothing new is written here meanwhile; it stays readable. Afterwards the storage holds nothing Varsto needs.", facts: facts, fields: [
        { name: "budget", label: "Most GB copied per day (empty: no limit)", type: "number", value: "", hint: "Limits egress costs; blocks that only need deleting do not count." },
        { name: "opts", label: "Options", checks: checks }
      ], ok: "Start draining" }).then(function (r) {
        if (!r) { return null; }
        var o = (r.values.opts || "").split(",");
        return api("POST", "/api/storage/drain", { name: name, budget_gb_per_day: r.values.budget, remove_when_empty: o.indexOf("remove") >= 0, confirm_cold_read: o.indexOf("cold") >= 0 }).then(function () { log("draining " + name + " started; the service moves its blocks after the next sync"); });
      });
    }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); return refreshStatus(); });
  }
  function stopDrain(name, drained) {
    dialog({ title: drained ? "Use " + name + " again?" : "Stop draining " + name + "?", text: "The storage takes new blocks again. Blocks already moved stay where they are now.", ok: drained ? "Use again" : "Stop draining" }).then(function (r) {
      if (!r) { return null; }
      return api("POST", "/api/storage/drain", { name: name, stop: true }).then(function () { log("draining " + name + " stopped"); });
    }).catch(function (e) { alertBox(e.message); }).then(function () { return refreshStatus(); });
  }

  // Backups (their own page): read-only snapshots of a directory of this
  // device, kept on storages only. Snapshots are listed and restored into a
  // directory the user names; they are never changed or deleted here.
  var backupsShown = null; // the backup whose snapshots are listed
  var backupsPoll = null;
  var backupList = [];
  var SCHEDULES = [["daily", "Daily"], ["weekly", "Weekly"], ["manual", "Only when I ask"]];
  function scheduleLabel(s) { for (var i = 0; i < SCHEDULES.length; i++) { if (SCHEDULES[i][0] === s) { return SCHEDULES[i][1]; } } return s || "–"; }
  function loadBackups() {
    fillBackupStorages();
    return api("GET", "/api/backups").then(renderBackups).catch(function (e) { log("backups: " + e.message); });
  }
  function fillBackupStorages(fresh) {
    var box = $("backupstorages"); var prev = {};
    if (!fresh) { box.querySelectorAll("input").forEach(function (i) { prev[i.value] = i.checked; }); }
    box.innerHTML = "";
    var list = ((lastStatus && lastStatus.storages) || []).filter(function (st) { return !st.carrier; });
    list.forEach(function (st) {
      var lab = el("label", "inline"); var c = el("input"); c.type = "checkbox"; c.name = "storage"; c.value = st.name;
      c.checked = prev[st.name] !== undefined ? prev[st.name] : true;
      lab.appendChild(c); var n = el("span", null, st.name); n.setAttribute("data-no-i18n", ""); lab.appendChild(n);
      if (st.cold) { lab.appendChild(pill("grey", "cold")); }
      box.appendChild(lab);
    });
    $("backupstorages-empty").classList.toggle("hidden", list.length > 0);
  }
  function renderBackups(list) {
    backupList = list;
    var tb = $("backups").querySelector("tbody"); tb.innerHTML = "";
    $("backups-empty").classList.toggle("hidden", list.length > 0);
    $("backups").classList.toggle("hidden", list.length === 0);
    list.forEach(function (b) {
      var tr = el("tr");
      function td(text, cls, label) { var d = el("td", cls, text); if (label) { d.dataset.label = label; } tr.appendChild(d); return d; }
      var nameCell = el("td"); var nm = el("span", null, b.name); nm.setAttribute("data-no-i18n", ""); nameCell.appendChild(nm);
      if (b.stopped) { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill("grey", "stopped")); }
      if (!b.this_device) { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill("accent", "other device")); }
      var sub = el("span", "sub", b.source_path + " · " + b.source_device); sub.title = b.source_path; sub.setAttribute("data-no-i18n", ""); nameCell.appendChild(sub);
      tr.appendChild(nameCell);
      td(b.snapshots, "num", "Snapshots");
      td(b.snapshot_requested ? "Taking a snapshot…" : b.latest_utc ? fmtWhen(b.latest_utc) : "None yet", "", "Latest snapshot");
      td(b.latest_utc ? fmtBytes(b.latest_bytes) : "–", "num", "Size");
      td(b.retention_days + " days", "", "Kept");
      td(b.this_device ? scheduleLabel(b.schedule) : "On the device it backs up", "", "Schedule");
      var act = el("td"); var menu = rowMenu(act, "backup:" + b.backup_id);
      var sn = el("button", "secondary", "Snapshots"); sn.type = "button"; sn.onclick = function () { showSnapshots(b.name); }; act.appendChild(sn);
      if (b.this_device && !b.stopped) { var tk = el("button", "secondary", "Take snapshot now"); tk.type = "button"; tk.onclick = function () { takeSnapshot(b.name); }; menu.appendChild(tk); }
      if (b.snapshots > 0) { var rs = el("button", "secondary", "Restore latest…"); rs.type = "button"; rs.onclick = function () { restoreSnapshot(b.name, "latest"); }; menu.appendChild(rs); }
      if (b.this_device && !b.stopped) { var se = el("button", "secondary", "Settings…"); se.type = "button"; se.onclick = function () { editBackup(b); }; menu.appendChild(se); }
      if (!b.stopped) { var sp = el("button", "secondary", "Stop…"); sp.type = "button"; sp.onclick = function () { stopBackup(b.name); }; menu.appendChild(sp); }
      menu.done();
      tr.appendChild(act); tb.appendChild(tr);
    });
    if (backupsShown && list.some(function (b) { return b.name === backupsShown; })) { showSnapshots(backupsShown, true); } else { backupsShown = null; $("backupsnaps").classList.add("hidden"); }
    // A requested snapshot is taken by the service: look again until it is.
    clearTimeout(backupsPoll);
    if (list.some(function (b) { return b.snapshot_requested; })) { backupsPoll = setTimeout(function () { if (currentPage === "backups") { loadBackups(); } }, 5000); }
  }
  // `refresh`: redraw the open list (after a reload) instead of toggling it.
  function showSnapshots(name, refresh) {
    var card = $("backupsnaps");
    if (!refresh && backupsShown === name && !card.classList.contains("hidden")) { backupsShown = null; card.classList.add("hidden"); return Promise.resolve(); }
    backupsShown = name;
    $("backupsnaps-name").textContent = name;
    if (!refresh) {
      // Shown at once, so the click is seen even while the service is busy.
      var tb0 = $("snapshots").querySelector("tbody"); tb0.innerHTML = "";
      var lr = el("tr"); var ld = el("td", "muted", "Loading…"); ld.colSpan = 6; lr.appendChild(ld); tb0.appendChild(lr);
      card.classList.remove("hidden");
      card.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
    return api("GET", "/api/backup/snapshots?backup=" + enc(name)).then(function (list) {
      if (backupsShown !== name) { return; }
      var tb = $("snapshots").querySelector("tbody"); tb.innerHTML = "";
      list.slice().reverse().forEach(function (sn) {
        var tr = el("tr");
        function td(text, cls, label) { var d = el("td", cls, text); if (label) { d.dataset.label = label; } tr.appendChild(d); }
        td(sn.seq, "num", "Number"); td(fmtWhen(sn.taken_utc), "", "Taken"); td(sn.files, "num", "Files"); td(fmtBytes(sn.bytes), "num", "Size"); td(fmtDate(sn.expires_utc), "", "Expires");
        var act = el("td"); var rb = el("button", "secondary", "Restore…"); rb.type = "button"; rb.onclick = function () { restoreSnapshot(name, String(sn.seq)); }; act.appendChild(rb); tr.appendChild(act);
        tb.appendChild(tr);
      });
      if (!list.length) { var tr = el("tr"); var d = el("td", "muted", "No snapshots yet"); d.colSpan = 6; tr.appendChild(d); tb.appendChild(tr); }
      $("backupsnaps").classList.remove("hidden");
    }).catch(function (e) { alertBox(e.message); });
  }
  function takeSnapshot(name) {
    busy(true);
    api("POST", "/api/backup/take", { backup: name, background: true }).then(function (r) {
      if (r.queued) { log("Snapshot of " + r.backup + " requested; it is taken in the background"); return; }
      log("Snapshot " + r.seq + " of " + r.backup + " taken: " + r.files + " files");
      if (r.skipped && r.skipped.length) { alertBox(r.skipped.length + " files could not be read and were left out: " + r.skipped.slice(0, 10).join(", ")); }
    }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); loadBackups(); });
  }
  function restoreSnapshot(name, which, overwrite, values) {
    var ask = values ? Promise.resolve({ values: values }) : dialog({
      title: "Restore a snapshot",
      text: "The files are written into the directory you name, which must be empty. Nothing is changed in the backed-up directory or in the snapshot.",
      fields: [
        { name: "to", label: "Restore into directory", placeholder: "/Users/me/Restored", required: true },
        { name: "paths", label: "Only these files or directories (optional)", placeholder: "Documents, Photos/2026", hint: "paths inside the snapshot, separated by commas" }
      ],
      ok: "Restore"
    });
    return ask.then(function (r) {
      if (!r) { return; }
      busy(true);
      return api("POST", "/api/backup/restore", { backup: name, snapshot: which, to: r.values.to, paths: r.values.paths || "", overwrite: !!overwrite }).then(function (x) {
        busy(false);
        log("Restored " + x.files_restored + " files of snapshot " + x.seq + " into " + x.to);
        if (x.unavailable && x.unavailable.length) { alertBox(x.unavailable.length + " files could not be restored: " + x.unavailable.slice(0, 10).join("; ")); }
      }, function (e) {
        busy(false);
        if (!overwrite && /not empty/.test(e.message)) {
          return confirmBox("The directory is not empty. Restore into it anyway, replacing files that have the same names?", { title: "Directory not empty", ok: "Restore anyway", danger: true }).then(function (yes) { if (yes) { return restoreSnapshot(name, which, true, r.values); } });
        }
        alertBox(e.message);
      });
    });
  }
  function editBackup(b) {
    dialog({
      title: "Backup settings",
      text: "A new retention applies to snapshots taken from now on; those already taken keep theirs.",
      fields: [
        { name: "retention_days", label: "Keep each snapshot (days)", type: "number", value: b.retention_days, required: true },
        { name: "schedule", label: "Schedule", options: SCHEDULES, value: b.schedule }
      ],
      ok: "Save"
    }).then(function (r) {
      if (!r) { return; }
      var days = parseInt(r.values.retention_days, 10);
      if (!(days > 0)) { alertBox("Keep each snapshot at least one day."); return; }
      var body = { backup: b.name, retention_days: days };
      if (SCHEDULES.some(function (x) { return x[0] === r.values.schedule; })) { body.schedule = r.values.schedule; }
      return api("POST", "/api/backup/set", body).then(loadBackups);
    }).catch(function (e) { alertBox(e.message); });
  }
  function stopBackup(name) {
    confirmBox("No more snapshots are taken. The snapshots kept are deleted as their time is up, and then the backup goes.", { title: "Stop this backup?", ok: "Stop backup", danger: true }).then(function (yes) {
      if (!yes) { return; }
      return api("POST", "/api/backup/stop", { backup: name }).then(function () { log("Backup stopped: " + name); return loadBackups(); });
    }).catch(function (e) { alertBox(e.message); });
  }
  $("addbackup").onsubmit = function (ev) {
    ev.preventDefault();
    var form = ev.target; var d = formData(form);
    var storages = []; var all = true;
    $("backupstorages").querySelectorAll("input").forEach(function (c) { if (c.checked) { storages.push(c.value); } else { all = false; } });
    if (!storages.length) { alertBox("Choose at least one storage."); return; }
    var days = parseInt(d.retention_days, 10);
    if (!(days > 0)) { alertBox("Keep each snapshot at least one day."); return; }
    busy(true);
    api("POST", "/api/backup", { name: d.name, path: d.path, retention_days: days, schedule: d.schedule, storages: all ? [] : storages, initial: true, background: true }).then(function (r) {
      // Back to a fresh form: the old name and directory would only be
      // refused as a duplicate.
      form.reset(); fillBackupStorages(true);
      log(r.queued ? "Backup added: " + d.name + "; its first snapshot is being taken in the background" : "Backup added: " + d.name);
      if (r.snapshot && r.snapshot.skipped && r.snapshot.skipped.length) { alertBox(r.snapshot.skipped.length + " files could not be read and were left out: " + r.snapshot.skipped.slice(0, 10).join(", ")); }
    }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); loadBackups(); });
  };

  // Import page: a folder of this device here; git-annex and cloud imports
  // are shown with their command (they run on the command line).
  var importCli = {
    annex: ["varsto import git-annex /path/to/repository", "Run it once for every disk that holds a clone of the repository: each run continues the same folder with what that disk has, and says which disk to insert next. Nothing is changed on the disks."],
    dropbox: ["rclone config create mydropbox dropbox\nvarsto import dropbox mydropbox:", "The first line signs in to Dropbox in your browser (once). Run the import again to bring changes over."],
    onedrive: ["rclone config create myonedrive onedrive\nvarsto import onedrive myonedrive:", "The first line signs in to OneDrive in your browser (once). Run the import again to bring changes over."],
    rclone: ["varsto import rclone remote:path", "Any remote set up in rclone (rclone config) works, Google Drive included."]
  };
  function importKind() {
    var k = $("import-kind").value; var cli = importCli[k];
    $("import-cli").classList.toggle("hidden", !cli);
    $("import-dir-fields").classList.toggle("hidden", !!cli);
    if (cli) { $("import-cli-cmd").textContent = cli[0]; $("import-cli-note").textContent = cli[1]; }
  }
  $("import-kind").onchange = importKind;
  $("import-where").onchange = function () { $("import-dest-label").classList.toggle("hidden", $("import-where").value !== "full"); };
  function loadImports() {
    return api("GET", "/api/import/status").then(renderImports).catch(function (e) { log("imports: " + e.message); });
  }
  function renderImports(list) {
    var tb = $("imports").querySelector("tbody"); tb.innerHTML = "";
    $("imports-empty").classList.toggle("hidden", list.length > 0);
    $("imports").classList.toggle("hidden", list.length === 0);
    list.forEach(function (s) {
      var tr = el("tr");
      var n = el("td"); var nm = el("span", null, s.folder); nm.setAttribute("data-no-i18n", ""); n.appendChild(nm); tr.appendChild(n);
      var src = el("td"); var sp = el("span", "sub", s.source); sp.setAttribute("data-no-i18n", ""); src.appendChild(sp); tr.appendChild(src);
      tr.appendChild(el("td", "num", String(s.files_total)));
      tr.appendChild(el("td", "num", String(s.files_awaiting)));
      tr.appendChild(el("td", "num", s.removed_files ? s.removed_files + " (" + fmtBytes(s.removed_bytes) + ")" : "0"));
      var act = el("td");
      if (s.kind === "dir") {
        var b = el("button", "secondary", "Remove safe files…"); b.type = "button";
        b.onclick = function () { cleanupImport(s.folder); };
        act.appendChild(b);
      }
      tr.appendChild(act); tb.appendChild(tr);
    });
  }
  function showWaiting(c) {
    var box = $("import-waiting"); box.innerHTML = "";
    $("import-waiting-box").classList.toggle("hidden", !c || !c.waiting_count);
    if (!c) { return; }
    c.waiting.forEach(function (w) {
      var li = el("li"); var p = el("span", null, showName(w.path)); p.setAttribute("data-no-i18n", ""); li.appendChild(p);
      li.appendChild(el("span", "sub", w.reason)); box.appendChild(li);
    });
  }
  function showCleanupPlan(folder, c) {
    $("import-cleanup").classList.toggle("hidden", !c || !c.eligible);
    showWaiting(c);
    if (!c || !c.eligible) { return; }
    $("import-cleanup-text").textContent = c.eligible + " file(s) (" + fmtBytes(c.eligible_bytes) + ") can be removed from " + c.source + " now.";
    $("import-cleanup-go").onclick = function () {
      confirmBox("Remove " + c.eligible + " file(s) (" + fmtBytes(c.eligible_bytes) + ") from " + c.source + "? Each one is checked once more first.", { title: "Remove source files?", ok: "Remove", danger: true }).then(function (yes) {
        if (!yes) { return; }
        busy(true);
        return api("POST", "/api/import/cleanup", { folder: folder, apply: true }).then(function (r) {
          log("Removed " + r.removed.length + " file(s) (" + fmtBytes(r.removed_bytes) + ") from the source");
          $("import-cleanup").classList.add("hidden"); showWaiting(r);
        }).then(function () { busy(false); loadImports(); }, function (e) { busy(false); throw e; });
      }).catch(function (e) { alertBox(e.message); });
    };
  }
  function cleanupImport(folder) {
    api("POST", "/api/import/cleanup", { folder: folder, apply: false }).then(function (c) {
      $("import-result").classList.remove("hidden");
      $("import-summary").innerHTML = "";
      if (!c.eligible) { $("import-summary").appendChild(el("li", null, "No source file can be removed yet.")); }
      showCleanupPlan(folder, c);
    }).catch(function (e) { alertBox(e.message); });
  }
  $("importform").onsubmit = function (ev) {
    ev.preventDefault();
    var d = formData(ev.target);
    if (!d.source) { alertBox("Choose the folder to import."); return; }
    if (d.where === "full" && !d.dest) { alertBox("Choose the directory for the copy."); return; }
    busy(true);
    api("POST", "/api/import/dir", { source: d.source, folder: d.folder, dest: d.where === "full" ? d.dest : "", selective: d.where !== "full", remove_source: !!d.remove_source }).then(function (r) {
      $("import-result").classList.remove("hidden");
      var ul = $("import-summary"); ul.innerHTML = "";
      ul.appendChild(el("li", null, "Imported " + r.imported_files + " file(s) (" + fmtBytes(r.imported_bytes) + ") into folder " + r.folder));
      if (r.already_ids) { ul.appendChild(el("li", null, r.already_ids + " file(s) were imported before")); }
      if (r.failed_count) { ul.appendChild(el("li", null, r.failed_count + " file(s) could not be read: " + r.failed.map(function (n) { return n.path; }).join(", "))); }
      if (r.skipped_count) { ul.appendChild(el("li", null, r.skipped_count + " item(s) not imported (links, special files, names Varsto cannot use): " + r.skipped.map(function (n) { return n.path; }).join(", "))); }
      if (r.kept_in_varsto_count) { ul.appendChild(el("li", null, r.kept_in_varsto_count + " file(s) were changed in Varsto and kept as they are")); }
      if (r.gone_at_source) { ul.appendChild(el("li", null, r.gone_at_source + " file(s) are gone from the source and kept in Varsto")); }
      showCleanupPlan(r.folder, r.cleanup);
      log("Imported into " + r.folder);
    }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); loadImports(); });
  };

  // Trash (its own page): files deleted on any device, kept for the trash
  // days and restorable on every device; the settings below the list.
  var trashItems = [], trashSelected = {}, trashStorageNow = "", trashStorages = [];
  function trashKey(i) { return i.folder_id + "/" + i.id; }
  function loadTrash() {
    // The storages for the settings: from the last status, or asked now (page opened first).
    var storages = lastStatus ? Promise.resolve(lastStatus) : api("GET", "/api/status");
    return Promise.all([api("GET", "/api/trash"), api("GET", "/api/trash/status"), storages]).then(function (r) {
      trashStorages = (r[2].storages || []).filter(function (x) { return !x.carrier; });
      trashItems = r[0]; renderTrashFolders(); renderTrash(); renderTrashStatus(r[1]);
    }).catch(function (e) { log("trash: " + e.message); });
  }
  function renderTrashFolders() {
    var sel = $("trashfolder"); var cur = sel.value; sel.innerHTML = "";
    var all = el("option", null, "All folders"); all.value = ""; sel.appendChild(all);
    var names = {}; trashItems.forEach(function (i) { names[i.folder] = true; });
    Object.keys(names).sort().forEach(function (n) { var o = el("option", null, n); o.value = n; o.setAttribute("data-no-i18n", ""); sel.appendChild(o); });
    sel.value = names[cur] ? cur : "";
  }
  function trashShown() {
    var q = $("trashsearch").value.trim().toLowerCase(); var f = $("trashfolder").value;
    return trashItems.filter(function (i) { return (!f || i.folder === f) && (!q || (i.folder + "/" + i.path).toLowerCase().indexOf(q) >= 0); });
  }
  function trashPicked() { return trashItems.filter(function (i) { return trashSelected[trashKey(i)]; }); }
  function trashButtons() {
    var n = trashPicked().length;
    $("trashrestore").disabled = n === 0; $("trashpurge").disabled = n === 0;
    $("trashcount").textContent = n ? n + " selected" : "";
    var shown = trashShown();
    $("trashall").checked = shown.length > 0 && shown.every(function (i) { return trashSelected[trashKey(i)]; });
  }
  function renderTrash() {
    var list = trashShown();
    var tb = $("trashlist").querySelector("tbody"); tb.innerHTML = "";
    var none = trashItems.length === 0;
    $("trash-empty").classList.toggle("hidden", !none);
    $("trashlist").classList.toggle("hidden", none);
    $("trashtools").classList.toggle("hidden", none);
    list.forEach(function (i) {
      var tr = el("tr");
      // Phone rows show the column names from data-label: in the page's language.
      function td(text, cls, label) { var d = el("td", cls, text); if (label) { d.dataset.label = actTr(label); } tr.appendChild(d); return d; }
      var c = el("td"); var cb = el("input"); cb.type = "checkbox"; cb.checked = !!trashSelected[trashKey(i)]; cb.setAttribute("aria-label", "Select");
      cb.onchange = function () { if (cb.checked) { trashSelected[trashKey(i)] = true; } else { delete trashSelected[trashKey(i)]; } trashButtons(); };
      c.appendChild(cb); tr.appendChild(c);
      var p = el("td"); p.dataset.label = actTr("Path"); var nm = el("span", null, i.path); nm.setAttribute("data-no-i18n", ""); p.appendChild(nm);
      if (i.cold_only) { p.appendChild(document.createTextNode(" ")); p.appendChild(pill("grey", "cold")); }
      if (i.local_copy) { p.appendChild(document.createTextNode(" ")); p.appendChild(pill("accent", "on this device")); }
      var sub = el("span", "sub", i.folder); sub.setAttribute("data-no-i18n", ""); p.appendChild(sub);
      tr.appendChild(p);
      td(fmtBytes(i.size), "num", "Size");
      td(fmtWhen(i.deleted_utc), "", "Deleted");
      td(i.deleted_by, "", "By").setAttribute("data-no-i18n", "");
      td(fmtDate(i.expires_utc), "", "Expires");
      var act = el("td"); var rb = el("button", "secondary", "Restore…"); rb.type = "button"; rb.onclick = function () { restoreTrash([i]); }; act.appendChild(rb);
      var menu = rowMenu(act, "trash:" + trashKey(i));
      var db = el("button", "secondary", "Delete permanently…"); db.type = "button"; db.onclick = function () { purgeTrash([i]); }; menu.appendChild(db);
      menu.done();
      tr.appendChild(act); tb.appendChild(tr);
    });
    if (!none && !list.length) { var tr = el("tr"); var d = el("td", "muted", "Nothing in the trash matches"); d.colSpan = 7; tr.appendChild(d); tb.appendChild(tr); }
    trashButtons();
  }
  function renderTrashStatus(st) {
    var f = $("trashsettings");
    if (document.activeElement !== f.days) { f.days.value = st.days; }
    var sel = $("trashstorage"); sel.innerHTML = "";
    var no = el("option", null, "None: deleted files stay where they are"); no.value = ""; sel.appendChild(no);
    trashStorages.forEach(function (x) {
      var o = el("option", null, x.name + (x.cold ? " (" + actTr("cold") + ")" : "")); o.value = x.name; o.setAttribute("data-no-i18n", ""); sel.appendChild(o);
    });
    if (st.storage && !sel.querySelector("option[value='" + CSS.escape(st.storage) + "']")) { var o = el("option", null, st.storage); o.value = st.storage; o.setAttribute("data-no-i18n", ""); sel.appendChild(o); }
    sel.value = st.storage || ""; trashStorageNow = st.storage || "";
    var dl = $("trashfacts"); dl.innerHTML = "";
    function fact(label, value) { dl.appendChild(el("dt", null, label)); var dd = el("dd", null, value); dd.setAttribute("data-no-i18n", ""); dl.appendChild(dd); }
    fact("In the trash", st.entries + " · " + fmtBytes(st.bytes));
    var where = Object.keys(st.by_storage || {}).map(function (n) { return n + " " + fmtBytes(st.by_storage[n]); });
    if (where.length) { fact("Kept on", where.join(", ")); }
    var fd = Object.keys(st.folder_days || {}).map(function (n) { return n + " " + st.folder_days[n]; });
    if (fd.length) { fact("Folders with their own days", fd.join(", ")); }
    if (st.local_copies) { fact("Copies on this device", st.local_copies + " · " + fmtBytes(st.local_copy_bytes)); }
    if (st.next_expiry_utc) { fact("Next expiry", fmtDate(st.next_expiry_utc)); }
    fact("Last cleanup", fmtWhen(st.last_upkeep_utc));
    var notes = (st.notes || []).slice(); if (st.drops_waiting) { notes.push(st.drops_waiting + " blocks wait for the cold storage's minimum storage time before they are deleted"); }
    $("trashnotes").textContent = notes.join(" ");
  }
  function trashByFolder(items) { var g = {}; items.forEach(function (i) { (g[i.folder] = g[i.folder] || []).push(i.path); }); return g; }
  function restoreTrash(items) {
    if (!items.length) { return; }
    dialog({
      title: items.length === 1 ? "Restore " + items[0].path + "?" : "Restore " + items.length + " files?",
      text: "Each file goes back where it was. If that name is taken now, it comes back as \"name (restored)\": nothing is overwritten. The restored files sync to your other devices.",
      fields: [{ name: "to", label: "Into another directory of the folder (optional)", placeholder: "Restored", hint: "empty: the original place" }],
      ok: "Restore"
    }).then(function (r) {
      if (!r) { return; }
      var to = (r.values.to || "").trim(); var groups = trashByFolder(items); var done = 0;
      busy(true);
      var chain = Promise.resolve();
      Object.keys(groups).forEach(function (folder) {
        chain = chain.then(function () {
          return api("POST", "/api/trash/restore-plan", { folder: folder, paths: groups[folder], to: to });
        }).then(function (p) {
          if (!p.cold_storages.length) { return false; }
          var text = fmtBytes(p.cold_bytes) + " of it is kept only on cold storage " + p.cold_storages.join(", ") + ". Reading it back starts a retrieval, which your provider bills" + (p.read_cost ? " (about " + p.read_cost + ")" : "") + " and which can take hours.";
          return dialog({ title: "Read from cold storage?", text: text, ok: "Read cold storage", danger: true }).then(function (x) { if (!x) { throw new Error("cancelled"); } return true; });
        }).then(function (cold) {
          return api("POST", "/api/trash/restore", { folder: folder, paths: groups[folder], to: to, confirm_cold_read: cold });
        }).then(function (x) {
          done += x.restored.length;
          if (x.unavailable && x.unavailable.length) { alertBox(x.unavailable.length + " files could not be restored: " + x.unavailable.slice(0, 10).join("; ")); }
        });
      });
      return chain.then(function () { log("Restored " + done + " files from the trash"); }, function (e) { if (e.message !== "cancelled") { alertBox(e.message); } })
        .then(function () { busy(false); trashSelected = {}; loadTrash(); });
    });
  }
  function purgeTrash(items) {
    if (!items.length) { return; }
    var text = items.length === 1 ? items[0].path + " is deleted for good, from every device and storage. It cannot be restored afterwards." : items.length + " files are deleted for good, from every device and storage. They cannot be restored afterwards.";
    confirmBox(text, { title: "Delete permanently?", ok: "Delete permanently", danger: true }).then(function (yes) {
      if (!yes) { return; }
      var groups = trashByFolder(items); var n = 0;
      busy(true);
      var chain = Promise.resolve();
      Object.keys(groups).forEach(function (folder) {
        chain = chain.then(function () { return api("POST", "/api/trash/purge", { folder: folder, paths: groups[folder] }); }).then(function (x) { n += x.entries; });
      });
      return chain.then(function () { log("Deleted " + n + " files permanently"); }, function (e) { alertBox(e.message); })
        .then(function () { busy(false); trashSelected = {}; loadTrash(); });
    });
  }
  $("trashsearch").addEventListener("input", renderTrash);
  $("trashfolder").addEventListener("change", renderTrash);
  $("trashall").onchange = function () { var on = $("trashall").checked; trashShown().forEach(function (i) { if (on) { trashSelected[trashKey(i)] = true; } else { delete trashSelected[trashKey(i)]; } }); renderTrash(); };
  $("trashrestore").onclick = function () { restoreTrash(trashPicked()); };
  $("trashpurge").onclick = function () { purgeTrash(trashPicked()); };
  $("trashempty").onclick = function () {
    var word = actTr("empty");
    dialog({ title: "Empty the trash?", text: "Every file in the trash (" + trashItems.length + ") is deleted for good, from every device and storage. This cannot be undone.", ok: "Empty trash", danger: true, confirmText: word }).then(function (r) {
      if (!r) { return; }
      busy(true);
      return api("POST", "/api/trash/purge", { all: true }).then(function (x) { log("Trash emptied: " + x.entries + " files deleted permanently"); }, function (e) { alertBox(e.message); })
        .then(function () { busy(false); trashSelected = {}; loadTrash(); });
    });
  };
  $("trashsettings").onsubmit = function (ev) {
    ev.preventDefault();
    var d = formData(ev.target); var days = parseInt(d.days, 10);
    if (!(days >= 1 && days <= 3650)) { alertBox("Keep deleted files from 1 to 3650 days."); return; }
    // The storage is sent only when it changed: setting one moves the trash there.
    var body = { days: days };
    if (d.storage !== trashStorageNow) { if (d.storage) { body.storage = d.storage; } else { body.no_storage = true; } }
    busy(true);
    api("POST", "/api/trash/set", body).then(function (st) { renderTrashStatus(st); log("Trash settings saved"); }, function (e) { alertBox(e.message); })
      .then(function () { busy(false); loadTrash(); });
  };

  // Version history: the versions of the selected file (Files page details)
  // and the settings card beside the trash settings.
  var versionsFor = "";
  function restoredName(path) {
    var slash = path.lastIndexOf("/"); var dir = path.slice(0, slash + 1); var name = path.slice(slash + 1);
    var dot = name.lastIndexOf(".");
    return dir + (dot > 0 ? name.slice(0, dot) + " (restored)" + name.slice(dot) : name + " (restored)");
  }
  function loadVersions(folder, f) {
    var key = folder + "/" + f.path; versionsFor = key;
    var box = $("fd-history"); var ul = $("fd-versions"); var note = $("fd-history-note");
    api("GET", "/api/history?folder=" + enc(folder) + "&path=" + enc(f.path)).then(function (h) {
      if (versionsFor !== key) { return; }
      ul.innerHTML = ""; box.classList.remove("hidden");
      // One sentence at a time, so it is translated as a whole.
      var msg = h.days === null ? "Version history is off for this folder: no new versions are kept." : h.versions.length ? "" : "No earlier versions";
      note.textContent = msg; note.classList.toggle("hidden", !msg);
      h.versions.forEach(function (v) {
        var li = el("li"); var body = el("div", "li-body");
        var when = el("div", null, fmtWhen(v.replaced_utc)); when.setAttribute("data-no-i18n", ""); body.appendChild(when);
        var by = v.author || v.replaced_by;
        var sub = el("div", "li-sub", fmtBytes(v.size) + " · " + by + (v.new_bytes < v.size ? " · " + actTr("own changes") + " " + fmtBytes(v.new_bytes) : ""));
        sub.setAttribute("data-no-i18n", ""); body.appendChild(sub);
        if (v.cold_only) { body.appendChild(pill("grey", "cold")); }
        li.appendChild(body);
        var rb = el("button", "secondary", "Restore…"); rb.type = "button"; rb.onclick = function () { restoreVersion(folder, f.path, v, false); }; li.appendChild(rb);
        var menu = rowMenu(li, "version:" + v.id);
        var cb = el("button", "secondary", "Restore as a copy…"); cb.type = "button"; cb.onclick = function () { restoreVersion(folder, f.path, v, true); }; menu.appendChild(cb);
        menu.done();
        ul.appendChild(li);
      });
    }).catch(function (e) { if (versionsFor === key) { box.classList.add("hidden"); } log("versions: " + e.message); });
  }
  function restoreVersion(folder, path, v, copy) {
    var when = fmtWhen(v.replaced_utc);
    var ask = copy
      ? dialog({ title: "Restore as a copy?", text: "The version from " + when + " is written as a new file beside the current one. Nothing is overwritten.", fields: [{ name: "as", label: "New name", value: restoredName(path).split("/").pop(), required: true }], ok: "Restore" })
      : dialog({ title: "Restore this version?", text: "The version from " + when + " becomes the current " + path + ". The current version is kept in the versions, so nothing is lost. The change syncs to your other devices.", ok: "Restore" });
    ask.then(function (r) {
      if (!r) { return; }
      var body = { folder: folder, path: path, version: v.id };
      if (copy) { body.as = (r.values.as || "").trim(); if (!body.as) { return; } }
      busy(true);
      return api("POST", "/api/history/restore-plan", body).then(function (p) {
        if (!p.cold_storages.length) { return false; }
        var text = fmtBytes(p.cold_bytes) + " of it is kept only on cold storage " + p.cold_storages.join(", ") + ". Reading it back starts a retrieval, which your provider bills" + (p.read_cost ? " (about " + p.read_cost + ")" : "") + " and which can take hours.";
        return dialog({ title: "Read from cold storage?", text: text, ok: "Read cold storage", danger: true }).then(function (x) { if (!x) { throw new Error("cancelled"); } return true; });
      }).then(function (cold) {
        body.confirm_cold_read = cold;
        return api("POST", "/api/history/restore", body);
      }).then(function (x) { log("Restored the version of " + x.path + " to " + x.to); }, function (e) { if (e.message !== "cancelled") { alertBox(e.message); } })
        .then(function () { busy(false); loadFiles(); });
    });
  }
  var historyFolderDays = {};
  function loadHistorySettings() {
    return Promise.all([api("GET", "/api/history/status"), api("GET", "/api/folders")]).then(function (r) {
      renderHistoryStatus(r[0], r[1]);
    }).catch(function (e) { log("history: " + e.message); });
  }
  function historyModeShown() {
    var f = $("historysettings"); var picked = !!f.folder.value; var own = f.mode.value === "days";
    $("historymode-label").classList.toggle("hidden", !picked);
    $("historyfolderdays-label").classList.toggle("hidden", !picked || !own);
    f.days.disabled = !f.on.checked;
  }
  function renderHistoryStatus(st, folders) {
    var f = $("historysettings");
    historyFolderDays = st.folder_days || {};
    if (document.activeElement !== f.days) { f.days.value = st.days || 90; }
    f.on.checked = st.days > 0;
    var sel = $("historyfolder"); var cur = sel.value; sel.innerHTML = "";
    var none = el("option", null, "No folder"); none.value = ""; sel.appendChild(none);
    (folders || []).forEach(function (x) { var o = el("option", null, x.name); o.value = x.name; o.setAttribute("data-no-i18n", ""); sel.appendChild(o); });
    sel.value = cur; if (sel.value !== cur) { sel.value = ""; }
    var dl = $("historyfacts"); dl.innerHTML = "";
    function fact(label, value) { dl.appendChild(el("dt", null, label)); var dd = el("dd", null, value); dd.setAttribute("data-no-i18n", ""); dl.appendChild(dd); }
    fact("Earlier versions", st.versions + " · " + fmtBytes(st.extra_bytes));
    (st.folders || []).filter(function (x) { return x.versions > 0 || x.days === null; }).forEach(function (x) {
      fact(x.folder, x.days === null ? actTr("off") : x.versions + " · " + fmtBytes(x.extra_bytes));
    });
    var where = Object.keys(st.by_storage || {}).map(function (n) { return n + " " + fmtBytes(st.by_storage[n]); });
    if (where.length) { fact("Kept on", where.join(", ")); }
    pickHistoryFolder();
  }
  function pickHistoryFolder() {
    var f = $("historysettings"); var d = historyFolderDays[f.folder.value];
    f.mode.value = d === undefined ? "vault" : d === 0 ? "off" : "days";
    f.folderdays.value = d ? d : "";
    historyModeShown();
  }
  $("historyfolder").addEventListener("change", pickHistoryFolder);
  $("historymode").addEventListener("change", historyModeShown);
  $("historysettings").on.addEventListener("change", historyModeShown);
  $("historysettings").onsubmit = function (ev) {
    ev.preventDefault();
    var d = formData(ev.target); var days = parseInt(d.days, 10);
    if (d.on && !(days >= 1 && days <= 3650)) { alertBox("Keep versions from 1 to 3650 days."); return; }
    var calls = [d.on ? { days: days } : { off: true }];
    if (d.folder) {
      if (d.mode === "vault") { calls.push({ folder: d.folder, days: 0 }); }
      else if (d.mode === "off") { calls.push({ folder: d.folder, off: true }); }
      else {
        var fd = parseInt(d.folderdays, 10);
        if (!(fd >= 1 && fd <= 3650)) { alertBox("Keep versions from 1 to 3650 days."); return; }
        calls.push({ folder: d.folder, days: fd });
      }
    }
    busy(true);
    var chain = Promise.resolve();
    calls.forEach(function (c) { chain = chain.then(function () { return api("POST", "/api/history/set", c); }); });
    chain.then(function () { log("Version history settings saved"); }, function (e) { alertBox(e.message); })
      .then(function () { busy(false); loadHistorySettings(); });
  };

  // Automatic verification (Policies page): status line, run now, schedule.
  var autoVerify = null;
  function fmtWhen(t) { return t ? new Date(t * 1000).toLocaleString() : "never"; }
  function renderAutoVerify(v) {
    if (!v) { return; }
    autoVerify = v; var s = v.schedule; var parts = [];
    parts.push(s.enabled ? "On: every " + s.interval_hours + " h, up to " + s.max_blocks + " blocks or " + Math.round(s.max_bytes / 1048576) + " MiB per run" : "Off");
    if (v.last_run_utc) {
      var r = v.last;
      parts.push("last run " + fmtWhen(v.last_run_utc) + (r ? ": " + r.blocks_verified + " block" + (r.blocks_verified === 1 ? "" : "s") + " verified" + (r.left_for_next_run ? ", " + r.left_for_next_run + " left for the next run" : "") + (r.corrupt.length ? ", " + r.corrupt.length + " corrupt" : "") + (r.missing.length ? ", " + r.missing.length + " missing" : "") : ""));
    } else { parts.push("not run yet"); }
    if (v.last_error) { parts.push("last error: " + v.last_error); }
    if (s.enabled) { parts.push("next run " + (v.last_run_utc ? fmtWhen(v.next_run_utc) : "at the next sync")); }
    $("av-text").textContent = parts.join(" · ");
    $("av-toggle").textContent = s.enabled ? "Turn off" : "Turn on";
  }
  function loadAutoVerify() { api("GET", "/api/verify").then(renderAutoVerify).catch(function () {}); }
  $("av-run").onclick = function () {
    busy(true); log("automatic verification started");
    api("POST", "/api/verify/run", {}).then(function (r) {
      var x = r.report; log("verification: " + x.blocks_verified + " blocks verified of " + x.due + " due, " + fmtBytes(x.bytes_downloaded) + " downloaded" + (x.corrupt.length ? ", CORRUPT: " + x.corrupt.join(", ") : "") + (x.missing.length ? ", MISSING: " + x.missing.join(", ") : ""));
      renderAutoVerify(r.status); busy(false); refreshStatus();
    }).catch(function (e) { log("verification failed: " + e.message); busy(false); });
  };
  $("av-toggle").onclick = function () {
    var on = !(autoVerify && autoVerify.schedule.enabled);
    api("POST", "/api/verify", { enabled: on }).then(renderAutoVerify).catch(function (e) { log("error: " + e.message); });
  };
  $("av-settings").onclick = function () {
    var s = (autoVerify || {}).schedule || {};
    dialog({ title: "Automatic verification", text: "A run downloads at most this much from your storages; egress fees may apply.", fields: [
      { name: "interval_hours", label: "Hours between runs", type: "number", value: s.interval_hours },
      { name: "max_mib", label: "Most MiB per run", type: "number", value: s.max_bytes ? Math.round(s.max_bytes / 1048576) : "" },
      { name: "max_blocks", label: "Most blocks per run", type: "number", value: s.max_blocks }
    ], ok: "Save" }).then(function (r) {
      if (!r) { return; }
      var n = function (x) { var v = parseInt(x, 10); return isNaN(v) ? undefined : v; };
      return api("POST", "/api/verify", { interval_hours: n(r.values.interval_hours), max_mib: n(r.values.max_mib), max_blocks: n(r.values.max_blocks) }).then(renderAutoVerify);
    }).catch(function (e) { log("error: " + e.message); });
  };

  // Automatic repair (Policies page): "N copies repaired, M could not be repaired: why".
  function renderRepair(v) {
    if (!v) { return; }
    var parts = []; var r = v.last;
    if (v.last_run_utc && r) {
      parts.push("last run " + fmtWhen(v.last_run_utc) + ": " + r.repaired.length + " cop" + (r.repaired.length === 1 ? "y" : "ies") + " repaired");
    } else { parts.push("Nothing has needed repair yet"); }
    if (v.total_repaired) { parts.push(v.total_repaired + " repaired in all"); }
    var losses = v.open_losses || [];
    if (losses.length) { parts.push(losses.length + " could not be repaired"); }
    var waiting = v.queued - losses.length;
    if (waiting > 0) { parts.push(waiting + " waiting"); }
    if (v.last_error) { parts.push("last error: " + v.last_error); }
    $("ar-text").textContent = parts.join(" · ");
    var ul = $("ar-losses"); ul.innerHTML = "";
    losses.forEach(function (l) { ul.appendChild(el("li", "bad", l.folder + ": block " + l.object + " on " + l.storage + " (" + l.kind + "): " + l.reason)); });
    $("ar-cold").classList.toggle("hidden", !losses.some(function (l) { return l.reason.indexOf("cold storage") >= 0; }));
  }
  function loadRepair() { api("GET", "/api/repair").then(renderRepair).catch(function () {}); }
  function runRepair(body, what) {
    busy(true); log(what + " started");
    api("POST", "/api/repair", body).then(function (r) {
      var x = r.report;
      log(what + ": " + x.repaired.length + " of " + x.found + " damaged copies " + (x.dry_run ? "would be repaired" : "repaired") + (x.already_intact ? ", " + x.already_intact + " already intact" : "") + (x.unrepairable.length ? ", " + x.unrepairable.length + " could not be repaired" : ""));
      x.repaired.forEach(function (c) { log("  " + c.object + " on " + c.storage + ": from " + c.source); });
      x.unrepairable.forEach(function (u) { log("  NOT REPAIRED " + u.object + " on " + u.storage + ": " + u.reason); });
      renderRepair(r.status); busy(false); refreshStatus();
    }).catch(function (e) { log(what + " failed: " + e.message); busy(false); });
  }
  $("ar-run").onclick = function () { runRepair({}, "repair"); };
  $("ar-preview").onclick = function () { runRepair({ dry_run: true }, "repair preview"); };
  $("ar-cold").onclick = function () {
    dialog({ title: "Repair from cold storage", text: "Reading a cold storage starts a retrieval, which your provider may bill and which can take hours. Read it to repair the copies that exist only there?", ok: "Read cold storage" }).then(function (r) {
      if (r) { runRepair({ from_cold: true }, "repair from cold storage"); }
    }).catch(function (e) { log("error: " + e.message); });
  };

  // Bit-rot check (Policies page): status, damaged files, run now, schedule.
  var scrubStatus = null;
  function renderScrub(v) {
    if (!v) { return; }
    scrubStatus = v; var s = v.schedule; var parts = []; var r = v.last;
    parts.push(s.enabled ? "On: everything is checked within " + s.scrub_days + " days, up to " + Math.round(s.max_local_bytes / 1048576) + " MiB from this device's disks and " + Math.round(s.max_remote_bytes / 1048576) + " MiB from remote storages per run" : "Off");
    if ((s.cold || []).length) { parts.push("cold storages included: " + s.cold.join(", ")); }
    if (v.last_run_utc && r) {
      parts.push("last run " + fmtWhen(r.finished_utc || v.last_run_utc) + ": " + (r.objects_checked + r.cache_checked) + " objects and " + r.files_checked + " files checked, " + (r.corrupt.length + r.missing.length + r.damaged_files.length + r.cache_dropped) + " problems found");
    } else { parts.push("not run yet"); }
    if (v.totals && v.totals.problems_found) { parts.push(v.totals.problems_found + " problems found and " + v.totals.files_restored + " files restored in all"); }
    if (v.last_error) { parts.push("last error: " + v.last_error); }
    if (s.enabled) { parts.push(v.last_run_utc ? "next run " + fmtWhen(v.next_run_utc) : "next run at the next sync"); }
    var box = $("sc-text"); box.innerHTML = "";
    parts.forEach(function (p, i) { if (i) { box.appendChild(document.createTextNode(" · ")); } box.appendChild(el("span", "", p)); });
    var ul = $("sc-files"); ul.innerHTML = "";
    (v.unrestored || []).forEach(function (d) { ul.appendChild(el("li", "bad", d.folder + ": " + d.path + " is damaged on disk and waits for a good copy")); });
    ((r && r.damaged_files) || []).filter(function (d) { return d.restored; }).forEach(function (d) { ul.appendChild(el("li", "", d.folder + ": " + d.path + " was damaged on disk; moved to " + d.moved_to + " and the synced version restored")); });
    $("sc-toggle").textContent = s.enabled ? "Turn off" : "Turn on";
  }
  function loadScrub() { api("GET", "/api/scrub").then(renderScrub).catch(function () {}); }
  $("sc-run").onclick = function () {
    busy(true); log("bit-rot check started");
    api("POST", "/api/scrub/run", {}).then(function (r) {
      var x = r.report;
      log("bit-rot check: " + (x.objects_checked + x.cache_checked) + " objects and " + x.files_checked + " files checked, " + (x.corrupt.length + x.missing.length + x.damaged_files.length + x.cache_dropped) + " problems found");
      x.corrupt.forEach(function (c) { log("  CORRUPT " + c); });
      x.missing.forEach(function (c) { log("  MISSING " + c); });
      renderScrub(r.status); loadRepair(); busy(false); refreshStatus();
    }).catch(function (e) { log("bit-rot check failed: " + e.message); busy(false); });
  };
  $("sc-toggle").onclick = function () {
    var on = !(scrubStatus && scrubStatus.schedule.enabled);
    api("POST", "/api/scrub", { enabled: on }).then(renderScrub).catch(function (e) { log("error: " + e.message); });
  };
  $("sc-settings").onclick = function () {
    var s = (scrubStatus || {}).schedule || {};
    dialog({ title: "Bit-rot check", text: "Everything is re-read at least once in this period. A run reads at most this much; remote storages may bill the downloads.", fields: [
      { name: "scrub_days", label: "Days to check everything", type: "number", value: s.scrub_days },
      { name: "interval_hours", label: "Hours between runs", type: "number", value: s.interval_hours },
      { name: "local_mib", label: "Most MiB per run from this device's disks", type: "number", value: s.max_local_bytes ? Math.round(s.max_local_bytes / 1048576) : "" },
      { name: "remote_mib", label: "Most MiB per run from remote storages", type: "number", value: s.max_remote_bytes ? Math.round(s.max_remote_bytes / 1048576) : "" }
    ], ok: "Save" }).then(function (r) {
      if (!r) { return; }
      var n = function (x) { var v = parseInt(x, 10); return isNaN(v) ? undefined : v; };
      return api("POST", "/api/scrub", { scrub_days: n(r.values.scrub_days), interval_hours: n(r.values.interval_hours), local_mib: n(r.values.local_mib), remote_mib: n(r.values.remote_mib) }).then(renderScrub);
    }).catch(function (e) { log("error: " + e.message); });
  };

  // Disk pools: one card per pool with its disks (attached or away), from /api/disks.
  function diskAction(path, body, verb) {
    busy(true); log(verb + " " + body.label + " started");
    return api("POST", path, body).then(function (r) {
      if (r.message) { log(r.message); }
      else if (r.bytes_checked !== undefined) { log(body.label + ": checked " + fmtBytes(r.bytes_checked) + ", " + r.bad.length + " bad, " + fmtBytes(r.bytes_removed) + " removed, " + fmtBytes(r.bytes_added) + " added" + (r.adopted ? ", " + r.adopted + " objects adopted" : "")); }
      else if (r.retired) { log(body.label + " retired; " + r.objects_only_here + " object" + (r.objects_only_here === 1 ? "" : "s") + " exist only on it"); }
    }).catch(function (e) { log(verb + " failed: " + e.message); alertBox(e.message); }).then(function () { busy(false); return refreshStatus(); });
  }
  function renderPools(storages) {
    var pools = storages.filter(function (st) { return st.kind === "pool"; });
    var box = $("pools"); box.innerHTML = "";
    var sel = $("diskpool"); sel.innerHTML = "";
    pools.forEach(function (p) { var o = document.createElement("option"); o.value = p.name; o.textContent = p.name; sel.appendChild(o); });
    $("adddisk").classList.toggle("hidden", pools.length === 0);
    if (!pools.length) { return; }
    api("GET", "/api/disks").then(function (disks) {
      pools.forEach(function (p) {
        var card = el("div", "card pool-card");
        var head = el("div", "card-head"); var title = el("h2", "card-title", "Pool " + p.name); title.appendChild(pill("grey", p.place || "home")); head.appendChild(title);
        var mine = disks.filter(function (d) { return d.pool === p.name; });
        var attached = mine.filter(function (d) { return d.attached; }).length;
        head.appendChild(el("span", "muted small", mine.length + " disk" + (mine.length === 1 ? "" : "s") + ", " + attached + " attached"));
        card.appendChild(head);
        if (!mine.length) { card.appendChild(el("p", "muted small", "No disks yet. Mount a disk and add it below; on the command line: varsto disk add <mount-path> --pool " + p.name + " --label <label>")); }
        var sug = el("div", "disk-suggest"); sug.dataset.suggestFor = p.name; card.appendChild(sug);
        if (mine.length) { card.appendChild(diskTable(mine)); }
        var grp = el("div", "pool-group"); grp.dataset.groupFor = p.name; card.appendChild(grp);
        box.appendChild(card);
      });
      renderDiskSuggest(pools);
      return api("GET", "/api/disk/groups").then(function (groups) {
        groups.forEach(function (g) {
          var c = document.querySelector('.pool-group[data-group-for="' + (window.CSS && CSS.escape ? CSS.escape(g.pool) : g.pool) + '"]');
          if (!c) { return; }
          var line = g.copies > 1 ? "Disk group: " + g.copies + " copies of every block on disks in different places" : "Disk group: one copy of every block (no rule)";
          line += "; places: " + Object.keys(g.places).map(function (k) { return k + " (" + g.places[k].join(", ") + ")"; }).join(", ");
          if (g.objects_short) { line += ". " + g.objects_short + " block" + (g.objects_short === 1 ? " is" : "s are") + " short of the rule (" + fmtBytes(g.bytes_short) + "): attach a disk kept elsewhere and check it."; }
          c.appendChild(el("p", "muted small", line + (g.warnings.length ? " " + g.warnings.join(" ") : "")));
          if (!isMobile()) { var gb = el("button", "secondary", "Disk group"); gb.type = "button"; gb.onclick = function () { editDiskGroup(g); }; c.appendChild(gb); }
        });
      });
    }).catch(function (e) { log("disks: " + e.message); });
  }
  // The pool's disks as a table; the column clicked sorts it (the choice is
  // kept in this browser). Natural directions: name A-Z, free/used/
  // reclaimable most first, last checked and last seen oldest first.
  var DISK_SORT_KEY = "varsto-disk-sort";
  function diskSort() {
    var v = null;
    try { v = JSON.parse(localStorage.getItem(DISK_SORT_KEY) || "null"); } catch (e) { /* storage blocked */ }
    return v && v.key ? v : { key: "name", reverse: false };
  }
  function setDiskSort(key) {
    var cur = diskSort();
    var next = { key: key, reverse: cur.key === key ? !cur.reverse : false };
    try { localStorage.setItem(DISK_SORT_KEY, JSON.stringify(next)); } catch (e) { /* not kept */ }
    return next;
  }
  function sortDisks(list, sort) {
    var unknownLast = function (a, b, desc) {
      if (a === null || a === undefined) { return (b === null || b === undefined) ? 0 : 1; }
      if (b === null || b === undefined) { return -1; }
      return desc ? b - a : a - b;
    };
    var cmp = {
      name: function () { return 0; },
      place: function (a, b) { return (a.place || "").localeCompare(b.place || ""); },
      free: function (a, b) { return unknownLast(a.free_bytes, b.free_bytes, true); },
      used: function (a, b) { return b.used_bytes - a.used_bytes; },
      reclaimable: function (a, b) { return b.reclaimable_bytes - a.reclaimable_bytes; },
      checked: function (a, b) { return unknownLast(a.oldest_check_utc, b.oldest_check_utc, false); },
      seen: function (a, b) { return (a.attached ? Infinity : a.last_seen_utc) - (b.attached ? Infinity : b.last_seen_utc) || 0; },
      fsck: function (a, b) { return unknownLast(a.fsck ? a.fsck.checked_utc : null, b.fsck ? b.fsck.checked_utc : null, false); }
    }[sort.key] || function () { return 0; };
    var byName = function (a, b) { return a.label.toLowerCase().localeCompare(b.label.toLowerCase()); };
    return list.slice().sort(function (a, b) {
      var o = cmp(a, b); if (sort.reverse) { o = -o; }
      var n = byName(a, b); if (sort.reverse && sort.key === "name") { n = -n; }
      return o || n;
    });
  }
  function diskTable(mine) {
    var wrap = el("div", "table-wrap disk-table");
    var cols = [["name", "Name"], ["place", "Place"], ["free", "Free space"], ["used", "Used"], ["reclaimable", "Reclaimable"], ["checked", "Last checked"], ["seen", "Last seen"], ["fsck", "File system"]];
    function draw() {
      wrap.innerHTML = "";
      var sort = diskSort();
      var table = el("table"); var thead = el("thead"); var hr = el("tr");
      cols.forEach(function (c) {
        var th = el("th", "sortable" + (c[0] === "free" || c[0] === "used" || c[0] === "reclaimable" ? " num" : ""));
        var b = el("button", "th-sort", c[1]); b.type = "button"; b.title = "Sort by this column (again: reverse)";
        if (sort.key === c[0]) { th.setAttribute("aria-sort", sort.reverse ? "descending" : "ascending"); b.appendChild(el("span", "sort-mark", sort.reverse ? " \u25b2" : " \u25bc")); }
        b.onclick = function () { setDiskSort(c[0]); draw(); };
        th.appendChild(b); hr.appendChild(th);
      });
      if (!isMobile()) { hr.appendChild(el("th", "", "")); }
      thead.appendChild(hr); table.appendChild(thead);
      var tb = el("tbody");
      sortDisks(mine, sort).forEach(function (d) {
        var tr = el("tr");
        var name = el("td"); name.appendChild(el("span", "", d.label + " "));
        name.appendChild(pill(d.attached ? "ok" : "grey", d.attached ? "attached" : "offline"));
        if (d.retired) { name.appendChild(pill("grey", "retired")); }
        if (d.failing) { var fp = pill("bad", "failing"); fp.title = d.failing_reason || ""; name.appendChild(fp); }
        if (d.attached && d.mount) { name.appendChild(el("span", "sub", d.mount)); }
        tr.appendChild(name);
        tr.appendChild(el("td", "", d.place));
        var free = el("td", "num", (d.free_bytes === null || d.free_bytes === undefined ? "?" : fmtBytes(d.free_bytes)) + " / " + fmtBytes(d.capacity_bytes));
        if (!d.attached && d.space_measured_utc) { free.title = "Measured " + fmtDate(d.space_measured_utc); }
        tr.appendChild(free);
        tr.appendChild(el("td", "num", fmtBytes(d.used_bytes)));
        var rec = el("td", "num", fmtBytes(d.reclaimable_bytes));
        if (d.pending_deletes) { rec.title = d.pending_deletes + " pending delete" + (d.pending_deletes === 1 ? "" : "s"); }
        tr.appendChild(rec);
        var chk = el("td", "", d.oldest_check_utc === null || d.oldest_check_utc === undefined ? "\u2014" : d.oldest_check_utc === 0 ? "never" : fmtDate(d.oldest_check_utc));
        if (d.copies_overdue) { chk.appendChild(el("span", "sub", Math.round(d.overdue_share * 100) + " % overdue")); }
        tr.appendChild(chk);
        tr.appendChild(el("td", "", d.attached ? "now" : d.last_seen_utc ? fmtDate(d.last_seen_utc) : "never"));
        var fs = el("td", "", d.fsck ? d.fsck.verdict : "\u2014");
        if (d.fsck) { fs.appendChild(el("span", "sub", fmtDate(d.fsck.checked_utc))); }
        tr.appendChild(fs);
        if (!isMobile()) {
          var acts = el("td");
          if (d.attached) {
            var c1 = el("button", "secondary", "Check"); c1.type = "button"; c1.title = "Verify sizes, apply pending deletes, add new blocks"; c1.onclick = function () { diskAction("/api/disk/check", { label: d.label, full: false }, "check"); }; acts.appendChild(c1);
            var c2 = el("button", "secondary", "Check fully"); c2.type = "button"; c2.title = "Re-hash every block on the disk"; c2.onclick = function () { diskAction("/api/disk/check", { label: d.label, full: true }, "full check"); }; acts.appendChild(c2);
            var ej = el("button", "secondary", "Eject"); ej.type = "button"; ej.title = "Write the disk index and sync; then unmount it yourself"; ej.onclick = function () { diskAction("/api/disk/eject", { label: d.label }, "eject"); }; acts.appendChild(ej);
          }
          var pb = el("button", "secondary", "Place"); pb.type = "button"; pb.title = "Where this disk is kept; disk groups keep copies in different places"; pb.onclick = function () { editDiskPlace(d); }; acts.appendChild(pb);
          if (!d.retired) { var rt = el("button", "secondary", "Retire"); rt.type = "button"; rt.title = "Nothing new goes to this disk"; rt.onclick = function () { dialog({ title: "Retire disk " + d.label + "?", text: "Nothing new is written to it; what it holds stays readable while attached.", ok: "Retire" }).then(function (yes) { if (yes) { diskAction("/api/disk/retire", { label: d.label }, "retire"); } }); }; acts.appendChild(rt); }
          tr.appendChild(acts);
        }
        tb.appendChild(tr);
      });
      table.appendChild(tb); wrap.appendChild(table);
    }
    draw();
    return wrap;
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) { return navigator.clipboard.writeText(text); }
    return new Promise(function (ok, fail) {
      var t = el("textarea"); t.value = text; document.body.appendChild(t); t.select();
      try { document.execCommand("copy") ? ok() : fail(new Error("copy refused")); } catch (e) { fail(e); } finally { t.remove(); }
    });
  }
  // One reason after another, each its own text so it can be translated.
  function reasonSpans(box, reasons) {
    reasons.forEach(function (r, i) { if (i) { box.appendChild(document.createTextNode("; ")); } box.appendChild(el("span", "", r.text)); });
  }
  // "Suggested next" per pool card (the interface cannot mount: it shows
  // the command), the attached disk to check instead, and disks left out.
  function renderDiskSuggest(pools) {
    api("GET", "/api/disk/suggest").then(function (r) {
      var s = r.suggestions;
      pools.forEach(function (p, idx) {
        var box = document.querySelector('.disk-suggest[data-suggest-for="' + (window.CSS && CSS.escape ? CSS.escape(p.name) : p.name) + '"]');
        if (!box) { return; }
        box.innerHTML = "";
        var mine = function (x) { return x.pool === p.name; };
        var top = s.ranked.filter(mine).filter(function (x) { return x.score >= 5; })[0];
        var att = s.attached.filter(mine).filter(function (x) { return x.score >= 5; })[0];
        if (top) {
          var n = el("div", "notice suggest-next");
          var line = el("div"); line.appendChild(el("strong", "", "Suggested next:")); line.appendChild(document.createTextNode(" «" + top.label + "» \u2014 "));
          reasonSpans(line, top.reasons); n.appendChild(line);
          var cmd = el("div", "suggest-cmd"); cmd.appendChild(el("code", "", top.command));
          var cb = el("button", "secondary", "Copy"); cb.type = "button"; cb.title = "Copy the command; run it in a terminal with the disk plugged in";
          cb.onclick = function () { copyText(top.command).then(function () { log("copied: " + top.command); }).catch(function (e) { alertBox(e.message); }); };
          cmd.appendChild(cb); n.appendChild(cmd);
          box.appendChild(n);
        } else {
          box.appendChild(el("p", "muted small", "No disk needs docking now."));
        }
        if (att) {
          var a = el("div", "notice");
          var al = el("div"); al.appendChild(document.createTextNode("«" + att.label + "» ")); al.appendChild(el("span", "", "is attached:")); al.appendChild(document.createTextNode(" "));
          reasonSpans(al, att.reasons); a.appendChild(al);
          if (!isMobile()) { var cn = el("button", "secondary", "Check now"); cn.type = "button"; cn.onclick = function () { diskAction("/api/disk/check", { label: att.label, full: false }, "check"); }; a.appendChild(cn); }
          box.appendChild(a);
        }
        s.excluded.filter(mine).forEach(function (x) {
          var w = el("div", "notice warn"); w.appendChild(document.createTextNode("«" + x.label + "»: ")); w.appendChild(el("span", "", x.warning)); box.appendChild(w);
        });
        if (idx === 0) {
          var lab = el("label", "inline muted"); var cbx = el("input"); cbx.type = "checkbox"; cbx.checked = !!r.settings.notify_overdue;
          cbx.onchange = function () { api("POST", "/api/disk/suggest/settings", { notify_overdue: cbx.checked }).then(function () { log(cbx.checked ? "weekly disk reminder on" : "weekly disk reminder off"); }).catch(function (e) { alertBox(e.message); cbx.checked = !cbx.checked; }); };
          lab.appendChild(cbx); lab.appendChild(el("span", "", "Remind me weekly when a disk is overdue for a check")); box.appendChild(lab);
        }
      });
    }).catch(function (e) { log("disk suggestion: " + e.message); });
  }
  function editDiskGroup(g) {
    dialog({ title: "Disk group of pool " + g.pool, text: "Keep this many copies of every block on disks kept in different places (1: one copy, no rule). Disks of other places get their copies when attached and checked; policies count each disk copy at its disk's place.", fields: [{ name: "copies", label: "Copies in different places", type: "number", value: g.copies }], ok: "Save" }).then(function (r) {
      if (!r) { return; }
      return api("POST", "/api/disk/group", { pool: g.pool, copies: Math.max(1, Math.floor(+r.values.copies) || 1) }).then(function () { log("pool " + g.pool + ": disk group rule saved"); return refreshStatus(); });
    }).catch(function (e) { alertBox(e.message); });
  }
  function editDiskPlace(d) {
    dialog({ title: "Where is " + d.label + " kept?", text: "A place such as home or offsite. Empty: the pool's place.", fields: [{ name: "place", label: "Place", value: d.place }], ok: "Save" }).then(function (r) {
      if (!r) { return; }
      return api("POST", "/api/disk/place", { label: d.label, place: r.values.place.trim() }).then(function () { log(d.label + " is kept at " + (r.values.place.trim() || "the pool's place")); return refreshStatus(); });
    }).catch(function (e) { alertBox(e.message); });
  }
  $("adddisk").onsubmit = function (ev) {
    ev.preventDefault(); var d = formData(ev.target); busy(true); log("adding disk " + d.label + " to pool " + d.pool);
    api("POST", "/api/disk/add", d).then(function (r) { ev.target.reset(); log("disk " + r.disk.label + " added to pool " + r.pool + ": " + fmtBytes(r.bytes_added) + " added (" + r.objects_added + " blocks)"); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); return refreshStatus(); });
  };

  function fmtTime(t) { return t ? new Date(t * 1000).toLocaleTimeString() : "never"; }
  // What the service did shows by itself: after each sync the overview and
  // the open file list are read again (no refresh button).
  var lastSyncs = null;
  function renderService(sv) {
    if (lastSyncs !== null && sv.syncs !== lastSyncs && busyCount === 0 && lastStatus) {
      refreshStatus().then(function () { if (currentPage === "files") { loadFiles(); } }).catch(function () {});
    }
    lastSyncs = sv.syncs;
    var state = sv.running ? (sv.paused ? "paused" : "running") : "stopped";
    var txt = sv.running ? "Watching " + sv.watching + " folder(s) · last sync " + fmtTime(sv.last_sync_utc) + (sv.last_result ? " (" + sv.last_result + ")" : "") + (sv.last_error ? " · last error: " + sv.last_error : "") + " · next in " + (sv.next_sync_utc ? Math.max(0, Math.round(sv.next_sync_utc - Date.now() / 1000)) + " s" : "-") : "The background service is not running; nothing syncs until it is started.";
    $("svc-text").textContent = txt;
    var sp = $("svc-pill"); sp.textContent = state === "running" ? "Running" : state === "paused" ? "Paused" : "Not running"; sp.className = "pill " + (state === "running" ? "ok" : state === "paused" ? "risk" : "bad");
    $("svc-dot").dataset.state = state;
    $("pause").textContent = sv.paused ? "Resume" : "Pause";
    $("pause").dataset.paused = sv.paused ? "1" : "0";
    renderSpace(sv.low_space || []);
  }
  // Places short of disk space: one line each (each translated on its own).
  function renderSpace(list) {
    var b = $("spacebanner"); if (!b) { return; }
    b.innerHTML = "";
    list.forEach(function (l) { var t = l.text || ""; b.appendChild(el("div", null, t.charAt(0).toUpperCase() + t.slice(1) + ".")); });
    b.classList.toggle("hidden", list.length === 0);
  }
  // The free space kept on the disk of a folder (here) or of a directory storage.
  function editMinFree(kind, name, current) {
    dialog({
      title: "Free space to keep",
      text: kind === "folder" ? "Downloads into this folder stop while its disk would keep less free space than this. Reading and uploading go on, and downloads resume by themselves when there is room again." : "Blocks are not written to this storage while its disk would keep less free space than this. The other storages still get them, and writing resumes by itself when there is room again.",
      fields: [{ name: "min_free", label: "Keep free", value: current || "5%", hint: "A share of the disk (5%) or an amount (10GB). The default is 5 %." }],
      ok: "Save", extra: current ? "Default" : null
    }).then(function (r) {
      if (!r) { return; }
      var v = r.action === "extra" ? "" : (r.values.min_free || "").trim();
      var body = kind === "folder" ? { folder: name, min_free: v } : { name: name, min_free: v };
      return api("POST", kind === "folder" ? "/api/folder/min-free" : "/api/storage/min-free", body).then(function () {
        log(name + ": " + (v || "5%") + " kept free");
        return refreshStatus();
      });
    }).catch(function (e) { alertBox(e.message); });
  }
  // The tray and menu bar pause and sync through the same service; follow them.
  var lastServicePoll = 0;
  function pollService() { if (!token || document.visibilityState !== "visible") { return; } lastServicePoll = Date.now(); api("GET", "/api/service").then(renderService).catch(function () {}); }
  // Every five seconds without the event stream; with it, the events ask
  // (serviceSoon) and a slow poll once a minute stays as a safety net.
  setInterval(function () { if (evsOk && Date.now() - lastServicePoll < 60000) { return; } pollService(); }, 5000);
  window.addEventListener("focus", pollService);
  $("pause").onclick = function () { api("POST", "/api/service/pause", { paused: $("pause").dataset.paused !== "1" }).then(renderService).catch(function (e) { log("error: " + e.message); }); };
  // Updates: checked by themselves (at start and every six hours); the
  // button and note appear only when a newer version exists.
  var updateInfo = null;
  function checkUpdate() {
    if (!token) { return; }
    api("GET", "/api/update/check").then(function (c) {
      updateInfo = c;
      var note = $("update-note"), btn = $("update");
      if (!c.newer) { note.classList.add("hidden"); btn.classList.add("hidden"); return; }
      note.textContent = "Varsto " + c.latest + " is available (you have " + c.current + ").";
      note.classList.remove("hidden");
      btn.textContent = c.available ? "Install " + c.latest : "Download " + c.latest;
      btn.classList.remove("hidden");
    }).catch(function () {});
  }
  setTimeout(checkUpdate, 3000);
  setInterval(checkUpdate, 6 * 3600 * 1000);
  $("update").onclick = function () {
    var c = updateInfo; if (!c) { return; }
    if (!c.available) { window.open(c.download_page, "_blank", "noopener"); return; }
    confirmBox("Install Varsto " + c.latest + " now? Varsto restarts afterwards.", { title: "Update Varsto", ok: "Install" }).then(function (yes) {
      if (!yes) { return; }
      busy(true); log("installing " + c.latest);
      return api("POST", "/api/update", {}).then(function (r) { log(r.message); if (r.updated) { log("the service is restarting; this page reconnects in a few seconds"); $("update").classList.add("hidden"); } busy(false); });
    }).catch(function (e) { log("update failed: " + e.message); busy(false); });
  };
  $("quit").onclick = function () {
    confirmBox("Folders stop syncing until the service is started again.", { title: "Quit Varsto?", ok: "Quit", danger: true }).then(function (yes) {
      if (!yes) { return; }
      api("POST", "/api/quit", {}).then(function () { log("the service is shutting down"); $("svc-dot").dataset.state = "stopped"; }).catch(function (e) { log("quit failed: " + e.message); });
    });
  };
  var busyCount = 0;
  function busy(on) { busyCount = Math.max(0, busyCount + (on ? 1 : -1)); document.querySelectorAll("button").forEach(function (b) { if (b.classList.contains("nav-item") || b.classList.contains("more-item") || b.classList.contains("tree-item") || b.classList.contains("folder-card") || b.closest("#modal") || b.closest("#viewer")) { return; } if (b.dataset.keepDisabled === "1") { return; } b.disabled = busyCount > 0; }); if (busyCount === 0) { updateToolbar(); } }
  function runSync(folder) {
    busy(true); log("sync " + (folder || "all") + " started");
    return api("POST", "/api/sync", folder ? { folder: folder } : {}).then(function (r) {
      r.forEach(function (x) { log(x.pull.folder + ": pulled " + x.pull.files_updated + " updated, " + x.pull.files_deleted + " deleted, " + x.pull.conflicts + " conflicts; pushed " + x.push.files_changed + " changed, " + x.push.chunks_uploaded + " chunks" + (x.pull.files_unavailable.length ? "; unavailable: " + x.pull.files_unavailable.join(", ") : "") + (x.pull.forked_devices.length ? "; FORKED: " + x.pull.forked_devices.join(", ") : "") + ((x.pull.renamed_locally || []).length ? "; kept under another name here because the disk ignores case: " + x.pull.renamed_locally.join(", ") : "") + ((x.push.read_only || (x.pull.kept_aside || []).length) ? "; read-only: your changes were not published" + (((x.pull.kept_aside || []).length + (x.push.kept_aside || []).length) ? " (kept aside: " + (x.pull.kept_aside || []).concat(x.push.kept_aside || []).join(", ") + ")" : "") : "") + ((x.pull.writes_refused || []).length ? "; not taken from read-only members: " + x.pull.writes_refused.join(", ") : "")); });
    }).catch(function (e) { log("sync failed: " + e.message); }).then(function () { busy(false); return refreshStatus().then(function () { if (currentPage === "files") { loadFiles(); } }); });
  }

  $("lock").onclick = function () { api("POST", "/api/lock").then(function (r) { if (r.exports_removed) { log("removed " + r.exports_removed + " decrypted cop" + (r.exports_removed === 1 ? "y" : "ies") + " made for other apps"); } return refreshState(); }).catch(function (e) { log("error: " + e.message); }); };
  // Files view: folder header, tree selection, rows, details pane and toolbar. On a phone the
  // card has two screens: the folder list and one folder (#filesmain[data-screen]).
  function setScreen(sc) { $("filesmain").dataset.screen = sc; }
  function showFolderList() { setScreen("list"); clearSelection(); }
  $("files-back").onclick = showFolderList;
  function markTree(name) { document.querySelectorAll("#foldertree .tree-item").forEach(function (b) { if (b.dataset.folder === name && name) { b.setAttribute("aria-current", "true"); } else { b.removeAttribute("aria-current"); } }); }
  // Where the folder's files are on a phone, in the user's words.
  function whereLine(f) {
    if (!f || !isMobile()) { return ""; }
    if (f.plain === false) { return "Encrypted on this phone: files are kept as encrypted blocks and open only in Varsto. Selective sync chooses which ones are kept here."; }
    if (appState.platform !== "android") { return ""; }
    var p = f.path || "";
    if (p.indexOf("/storage/emulated/0/") === 0 && p.indexOf("/Android/data/") < 0) { return "On this phone: Internal storage/" + p.slice("/storage/emulated/0/".length) + ", visible in My Files."; }
    return "Plain files inside the app's own space only; other apps cannot see them.";
  }
  function updateFilesHead() {
    var f = folderByName($("filesfolder").value);
    $("files-sub").textContent = f ? [f.path, f.files + " file" + (f.files === 1 ? "" : "s"), fmtBytes(f.bytes), f.selective ? "selective sync" : null, f.shared ? "shared" : null].filter(Boolean).join(" · ") : "";
    if (f && isMobile()) { $("files-sub").textContent = [f.files + " file" + (f.files === 1 ? "" : "s"), fmtBytes(f.bytes), f.selective ? "selective sync" : null].filter(Boolean).join(" · "); }
    var w = whereLine(f); $("files-where").textContent = w; $("files-where").classList.toggle("hidden", !w);
    // Selective sync is the same choice in every folder; in a folder kept
    // encrypted on a phone the synced files are kept as encrypted blocks.
    $("selectivetoggle").checked = !!(f && f.selective);
    $("files-share").disabled = !f || !!(lastStatus && lastStatus.member);
    $("files-upload").disabled = !f;
    $("files-mkdir").disabled = !f;
    updateToolbar();
  }
  function openFolder(name) { if (fsEdit && fsEdit.folder !== name) { closeFolderSettings(); } $("filesfolder").value = name; markTree(name); updateFilesHead(); showFolderForms(false); setScreen("folder"); nav("files"); loadFiles(); }
  function showFolderForms(on, byUser) { $("folderforms").classList.toggle("hidden", !on); if (byUser) { $("folderforms").dataset.user = on ? "1" : "0"; } if (on && byUser) { var inp = $("addfolder").querySelector("input[name=name]"); setTimeout(function () { inp.focus(); }, 50); } }
  $("treeadd").onclick = function () { nav("files"); showFolderForms(true, true); window.scrollTo(0, document.body.scrollHeight); };
  $("filesadd").onclick = function () { var open = $("folderforms").classList.contains("hidden"); showFolderForms(open, true); if (open) { $("folderforms").scrollIntoView({ block: "start", behavior: "smooth" }); } };
  $("folderlist-add").onclick = function () { showFolderForms(true, true); $("folderforms").scrollIntoView({ block: "start", behavior: "smooth" }); };
  document.querySelectorAll("[data-close-forms]").forEach(function (b) { b.onclick = function () { showFolderForms(false, true); }; });

  // Open or share a file on the phone: fetch it first if it is only a placeholder, then hand the
  // real path to the shell, which builds a content URI and starts the system chooser. A folder kept
  // encrypted here has no plain file: the service writes a decrypted copy for this hand-off only.
  function openOnPhone(folder, f, share) {
    var ready;
    if (encryptedHere(folder)) {
      busy(true);
      ready = api("POST", "/api/export", { folder: folder, path: f.path }).then(function (r) { busy(false); return r.path; }, function (e) { busy(false); throw e; });
    } else {
      ready = (f.state === "local" ? Promise.resolve() : (busy(true), api("POST", "/api/fetch", { folder: folder, path: f.path }).then(function () { log("fetched " + f.path); busy(false); }, function (e) { busy(false); throw e; }))).then(function () { return f.disk; });
    }
    ready.then(function (disk) {
      if (!droid) { throw new Error("opening files in other apps is not available in this shell yet"); }
      if (share) { droid.shareFile(disk); } else { droid.openFile(disk); }
      setTimeout(loadFiles, 1500);
    }).catch(function (e) { log((share ? "share" : "open") + " failed: " + e.message); alertBox(e.message); });
  }
  // Folders kept encrypted on the phone: handing a file to another app writes a decrypted copy,
  // so say so once per session before the first one.
  function encryptedHere(folder) { var fs = folderByName(folder); return !!(fs && fs.path && fs.plain === false); }
  var handOffOk = false;
  function handOff(folder, f, share) {
    if (!encryptedHere(folder) || handOffOk) { return openOnPhone(folder, f, share); }
    confirmBox("Varsto writes a decrypted copy of " + f.path.split("/").pop() + " to this phone and gives it to the app you choose. Varsto removes its copy when it locks or restarts; the other app may keep its own.", { title: share ? "Share a decrypted copy?" : "Open in another app?", ok: share ? "Share" : "Open" }).then(function (yes) { if (yes) { handOffOk = true; openOnPhone(folder, f, share); } });
  }

  // In-app viewer: /api/view decrypts in memory (with range requests for seeking), so pictures,
  // video, audio and text of an encrypted folder are shown without a plaintext copy on the phone.
  var VIEW_KINDS = { image: "jpg jpeg png gif webp avif bmp", video: "mp4 m4v webm mov 3gp mkv", audio: "mp3 m4a aac ogg oga opus wav flac", text: "txt md csv log json xml html htm svg js css rs py sh yaml yml toml ini conf", pdf: "pdf" };
  function viewKind(path) { var ext = (path.split("/").pop().split(".").slice(1).pop() || "").toLowerCase(); for (var k in VIEW_KINDS) { if (ext && (" " + VIEW_KINDS[k] + " ").indexOf(" " + ext + " ") >= 0) { return k; } } return null; }
  function viewUrl(folder, path) { return "/api/view?folder=" + enc(folder) + "&path=" + enc(path) + "&token=" + enc(token); }
  var viewer = { folder: "", list: [], i: 0, open: false };
  function openViewer(folder, list, i) {
    viewer.folder = folder; viewer.list = list; viewer.i = i;
    if (!viewer.open) { viewer.open = true; try { history.pushState({ viewer: 1 }, ""); } catch (e) {} }
    $("viewer").classList.remove("hidden"); document.body.classList.add("modal-open");
    showViewerItem();
  }
  function clearStage() { var st = $("viewer-stage"); st.querySelectorAll("video, audio").forEach(function (m) { m.pause(); m.removeAttribute("src"); m.load(); }); st.innerHTML = ""; }
  function viewerMsg(text) { var m = el("div", "viewer-msg"); m.appendChild(el("p", null, text)); return m; }
  function showViewerItem() {
    var f = viewer.list[viewer.i]; var kind = viewKind(f.path); var url = viewUrl(viewer.folder, f.path);
    clearStage(); var st = $("viewer-stage");
    $("viewer-name").textContent = showName(f.path.split("/").pop()); $("viewer-name").title = showName(f.path);
    $("viewer-prev").disabled = viewer.i <= 0; $("viewer-next").disabled = viewer.i >= viewer.list.length - 1;
    var fail = function () { clearStage(); st.appendChild(viewerMsg("This file cannot be shown here. Use Open in another app.")); };
    if (kind === "image") { var im = document.createElement("img"); im.alt = f.path; im.onerror = fail; im.src = url; st.appendChild(im); }
    else if (kind === "video" || kind === "audio") { var m = document.createElement(kind); m.controls = true; m.preload = "metadata"; m.setAttribute("playsinline", ""); m.onerror = fail; m.src = url; st.appendChild(m); }
    else if (kind === "text") {
      // The first 256 KiB is plenty to read; the rest stays where it is.
      fetch(url, { headers: { Range: "bytes=0-262143" } }).then(function (r) { if (!r.ok) { throw new Error(r.statusText); } return r.text(); }).then(function (t) { if (viewer.list[viewer.i] === f) { st.appendChild(el("pre", null, t + (f.size > 262144 ? "\n…" : ""))); } }).catch(fail);
    }
    else { st.appendChild(viewerMsg(kind === "pdf" ? "PDF files cannot be shown inside the app. Open in another app hands a decrypted copy to a PDF viewer." : "This kind of file cannot be shown here. Use Open in another app.")); }
    $("viewer-open").classList.toggle("hidden", !droid); $("viewer-share").classList.toggle("hidden", !droid);
  }
  function closeViewer(fromHistory) {
    if (!viewer.open) { return; }
    viewer.open = false; clearStage(); $("viewer").classList.add("hidden"); document.body.classList.remove("modal-open");
    if (!fromHistory) { try { history.back(); } catch (e) {} }
  }
  function stepViewer(d) { var j = viewer.i + d; if (viewer.open && j >= 0 && j < viewer.list.length) { viewer.i = j; showViewerItem(); } }
  $("viewer-close").onclick = function () { closeViewer(false); };
  $("viewer-prev").onclick = function () { stepViewer(-1); };
  $("viewer-next").onclick = function () { stepViewer(1); };
  $("viewer-open").onclick = function () { handOff(viewer.folder, viewer.list[viewer.i], false); };
  $("viewer-share").onclick = function () { handOff(viewer.folder, viewer.list[viewer.i], true); };
  $("viewer-details").onclick = function () { var f = viewer.list[viewer.i]; closeViewer(false); document.querySelectorAll("#files tbody tr").forEach(function (tr) { if (tr.dataset.path === f.path) { selectFile(f, tr); tr.scrollIntoView({ block: "center" }); } }); };
  // Android's back button goes back in the web view's history: it closes the viewer first.
  window.addEventListener("popstate", function () { closeViewer(true); });
  document.addEventListener("keydown", function (ev) { if (!viewer.open) { return; } if (ev.key === "Escape") { closeViewer(false); } else if (ev.key === "ArrowLeft") { stepViewer(-1); } else if (ev.key === "ArrowRight") { stepViewer(1); } });
  (function () {
    var x0 = null;
    $("viewer-stage").addEventListener("touchstart", function (ev) { x0 = ev.touches.length === 1 ? ev.touches[0].clientX : null; }, { passive: true });
    $("viewer-stage").addEventListener("touchend", function (ev) { if (x0 === null) { return; } var dx = ev.changedTouches[0].clientX - x0; x0 = null; if (Math.abs(dx) > 70) { stepViewer(dx < 0 ? 1 : -1); } });
  })();

  function fileActions(folder, f, full) {
    var out = [];
    if (phoneActions()) {
      if (f.state !== "missing") {
        var enc2 = encryptedHere(folder);
        if (enc2 && viewKind(f.path)) { var vb = el("button", full ? "" : "secondary"); vb.type = "button"; if (full) { vb.appendChild(icon("image")); } vb.appendChild(document.createTextNode("View")); vb.onclick = function (ev) { ev.stopPropagation(); openViewer(folder, [f], 0); }; out.push(vb); }
        var ob = el("button", "secondary"); ob.type = "button"; if (full) { ob.appendChild(icon("open")); } ob.appendChild(document.createTextNode(enc2 ? "Open in another app" : "Open")); ob.title = enc2 ? "Hands a decrypted copy to the app you choose" : ""; ob.onclick = function (ev) { ev.stopPropagation(); handOff(folder, f, false); }; out.push(ob);
        var sb = el("button", "secondary"); sb.type = "button"; if (full) { sb.appendChild(icon("share")); } sb.appendChild(document.createTextNode("Share")); sb.title = enc2 ? "Hands a decrypted copy to the app you choose" : ""; sb.onclick = function (ev) { ev.stopPropagation(); handOff(folder, f, true); }; out.push(sb);
      }
    } else if (f.state !== "missing") {
      var open = document.createElement("a"); open.className = "button secondary"; if (full) { open.appendChild(icon("open")); } open.appendChild(document.createTextNode("Open"));
      open.href = "/api/open?folder=" + enc(folder) + "&path=" + enc(f.path) + "&token=" + enc(token); open.onclick = function (ev) { ev.stopPropagation(); setTimeout(loadFiles, 1500); }; out.push(open);
    }
    var b = document.createElement("button"); b.type = "button"; b.className = "secondary";
    if (f.state === "placeholder" || f.state === "missing") { if (full) { b.className = ""; b.appendChild(icon("download")); } b.appendChild(document.createTextNode("Download")); b.onclick = function (ev) { ev.stopPropagation(); fetchFile(folder, f.path); }; }
    else { if (full) { b.appendChild(icon("free")); } b.appendChild(document.createTextNode("Free up space")); b.onclick = function (ev) { ev.stopPropagation(); freeFile(folder, f.path); }; }
    out.push(b);
    return out;
  }
  function selectFile(f, tr) {
    selectedFile = f;
    document.querySelectorAll("#files tbody tr").forEach(function (r) { r.classList.toggle("selected", r === tr); });
    var folder = $("filesfolder").value; var fs = folderByName(folder);
    var d = $("filedetails"); d.classList.remove("hidden"); document.querySelector(".files-layout").classList.add("with-details");
    var pv = $("fd-preview"); pv.innerHTML = "";
    if (f.media) { var im = document.createElement("img"); im.alt = ""; im.src = "/api/thumb?folder=" + enc(folder) + "&path=" + enc(f.path) + "&token=" + enc(token); im.onerror = function () { im.remove(); pv.appendChild(icon("image")); }; pv.appendChild(im); } else { pv.appendChild(icon("files")); }
    $("fd-name").textContent = showName(f.path);
    var st = $("fd-state"); st.innerHTML = ""; st.appendChild(stateSquare(f)); st.appendChild(document.createTextNode(fileStateLabel(f)));
    $("fd-size").textContent = fmtBytes(f.size);
    $("fd-modified").textContent = fmtDate(f.modified_utc) || "unknown";
    $("fd-used").textContent = f.last_accessed_utc ? fmtDate(f.last_accessed_utc) : "never";
    // Device copy first, then the storages. Storage counts are folder-wide and
    // leave out transferrers, which carry blocks only until they are delivered.
    var copies = [f.state === "placeholder" || f.state === "missing" ? "not on this device" : "on this device"];
    if (fs) {
      var names = lastStatus ? lastStatus.storages.filter(function (st) { return !st.carrier; }).map(function (st) { return st.name; }) : [];
      copies.push(fs.chunks_without_storage_copy > 0 ? fs.chunks_without_storage_copy + " of the folder's " + fs.chunks + " blocks still lack a storage copy" : names.length ? "every block of this folder is on " + (names.length === 1 ? "storage " : names.length + " storages: ") + names.join(", ") : "no storage holds this folder");
      if (fs.chunks_verified_elsewhere > 0) { copies.push(fs.chunks_verified_elsewhere + " verified by another device"); }
    }
    $("fd-copies").textContent = copies.join("; ") || "unknown";
    // File metadata (`fsmeta`): a link's target, permissions, owner, attributes.
    var meta = [["link", f.symlink || ""],
      ["mode", f.mode_text ? f.mode_text + " (" + ("000" + f.mode.toString(8)).slice(-4) + ")" : ""],
      ["owner", f.owner || ""], ["xattrs", (f.xattrs || []).join(", ")]];
    meta.forEach(function (m) { $("fd-" + m[0]).textContent = m[1]; $("fd-" + m[0]).classList.toggle("hidden", !m[1]); $("fd-" + m[0] + "-dt").classList.toggle("hidden", !m[1]); });
    if (f.symlink) {
      var ld = $("fd-link"); ld.textContent = ""; ld.appendChild(el("code", "", f.symlink));
      if (f.symlink_absolute) { ld.appendChild(document.createTextNode(" ")); ld.appendChild(el("span", "muted", "(absolute: it may point elsewhere on another device)")); }
    }
    var acts = $("fd-actions"); acts.innerHTML = "";
    fileActions(folder, f, true).forEach(function (b) { acts.appendChild(b); });
    showAnalysis(folder, f);
    $("fd-history").classList.add("hidden");
    loadVersions(folder, f);
    showChanges(folder, f);
    updateToolbar();
  }
  // Change history (`/api/changes`): who changed what and when, from the
  // signed manifests. One line per version.
  var ACTION_LABELS = { created: "Created", modified: "Modified", deleted: "Deleted", restored: "Restored" };
  function changeItem(c, withPath) {
    var li = el("li"); var body = el("div", "li-body"); var title = el("div", "li-title");
    if (c.action === "renamed") {
      title.appendChild(el("span", null, c.from ? "Renamed from" : "Renamed to"));
      title.appendChild(document.createTextNode(" "));
      var other = el("span", null, c.from || c.to || ""); other.setAttribute("data-no-i18n", ""); title.appendChild(other);
    } else {
      title.appendChild(el("span", null, ACTION_LABELS[c.action] || c.action));
    }
    if (withPath) { title.appendChild(document.createTextNode(" ")); var pth = el("span", "muted", c.path); pth.setAttribute("data-no-i18n", ""); title.appendChild(pth); }
    if (!c.verified) { var nv = pill("grey", "not verified"); nv.title = "The file list that named this version was not announced in a signed ledger entry this device holds"; title.appendChild(nv); }
    body.appendChild(title);
    var who = c.device_name + (c.user ? " (" + c.user + ")" : "");
    var parts = [c.time_utc ? new Date(c.time_utc * 1000).toLocaleString() : "", who];
    if (c.action !== "deleted" && !(c.action === "renamed" && c.to)) { parts.push(fmtBytes(c.size)); }
    if (c.hash) { parts.push(c.hash.slice(0, 8)); }
    var sub = el("div", "li-sub", parts.filter(Boolean).join(" · ")); sub.setAttribute("data-no-i18n", ""); body.appendChild(sub);
    li.appendChild(body);
    return li;
  }
  function showChanges(folder, f) {
    var ul = $("fd-changes-list"); ul.innerHTML = "";
    api("GET", "/api/changes?folder=" + enc(folder) + "&path=" + enc(f.path) + "&limit=20").then(function (r) {
      if (selectedFile !== f) { return; }
      ul.innerHTML = "";
      r.changes.forEach(function (c) { ul.appendChild(changeItem(c, c.path !== f.path)); });
      if (!r.changes.length) { ul.appendChild(el("li", "muted small", "No changes recorded yet")); }
    }).catch(function () {});
  }
  function loadRecentChanges() {
    var folder = $("filesfolder").value; if (!folder) { return; }
    var v = formData($("rc-form"));
    var q = "folder=" + enc(folder) + "&limit=200";
    ["path", "device", "user", "since"].forEach(function (k) { if ((v[k] || "").trim()) { q += "&" + k + "=" + enc(v[k].trim()); } });
    var ul = $("rc-list");
    api("GET", "/api/changes?" + q).then(function (r) {
      ul.innerHTML = "";
      r.changes.forEach(function (c) { ul.appendChild(changeItem(c, true)); });
      if (!r.changes.length) { ul.appendChild(el("li", "muted small", "No changes match")); }
      if (r.truncated) { ul.appendChild(el("li", "muted small", "Older changes are left out; narrow the search.")); }
    }).catch(function (e) { alertBox(e.message); });
  }
  $("files-changes").onclick = function () {
    var box = $("recentchanges"); var show = box.classList.contains("hidden");
    box.classList.toggle("hidden", !show);
    if (show) { loadRecentChanges(); }
  };
  $("rc-close").onclick = function () { $("recentchanges").classList.add("hidden"); };
  $("rc-form").onsubmit = function (ev) { ev.preventDefault(); loadRecentChanges(); };
  // The file's analysis (`/api/analysis`): what an assistant or the user
  // recorded about its contents. A listing has the first 500 characters; the
  // whole text is asked for when there is more.
  function showAnalysis(folder, f) {
    var has = !!f.analysis;
    $("fd-analysis-empty").classList.toggle("hidden", has);
    ["fd-analysis-text", "fd-analysis-tags", "fd-analysis-meta"].forEach(function (id) { $(id).classList.toggle("hidden", !has); });
    $("fd-analysis-stale").classList.toggle("hidden", !(has && f.analysis_stale));
    $("fd-analysis-clear").classList.toggle("hidden", !has);
    $("fd-analysis-edit").textContent = has ? "Edit analysis" : "Write analysis";
    $("fd-analysis-text").textContent = has ? f.analysis + (f.analysis_truncated ? "…" : "") : "";
    var tags = $("fd-analysis-tags"); tags.innerHTML = "";
    (f.analysis_tags || []).forEach(function (t) { tags.appendChild(el("span", "tag", t)); });
    $("fd-analysis-device").textContent = f.analysis_author || "";
    $("fd-analysis-by").textContent = f.analysis_by || "–";
    $("fd-analysis-date").textContent = f.analysis_utc ? fmtDate(f.analysis_utc) : "";
    if (has && f.analysis_truncated) {
      api("GET", "/api/analysis?folder=" + enc(folder) + "&path=" + enc(f.path)).then(function (r) {
        if (selectedFile === f && r.analysis) { $("fd-analysis-text").textContent = r.analysis.analysis; }
      }).catch(function () {});
    }
  }
  $("fd-analysis-edit").onclick = function () {
    var f = selectedFile; if (!f) { return; }
    var folder = $("filesfolder").value;
    var full = f.analysis && f.analysis_truncated ? api("GET", "/api/analysis?folder=" + enc(folder) + "&path=" + enc(f.path)).then(function (r) { return r.analysis ? r.analysis.analysis : ""; }) : Promise.resolve(f.analysis || "");
    full.then(function (text) {
      return dialog({ title: "File analysis", text: f.path, fields: [
        { name: "analysis", label: "What the file contains", textarea: true, rows: 10, value: text, maxlength: 16384 },
        { name: "tags", label: "Tags", value: (f.analysis_tags || []).join(", "), hint: "separated by commas" }
      ], ok: "Save" });
    }).then(function (r) {
      if (!r) { return; }
      var tags = r.values.tags.split(",").map(function (t) { return t.trim(); }).filter(Boolean);
      return api("POST", "/api/analysis", { folder: folder, path: f.path, analysis: r.values.analysis, tags: tags }).then(function () { log("saved the analysis of " + f.path); loadFiles(); });
    }).catch(function (e) { alertBox(e.message); });
  };
  $("fd-analysis-clear").onclick = function () {
    var f = selectedFile; if (!f) { return; }
    var folder = $("filesfolder").value;
    confirmBox("The analysis of this file is removed on every device.", { title: "Clear analysis?", ok: "Clear analysis", danger: true }).then(function (yes) {
      if (!yes) { return; }
      return api("POST", "/api/analysis/clear", { folder: folder, path: f.path }).then(function () { log("cleared the analysis of " + f.path); loadFiles(); });
    }).catch(function (e) { alertBox(e.message); });
  };
  // The filter matches every word in the path, the tags or the analysis.
  function matchesFilter(f, words) {
    var hay = (f.path + " " + (f.analysis_tags || []).join(" ") + " " + (f.analysis || "")).toLowerCase();
    return words.every(function (w) { return hay.indexOf(w) >= 0; });
  }
  var filterTimer = null;
  $("files-filter").addEventListener("input", function () { clearTimeout(filterTimer); filterTimer = setTimeout(loadFiles, 250); });
  function clearSelection() { selectedFile = null; document.querySelectorAll("#files tbody tr").forEach(function (r) { r.classList.remove("selected"); }); $("filedetails").classList.add("hidden"); document.querySelector(".files-layout").classList.remove("with-details"); updateToolbar(); }
  $("fd-close").onclick = clearSelection;
  function updateToolbar() {
    var f = selectedFile; var folder = folderByName($("filesfolder").value);
    $("files-download").disabled = !f || !(f.state === "placeholder" || f.state === "missing");
    // Without a selection the button frees every downloaded file of an "encrypted here" folder.
    var folderWide = !f && !!folder && folder.plain === false && isMobile();
    $("files-free").disabled = f ? f.state !== "local" : !folderWide;
    $("files-free").title = folderWide ? "Remove the encrypted blocks of every downloaded file of this folder from this phone" : "Keep only a placeholder of the selected file here";
  }
  // Large fetches whose blocks are on pool disks: the service returns a plan
  // and the dialog walks through it disk by disk ("Disk inserted"), or the
  // user fetches from the network instead.
  function fmtSecs(x) { var t = Math.round(x || 0); if (t >= 3600) { return Math.floor(t / 3600) + " h " + Math.floor(t / 60) % 60 + " min"; } if (t >= 60) { return Math.floor(t / 60) + " min"; } return t + " s"; }
  function planCost(cost, currency) { return cost === null || cost === undefined ? "price unknown" : cost.toFixed(2) + " " + (currency || ""); }
  function runDiskPlan(folder, path, plan, note) {
    var k = -1;
    for (var i = 0; i < plan.steps.length; i++) { if (plan.steps[i].state === "pending") { k = i; break; } }
    if (k < 0) { planNetwork(folder, path); return; }
    var s = plan.steps[k], r = plan.remote;
    dialog({ title: "Fetch from disks", text: " ", ok: s.attached ? "Copy from the disk" : "Disk inserted", extra: r.possible ? "Fetch from the network instead" : "", cancel: "Stop" }).then(function (a) {
      if (!a) { api("POST", "/api/fetch/plan/cancel", {}).catch(function () {}); log(path + ": stopped; nothing more is fetched from the disks"); return; }
      if (a.action === "extra") { planNetwork(folder, path); return; }
      busy(true);
      api("POST", "/api/fetch/plan/step", { step: k }).then(function (res) {
        busy(false);
        if (res.needs_disk) { runDiskPlan(folder, path, plan, "Disk " + s.label + " was not found: insert it and try again."); return; }
        // The file system check before mounting left errors: nothing was mounted; stop here.
        if (res.fsck_failed) { log(res.error); $("needsdisk").textContent = res.error; $("needsdisk").classList.remove("hidden"); return; }
        log(res.outcome.message);
        if (res.finished) { log("fetched " + path); loadFiles(); return; }
        runDiskPlan(folder, path, res.plan, res.outcome.message);
      }).catch(function (e) { busy(false); log("fetch failed: " + e.message); });
    });
    // The text: one sentence per element, so each is translated on its own.
    var tx = $("modal-text"); tx.innerHTML = "";
    function line(t, cls) { var d = el("div", cls || "", t); tx.appendChild(d); return d; }
    if (note) { line(note, "notice"); }
    line(plan.reason);
    plan.steps.forEach(function (st, i) {
      var d = line((i + 1) + ". " + st.label + " (" + st.place + "), " + fmtBytes(st.bytes), i === k ? "strong" : "muted");
      var state = st.state === "done" ? "done" : st.state === "skipped" ? "skipped" : st.attached ? "attached" : "";
      if (state) { d.appendChild(document.createTextNode(" ")); d.appendChild(el("span", "", state)); }
    });
    line(s.attached ? "Disk " + s.label + " is attached: choose Copy from the disk." : "Insert disk " + s.label + " (" + s.place + ") into the dock, then choose Disk inserted.");
    line(r.possible ? "From the network instead: " + fmtBytes(r.bytes) + ", " + planCost(r.cost, r.currency) + ", about " + fmtSecs(r.secs) + "." : "The network does not have every block: the disks are needed.", "muted");
  }
  function planNetwork(folder, path) {
    busy(true);
    api("POST", "/api/fetch/plan/network", {}).then(function (res) {
      (res.files_failed || []).forEach(function (f) { log(f.path + ": " + f.error); });
      if (res.finished) { log("fetched " + path); }
    }).catch(function (e) { log("fetch failed: " + e.message); }).then(function () { busy(false); loadFiles(); });
  }
  function fetchFile(folder, path) {
    busy(true); $("needsdisk").classList.add("hidden");
    api("POST", "/api/fetch", { folder: folder, path: path }).then(function (r) {
      if (r.plan) { runDiskPlan(folder, path, r.plan, ""); return; }
      if (r.needs_disk) {
        var msg = "This file is on disk " + r.needs_disk.label + " (" + r.needs_disk.place + "). Attach it and try again.";
        $("needsdisk").textContent = msg; $("needsdisk").classList.remove("hidden"); log(path + ": " + msg);
        return;
      }
      log("fetched " + path);
    }).catch(function (e) { log("fetch failed: " + e.message); }).then(function () { busy(false); loadFiles(); });
  }
  function freeFile(folder, path) { api("POST", "/api/free", { folder: folder, path: path }).then(function () { log(path + " is now a placeholder"); }).catch(function (e) { log("free failed: " + e.message); }).then(function () { loadFiles(); refreshStatus(); }); }
  function freeFolder(folder) { busy(true); api("POST", "/api/free", { folder: folder }).then(function (r) { log(folder + ": removed " + r.freed + " local cop" + (r.freed === 1 ? "y" : "ies") + (r.kept ? ", kept " + r.kept + " not yet stored elsewhere" : "")); }).catch(function (e) { log("free failed: " + e.message); }).then(function () { busy(false); loadFiles(); refreshStatus(); }); }
  // Phones: a compact list like Resilio Sync. A tap opens a file; a long
  // press starts selecting, then taps add or remove files, and the bar at
  // the bottom downloads or frees all of them.
  var multi = { on: false, sel: {}, rows: [] };
  function selPaths() { return Object.keys(multi.sel); }
  function renderSel() {
    var n = selPaths().length;
    if (multi.on && n === 0) { multi.on = false; }
    $("selbar").classList.toggle("hidden", !multi.on);
    $("files").classList.toggle("selecting", multi.on);
    $("sel-count").textContent = n + " selected";
    document.querySelectorAll("#files tbody tr[data-path]").forEach(function (tr) { var on = !!multi.sel[tr.dataset.path]; tr.classList.toggle("picked", on); tr.setAttribute("aria-selected", on ? "true" : "false"); });
    var files = selPaths().map(function (p) { return multi.sel[p]; });
    $("sel-download").disabled = !files.some(function (f) { return f.state === "placeholder" || f.state === "missing"; });
    $("sel-free").disabled = !files.some(function (f) { return f.state === "local"; });
  }
  function togglePick(f) { if (multi.sel[f.path]) { delete multi.sel[f.path]; } else { multi.sel[f.path] = f; } renderSel(); }
  function endSelect() { multi.on = false; multi.sel = {}; renderSel(); }
  $("sel-cancel").onclick = endSelect;
  $("sel-all").onclick = function () { multi.rows.forEach(function (f) { multi.sel[f.path] = f; }); renderSel(); };
  function eachSelected(want, fn, done) {
    var folder = $("filesfolder").value; var list = selPaths().map(function (p) { return multi.sel[p]; }).filter(want);
    endSelect(); busy(true);
    var chain = Promise.resolve();
    list.forEach(function (f) { chain = chain.then(function () { return fn(folder, f).catch(function (e) { log(f.path + ": " + e.message); }); }); });
    return chain.then(function () { busy(false); log(done(list.length)); loadFiles(); refreshStatus(); });
  }
  $("sel-download").onclick = function () { eachSelected(function (f) { return f.state === "placeholder" || f.state === "missing"; }, function (folder, f) { return api("POST", "/api/fetch", { folder: folder, path: f.path }); }, function (n) { return "downloaded " + n + " file" + (n === 1 ? "" : "s"); }); };
  $("sel-free").onclick = function () { eachSelected(function (f) { return f.state === "local"; }, function (folder, f) { return api("POST", "/api/free", { folder: folder, path: f.path }); }, function (n) { return "freed " + n + " file" + (n === 1 ? "" : "s") + " on this device"; }); };
  // Long press: about half a second without moving the finger.
  function onLongPress(node, fn) {
    var timer = null, fired = false, x = 0, y = 0;
    node.addEventListener("touchstart", function (e) { fired = false; var t = e.touches[0]; x = t.clientX; y = t.clientY; timer = setTimeout(function () { fired = true; timer = null; if (navigator.vibrate) { navigator.vibrate(15); } fn(); }, 480); }, { passive: true });
    node.addEventListener("touchmove", function (e) { var t = e.touches[0]; if (timer && (Math.abs(t.clientX - x) > 10 || Math.abs(t.clientY - y) > 10)) { clearTimeout(timer); timer = null; } }, { passive: true });
    node.addEventListener("touchend", function (e) { if (timer) { clearTimeout(timer); timer = null; } if (fired) { e.preventDefault(); } });
    node.addEventListener("contextmenu", function (e) { e.preventDefault(); if (!fired) { fn(); } });
    return function () { return fired; };
  }
  $("files-download").onclick = function () { if (selectedFile) { fetchFile($("filesfolder").value, selectedFile.path); } };
  $("files-free").onclick = function () { var folder = $("filesfolder").value; if (selectedFile) { freeFile(folder, selectedFile.path); } else if (folder) { freeFolder(folder); } };
  $("files-share").onclick = function () { var f = folderByName($("filesfolder").value); if (f) { shareFolder(f); } };

  // Adding files: each chosen file goes up as a raw POST /api/upload body; new subfolders made in
  // this session are shown as rows (the ledger lists files only) so files can be added into them.
  var uploadPrefix = "";
  var newDirs = {};
  $("files-upload").onclick = function () { uploadPrefix = ""; $("fileinput").click(); };
  $("fileinput").onchange = function () { var files = Array.prototype.slice.call($("fileinput").files || []); $("fileinput").value = ""; uploadFiles($("filesfolder").value, files, uploadPrefix); };
  // Adding files: a line per file ("Adding 2 of 6: name") and a bar for that
  // file. The bar first follows the file going to the service on this device,
  // then its blocks going to the storages (`/api/progress`, answered while
  // the upload holds the vault).
  function uploadFiles(folder, files, prefix) {
    if (!folder || !files.length) { return; }
    var prog = $("files-progress"); prog.classList.remove("hidden"); prog.textContent = "";
    var line = el("div", "upload-line", ""); var bar = el("div", "upload-bar", ""); var fill = el("span", "", ""); bar.appendChild(fill);
    var sub = el("div", "upload-sub muted small", "");
    prog.appendChild(line); prog.appendChild(bar); prog.appendChild(sub);
    function show(pct, text) { fill.style.width = Math.max(0, Math.min(100, pct)) + "%"; sub.textContent = text || ""; }
    var done = 0, failed = 0; busy(true);
    function sendOne(f, rel) {
      return new Promise(function (resolve, reject) {
        var x = new XMLHttpRequest();
        x.open("POST", "/api/upload?folder=" + enc(folder) + "&path=" + enc(rel));
        x.setRequestHeader("X-Varsto-Token", token); x.setRequestHeader("Content-Type", "application/octet-stream");
        var poll = null;
        x.upload.onprogress = function (e) { if (e.lengthComputable) { show(e.loaded / e.total * 50, "Reading " + fmtBytes(e.loaded) + " of " + fmtBytes(e.total)); } };
        x.upload.onload = function () {
          show(50, "Encrypting and sending to the storages");
          poll = setInterval(function () {
            api("GET", "/api/progress").then(function (p) {
              var t = (p.transfers || []).filter(function (t) { return t.kind === "upload" && t.folder === folder && t.path === rel; })[0];
              if (t) { show(50 + t.percent / 2, "Sending to the storages: " + fmtBytes(t.done) + " of " + fmtBytes(t.total) + (t.bytes_per_sec ? ", " + fmtBytes(t.bytes_per_sec) + "/s" : "")); }
            }).catch(function () {});
          }, 700);
        };
        function end() { if (poll) { clearInterval(poll); } }
        x.onload = function () { end(); var j = {}; try { j = JSON.parse(x.responseText); } catch (e) { /* not JSON */ } if (x.status >= 200 && x.status < 300) { resolve(j); } else { reject(new Error(j.error || x.statusText || ("HTTP " + x.status))); } };
        x.onerror = function () { end(); reject(new Error("the connection to Varsto was lost")); };
        x.send(f);
      });
    }
    function step(i) {
      if (i >= files.length) {
        prog.textContent = failed ? done + " of " + files.length + " files added to " + folder + "; " + failed + " failed" : files.length + " file" + (files.length === 1 ? "" : "s") + " added to " + folder + (prefix ? "/" + prefix : "");
        setTimeout(function () { prog.classList.add("hidden"); }, 4000);
        busy(false); loadFiles();
        return runSync(folder);
      }
      var f = files[i]; var rel = (prefix ? prefix + "/" : "") + f.name;
      line.textContent = "Adding " + (i + 1) + " of " + files.length + ": " + f.name + " (" + fmtBytes(f.size) + ")";
      show(0, "");
      return sendOne(f, rel)
        .then(function (j) { done++; show(100, ""); log("added " + rel + " (" + fmtBytes(f.size) + ") to " + folder + (j.push ? "; " + j.push.chunks_uploaded + " chunks pushed" : "")); })
        .catch(function (e) { failed++; log("adding " + rel + " failed: " + e.message); })
        .then(function () { return step(i + 1); });
    }
    return step(0);
  }
  $("files-mkdir").onclick = function () {
    var folder = $("filesfolder").value; if (!folder) { return; }
    dialog({ title: "New folder in " + folder, fields: [{ name: "name", label: "Name", placeholder: "Receipts", required: true }], ok: "Create" }).then(function (r) {
      if (!r) { return; }
      var name = r.values.name.trim().replace(/^\/+|\/+$/g, "");
      if (!name || name.indexOf("..") >= 0) { return alertBox("Please give a plain folder name."); }
      return api("POST", "/api/mkdir", { folder: folder, path: name }).then(function () {
        (newDirs[folder] = newDirs[folder] || []).push(name);
        log("created " + name + " in " + folder + "; it is listed on other devices once a file is in it");
        loadFiles();
      });
    }).catch(function (e) { alertBox(e.message); });
  };
  function loadFiles() {
    var folder = $("filesfolder").value; if (!folder) { return; }
    filesLoadedFor = folder;
    var keep = selectedFile ? selectedFile.path : null;
    api("GET", "/api/files?folder=" + enc(folder)).then(function (rows) {
      var words = ($("files-filter").value || "").toLowerCase().split(/\s+/).filter(Boolean);
      var filtered = words.length > 0;
      if (filtered) { rows = rows.filter(function (f) { return matchesFilter(f, words); }); }
      var tb = $("files").querySelector("tbody"); tb.innerHTML = "";
      var dirs = (newDirs[folder] || []).filter(function (d) { return !rows.some(function (r) { return r.path.indexOf(d + "/") === 0; }); });
      var empty = $("files-empty");
      empty.querySelector(".empty-title").textContent = rows.length || dirs.length ? "" : filtered ? "No files match the filter" : "This folder is empty";
      empty.querySelector(".muted").textContent = rows.length || dirs.length || filtered ? "" : "Add files here, or put them in " + folder + " on any device; they appear after a sync.";
      empty.classList.toggle("hidden", rows.length > 0 || dirs.length > 0);
      dirs.forEach(function (d) {
        var tr = document.createElement("tr"); tr.className = "dir-row";
        var nameCell = document.createElement("td"); var wrap = el("span", "file-name"); var fi = el("span", "file-icon"); fi.appendChild(icon("folders")); wrap.appendChild(fi); wrap.appendChild(document.createTextNode(d + "/")); nameCell.appendChild(wrap); tr.appendChild(nameCell);
        var sz = document.createElement("td"); sz.className = "num muted"; sz.textContent = "–"; tr.appendChild(sz);
        var st = document.createElement("td"); st.appendChild(pill("grey", "Empty folder")); tr.appendChild(st);
        var lu = document.createElement("td"); lu.className = "muted"; lu.textContent = "New"; tr.appendChild(lu);
        var act = document.createElement("td"); var ab = el("button", "secondary"); ab.type = "button"; ab.appendChild(icon("upload")); ab.appendChild(document.createTextNode("Add files")); ab.onclick = function (ev) { ev.stopPropagation(); uploadPrefix = d; $("fileinput").click(); }; act.appendChild(ab); tr.appendChild(act);
        tb.appendChild(tr);
      });
      var reselect = null;
      var viewable = isMobile() && encryptedHere(folder) ? rows.filter(function (r) { return r.state !== "missing" && viewKind(r.path); }) : [];
      var compact = isMobile();
      multi.rows = rows;
      Object.keys(multi.sel).forEach(function (p) { var still = rows.filter(function (r) { return r.path === p; })[0]; if (still) { multi.sel[p] = still; } else { delete multi.sel[p]; } });
      $("files").classList.toggle("compact", compact);
      rows.forEach(function (f) {
        var tr = document.createElement("tr"); tr.dataset.path = f.path;
        if (compact) {
          tr.className = "mrow";
          var cell = document.createElement("td"); var row = el("div", "mrow-in");
          var pick = el("span", "mrow-pick"); pick.setAttribute("aria-hidden", "true"); row.appendChild(pick);
          var media = el("span", "mrow-thumb");
          if (f.media) { var mi = document.createElement("img"); mi.alt = ""; mi.loading = "lazy"; mi.src = "/api/thumb?folder=" + enc(folder) + "&path=" + enc(f.path) + "&token=" + enc(token); mi.onerror = function () { mi.replaceWith(icon("image")); }; media.appendChild(mi); } else { media.appendChild(icon("files")); }
          row.appendChild(media);
          var slash = f.path.lastIndexOf("/");
          var body = el("div", "mrow-body");
          body.appendChild(el("div", "mrow-name", showName(slash >= 0 ? f.path.slice(slash + 1) : f.path)));
          body.appendChild(el("div", "mrow-sub", [slash >= 0 ? showName(f.path.slice(0, slash)) : null, fmtBytes(f.size), fileStateLabel(f)].filter(Boolean).join(" · ")));
          row.appendChild(body);
          row.appendChild(stateSquare(f));
          cell.appendChild(row); tr.appendChild(cell); tb.appendChild(tr);
          var mvi = viewable.indexOf(f);
          var wasLong = onLongPress(tr, function () { multi.on = true; togglePick(f); });
          tr.onclick = function () {
            if (wasLong()) { return; }
            if (multi.on) { togglePick(f); return; }
            if (mvi >= 0) { openViewer(folder, viewable, mvi); } else if (selectedFile && selectedFile.path === f.path) { clearSelection(); } else { selectFile(f, tr); }
          };
          if (keep && f.path === keep) { reselect = { f: f, tr: tr }; }
          return;
        }
        function td(t, cls, label) { var d = document.createElement("td"); d.textContent = t; if (cls) { d.className = cls; } if (label) { d.dataset.label = label; } tr.appendChild(d); }
        var nameCell = document.createElement("td"); var wrap = el("span", "file-name");
        wrap.appendChild(stateSquare(f));
        if (f.media) { var im = document.createElement("img"); im.className = "thumb"; im.alt = ""; im.loading = "lazy"; im.src = "/api/thumb?folder=" + enc(folder) + "&path=" + enc(f.path) + "&token=" + enc(token); im.onerror = function () { var fi = el("span", "file-icon"); fi.appendChild(icon("image")); im.replaceWith(fi); }; wrap.appendChild(im); }
        else { var fi = el("span", "file-icon"); fi.appendChild(icon("files")); wrap.appendChild(fi); }
        var fname = el("span", null, showName(f.path)); fname.setAttribute("data-no-i18n", ""); wrap.appendChild(fname);
        if (f.analysis) { var ap = pill(f.analysis_stale ? "risk" : "accent", f.analysis_stale ? "Analysis stale" : "Analysed"); ap.title = f.analysis.slice(0, 200); ap.classList.add("analysis-pill"); wrap.appendChild(ap); }
        nameCell.appendChild(wrap); tr.appendChild(nameCell);
        td(fmtBytes(f.size), "num");
        var st = document.createElement("td"); st.appendChild(pill(f.state === "placeholder" ? "grey" : f.state === "missing" ? "bad" : "ok", fileStateLabel(f))); tr.appendChild(st);
        td(f.last_accessed_utc ? fmtDate(f.last_accessed_utc) : "Never here", f.last_accessed_utc ? "" : "muted", "Last used");
        var act = document.createElement("td");
        fileActions(folder, f, false).forEach(function (b) { act.appendChild(b); });
        tr.appendChild(act); tb.appendChild(tr);
        var vi = viewable.indexOf(f);
        tr.onclick = vi >= 0 ? function () { openViewer(folder, viewable, vi); } : function () { if (selectedFile && selectedFile.path === f.path && tr.classList.contains("selected")) { clearSelection(); } else { selectFile(f, tr); } };
        if (keep && f.path === keep) { reselect = { f: f, tr: tr }; }
      });
      if (reselect) { selectFile(reselect.f, reselect.tr); } else { clearSelection(); }
      renderSel();
    }).catch(function (e) { log("error: " + e.message); });
  }
  $("filesfolder").onchange = function () { multi.sel = {}; multi.on = false; markTree($("filesfolder").value); updateFilesHead(); clearSelection(); setScreen("folder"); loadFiles(); if (!$("recentchanges").classList.contains("hidden")) { loadRecentChanges(); } };
  $("selectivetoggle").onchange = function () { api("POST", "/api/selective", { folder: $("filesfolder").value, on: $("selectivetoggle").checked }).then(function () { log("selective sync " + ($("selectivetoggle").checked ? "on" : "off")); return refreshStatus(); }).catch(function (e) { log("error: " + e.message); }); };
  // ----- Folder settings: ignore rules and file metadata -----
  // The shared rules are the folder's .varstoignore (synced like any file);
  // the local ones stay in this device's configuration. Testing a path uses
  // what is being edited, saved or not.
  var fsEdit = null;
  function fsLines(text) { return text.split("\n").map(function (l) { return l.replace(/\s+$/, ""); }); }
  function fsRenderLocal() {
    var ul = $("fs-local"); ul.innerHTML = "";
    fsEdit.local.forEach(function (p, i) {
      var li = el("li"); li.appendChild(el("span", "", p));
      var b = el("button", "secondary", "Remove"); b.type = "button";
      b.onclick = function () { fsEdit.local.splice(i, 1); fsRenderLocal(); };
      li.appendChild(b); ul.appendChild(li);
    });
    $("fs-local-empty").classList.toggle("hidden", fsEdit.local.length > 0);
  }
  function fsRenderSuggestions() {
    var box = $("fs-suggestions"); box.innerHTML = "";
    var have = fsLines($("fs-synced").value);
    fsEdit.suggested.filter(function (p) { return have.indexOf(p) < 0; }).forEach(function (p) {
      var b = el("button", "secondary", p); b.type = "button"; b.title = "Add to the shared rules";
      b.onclick = function () { var t = $("fs-synced").value; $("fs-synced").value = t + (t && !/\n$/.test(t) ? "\n" : "") + p + "\n"; fsRenderSuggestions(); };
      box.appendChild(b);
    });
    if (!box.childNodes.length) { box.appendChild(el("span", "muted", "all added")); }
  }
  function openFolderSettings() {
    var folder = $("filesfolder").value;
    if (!folder) { return; }
    Promise.all([api("GET", "/api/folder/ignore?folder=" + enc(folder)), api("GET", "/api/folder/settings?folder=" + enc(folder))]).then(function (r) {
      var ig = r[0], st = r[1];
      fsEdit = { folder: folder, local: ig.local.slice(), suggested: ig.suggested, original: ig.synced, applies: ig.applies_here };
      $("fs-folder").textContent = folder;
      $("fs-synced").value = ig.synced;
      $("fs-synced").disabled = !ig.applies_here;
      $("fs-encrypted").classList.toggle("hidden", ig.applies_here);
      $("fs-nested").textContent = ig.nested.length ? "Rules also in subfolders: " + ig.nested.join(", ") : "";
      $("fs-nested").classList.toggle("hidden", !ig.nested.length);
      fsRenderLocal(); fsRenderSuggestions();
      $("fs-test-result").textContent = "";
      ["permissions", "symlinks", "xattrs", "ownership"].forEach(function (k) { $("fs-" + k).checked = !!st.settings[k]; });
      var caps = st.caps, cannot = [];
      if (caps.mode === "None") { cannot.push("This system cannot keep permissions."); } else if (caps.mode === "ReadOnly") { cannot.push("This system keeps only the read-only flag of permissions."); }
      if (!caps.symlinks) { cannot.push("This system cannot create symbolic links."); }
      if (!caps.xattrs) { cannot.push("This system cannot keep extended attributes."); }
      if (!caps.owner) { cannot.push("This system cannot keep ownership."); }
      if (cannot.length) { cannot.push("What other devices set stays as it is."); }
      var capsBox = $("fs-caps"); capsBox.innerHTML = "";
      cannot.forEach(function (c) { capsBox.appendChild(el("span", "", c)); capsBox.appendChild(document.createTextNode(" ")); });
      $("foldersettings").classList.remove("hidden");
      $("foldersettings").scrollIntoView({ block: "nearest" });
    }).catch(function (e) { log("error: " + e.message); });
  }
  function closeFolderSettings() { fsEdit = null; $("foldersettings").classList.add("hidden"); }
  $("files-settings").onclick = function () { if (fsEdit && fsEdit.folder === $("filesfolder").value) { closeFolderSettings(); } else { openFolderSettings(); } };
  $("fs-close").onclick = closeFolderSettings;
  $("fs-cancel").onclick = closeFolderSettings;
  $("fs-synced").oninput = function () { if (fsEdit) { fsRenderSuggestions(); } };
  function fsAddLocal() {
    var p = $("fs-local-add").value.replace(/\s+$/, "");
    if (!p.trim() || !fsEdit) { return; }
    if (fsEdit.local.indexOf(p) < 0) { fsEdit.local.push(p); }
    $("fs-local-add").value = ""; fsRenderLocal();
  }
  $("fs-local-addbtn").onclick = fsAddLocal;
  $("fs-local-add").onkeydown = function (ev) { if (ev.key === "Enter") { ev.preventDefault(); fsAddLocal(); } };
  function fsTest() {
    var path = $("fs-test").value.trim();
    if (!path || !fsEdit) { return; }
    var body = { folder: fsEdit.folder, path: path, local: fsEdit.local };
    if (fsEdit.applies) { body.synced = $("fs-synced").value; }
    api("POST", "/api/folder/check-ignore", body).then(function (v) {
      var out = $("fs-test-result"); out.innerHTML = "";
      if (!v.pattern) { out.appendChild(el("span", "", "Not ignored: no pattern matches.")); return; }
      var sep = function () { out.appendChild(document.createTextNode(" · ")); };
      out.appendChild(el("strong", "", v.ignored ? "Ignored" : "Included")); sep();
      out.appendChild(el("span", "", "pattern")); out.appendChild(document.createTextNode(" ")); out.appendChild(el("code", "", v.pattern)); sep();
      if (v.source === "local") { out.appendChild(el("span", "", "this device's rules")); } else { out.appendChild(el("code", "", v.source)); }
      sep(); out.appendChild(el("span", "", "line " + v.line));
      if (v.matched_path && v.matched_path !== path.replace(/^\/+|\/+$/g, "")) {
        sep(); out.appendChild(el("span", "", "through the folder")); out.appendChild(document.createTextNode(" ")); out.appendChild(el("code", "", v.matched_path + "/"));
      }
    }).catch(function (e) { $("fs-test-result").textContent = e.message; });
  }
  $("fs-testbtn").onclick = fsTest;
  $("fs-test").onkeydown = function (ev) { if (ev.key === "Enter") { ev.preventDefault(); fsTest(); } };
  $("fs-save").onclick = function () {
    if (!fsEdit) { return; }
    var folder = fsEdit.folder;
    var body = { folder: folder, local: fsEdit.local };
    if (fsEdit.applies && $("fs-synced").value !== fsEdit.original) { body.synced = $("fs-synced").value; }
    var settings = { folder: folder };
    ["permissions", "symlinks", "xattrs", "ownership"].forEach(function (k) { settings[k] = $("fs-" + k).checked; });
    api("POST", "/api/folder/ignore", body).then(function () {
      return api("POST", "/api/folder/settings", settings);
    }).then(function () {
      log("folder settings saved for " + folder);
      closeFolderSettings(); loadFiles();
    }).catch(function (e) { log("error: " + e.message); });
  };
  $("dupes").onclick = function () {
    api("GET", "/api/dupes?folder=" + enc($("dupefolder").value)).then(function (g) {
      $("dupeout").textContent = g.length ? g.map(function (x) { return fmtBytes(x.size) + ": " + x.paths.join(", "); }).join("\n") : "no duplicates";
    }).catch(function (e) { log("dupes failed: " + e.message); });
  };
  $("unlockform").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/unlock", formData(ev.target)).then(function () { ev.target.reset(); return refreshState(); }).catch(function (e) { alertBox(e.message); }); };
  $("init").onsubmit = function (ev) {
    ev.preventDefault();
    api("POST", "/api/init", formData(ev.target)).then(function (r) {
      ev.target.reset();
      // The key is shown once: in a dialog now, and on the overview until the user confirms.
      $("vaultkey-text").textContent = "Vault key (shown once, write it down and keep it offline): " + r.vault_key;
      $("vaultkey").classList.remove("hidden");
      return dialog({ title: "Your vault key", text: "Write it down and keep it offline: it is the only way to add other devices or recover the data. It is shown once.", code: r.vault_key, ok: "Continue", cancel: false }).then(function () { return refreshState(); });
    }).catch(function (e) { alertBox(e.message); });
  };
  $("vaultkey-done").onclick = function () { $("vaultkey").classList.add("hidden"); $("vaultkey-text").textContent = ""; };
  // Where the joined vault lives: a bucket is the only choice on a phone.
  function applyJoinKind() { var k = $("joinkind").value; document.querySelectorAll("#join [data-joinkind]").forEach(function (d) { d.classList.toggle("hidden", d.getAttribute("data-joinkind") !== k); }); document.querySelectorAll("#join [data-joinkind] input").forEach(function (i) { i.required = !i.closest("[data-joinkind]").classList.contains("hidden") && i.name !== "region"; }); }
  $("joinkind").onchange = applyJoinKind;
  function applyShareKind() { var k = $("sharekind").value; document.querySelectorAll("#acceptshare [data-sharekind]").forEach(function (d) { d.classList.toggle("hidden", d.getAttribute("data-sharekind") !== k); }); document.querySelectorAll("#acceptshare [data-sharekind] input").forEach(function (i) { i.required = !i.closest("[data-sharekind]").classList.contains("hidden") && i.name !== "region"; }); }
  $("sharekind").onchange = applyShareKind;
  applyShareKind();
  function joinKindForDevice() { if (isMobile()) { $("joinkind").value = "s3"; $("joinkind").querySelector('option[value="local-dir"]').disabled = true; } applyJoinKind(); }
  joinKindForDevice();
  // The code field opens the number pad (type=tel) and groups the digits as typed.
  $("pair").querySelector("input[name=code]").addEventListener("input", function (ev) {
    var d = ev.target.value.replace(/[^0-9]/g, "").slice(0, 9);
    ev.target.value = d.replace(/^(\d{3})(\d{1,3})?(\d{1,3})?$/, function (m, a, b, c) { return a + (b ? "-" + b : "") + (c ? "-" + c : ""); });
  });
  $("pair").onsubmit = function (ev) {
    ev.preventDefault(); var d = formData(ev.target); busy(true); log("looking for the device showing code " + d.code);
    api("POST", "/api/pair/join", d).then(function (r) { ev.target.reset(); log("paired with " + r.from + ": " + r.storages.join("; ")); nav("files"); return refreshState(); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); });
  };
  // Adding a device: show the code until the new device has fetched the vault.
  var pairTimer = null;
  function pairButtons(open) { $("pairstart").classList.toggle("hidden", open); $("pairstop").classList.toggle("hidden", !open); }
  function renderPair(s) {
    $("pairbox").classList.remove("hidden"); pairButtons(s.open); $("paircode").textContent = s.open ? s.code : "";
    renderQr($("pairqr"), s.open ? s.uri : "").catch(function () {});
    if (s.open) {
      $("pairinfo").textContent = "On the new device choose Pair with your other device and type this code. It works once, for " + Math.max(1, Math.ceil(s.expires_in_secs / 60)) + " more minute(s)." + (s.addresses.length ? " If the new device does not find this one, give it the address " + s.addresses.join(" or ") + "." : "") + (s.failed_attempts ? " Wrong codes so far: " + s.failed_attempts + " of 3." : "");
      return;
    }
    if (pairTimer) { clearInterval(pairTimer); pairTimer = null; }
    $("pairinfo").textContent = s.paired_with ? "Sent the vault to " + s.paired_with + ". It appears among the devices after its first sync." : "The code is no longer valid (" + (s.closed_reason || "closed") + "). Choose Add a device for a new one.";
    if (s.paired_with) { log("added device " + s.paired_with); }
  }
  function pollPair() { api("GET", "/api/pair/status").then(function (s) { if (s.code) { renderPair(s); if (s.open && !pairTimer) { pairTimer = setInterval(pollPair, 1500); } } }).catch(function () {}); }
  if (token) { pollPair(); }
  $("pairstart").onclick = function () { api("POST", "/api/pair/start", {}).then(function (s) { renderPair(s); if (!pairTimer) { pairTimer = setInterval(pollPair, 1500); } }).catch(function (e) { alertBox(e.message); }); };
  $("pairscan").onclick = function () { scanQr("pair").then(function (info) { if (info) { fillPair(info); } }); };
  $("sharetokenscan").onclick = function () {
    scanQr("token").then(function (info) { if (info) { $("acceptshare").querySelector("input[name=token]").value = info.text; log("scanned the sealed share token for " + info.folder); } });
  };
  $("pairstop").onclick = function () { api("POST", "/api/pair/stop", {}).then(function () { if (pairTimer) { clearInterval(pairTimer); pairTimer = null; } $("pairbox").classList.add("hidden"); pairButtons(false); }).catch(function (e) { alertBox(e.message); }); };
  $("join").onsubmit = function (ev) { ev.preventDefault(); busy(true); api("POST", "/api/join", formData(ev.target)).then(function () { ev.target.reset(); log("joined the vault; attach folders under Files"); nav("files"); return refreshState(); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); }); };
  $("replicatoken").onclick = function () { api("GET", "/api/replica/token").then(function (r) { $("replicaout").textContent = "Replica token (give to the device that will hold your encrypted copies without being able to open them): " + r.token; $("replicaout").classList.remove("hidden"); }).catch(function (e) { alertBox(e.message); }); };
  $("sharerequest").onclick = function () {
    var nm = $("acceptshare").querySelector("input[name=name]");
    api("POST", "/api/share/request", { name: nm ? nm.value.trim() : "" }).then(function (r) {
      $("sharerequestout").textContent = r.request_code + "\n\nFingerprint: " + r.fingerprint + "\nThe owner sees the same six words for this code. Read them to each other over a call or in person before the owner shares.";
      $("sharerequestout").classList.remove("hidden");
      return renderQr($("sharerequestqr"), r.request_code);
    }).catch(function (e) { alertBox(e.message); });
  };
  // Organization (business use): nothing of it shows for a vault without one.
  $("orgrequest").onclick = function () {
    var nm = $("orgjoin").querySelector("input[name=name]");
    if (!nm.value.trim()) { nm.focus(); return alertBox("Give the device a name first: it is part of the code and the fingerprint."); }
    api("POST", "/api/org/request", { name: nm.value.trim() }).then(function (r) {
      $("orgrequestout").textContent = r.request_code + "\n\nFingerprint: " + r.fingerprint + "\nThe administrator sees the same six words for this code. Read them to each other over a call or in person before they approve.";
      $("orgrequestout").classList.remove("hidden");
    }).catch(function (e) { alertBox(e.message); });
  };
  $("orgjoin").onsubmit = function (ev) { ev.preventDefault(); busy(true); api("POST", "/api/org/join", formData(ev.target)).then(function (r) { ev.target.reset(); $("orgrequestout").classList.add("hidden"); log("joined the vault of " + r.organization + " for " + r.user + "; attach folders under Files"); nav("files"); return refreshState(); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); }); };
  $("orgcreate").onclick = function () {
    dialog({
      title: "Set up an organization",
      text: "This device becomes the first administrator and every device in the vault today belongs to the person you name. You will be shown the organization's root words once: they appoint and dismiss administrators and are not stored on any device.",
      fields: [{ name: "name", label: "Organization name", placeholder: "Acme", required: true }, { name: "user", label: "Your user name (owner of the current devices)", placeholder: "alice", required: true }],
      ok: "Create"
    }).then(function (r) {
      if (!r) { return; }
      busy(true);
      return api("POST", "/api/org/create", { name: r.values.name.trim(), user: r.values.user.trim() }).then(function (c) {
        log("organization " + c.name + " created");
        return dialog({ title: "Root words of " + c.name, text: "Write these down and keep them offline, away from the vault's recovery kit. They are not stored on any device and are needed only to appoint or dismiss administrators.", code: c.root_words, ok: "I wrote them down", cancel: false });
      }).then(function () { return refreshStatus(); }).then(function () { nav("organization"); }).catch(function (e) { alertBox(e.message, "Could not create the organization"); }).then(function () { busy(false); });
    });
  };
  var lastOrg = null;
  var PLATFORM_NAMES = { linux: "Linux", macos: "macOS", windows: "Windows", android: "Android", ios: "iOS" };
  // "this organization (Acme) does not allow Windows devices" as a sentence.
  function orgBlockedText(why) { return why.charAt(0).toUpperCase() + why.slice(1) + ". This device does not sync or open the vault until an administrator allows it."; }
  function orgDevice(d, admin, user) {
    var li = el("li"); var body = el("div", "li-body"); var title = el("div", "li-title", d.name);
    if (d.admin) { title.appendChild(pill("accent", "admin")); }
    if (d.this_device) { title.appendChild(pill("grey", "This device")); }
    if (d.revoked) { title.appendChild(pill("risk", "Removed")); }
    if (d.refused && !d.revoked) { var lp = pill("risk", "Locked out"); lp.title = "The organization " + d.refused; title.appendChild(lp); }
    body.appendChild(title);
    body.appendChild(el("div", "li-sub", [deviceSystem(d) || PLATFORM_NAMES[d.platform] || d.platform || "", d.added_utc ? "added " + fmtDate(d.added_utc) : "", d.device_id.slice(0, 8)].filter(Boolean).join(" · ")));
    li.appendChild(body);
    if (admin && !d.this_device && !d.revoked && user) {
      var a = el("div", "li-actions"); var b = el("button", "secondary danger small", "Remove device…"); b.type = "button";
      b.onclick = function () { removeDevice({ device_id: d.device_id, name: d.name }); }; a.appendChild(b); li.appendChild(a);
    }
    return li;
  }
  function loadOrg() {
    if (document.body.dataset.view !== "app") { return; }
    api("GET", "/api/org").then(function (o) {
      if (o.exists === false) { lastOrg = null; nav("settings"); return; }
      lastOrg = o;
      var admin = !!o.this_device_admin;
      $("org-name").textContent = o.name;
      $("org-me").textContent = "Organization " + o.org_id.slice(0, 8) + " · this device is " + (admin ? "an administrator" : o.this_device_listed ? "a member" : "not in the organization") + (o.this_user ? ", owned by " + o.this_user : "") + " · " + o.users.length + (o.users.length === 1 ? " person" : " people") + ", " + o.admins.length + (o.admins.length === 1 ? " administrator" : " administrators");
      $("org-unlisted-note").classList.toggle("hidden", o.this_device_listed);
      $("org-unlisted-note").textContent = o.this_device_listed ? "" : "This device is not in the organization yet: the other devices ignore what it writes until an administrator adds it (Organization page on their device, or varsto org add-device).";
      $("org-blocked-note").textContent = o.this_device_blocked ? orgBlockedText(o.this_device_blocked) : "";
      $("org-blocked-note").classList.toggle("hidden", !o.this_device_blocked);
      var ul = $("org-users"); ul.innerHTML = "";
      o.users.forEach(function (u) {
        var li = el("li"); var body = el("div", "li-body"); var title = el("div", "li-title", u.user); body.appendChild(title);
        var sub = el("ul", "list compact-list"); u.devices.forEach(function (d) { sub.appendChild(orgDevice(d, admin, u.user)); }); body.appendChild(sub); li.appendChild(body);
        if (admin && !u.devices.some(function (d) { return d.this_device; })) {
          var a = el("div", "li-actions"); var b = el("button", "secondary danger", "Remove " + u.user + "…"); b.type = "button";
          b.onclick = function () { removeUser(u); }; a.appendChild(b); li.appendChild(a);
        }
        ul.appendChild(li);
      });
      var un = $("org-unlisted"); un.innerHTML = "";
      $("org-unlisted-head").classList.toggle("hidden", !o.unlisted.length);
      o.unlisted.forEach(function (d) {
        var li = el("li"); var body = el("div", "li-body"); body.appendChild(el("div", "li-title", d.name)); body.appendChild(el("div", "li-sub", "enrolled " + fmtDate(d.enrolled_utc) + " · " + d.device_id.slice(0, 8))); li.appendChild(body);
        if (admin) {
          var a = el("div", "li-actions"); var b = el("button", "secondary", "Add to organization…"); b.type = "button";
          b.onclick = function () {
            dialog({ title: "Add " + d.name, text: "Whose device is this? It then counts as theirs and the other devices accept what it writes.", fields: [{ name: "user", label: "Person (user name)", required: true }], ok: "Add" }).then(function (r) {
              if (!r) { return; }
              return api("POST", "/api/org/add-device", { device: d.device_id, user: r.values.user.trim() }).then(function () { log("added " + d.name + " for " + r.values.user); loadOrg(); });
            }).catch(function (e) { alertBox(e.message); });
          };
          a.appendChild(b); li.appendChild(a);
        }
        un.appendChild(li);
      });
      var rm = $("org-removed"); rm.innerHTML = "";
      $("org-removed-box").classList.toggle("hidden", !o.removed.length);
      o.removed.forEach(function (r) {
        var li = el("li"); var body = el("div", "li-body"); body.appendChild(el("div", "li-title", r.name + " (" + r.user + ")")); body.appendChild(el("div", "li-sub", "removed " + fmtDate(r.removed_utc) + (r.wipe ? ", wipe ordered" : "") + " · " + r.device.slice(0, 8))); li.appendChild(body); rm.appendChild(li);
      });
      var ad = $("org-admins"); ad.innerHTML = "";
      o.admins.forEach(function (d) { ad.appendChild(orgDevice(d, false, null)); });
      $("org-admin-card").classList.toggle("hidden", !admin);
      var pf = $("org-policy");
      ["members_may_share", "members_may_add_storages", "members_may_set_policies", "members_may_add_devices"].forEach(function (k) { var i = pf.querySelector("input[name=" + k + "]"); i.checked = !!o.policy[k]; i.disabled = !admin; });
      var allowed = o.policy.allowed_platforms || [];
      pf.querySelectorAll("input[data-platform]").forEach(function (i) { i.checked = !allowed.length || allowed.indexOf(i.dataset.platform) >= 0; i.disabled = !admin; });
      pf.min_app_version.value = o.policy.min_app_version || ""; pf.min_app_version.disabled = !admin;
      $("org-policy-save").classList.toggle("hidden", !admin);
      var lg = $("org-log"); lg.innerHTML = "";
      o.log.slice().reverse().forEach(function (e) {
        var li = el("li"); var body = el("div", "li-body"); body.appendChild(el("div", "li-title", e.text)); body.appendChild(el("div", "li-sub", fmtDate(e.utc) + " · " + e.issuer_name + " #" + e.seq)); li.appendChild(body); lg.appendChild(li);
      });
      if (!o.log.length) { lg.appendChild(el("li", "muted small", "nothing yet")); }
    }).catch(function (e) { log("error: " + e.message); });
  }
  function removeUser(u) {
    var names = u.devices.filter(function (d) { return !d.revoked; }).map(function (d) { return d.name; });
    dialog({
      title: "Remove " + u.user + "?",
      text: "Every device of " + u.user + " (" + (names.join(", ") || "none active") + ") is cut off at once: their ledger entries from now on are ignored, the other devices refuse their peer connections, and the vault gets new keys that only the remaining devices receive. What they could read until now they can still read, and their storage credentials work until you change them at the provider. Remove and wipe also orders their devices to delete their keys, sync state and folder contents the next time they reach a storage. The log records who did this. This cannot be undone.",
      fields: [{ name: "confirm", label: "Type the user name to confirm", placeholder: u.user, required: true }],
      ok: "Remove and wipe", extra: "Remove without wipe", danger: true
    }).then(function (r) {
      if (!r) { return; }
      if (r.values.confirm.trim() !== u.user) { return alertBox("The name does not match, so nothing was changed."); }
      var wipe = r.action === "ok";
      return api("POST", "/api/org/remove-user", { user: u.user, wipe: wipe, confirm: u.user }).then(function (rep) {
        log("removed " + rep.user + " (" + rep.devices.join(", ") + ")" + (wipe ? " with a wipe order" : "") + "; vault key epoch " + rep.revoke.key_epoch);
        var text = rep.user + " was removed with " + rep.devices.join(", ") + ". New keys went to: " + (rep.revoke.keys_sent_to.join(", ") || "no other device") + ".";
        if (rep.revoke.keys_pending_for.length) { text += " Waiting for " + rep.revoke.keys_pending_for.join(", ") + "."; }
        text += " Print a new recovery kit now.";
        return alertBox(text, "User removed").then(function () { loadOrg(); return refreshStatus(); });
      });
    }).catch(function (e) { log("error: " + e.message); alertBox(e.message, "Could not remove the user"); });
  }
  $("org-approve").onsubmit = function (ev) {
    ev.preventDefault();
    var v = formData(ev.target);
    api("POST", "/api/org/fingerprint", { code: v.code.trim() }).then(function (f) {
      return dialog({
        title: "Approve " + (f.name || f.device_id.slice(0, 8)) + " for " + v.user.trim() + "?",
        text: (f.platform ? "The device says it runs " + (PLATFORM_NAMES[f.platform] || f.platform) + ". " : "") + "Ask the person to read the six words their device shows. Approve only if they match exactly: different words mean the code was changed on its way.",
        code: f.fingerprint,
        ok: "The words match, approve"
      }).then(function (r) {
        if (!r) { return null; }
        return api("POST", "/api/org/approve", { code: v.code.trim(), user: v.user.trim(), fingerprint: f.fingerprint });
      });
    }).then(function (a) {
      if (!a) { return; }
      ev.target.reset();
      $("org-approveout").textContent = "Approved " + a.name + " for " + a.user + ". Send this token back; only that device can open it:\n\n" + a.token;
      $("org-approveout").classList.remove("hidden");
      log("approved " + a.name + " for " + a.user);
      loadOrg();
    }).catch(function (e) { alertBox(e.message, "Not approved"); });
  };
  $("org-policy").onsubmit = function (ev) {
    ev.preventDefault();
    var v = formData(ev.target);
    var boxes = ev.target.querySelectorAll("input[data-platform]"), ticked = [];
    boxes.forEach(function (i) { delete v[i.name]; if (i.checked) { ticked.push(i.dataset.platform); } });
    if (!ticked.length) { alertBox("Tick at least one platform."); return; }
    // Every platform ticked: no restriction.
    v.allowed_platforms = ticked.length === boxes.length ? [] : ticked;
    v.min_app_version = (v.min_app_version || "").trim();
    api("POST", "/api/org/policy", v).then(function () { log("organization policy saved"); loadOrg(); }).catch(function (e) { alertBox(e.message, "Policy not saved"); });
  };
  $("org-admin").onsubmit = function (ev) {
    ev.preventDefault();
    var action = (ev.submitter && ev.submitter.dataset.action) || "add";
    var v = formData(ev.target);
    api("POST", "/api/org/admin", { action: action, device: v.device.trim(), root_words: v.root_words.trim() }).then(function () { ev.target.reset(); log(v.device + (action === "add" ? " is now an administrator" : " is no longer an administrator")); loadOrg(); }).catch(function (e) { alertBox(e.message); });
  };
  $("org-export").onclick = function () {
    api("GET", "/api/org/log").then(function (r) {
      var blob = new Blob([JSON.stringify(r.log, null, 2)], { type: "application/json" });
      var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "varsto-organization-log.json"; document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    }).catch(function (e) { alertBox(e.message); });
  };
  function loadP2p() {
    if (document.body.dataset.view !== "app") { return; }
    api("GET", "/api/p2p").then(function (p) {
      var f = $("p2pform");
      f.enabled.checked = !!p.config.enabled; f.port.value = p.config.port || 17893;
      f.port_mapping.checked = p.config.port_mapping !== false;
      f.public_addrs.value = (p.config.public_addrs || []).join(", ");
      f.stun.value = (p.config.stun || []).join(", ");
      var peers = p.peers || [];
      $("p2pstatus").textContent = (p.listen ? "Listening on " + p.listen + ". " : "Not listening (enable and restart the service). ") + peers.length + " peers known (" + p.lan_peers + " on the LAN), " + p.chunks_from_peers + " blocks received from peers since start.";
      var nat = p.listen ? ("NAT: " + (p.nat || "unknown") + ". " + ((p.public || []).length ? "Public address " + p.public.join(", ") + ". " : "No public address observed. ") + (p.reachable ? "Reachable from the internet; this device relays for the others." : "Not reachable directly" + ((p.relays || []).length ? "; registered with relay " + p.relays.join(", ") + "." : "; no relay yet.")) + (p.cert_sha256 ? " Certificate " + p.cert_sha256.slice(0, 16) + "." : "")) : "";
      $("p2pnat").textContent = nat;
      $("p2pmap").textContent = p.listen ? portmapText(p.portmap) : "";
      var paths = p.paths || [];
      var tb = $("p2ppaths").querySelector("tbody"); tb.innerHTML = "";
      $("p2ppaths").classList.toggle("hidden", !paths.length);
      paths.forEach(function (x) {
        var tr = document.createElement("tr");
        [x.name || x.device.slice(0, 8), x.path + (x.ok || x.path === "untried" || x.path === "unreachable" ? "" : " (refused)"), x.addr || ""].forEach(function (c) { var td = document.createElement("td"); td.textContent = c; tr.appendChild(td); });
        tb.appendChild(tr);
      });
    }).catch(function () {});
  }
  // "Router port opened via UPnP: 203.0.113.5:17893" or "not available".
  function portmapText(m) {
    if (!m || !m.state) { return ""; }
    if (m.state === "off") { return "Router port mapping is off."; }
    if (m.state === "trying" || m.state === "") { return "Router port: asking the router\u2026"; }
    if (m.state !== "mapped") { return "Router port: not available."; }
    var via = { "pcp": "PCP", "nat-pmp": "NAT-PMP", "upnp": "UPnP" }[m.method] || m.method;
    var addrs = m.tcp && m.udp && m.tcp === m.udp ? m.tcp : [m.tcp ? m.tcp + " (TCP)" : "", m.udp ? m.udp + " (UDP)" : ""].filter(Boolean).join(", ");
    return (m.existing ? "Router port already open via " : "Router port opened via ") + via + ": " + addrs + ".";
  }
  $("p2pbox").ontoggle = function () { if ($("p2pbox").open) { loadP2p(); } };
  // Live activity (Overview "Now" card, Devices page): /api/activity every two
  // seconds while one of them is shown. Asking is what keeps the service
  // asking the other devices; nobody watching, nothing is asked. A sentence
  // per task comes from a translated template with the name put in untranslated.
  var ACT_TEMPLATES = {
    "sync_scan": "Looking for changes in folder «{s}»",
    "upload": "Uploading folder «{s}»",
    "download": "Fetching changes to folder «{s}»",
    "download.file": "Fetching a file of folder «{s}»",
    "download.export": "Decrypting a file of folder «{s}»",
    "folder_purge": "Deleting the data of folder «{s}»",
    "strongroom_convert": "Re-encrypting folder «{s}» for the Strongroom",
    "disk_check": "Checking disk «{s}»",
    "disk_check.verify": "Checking the blocks of disk «{s}»",
    "disk_check.fill": "Filling disk «{s}»",
    "disk_fill": "Filling disk «{s}»",
    "backup_snapshot": "Taking a snapshot of backup «{s}»",
    "restore": "Restoring backup «{s}»",
    "repair": "Repairing damaged block copies",
    "verify": "Verifying stored blocks",
    "fsck": "Checking the vault",
    "fsck.verify": "Verifying every block of the vault",
    "data_move": "Moving the data of folder «{s}»",
    "storage_removal": "Copying blocks off storage «{s}»",
    "storage_removal.delete": "Deleting the data on storage «{s}»",
    "disk_init": "Preparing disk «{s}»",
    "disk_fsck": "Checking the file system of disk «{s}»",
    "disk_insert": "Bringing disk «{s}» up to date",
    "disk_insert.tidy": "Tidying disk «{s}»",
    "disk_insert.verify": "Checking the blocks of disk «{s}»",
    "disk_insert.fill": "Filling disk «{s}»",
    "disk_fetch": "Copying blocks from disk «{s}»",
    "disk_fetch.write": "Writing files fetched from disk «{s}»",
    "disk_unmount": "Unmounting disk «{s}»",
    "scrub": "Checking storage «{s}» for bit rot",
    "scrub.disk": "Checking disk «{s}» for bit rot",
    "scrub.files": "Checking the files of folder «{s}» for bit rot",
    "scrub.cache": "Checking the block cache for bit rot",
    "ledger_rebuild": "Rebuilding the ledger",
    "ledger_rebuild.own": "Restoring this device's ledger from the storages",
    "ledger_rebuild.others": "Fetching the other devices' ledgers again",
    "ledger_rebuild.manifests": "Reading the folders' file lists",
    "ledger_rebuild.list": "Listing the stored blocks",
    "ledger_rebuild.verify": "Checking the stored blocks",
    "ledger_rebuild.seal": "Recording where the blocks are",
    "restic": "Checking that the restic mirror is complete",
    "restic.backup": "Backing up the mirror with restic",
    "restic.forget": "Removing old restic snapshots",
    "restic.repo_check": "Checking the restic repository",
    "trash_restore": "Restoring files of folder «{s}» from the trash",
    "trash_purge": "Deleting files from the trash for good",
    "trash_purge.drop": "Deleting files from the trash for good",
    "trash_move": "Moving deleted files of folder «{s}» to the trash storage",
    "drain": "Draining storage «{s}»",
    "drain.records": "Copying the records off storage «{s}»",
    "history_restore": "Restoring an earlier version of a file of folder «{s}»"
  };
  var actTimer = null, actBusy = false, lastActivity = null;
  function actTr(s) { return window.varstoLang ? window.varstoLang.t(s) : s; }
  function actRaw(text, cls) { var x = el("span", cls || null, text); x.setAttribute("data-no-i18n", ""); return x; }
  // "Checking the blocks of disk «{s}»" in the page's language, the name as data.
  function actSentence(t) {
    var tpl = ACT_TEMPLATES[t.kind + "." + t.phase] || ACT_TEMPLATES[t.kind] || (t.kind.replace(/_/g, " ") + (t.subject ? " «{s}»" : ""));
    var out = el("span", "act-what"); out.setAttribute("data-no-i18n", "");
    var parts = actTr(tpl).split("{s}");
    parts.forEach(function (p, i) { if (p) { out.appendChild(document.createTextNode(p)); } if (i < parts.length - 1) { out.appendChild(actRaw(t.subject || "")); } });
    if (t.detail) { out.appendChild(document.createTextNode(" (")); out.appendChild(actRaw(t.detail)); out.appendChild(document.createTextNode(")")); }
    return out;
  }
  function actTime(t) {
    var lang = window.varstoLang ? window.varstoLang.get() : undefined;
    try { return new Date(t * 1000).toLocaleTimeString(lang, { hour: "2-digit", minute: "2-digit" }); } catch (e) { return new Date(t * 1000).toLocaleTimeString(); }
  }
  function actCount(t, n) { return t.unit === "bytes" ? fmtBytes(n) : String(n); }
  // One task: the sentence, its numbers, and a bar (moving when the total is unknown).
  function actTask(t, who) {
    var box = el("div", "act");
    var head = el("div", "act-head");
    if (who) { head.appendChild(actRaw(who, "act-who")); }
    head.appendChild(actSentence(t));
    var meta = [];
    if (t.percent !== null && t.percent !== undefined) { meta.push(t.percent + " %"); meta.push(actCount(t, t.done) + " / " + actCount(t, t.total)); }
    else if (t.done > 0) { meta.push(actCount(t, t.done)); }
    if (t.rate > 0) { meta.push(t.unit === "bytes" ? fmtRate(t.rate) : t.rate + "/s"); }
    var m = actRaw(meta.join(" · "), "act-meta"); head.appendChild(m);
    if (t.eta_utc) { var e = el("span", "act-meta"); e.setAttribute("data-no-i18n", ""); e.textContent = actTr("ready about {t}").replace("{t}", actTime(t.eta_utc)); head.appendChild(e); }
    box.appendChild(head);
    var bar = el("div", "act-bar" + (t.percent === null || t.percent === undefined ? " indeterminate" : "")); var fill = el("i"); if (t.percent !== null && t.percent !== undefined) { fill.style.width = t.percent + "%"; } bar.appendChild(fill);
    box.appendChild(bar);
    return box;
  }
  // A peer that cannot tell right now: why, with what it said last when there is something.
  function actNote(p) {
    if (p.status === "ok" && !p.stale) { return null; }
    if (p.status === "ok" || (p.status === "unreachable" && p.activity)) { return "Last heard " + (p.age_secs || 0) + " s ago, not answering now"; }
    return { unreachable: "Not reachable", unsupported: "Runs an older version that does not tell", refused: "Does not share its activity with this device", pending: "Asking…" }[p.status] || null;
  }
  function renderActivity(r) {
    lastActivity = r;
    var me = r.me || { tasks: [] };
    taskbarRender(me);
    var peers = r.peers || [];
    // Overview: every busy device, this one first; hidden when all are idle.
    var ul = $("nowlist"); ul.innerHTML = "";
    var rows = [];
    if ((me.tasks || []).length) { rows.push({ who: me.name || actTr("This device"), tasks: me.tasks }); }
    peers.forEach(function (p) { var ts = (p.activity && p.activity.tasks) || []; if (ts.length && p.status === "ok") { rows.push({ who: p.name || p.device.slice(0, 8), tasks: ts, note: actNote(p) }); } });
    rows.forEach(function (row) {
      var li = el("li");
      row.tasks.forEach(function (t) { li.appendChild(actTask(t, row.who)); });
      if (row.note) { li.appendChild(el("div", "li-sub", row.note)); }
      ul.appendChild(li);
    });
    $("nowcard").classList.toggle("hidden", !rows.length);
    // Devices page: under each device, its tasks or why it cannot tell.
    document.querySelectorAll("#devicelist .li-activity").forEach(function (box) {
      box.innerHTML = "";
      var id = box.dataset.device;
      var tasks = [], note = null;
      if (me.device === id) { tasks = me.tasks || []; }
      else {
        var p = peers.filter(function (x) { return x.device === id; })[0];
        if (p) { tasks = (p.activity && p.activity.tasks) || []; note = actNote(p); if (p.status !== "ok" && p.status !== "unreachable") { tasks = []; } }
      }
      tasks.forEach(function (t) { box.appendChild(actTask(t, null)); });
      if (note && (tasks.length || note !== "Asking…")) { box.appendChild(el("div", "li-sub muted small", note)); }
    });
  }
  function activityWanted() { return (currentPage === "overview" || currentPage === "peers") && document.body.dataset.view === "app" && document.visibilityState !== "hidden"; }
  function activityWatch() {
    streamUpdate();
    if (!activityWanted() || evsOk) { if (actTimer) { clearTimeout(actTimer); actTimer = null; } return; }
    if (actTimer || actBusy) { return; }
    actBusy = true;
    api("GET", "/api/activity").then(renderActivity).catch(function () {}).then(function () {
      actBusy = false;
      if (activityWanted() && !evsOk && !actTimer) { actTimer = setTimeout(function () { actTimer = null; activityWatch(); }, 2000); }
    });
  }
  // Progress at the top of the window: this device's tasks that have run for
  // 5 s or more (a snapshot, an upload, a scrub, a restore...), with the
  // sentence of the Now card, the percentage and the expected finish. Asked
  // for every second while it shows or a request you started is still
  // running, every five seconds otherwise (the Now card's two-second poll
  // feeds it on the Overview and Peers pages); never while the page is
  // hidden. Only this device: `?mine=1` does not ask the peers.
  function taskbarWanted() { return document.body.dataset.view === "app" && document.visibilityState !== "hidden" && !!token; }
  function taskbarFast() { return tbOn || working > 0; }
  function taskbarSchedule(ms) {
    if (tbTimer) { clearTimeout(tbTimer); tbTimer = null; }
    if (!taskbarWanted()) { return; }
    tbTimer = setTimeout(taskbarPoll, ms !== undefined ? ms : (taskbarFast() ? 1000 : 5000));
  }
  // A request you started: look again in a second.
  function taskbarSoon() { if (!tbBusy && taskbarWanted() && (!tbTimer || !tbOn)) { taskbarSchedule(1000); } }
  function taskbarPoll() {
    tbTimer = null;
    if (!taskbarWanted()) { return; }
    // The event stream brings this device's tasks as they change.
    if (evsOk) { taskbarSchedule(5000); return; }
    // The Now card asks every two seconds anyway; between its answers only the fast mode asks.
    if (activityWanted() && !taskbarFast()) { taskbarSchedule(); return; }
    tbBusy = true;
    fetch("/api/activity?mine=1", { headers: { "X-Varsto-Token": token } }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { if (j) { taskbarRender(j.me || { tasks: [] }); } }).catch(function () {})
      .then(function () { tbBusy = false; taskbarSchedule(); });
  }
  function taskbarRender(me) {
    var now = Date.now() / 1000;
    var long = (me.tasks || []).filter(function (t) { return now - t.started_utc >= TB_AFTER; });
    long.sort(function (a, b) { return a.started_utc - b.started_utc; });
    var bar = $("taskbar");
    if (!long.length) {
      if (tbOn && !tbHide) {
        // A brief "done", then away.
        bar.classList.add("done"); bar.classList.remove("unknown");
        $("tb-bar").classList.remove("indeterminate"); $("tb-bar").firstChild.style.width = "100%";
        var txt = $("tb-text"); txt.innerHTML = ""; txt.appendChild(el("span", "tb-done", actTr("Done"))); if (tbLastWhat) { txt.appendChild(document.createTextNode(" · ")); txt.appendChild(tbLastWhat); }
        $("tb-meta").textContent = "";
        bar.setAttribute("aria-valuenow", "100"); bar.setAttribute("aria-valuetext", actTr("Done"));
        tbHide = setTimeout(function () { tbHide = null; tbOn = false; bar.classList.add("hidden"); bar.classList.remove("done"); taskbarSchedule(); }, 1000);
      }
      return;
    }
    if (tbHide) { clearTimeout(tbHide); tbHide = null; }
    var t = long[0];
    var what = actSentence(t);
    var text = $("tb-text"); text.innerHTML = "";
    if (long.length > 1) { text.appendChild(el("span", "tb-count", actTr("{n} tasks").replace("{n}", long.length))); text.appendChild(document.createTextNode(" · ")); }
    text.appendChild(what);
    tbLastWhat = what.cloneNode(true);
    var known = t.percent !== null && t.percent !== undefined;
    var meta = [];
    if (known) { meta.push(t.percent + " %"); }
    else if (t.done > 0) { meta.push(actCount(t, t.done)); }
    if (t.eta_utc) { meta.push(actTr("ready about {t}").replace("{t}", actTime(t.eta_utc))); }
    $("tb-meta").textContent = meta.join(" · ");
    var b = $("tb-bar"); b.classList.toggle("indeterminate", !known); b.firstChild.style.width = known ? t.percent + "%" : "";
    bar.classList.toggle("unknown", !known); bar.classList.remove("done", "hidden");
    if (known) { bar.setAttribute("aria-valuenow", String(t.percent)); } else { bar.removeAttribute("aria-valuenow"); }
    bar.setAttribute("aria-valuetext", text.textContent + (meta.length ? " (" + meta.join(", ") + ")" : ""));
    var startedFast = !tbOn; tbOn = true;
    if (startedFast && !tbBusy) { taskbarSchedule(); }
  }
  document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") { taskbarSchedule(0); } else if (tbTimer) { clearTimeout(tbTimer); tbTimer = null; } });
  taskbarSchedule(1000);

  // Event stream (GET /api/events, Server-Sent Events): what the service
  // does arrives as it happens, so the page stops asking every few seconds.
  // This device's tasks (the bar at the top, the Now card), the transfers,
  // and, while the Overview or Peers page shows, the other devices'
  // activity and the traffic come with it; syncs, changes, problems and
  // notifications make the page load the service's summary once. The
  // stream is closed while the page is hidden; when it drops, the browser
  // reconnects (and the page with doubling waits, up to a minute), the
  // missed events are replayed from the service's ring (Last-Event-ID), and
  // meanwhile the old polls take over.
  var evs = null, evsOk = false, evsKey = null, evsLast = 0, evsRetry = 1000, evsTimer = null;
  var evsMe = { device: "", name: "" }, evsTasks = {}, evsPeers = [], evsSoon = null, evsStatusSoon = null;
  function streamWanted() { return !!token && document.body.dataset.view === "app" && document.visibilityState !== "hidden" && typeof EventSource !== "undefined"; }
  function streamClose() {
    if (evs) { evs.close(); evs = null; }
    if (evsTimer) { clearTimeout(evsTimer); evsTimer = null; }
    evsKey = null;
    if (evsOk) { evsOk = false; activityWatch(); trafficWatch(); taskbarSchedule(0); }
  }
  function streamUpdate() {
    if (!streamWanted()) { if (evs || evsTimer) { streamClose(); } return; }
    var peers = activityWanted(), traffic = trafficWanted();
    var key = (peers ? "p" : "") + (traffic ? "t" : "");
    if ((evs || evsTimer) && key === evsKey) { return; }
    if (evs) { evs.close(); evs = null; }
    if (evsTimer) { clearTimeout(evsTimer); evsTimer = null; }
    evsKey = key;
    var url = "/api/events?token=" + enc(token) + (peers ? "&peers=1" : "") + (traffic ? "&traffic=1" : "") + (evsLast ? "&last_id=" + evsLast : "");
    var es = new EventSource(url); evs = es;
    es.onopen = function () { if (evs !== es) { return; } evsRetry = 1000; };
    es.onerror = function () {
      if (evs !== es) { return; }
      var was = evsOk; evsOk = false;
      if (was) { activityWatch(); trafficWatch(); taskbarSchedule(0); }
      // The browser tries again by itself unless the answer was an error.
      if (es.readyState === 2) {
        evs = null;
        evsTimer = setTimeout(function () { evsTimer = null; evsKey = null; streamUpdate(); }, evsRetry);
        evsRetry = Math.min(evsRetry * 2, 60000);
      }
    };
    function on(kind, fn) {
      es.addEventListener(kind, function (ev) {
        if (evs !== es) { return; }
        if (ev.lastEventId) { evsLast = +ev.lastEventId || evsLast; }
        var m = null; try { m = JSON.parse(ev.data); } catch (e) { return; }
        fn(m.data || {}, m);
      });
    }
    on("hello", function (d) {
      // A smaller number than we had: the service started again.
      var restarted = evsLast && d.last_id < evsLast;
      if (!evsLast || restarted) { evsLast = d.last_id; }
      var a = d.activity || {}; evsMe = { device: a.device || "", name: a.name || "" };
      evsTasks = {}; (a.tasks || []).forEach(function (t) { evsTasks[t.id] = t; });
      var first = !evsOk; evsOk = true;
      if (actTimer) { clearTimeout(actTimer); actTimer = null; }
      if (trafficTimer) { clearTimeout(trafficTimer); trafficTimer = null; }
      tasksChanged();
      if (restarted) { statusSoon(); }
      if (first) { serviceSoon(); }
    });
    on("reset", function () { statusSoon(); serviceSoon(); });
    on("activity.started", function (t) { evsTasks[t.id] = t; tasksChanged(); });
    on("activity.progress", function (t) { evsTasks[t.id] = t; tasksChanged(); });
    on("activity.finished", function (t) { delete evsTasks[t.id]; tasksChanged(); });
    on("activity.peers", function (d) { evsPeers = d.peers || []; tasksChanged(); });
    on("traffic", function (d) { if (trafficWanted()) { renderTraffic(d); } });
    on("transfers", function (d) { transferFollowers.forEach(function (f) { f(d); }); });
    on("sync.finished", function () { serviceSoon(); });
    on("sync.started", function () {});
    ["policy.changed", "ledger.health", "backup", "trash", "files.new", "space.low", "space.ok", "storage.problem", "storage.ok", "folder.paused", "peer.connected", "peer.disconnected"].forEach(function (k) { on(k, function () { serviceSoon(); }); });
    on("config.changed", function () { serviceSoon(); statusSoon(); });
    on("notification", function (d) { if (d.title) { log(d.title + ": " + (d.body || "")); } });
  }
  // This device's tasks changed: the bar at the top and the Now card.
  function tasksChanged() {
    var tasks = Object.keys(evsTasks).map(function (k) { return evsTasks[k]; }).sort(function (a, b) { return a.started_utc - b.started_utc; });
    var me = { device: evsMe.device, name: evsMe.name, tasks: tasks };
    taskbarRender(me);
    if (activityWanted()) { renderActivity({ me: me, peers: evsPeers }); }
  }
  // Several events in a row ask once.
  function serviceSoon() { if (evsSoon) { return; } evsSoon = setTimeout(function () { evsSoon = null; pollService(); }, 300); }
  function statusSoon() { if (evsStatusSoon) { return; } evsStatusSoon = setTimeout(function () { evsStatusSoon = null; if (busyCount === 0) { refreshStatus().catch(function () {}); } }, 500); }
  document.addEventListener("visibilitychange", streamUpdate);

  // Recovery package: what to keep outside your devices and how to restore,
  // from GET /api/recovery/guide. Every sentence comes as an English
  // template with named values ({t, p}); the template is translated like any
  // other interface string and the values (bucket names, paths) go in as they
  // are. Commands are never translated. The ticks are a personal checklist
  // kept in this browser (localStorage), not vault state.
  var lastGuide = null;
  function rgKey() { return "varsto-recovery-ticks:" + (lastGuide ? lastGuide.vault_id : ""); }
  function rgTicks() { try { return JSON.parse(localStorage.getItem(rgKey()) || "{}") || {}; } catch (e) { return {}; } }
  function rgSetTick(id, on) { var t = rgTicks(); if (on) { t[id] = Date.now(); } else { delete t[id]; } try { localStorage.setItem(rgKey(), JSON.stringify(t)); } catch (e) {} }
  // Text with `code` spans as <code>.
  function rgCodeText(parent, s) { s.split("`").forEach(function (part, i) { if (!part) { return; } if (i % 2) { var c = el("code", null, part); parent.appendChild(c); } else { parent.appendChild(document.createTextNode(part)); } }); }
  function rgText(t, cls) {
    var out = el("span", cls || null); out.setAttribute("data-no-i18n", "");
    var tpl = actTr(t.t), p = t.p || {}, re = /\{([a-z_]+)\}/g, last = 0, m;
    while ((m = re.exec(tpl))) {
      if (m.index > last) { rgCodeText(out, tpl.slice(last, m.index)); }
      if (Object.prototype.hasOwnProperty.call(p, m[1])) { out.appendChild(actRaw(p[m[1]], "rg-val")); } else { out.appendChild(document.createTextNode(m[0])); }
      last = re.lastIndex;
    }
    if (last < tpl.length) { rgCodeText(out, tpl.slice(last)); }
    return out;
  }
  function rgPlain(t) { var tpl = actTr(t.t), p = t.p || {}; return tpl.replace(/\{([a-z_]+)\}/g, function (all, k) { return Object.prototype.hasOwnProperty.call(p, k) ? p[k] : all; }); }
  function rgLabelled(label, t) { var li = el("li"); li.appendChild(el("span", "rg-label", label)); li.appendChild(document.createTextNode(" ")); li.appendChild(rgText(t)); return li; }
  function rgTicked(item, ticks) { return item.status === "done" || (item.status === "check" && !!ticks[item.id]); }
  function rgCount() {
    if (!lastGuide) { return; }
    var ticks = rgTicks(), need = lastGuide.items.filter(function (i) { return i.status !== "info"; });
    var done = need.filter(function (i) { return rgTicked(i, ticks); }).length;
    var c = $("rg-count"); c.textContent = actTr("{done} of {all} done").replace("{done}", done).replace("{all}", need.length); c.setAttribute("data-no-i18n", "");
    c.classList.toggle("rg-all", done === need.length);
  }
  function renderGuide(g) {
    lastGuide = g;
    var ticks = rgTicks();
    var intro = $("rg-intro"); intro.innerHTML = "";
    g.intro.forEach(function (t) { var p = el("p", "small"); p.appendChild(rgText(t)); intro.appendChild(p); });
    var ul = $("rg-items"); ul.innerHTML = "";
    g.items.forEach(function (it) {
      var li = el("li", "rg-item rg-" + it.status);
      var head = el(it.status === "info" ? "div" : "label", "rg-title");
      if (it.status !== "info") {
        var cb = el("input"); cb.type = "checkbox"; cb.checked = rgTicked(it, ticks); cb.dataset.id = it.id;
        if (it.status === "done") { cb.disabled = true; }
        cb.onchange = function () { rgSetTick(it.id, cb.checked); li.classList.toggle("rg-ticked", cb.checked); rgCount(); };
        head.appendChild(cb);
        li.classList.toggle("rg-ticked", cb.checked);
      } else { head.appendChild(icon("info", "rg-info-icon")); }
      head.appendChild(rgText(it.title, "rg-title-text"));
      if (!it.essential && it.status !== "info") { head.appendChild(el("span", "pill grey", "optional")); }
      if (it.status === "outdated") { head.appendChild(el("span", "pill bad", "out of date")); }
      li.appendChild(head);
      if (it.status_note) { var n = el("div", "rg-status small"); n.appendChild(rgText(it.status_note)); li.appendChild(n); }
      var d = el("ul", "rg-details small");
      d.appendChild(rgLabelled(actTr("What:"), it.what));
      d.appendChild(rgLabelled(actTr("Why:"), it.why));
      (it.location || []).forEach(function (l) { var x = el("li", "rg-loc"); x.appendChild(rgText(l)); d.appendChild(x); });
      (it.keep || []).forEach(function (k) { d.appendChild(rgLabelled(actTr("Keep:"), k)); });
      d.appendChild(rgLabelled(actTr("If missing:"), it.missing));
      li.appendChild(d);
      if (it.literal && it.literal.length) { li.appendChild(el("pre", "rg-literal", it.literal.join("\n"))); }
      ul.appendChild(li);
    });
    function steps(list, box, numbered) {
      box.innerHTML = "";
      list.forEach(function (s) {
        var li = el(numbered ? "li" : "div", "rg-step");
        var h = el("h3", "rg-step-title"); h.appendChild(rgText(s.title)); li.appendChild(h);
        (s.notes || []).forEach(function (n) { var p = el("p", "small"); p.appendChild(rgText(n)); li.appendChild(p); });
        if (s.commands && s.commands.length) { var pre = el("pre", "rg-cmd", s.commands.join("\n")); li.appendChild(pre); }
        box.appendChild(li);
      });
    }
    steps(g.steps, $("rg-steps"), true);
    steps(g.alternatives || [], $("rg-alt"), false);
    $("rg-altcard").classList.toggle("hidden", !(g.alternatives || []).length);
    rgCount();
  }
  function loadGuide() {
    var go = function () { api("GET", "/api/recovery/guide").then(function (g) { (window.varstoLang && window.varstoLang.ready ? window.varstoLang.ready : function (f) { f(); })(function () { renderGuide(g); }); }).catch(function (e) { log("recovery guide: " + e.message); }); };
    go();
  }
  // Help: where this device stands, where the data is, what needs attention
  // and what to do next, from GET /api/help (answered without a vault and
  // while it is locked too). Sentences come as {t, p} like the recovery
  // guide's and are translated the same way (rgText). The Help page shows it
  // in the app; the setup and unlock screens show it in a panel above them.
  var lastHelp = null, helpWanted = null, helpLoading = null, helpAuto = false;
  var HELP_GUIDE_FOR = { overview: "start", files: "folders", shared: "sharing", storages: "storages", backups: "backups", import: "imports", trash: "trash", policies: "policies", peers: "devices", organization: "devices", settings: "start", recovery: "recovery", more: "start", help: "start" };
  var HELP_LEVELS = { urgent: ["bad", "Urgent"], important: ["risk", "Next"], suggested: ["accent", "Suggested"], tip: ["grey", "Tip"] };
  function helpFlash(e) { e.classList.remove("help-flash"); void e.offsetWidth; e.classList.add("help-flash"); setTimeout(function () { e.classList.remove("help-flash"); }, 2400); }
  function helpReveal(e, focus) {
    if (!e) { return; }
    setTimeout(function () {
      e.scrollIntoView({ block: "center", behavior: "smooth" }); helpFlash(e);
      if (!focus) { return; }
      var f = e.matches("button") ? e : e.querySelector("input:not([type=hidden]):not([type=checkbox]), select, textarea, button");
      if (f) { try { f.focus({ preventScroll: true }); } catch (x) { f.focus(); } }
    }, 80);
  }
  // Carry out a step's action: go to the page and open or show what it names.
  function helpGo(a) {
    if (!a) { return; }
    var view = document.body.dataset.view;
    if (a.page === "setup" || a.page === "unlock") { helpReveal($(a.target), true); return; }
    if (view !== "app") { return; }
    var t = a.target || "";
    nav(a.page);
    if (t === "do:sync") { runSync().then(function () { if (currentPage === "help") { loadHelp(); } }); return; }
    if (t === "kit") { $("rg-kit").click(); return; }
    if (t === "addfolder" || t === "attachfolder") { showFolderForms(true, true); helpReveal($(t), t === "addfolder"); return; }
    if (t) { var e = $(t); helpReveal(e, !!e && (e.tagName === "FORM" || e.tagName === "BUTTON")); }
  }
  // Decimal sizes, as in the sentences (the engine's human_bytes).
  function helpBytes(n) { var u = ["B", "kB", "MB", "GB", "TB"], i = 0; while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; } return i ? n.toFixed(1) + " " + u[i] : n + " B"; }
  function helpFigure(value, label) { var d = el("div", "help-fig"); d.appendChild(actRaw(String(value), "help-fig-value")); d.appendChild(el("span", "help-fig-label", label)); return d; }
  // A bar of the data by kept copies: none, one, two or more.
  function helpCopyBar(f) {
    var wrap = el("div", "help-copies");
    if (!f.bytes) { return wrap; }
    var none = f.unkept_bytes, two = f.two_plus_bytes, one = Math.max(0, f.bytes - none - two);
    var bar = el("div", "help-bar"); bar.setAttribute("role", "img");
    [[two, "c2", "On two or more storages"], [one, "c1", "On one storage"], [none, "c0", "Only on devices"]].forEach(function (x) {
      if (!x[0]) { return; }
      var seg = el("i", "help-seg " + x[1]); seg.style.flexGrow = String(x[0]); seg.title = actTr(x[2]) + ": " + helpBytes(x[0]); bar.appendChild(seg);
    });
    wrap.appendChild(bar);
    var leg = el("div", "help-legend small");
    [[two, "c2", "On two or more storages"], [one, "c1", "On one storage"], [none, "c0", "Only on devices"]].forEach(function (x) {
      var it = el("span", "help-legend-item"); it.appendChild(el("i", "help-seg " + x[1])); it.appendChild(el("span", null, x[2])); it.appendChild(document.createTextNode(" ")); it.appendChild(actRaw(helpBytes(x[0]), "help-legend-val")); leg.appendChild(it);
    });
    wrap.appendChild(leg);
    return wrap;
  }
  function renderHelpNow(h, box) {
    box.innerHTML = "";
    var head = el("p", "help-headline"); head.appendChild(rgText(h.headline)); box.appendChild(head);
    if (h.phase === "ready") {
      var f = h.figures, figs = el("div", "help-figures");
      figs.appendChild(helpFigure(f.devices, "Devices"));
      figs.appendChild(helpFigure(f.storages, "Storages"));
      figs.appendChild(helpFigure(f.folders, "Folders"));
      figs.appendChild(helpFigure(f.files, "Files"));
      figs.appendChild(helpFigure(helpBytes(f.bytes), "Data"));
      if (f.disks) { figs.appendChild(helpFigure(f.disks - f.disks_away + " / " + f.disks, "Pool disks attached")); }
      box.appendChild(figs);
      box.appendChild(helpCopyBar(f));
    }
    var ul = el("ul", "help-summary");
    h.summary.forEach(function (t) { var li = el("li"); li.appendChild(rgText(t)); ul.appendChild(li); });
    box.appendChild(ul);
    if ((h.attention || []).length) {
      var at = el("ul", "help-attn");
      h.attention.forEach(function (a) {
        var li = el("li", "help-attn-" + a.level);
        li.appendChild(icon(a.level === "info" ? "info" : "warn", "help-attn-icon"));
        li.appendChild(rgText(a.text)); at.appendChild(li);
      });
      box.appendChild(at);
    }
    if ((h.folders || []).length || (h.storages || []).length || (h.details || []).length) {
      var d = el("details", "help-details"); d.appendChild(el("summary", null, "Where your data is, in detail"));
      function list(title, rows) {
        if (!rows.length) { return; }
        d.appendChild(el("h4", "help-sub", title));
        var u = el("ul", "help-detail-list small"); rows.forEach(function (t) { var li = el("li"); li.appendChild(rgText(t)); u.appendChild(li); }); d.appendChild(u);
      }
      list("Folders", (h.folders || []).map(function (x) { return x.line; }));
      list("Storages", (h.storages || []).map(function (x) { return x.line; }));
      list("More", h.details || []);
      box.appendChild(d);
    }
  }
  function helpStepCard(s, n, first) {
    var li = el("li", "help-step help-lv-" + s.level + (first ? " help-first" : ""));
    li.dataset.step = s.id;
    li.appendChild(el("span", "help-num", n ? String(n) : "?"));
    var body = el("div", "help-step-body");
    var head = el("div", "help-step-head");
    head.appendChild(rgText(s.title, "help-step-title"));
    var lv = HELP_LEVELS[s.level] || HELP_LEVELS.tip; head.appendChild(pill(lv[0], lv[1]));
    body.appendChild(head);
    var why = el("p", "help-why"); why.appendChild(rgText(s.why)); body.appendChild(why);
    if ((s.how || []).length) { var ul = el("ul", "help-how"); s.how.forEach(function (t) { var x = el("li"); x.appendChild(rgText(t)); ul.appendChild(x); }); body.appendChild(ul); }
    var acts = el("div", "help-actions");
    if (s.action) {
      var b = el("button", first ? "" : "secondary"); b.type = "button"; b.textContent = rgPlain(s.action.label); b.setAttribute("data-no-i18n", "");
      b.dataset.action = s.action.page + (s.action.target ? ":" + s.action.target : "");
      b.onclick = function () { helpGo(s.action); }; acts.appendChild(b);
    }
    var pre = null;
    if (s.command) {
      pre = el("pre", "help-cmd hidden", s.command);
      var cb = el("button", "secondary help-mini", "Show the command"); cb.type = "button";
      cb.onclick = function () { var hid = pre.classList.toggle("hidden"); cb.textContent = actTr(hid ? "Show the command" : "Hide the command"); };
      acts.appendChild(cb);
    }
    if (s.guide) { var gb = el("button", "linkish help-mini", "Read the guide"); gb.type = "button"; gb.onclick = function () { helpOpenGuide(s.guide, li.closest("#prehelp") ? "prehelp" : "page"); }; acts.appendChild(gb); }
    if (acts.children.length) { body.appendChild(acts); }
    if (pre) { body.appendChild(pre); }
    li.appendChild(body);
    return li;
  }
  // Steps the page adds by itself: a newer version (the interface checks for updates).
  function helpExtraSteps(h) {
    var out = [];
    if (h.phase === "ready" && updateInfo && updateInfo.newer) {
      out.push({ id: "update", level: "suggested", title: { t: "Install Varsto {latest}", p: { latest: updateInfo.latest } }, why: { t: "A newer version is available (you have {current}).", p: { current: updateInfo.current } }, how: [], action: { page: "overview", target: "update", label: { t: "Show the update" } }, command: "varsto update" });
    }
    return out;
  }
  function renderHelpSteps(h, ol, tipsOl) {
    ol.innerHTML = "";
    var steps = h.steps.concat(helpExtraSteps(h));
    if (!steps.length) {
      var ok = el("li", "help-allok"); ok.appendChild(icon("check")); ok.appendChild(el("span", null, "Everything is in order. Nothing needs doing now.")); ol.appendChild(ok);
    }
    steps.forEach(function (s, i) { ol.appendChild(helpStepCard(s, i + 1, i === 0)); });
    if (tipsOl) {
      tipsOl.innerHTML = "";
      (h.tips || []).forEach(function (s) { tipsOl.appendChild(helpStepCard(s, 0, false)); });
    }
  }
  // The guides are one template, cloned where they are shown; links to the
  // feature pages follow the interface's language.
  function helpGuides(box) {
    if (box.dataset.filled) { return; }
    box.dataset.filled = "1";
    box.appendChild(document.importNode($("tpl-guides").content, true));
    var lang = window.varstoLang ? window.varstoLang.get() : "en";
    box.querySelectorAll("a[data-site]").forEach(function (a) { a.href = "https://varsto.net" + (lang === "en" ? "" : "/" + lang) + a.dataset.site; });
  }
  function helpOpenGuide(topic, where) {
    var box = where === "prehelp" ? $("prehelp-guides") : $("help-guides");
    helpGuides(box);
    if (where === "prehelp") { $("prehelp-guidebox").open = true; }
    var d = box.querySelector('[data-guide="' + topic + '"]');
    if (d) { d.open = true; helpReveal(d.querySelector("summary") || d, false); }
  }
  // Places and storage kinds are words of the interface ("home", "cloud",
  // "directory"): translated, unlike names.
  function helpLocalize(x) {
    if (Array.isArray(x)) { x.forEach(helpLocalize); return; }
    if (!x || typeof x !== "object") { return; }
    if (typeof x.t === "string" && x.p) {
      ["kind", "place", "places"].forEach(function (k) { if (typeof x.p[k] === "string") { x.p[k] = x.p[k].split(", ").map(function (w) { return actTr(w); }).join(", "); } });
      return;
    }
    Object.keys(x).forEach(function (k) { helpLocalize(x[k]); });
  }
  function renderHelp(h) {
    helpLocalize(h);
    lastHelp = h;
    var inApp = document.body.dataset.view === "app";
    // Both places: the view may change while the answer is on its way.
    renderHelpNow(h, $("help-now"));
    renderHelpSteps(h, $("help-next"), $("help-tips"));
    $("help-tipsbox").classList.toggle("hidden", !(h.tips || []).length);
    helpGuides($("help-guides"));
    renderHelpNow(h, $("prehelp-now"));
    renderHelpSteps({ steps: h.steps.concat(h.tips || []), phase: h.phase }, $("prehelp-next"), null);
    helpGuides($("prehelp-guides"));
    if (helpWanted) { var g = helpWanted; helpWanted = null; helpOpenGuide(g, inApp ? "page" : "prehelp"); }
    renderHelpBanner(h);
  }
  function loadHelp() {
    if (!token) { return Promise.resolve(); }
    if (helpLoading) { return helpLoading; }
    helpLoading = api("GET", "/api/help").then(function (h) {
      return new Promise(function (res) { (window.varstoLang && window.varstoLang.ready ? window.varstoLang.ready : function (f) { f(); })(function () { renderHelp(h); res(h); }); });
    }).catch(function (e) { log("help: " + e.message); }).then(function (h) { helpLoading = null; return h; });
    return helpLoading;
  }
  // Overview: the first step that matters, with its button, until all is done.
  var helpBannerAt = 0;
  function renderHelpBanner(h) {
    var s = h && h.phase === "ready" ? h.steps.filter(function (x) { return x.level === "urgent" || x.level === "important"; })[0] : null;
    var box = $("helpnext");
    box.classList.toggle("hidden", !s);
    if (!s) { return; }
    box.classList.toggle("warn", s.level === "urgent");
    var t = $("helpnext-title"); t.innerHTML = ""; t.appendChild(rgText(s.title));
    var b = $("helpnext-go");
    b.classList.toggle("hidden", !s.action);
    if (s.action) { b.textContent = rgPlain(s.action.label); b.setAttribute("data-no-i18n", ""); b.onclick = function () { helpGo(s.action); }; }
  }
  // After the status changes: refresh the banner (at most every 20 s), and
  // on a vault without a storage open Help once per session.
  function helpAfterStatus(s) {
    if (!s) { return; }
    var now = Date.now();
    if (!s.member && !(s.storages || []).length && !helpAuto) {
      helpAuto = true;
      var seen = false; try { seen = sessionStorage.getItem("varsto-help-auto") === "1"; sessionStorage.setItem("varsto-help-auto", "1"); } catch (e) {}
      if (!seen && currentPage !== "help") { nav("help"); return; }
    }
    if (now - helpBannerAt > 20000 || currentPage === "help") { helpBannerAt = now; loadHelp(); }
  }
  // The setup and unlock screens: the panel above them, open on the setup screen.
  function showPreHelp(open) {
    $("prehelp").classList.remove("hidden");
    preHelpOpen(open);
    loadHelp();
  }
  function preHelpOpen(open) {
    $("prehelp-body").classList.toggle("hidden", !open);
    $("prehelp-toggle").textContent = actTr(open ? "Hide help" : "Show help");
  }
  $("prehelp-toggle").onclick = function () { preHelpOpen($("prehelp-body").classList.contains("hidden")); };
  $("help-reload").onclick = function () { loadHelp(); };
  // The "?" in the page header: the guide for this page.
  $("pagehelp").onclick = function () {
    if (document.body.dataset.view === "app") { helpWanted = HELP_GUIDE_FOR[currentPage] || "start"; if (currentPage === "help") { var g = helpWanted; helpWanted = null; helpOpenGuide(g, "page"); } else { nav("help"); } return; }
    preHelpOpen(true); helpOpenGuide("start", "prehelp");
  };
  // The checklist as plain text in the page's language, with the ticks.
  function guideText(g) {
    var ticks = rgTicks(), out = [];
    var title = actTr("Varsto recovery package");
    out.push(title.toUpperCase(), "");
    g.intro.forEach(function (t) { out.push(rgPlain(t), ""); });
    out.push(actTr("What to keep").toUpperCase());
    g.items.forEach(function (it) {
      var mark = it.status === "info" ? " - " : it.status === "outdated" ? "[!]" : rgTicked(it, ticks) ? "[x]" : "[ ]";
      out.push("", mark + " " + rgPlain(it.title) + (it.essential || it.status === "info" ? "" : " (" + actTr("optional") + ")"));
      if (it.status_note) { out.push("    " + rgPlain(it.status_note)); }
      out.push("    " + actTr("What:") + " " + rgPlain(it.what), "    " + actTr("Why:") + " " + rgPlain(it.why));
      (it.location || []).forEach(function (l) { out.push("    * " + rgPlain(l)); });
      (it.keep || []).forEach(function (k) { out.push("    " + actTr("Keep:") + " " + rgPlain(k)); });
      (it.literal || []).forEach(function (l) { out.push("      " + l); });
      out.push("    " + actTr("If missing:") + " " + rgPlain(it.missing));
    });
    function steps(list, numbered) { list.forEach(function (s, i) { out.push("", (numbered ? (i + 1) + ". " : "- ") + rgPlain(s.title)); (s.notes || []).forEach(function (n) { out.push("   " + rgPlain(n)); }); (s.commands || []).forEach(function (c) { out.push("     $ " + c); }); }); }
    out.push("", actTr("Restoring on a new device").toUpperCase());
    steps(g.steps, true);
    if ((g.alternatives || []).length) { out.push("", actTr("Without Varsto").toUpperCase()); steps(g.alternatives, false); }
    return out.join("\n") + "\n";
  }
  $("rg-print").onclick = function () { window.print(); };
  $("rg-reload").onclick = loadGuide;
  $("rg-download").onclick = function () {
    if (!lastGuide) { return; }
    var blob = new Blob([guideText(lastGuide)], { type: "text/plain;charset=utf-8" });
    var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "varsto-recovery-package.txt";
    document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  };
  // The kit holds the vault key: it is printed on the command line, which asks for the passphrase.
  $("rg-kit").onclick = function () {
    dialog({ title: "Print the recovery kit", text: "The kit is the vault key as 24 words. For safety it is printed on the command line of this computer, which asks for your passphrase: run the command below and print or copy the words by hand. With --shares it also prints three shares, any two of which rebuild the key.", code: "varsto recovery kit\nvarsto recovery kit --shares", ok: "Close", cancel: false }).then(function () { loadGuide(); });
  };
  // Traffic view (Peers page): /api/p2p/traffic every second while the page is shown.
  // The service answers it without waiting for a sync, so it stays live during long transfers.
  var trafficTimer = null, trafficBusy = false, lastTraffic = null;
  var SVGNS = "http://www.w3.org/2000/svg";
  function trafficWanted() { return currentPage === "peers" && document.body.dataset.view === "app" && document.visibilityState !== "hidden"; }
  function trafficWatch() {
    streamUpdate();
    if (!trafficWanted() || evsOk) { if (trafficTimer) { clearTimeout(trafficTimer); trafficTimer = null; } return; }
    if (trafficTimer || trafficBusy) { return; }
    trafficBusy = true;
    api("GET", "/api/p2p/traffic").then(renderTraffic).catch(function () {}).then(function () {
      trafficBusy = false;
      if (trafficWanted() && !evsOk && !trafficTimer) { trafficTimer = setTimeout(function () { trafficTimer = null; trafficWatch(); }, 1000); }
    });
  }
  function fmtRate(n) { return fmtBytes(n) + "/s"; }
  function fmtAgo(t, now) {
    if (!t) { return "never"; }
    var s = Math.max(0, now - t);
    if (s < 2) { return "now"; }
    if (s < 60) { return s + " s ago"; }
    if (s < 3600) { return Math.floor(s / 60) + " min ago"; }
    return new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  function peerName(name, dev) { return name || (dev || "").slice(0, 8); }
  // Short path label and pill class: LAN, direct, via <relay>, or not yet.
  function pathShort(p) {
    if (!p) { return ["not yet", "grey"]; }
    if (p === "direct-lan") { return ["LAN", "ok"]; }
    if (p === "direct") { return ["direct", "accent"]; }
    if (p.indexOf("relayed via ") === 0) { return ["via " + p.slice(12), "risk"]; }
    return [p, "grey"];
  }
  function svgEl(tag, attrs, cls, text) {
    var e = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (cls) { e.setAttribute("class", cls); }
    if (text !== undefined) { e.textContent = text; }
    return e;
  }
  function clip(s, n) { return s.length > n ? s.slice(0, Math.max(1, n - 1)) + "…" : s; }
  function renderSpark(h) {
    var sp = $("tr-spark"); sp.innerHTML = "";
    var down = h.rx || [], up = h.tx || [], relay = h.relay || [];
    var n = down.length || 60, max = 1;
    for (var i = 0; i < n; i++) { max = Math.max(max, (down[i] || 0) + (relay[i] || 0), up[i] || 0); }
    function pts(get) { var out = []; for (var i = 0; i < n; i++) { out.push((i * 120 / (n - 1)).toFixed(1) + "," + (31 - get(i) / max * 28).toFixed(1)); } return out.join(" "); }
    var dl = pts(function (i) { return (down[i] || 0) + (relay[i] || 0); });
    sp.appendChild(svgEl("line", { x1: 0, y1: 31.5, x2: 120, y2: 31.5 }, "sp-base"));
    sp.appendChild(svgEl("polygon", { points: "0,31 " + dl + " 120,31" }, "sp-area"));
    sp.appendChild(svgEl("polyline", { points: dl }, "sp-down"));
    sp.appendChild(svgEl("polyline", { points: pts(function (i) { return up[i] || 0; }) }, "sp-up"));
  }
  // Flow diagram: this device on the left, peers on the right; a relayed path bends
  // through a "via" node, and what this device relays for others is drawn through it.
  function renderFlow(r, peers) {
    var box = $("tr-flow"); box.innerHTML = "";
    if (!r.device || !peers.length) { return; }
    var W = Math.min(820, Math.max(300, box.clientWidth || 600)), narrow = W < 560;
    var shown = peers.slice(0, 10), rowH = narrow ? 58 : 62, top = 8;
    var H = Math.max(shown.length * rowH, 76) + top * 2;
    var meW = narrow ? 90 : 150, peerW = narrow ? Math.min(118, W * 0.36) : 200, nodeH = 44;
    var meX = 0, meY = H / 2 - nodeH / 2, peerX = W - peerW, gapL = meX + meW, gapR = peerX;
    var svg = svgEl("svg", { width: W, height: H, viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Traffic between this device and its peers" });
    var defs = svgEl("defs");
    ["rx", "tx", "relay"].forEach(function (k) {
      var m = svgEl("marker", { id: "tr-arrow-" + k, viewBox: "0 0 10 10", refX: 7, refY: 5, markerWidth: 8, markerHeight: 8, markerUnits: "userSpaceOnUse", orient: "auto" }, "tr-marker " + k);
      m.appendChild(svgEl("path", { d: "M0,0 L10,5 L0,10 z" }));
      defs.appendChild(m);
    });
    svg.appendChild(defs);
    var edges = svgEl("g"), labels = svgEl("g"), nodes = svgEl("g");
    svg.appendChild(edges); svg.appendChild(nodes); svg.appendChild(labels);
    var pos = {};
    shown.forEach(function (p, i) { pos[p.device] = { y: top + i * rowH + rowH / 2 }; });
    var meCy = H / 2;
    function curve(x1, y1, x2, y2) { var mx = (x1 + x2) / 2; return "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2; }
    function edge(d, cls, bps) {
      var w = bps > 0 ? Math.min(5, 1.5 + Math.log(1 + bps / 4096) / Math.LN10 * 1.2) : 1.25;
      var e = svgEl("path", { d: d, "stroke-width": w.toFixed(2) }, "tr-edge " + cls + (bps > 0 ? " flowing" : ""));
      if (bps > 0) { e.setAttribute("marker-end", "url(#tr-arrow-" + cls.split(" ")[0] + ")"); }
      edges.appendChild(e);
    }
    function label(x, y, arrow, cls, text, anchor) {
      var t = svgEl("text", { x: x, y: y, "text-anchor": anchor || "middle" }, "tr-label");
      t.appendChild(svgEl("tspan", {}, "tr-arrow " + cls, arrow + " "));
      t.appendChild(svgEl("tspan", {}, "", text));
      labels.appendChild(t);
    }
    shown.forEach(function (p) {
      var y = pos[p.device].y, via = p.path.indexOf("relayed via ") === 0 ? p.path.slice(12) : "";
      var x1 = gapL + 2, x2 = gapR - 2, live = p.rx_bps > 0 || p.tx_bps > 0;
      var spread = Math.max(-14, Math.min(14, (y - meCy) / 6)), ys = meCy + spread;
      var hx = x1 + (x2 - x1) * (narrow ? 0.55 : 0.3), hopW = 0;
      if (via) {
        // The hop node sits on the peer's row; both halves of the path pass through it.
        var txt = "via " + clip(via, narrow ? 6 : 14); hopW = Math.round(txt.length * 6.4 + 14);
        var g = svgEl("g", {}, "tr-hop");
        g.appendChild(svgEl("rect", { x: hx - hopW / 2, y: y - 11, width: hopW, height: 22, rx: 11 }));
        g.appendChild(svgEl("text", { x: hx, y: y + 4, "text-anchor": "middle" }, "", txt));
        nodes.appendChild(g);
      }
      if (!p.path) { return; }
      var lanes = [];
      if (p.rx_bps > 0) { lanes.push(["rx", p.rx_bps, 1]); }
      if (p.tx_bps > 0) { lanes.push(["tx", p.tx_bps, -1]); }
      if (!lanes.length) { lanes.push(["idle", 0, 0]); }
      lanes.forEach(function (l, i) {
        var off = lanes.length > 1 ? (i ? 3 : -3) : 0, cls = l[0];
        var a = [x1, ys + off], b = [x2, y + off];
        var segs = via ? [[a, [hx - hopW / 2, y + off]], [[hx + hopW / 2, y + off], b]] : [[a, b]];
        // Downloads point at this device, uploads at the peer.
        if (l[2] > 0) { segs = segs.map(function (s) { return [s[1], s[0]]; }).reverse(); }
        segs.forEach(function (s) { edge(curve(s[0][0], s[0][1], s[1][0], s[1][1]), cls, l[1]); });
      });
      // Speeds sit next to the peer, above its edge (and below it for a second direction).
      var lx = x2 - 6, ly = y - 13;
      if (!live) { return; }
      var rows = [];
      if (p.rx_bps > 0) { rows.push(["↓", "rx", fmtRate(p.rx_bps)]); }
      if (p.tx_bps > 0) { rows.push(["↑", "tx", fmtRate(p.tx_bps)]); }
      rows.forEach(function (row, i) { label(lx, i ? y + 23 : ly, row[0], row[1], row[2], "end"); });
    });
    // Relay flows: from one peer, through this device, to another.
    (r.relays || []).forEach(function (f, i) {
      var a = pos[f.from], b = pos[f.to];
      if (!a || !b || !(f.bps > 0)) { return; }
      var px = gapL + 14, py = meCy + 18 + i * 4;
      edge(curve(gapR - 2, a.y + 6, px, py) + " " + curve(px, py, gapR - 2, b.y + 6).replace(/^M[^ ]+ /, ""), "relay", f.bps);
      label(gapR - 6, b.y + 23, "\u21c4", "relay", "from " + peerName(f.from_name, f.from) + " " + fmtRate(f.bps), "end");
    });
    function node(x, y, w, cls, t1, t2) {
      var g = svgEl("g", {}, "tr-node " + cls);
      g.appendChild(svgEl("rect", { x: x, y: y, width: w, height: nodeH, rx: 10 }));
      var chars = Math.floor((w - 20) / 7.2);
      g.appendChild(svgEl("text", { x: x + 10, y: y + 18 }, "t1", clip(t1, chars)));
      g.appendChild(svgEl("text", { x: x + 10, y: y + 34 }, "t2", clip(t2, Math.floor((w - 20) / 6.2))));
      nodes.appendChild(g);
    }
    node(meX, meY, meW, "me", r.name || "This device", "this device");
    shown.forEach(function (p) {
      var live = p.rx_bps > 0 || p.tx_bps > 0;
      var sub = p.path ? pathShort(p.path)[0] + (p.active ? " · " + p.active + " active" : "") : "no traffic yet";
      node(peerX, pos[p.device].y - nodeH / 2, peerW, (live ? "busy" : "") + (p.path ? "" : " never"), peerName(p.name, p.device), sub);
    });
    box.appendChild(svg);
    if (peers.length > shown.length) { box.appendChild(el("p", "muted small", (peers.length - shown.length) + " more devices in the table below.")); }
  }
  function renderTraffic(r) {
    lastTraffic = r;
    var t = r.totals || {};
    var now = $("tr-now"); now.innerHTML = "";
    [["↓ ", "tr-down", t.rx_bps], ["↑ ", "tr-up", t.tx_bps]].concat(t.relay_bps || t.relay_total ? [["⇄ ", "tr-relay", t.relay_bps]] : []).forEach(function (x) {
      var s = el("span", "tr-rate"); s.appendChild(el("b", x[1], x[0])); s.appendChild(document.createTextNode(fmtRate(x[2] || 0))); now.appendChild(s);
    });
    renderSpark(r.history || {});
    // Busiest first, then the most recently active, then by name.
    var peers = (r.peers || []).slice().sort(function (a, b) {
      return (b.rx_bps + b.tx_bps) - (a.rx_bps + a.tx_bps) || (b.last_seen_utc || 0) - (a.last_seen_utc || 0) || peerName(a.name, a.device).localeCompare(peerName(b.name, b.device));
    });
    $("tr-note").textContent = !r.device ? "Peer-to-peer is not running on this device; enable it below and restart the service."
      : !peers.length ? "No other devices known yet."
      : "Since the service started: " + fmtBytes(t.rx_total) + " received in " + t.objects_in + " blocks, " + fmtBytes(t.tx_total) + " sent in " + t.objects_out + " blocks" + (t.relay_total ? ", " + fmtBytes(t.relay_total) + " relayed for other devices" : "") + ". Speeds are averages over the last " + r.window_secs + " seconds.";
    renderFlow(r, peers);
    var tb = $("tr-table").querySelector("tbody"); tb.innerHTML = "";
    $("tr-table").classList.toggle("hidden", !peers.length);
    peers.forEach(function (p) {
      var tr = document.createElement("tr");
      var td = el("td"); td.appendChild(document.createTextNode(peerName(p.name, p.device))); var sub = (p.name ? p.device.slice(0, 8) : "") + (p.active ? (p.name ? " \u00b7 " : "") + p.active + " active" : ""); if (sub) { td.appendChild(el("span", "sub", sub)); } tr.appendChild(td);
      var ps = pathShort(p.path); td = el("td"); td.appendChild(pill(ps[1], ps[0])); tr.appendChild(td);
      td = el("td", "tr-addr", p.addr || ""); if (p.addr) { td.dataset.label = "at"; } tr.appendChild(td);
      [["Down", fmtRate(p.rx_bps)], ["Up", fmtRate(p.tx_bps)], ["Received", fmtBytes(p.rx_total)], ["Sent", fmtBytes(p.tx_total)]].forEach(function (c) { var d = el("td", "num", c[1]); d.dataset.label = c[0]; tr.appendChild(d); });
      td = el("td", "tr-last", fmtAgo(p.last_seen_utc, r.now_utc)); td.dataset.label = "Last"; tr.appendChild(td);
      tb.appendChild(tr);
    });
    var rl = (r.relays || []), ul = $("tr-relays").querySelector("ul"); ul.innerHTML = "";
    $("tr-relays").classList.toggle("hidden", !rl.length);
    rl.forEach(function (f) {
      var li = el("li"), ic = el("span", "li-icon"); ic.appendChild(icon("sharing")); li.appendChild(ic);
      var body = el("div", "li-body");
      body.appendChild(el("div", "li-title", peerName(f.from_name, f.from) + " → " + peerName(f.to_name, f.to)));
      body.appendChild(el("div", "li-sub", fmtRate(f.bps) + " now · " + fmtBytes(f.total) + " in " + f.objects + " blocks · " + fmtAgo(f.last_seen_utc, r.now_utc)));
      li.appendChild(body); ul.appendChild(li);
    });
  }
  window.addEventListener("resize", function () { if (lastTraffic && currentPage === "peers") { renderTraffic(lastTraffic); } });
  // "Where your data is" (Overview): folders on the left, the storages and devices
  // that hold their bytes on the right, ribbons as wide as the bytes (one scale for
  // both sides, so every extra copy makes the right side taller). Loaded with the
  // status; phones and narrow cards get proportional bars instead.
  var lastWhere = null, whereBusy = false, whereWidth = 0;
  function loadWhere() {
    if (whereBusy) { return; }
    whereBusy = true;
    api("GET", "/api/data/locations").then(function (d) { lastWhere = d; renderWhere(d); }).catch(function () {}).then(function () { whereBusy = false; });
  }
  var WD_ORDER = { own: 0, ext: 1, cold: 2, carrier: 3, other: 4 };
  var WD_PLACE = { own: "own device or disk", ext: "external storage", cold: "cold storage", carrier: "transferrer", other: "seen only in other devices' records" };
  function wdStorageClass(s) {
    if (s.carrier) { return "carrier"; }
    if (s.cold) { return "cold"; }
    if (!s.configured) { return s.kind === "replica" ? "ext" : "other"; }
    return s.place === "home" ? "own" : "ext";
  }
  function wdKind(s) { return { directory: "directory", s3: "S3", rclone: "rclone", pool: "disk pool", transferrer: "transferrer", replica: "replica device", unknown: "not configured here" }[s.kind] || s.kind; }
  function fmtShare(x) { if (!(x > 0)) { return "0 %"; } if (x < 0.01) { return "<1 %"; } return Math.round(x * 100) + " %"; }
  function wdCost(s) { return s.monthly_cost != null ? "about " + s.monthly_cost.toFixed(2) + " " + (s.currency || "") + " a month" : ""; }
  // The nodes on the right: storages grouped by kind of place, then devices.
  function wdTargets(d) {
    var st = d.storages.filter(function (s) { return s.bytes > 0 || s.configured; }).map(function (s) {
      var c = wdStorageClass(s);
      var lines = [s.name + " — " + wdKind(s) + (s.place ? ", place " + s.place : ""), WD_PLACE[c],
        fmtBytes(s.bytes) + " in " + s.blocks + " block" + (s.blocks === 1 ? "" : "s") + " (" + fmtShare(s.share) + " of the data)"];
      if (s.bytes > 0) { lines.push("Verified by another device: " + fmtBytes(s.verified_bytes)); }
      if (wdCost(s)) { lines.push(wdCost(s)); }
      return { key: "s:" + s.name, name: s.name, cls: c, bytes: s.bytes, share: s.share, group: "Storages", title: lines.join("\n"), sub: s.carrier ? "passes on" : s.cold ? "cold" : "" };
    });
    st.sort(function (a, b) { return WD_ORDER[a.cls] - WD_ORDER[b.cls] || b.bytes - a.bytes || a.name.localeCompare(b.name); });
    var dv = d.devices.filter(function (x) { return x.bytes > 0 || x.this_device; }).map(function (x) {
      return { key: "d:" + x.device_id, name: x.name, sub: x.this_device ? "this device" : x.revoked ? "removed" : "", cls: "own dev", bytes: x.bytes, share: x.share, group: "Devices",
        title: x.name + (x.this_device ? " — this device" : "") + (x.revoked ? " (removed from the vault)" : "") + "\nFiles on the device: " + fmtBytes(x.bytes) + " in " + x.blocks + " block" + (x.blocks === 1 ? "" : "s") + " (" + fmtShare(x.share) + " of the data)" };
    });
    return st.concat(dv);
  }
  // Folders on the left; past ten, the smallest are merged into one node.
  function wdSources(d) {
    var fs = d.folders.filter(function (f) { return f.bytes > 0; });
    if (fs.length > 10) {
      var rest = fs.slice(9), m = { name: rest.length + " more folders", bytes: 0, blocks: 0, storages: {}, devices: {}, unkept_bytes: 0, merged: rest.map(function (f) { return f.name; }) };
      rest.forEach(function (f) {
        m.bytes += f.bytes; m.blocks += f.blocks; m.unkept_bytes += f.unkept_bytes;
        Object.keys(f.storages).forEach(function (k) { m.storages[k] = (m.storages[k] || 0) + f.storages[k]; });
        Object.keys(f.devices).forEach(function (k) { m.devices[k] = (m.devices[k] || 0) + f.devices[k]; });
      });
      fs = fs.slice(0, 9).concat([m]);
    }
    return fs.map(function (f) {
      var flows = {};
      Object.keys(f.storages).forEach(function (k) { flows["s:" + k] = f.storages[k]; });
      Object.keys(f.devices).forEach(function (k) { flows["d:" + k] = f.devices[k]; });
      var where = Object.keys(f.storages).sort(function (a, b) { return f.storages[b] - f.storages[a]; }).map(function (k) { return k + " " + fmtBytes(f.storages[k]); });
      var title = f.name + " — " + fmtBytes(f.bytes) + " in " + f.blocks + " block" + (f.blocks === 1 ? "" : "s") + " (" + fmtShare(f.bytes / d.total_bytes) + " of the data)" +
        "\nOn storages: " + (where.join(", ") || "none") + (f.unkept_bytes ? "\nNot kept on any storage: " + fmtBytes(f.unkept_bytes) : "") + (f.merged ? "\n" + f.merged.join(", ") : "");
      return { name: f.name, bytes: f.bytes, flows: flows, title: title, warn: f.unkept_bytes > 0 };
    });
  }
  function svgTitle(node, text) { node.appendChild(svgEl("title", {}, "", text)); return node; }
  function renderCopies(d) {
    var h = $("wd-hist"); h.innerHTML = "";
    var c = d.copies, W = 176, H = 64, bw = 32, gap = 12, top = 14, base = 46;
    var rows = [["0", c.none, c.bytes[0], "none"], ["1", c.one, c.bytes[1], "one"], ["2", c.two, c.bytes[2], "two"], ["3+", c.three_plus, c.bytes[3], "more"]];
    var max = Math.max(1, c.bytes[0], c.bytes[1], c.bytes[2], c.bytes[3]);
    h.setAttribute("viewBox", "0 0 " + W + " " + H); h.setAttribute("width", W); h.setAttribute("height", H);
    h.appendChild(svgEl("line", { x1: 0, y1: base + 0.5, x2: W, y2: base + 0.5 }, "wd-hist-base"));
    rows.forEach(function (r, i) {
      var x = i * (bw + gap) + 4, share = d.total_bytes ? r[2] / d.total_bytes : 0;
      var bh = r[2] > 0 ? Math.max(3, (base - top) * r[2] / max) : 0;
      var g = svgEl("g", {}, "wd-hist-col " + r[3] + (r[2] > 0 ? "" : " zero"));
      g.appendChild(svgEl("rect", { x: x, y: top - 12, width: bw, height: base - top + 30 }, "wd-hit"));
      if (bh) { g.appendChild(svgEl("path", { d: "M" + x + "," + base + " V" + (base - bh + 3) + " q0,-3 3,-3 h" + (bw - 6) + " q3,0 3,3 V" + base + " z" }, "wd-hist-bar")); }
      g.appendChild(svgEl("text", { x: x + bw / 2, y: base - bh - 4, "text-anchor": "middle" }, "wd-hist-val", r[2] > 0 ? fmtShare(share) : ""));
      g.appendChild(svgEl("text", { x: x + bw / 2, y: base + 14, "text-anchor": "middle" }, "wd-hist-lab", r[0] + "×"));
      svgTitle(g, (r[0] === "1" ? "1 copy" : r[0] + " copies") + " on storages: " + r[1] + " block" + (r[1] === 1 ? "" : "s") + ", " + fmtBytes(r[2]) + " (" + fmtShare(share) + ")" + (r[0] === "0" && r[1] ? "\nThese blocks are only on devices." : ""));
      h.appendChild(g);
    });
  }
  function renderWhere(d) {
    var card = $("wherecard");
    var shown = d && d.total_bytes > 0;
    card.classList.toggle("hidden", !shown);
    if (!shown) { return; }
    $("wd-bytes").textContent = fmtBytes(d.total_bytes);
    var avg = $("wd-avg"); avg.textContent = "kept " + d.copies.average.toFixed(1) + "× on average";
    avg.removeAttribute("title");
    avg.dataset.help = "On average every byte of your data is kept " + d.copies.average.toFixed(1) + " times on your storages (buckets, folders, disk pools). Copies on your devices are not counted here, and neither are transferrers, which carry blocks only until they are delivered. " + (d.copies.average < 2 ? "With fewer than 2 copies, losing one storage can lose data: add a storage or a policy that asks for more copies." : "With 2 or more copies, one storage can be lost without losing data.");
    avg.className = "wd-avg" + (d.copies.none ? " bad" : d.copies.average < 2 ? " risk" : "");
    var nf = d.folders.filter(function (f) { return f.bytes > 0; }).length;
    var ns = d.storages.filter(function (s) { return s.bytes > 0; }).length;
    var nd = d.devices.filter(function (x) { return x.bytes > 0; }).length;
    $("wd-total").textContent = d.total_blocks + " block" + (d.total_blocks === 1 ? "" : "s") + " · " + nf + " folder" + (nf === 1 ? "" : "s") + " · " + ns + " storage" + (ns === 1 ? "" : "s") + " · " + nd + " device" + (nd === 1 ? "" : "s");
    renderCopies(d);
    var targets = wdTargets(d), present = {};
    targets.forEach(function (t) { present[t.cls.split(" ")[0]] = true; });
    document.querySelectorAll("#wherecard .wd-legend .wd-sw").forEach(function (sw) { var k = sw.classList[1]; sw.parentNode.classList.toggle("hidden", !present[k]); });
    var unknown = d.folders.filter(function (f) { return f.bytes === 0 && !f.attached; }).length;
    $("wd-note").textContent = "Encrypted sizes; every copy counts at its storage." + (unknown ? " " + unknown + " folder" + (unknown === 1 ? " is" : "s are") + " not attached here and not counted." : "");
    var box = $("wd-chart");
    var W = box.clientWidth;
    if (!W) { return; }
    whereWidth = W; box.innerHTML = "";
    if (isMobile() || W < 520) { renderWhereBars(box, targets); } else { renderWhereFlow(box, d, wdSources(d), targets, Math.min(W, 1100)); }
  }
  function renderWhereBars(box, targets) {
    var group = "";
    targets.forEach(function (t) {
      if (t.group !== group) { group = t.group; box.appendChild(el("div", "wd-bars-head", group)); }
      var row = el("div", "wd-bar-row"); row.title = t.title;
      var top = el("div", "wd-bar-top"); top.appendChild(el("span", "wd-bar-name", t.name + (t.sub ? " · " + t.sub : ""))); top.appendChild(el("span", "wd-bar-val", fmtBytes(t.bytes) + " · " + fmtShare(t.share)));
      row.appendChild(top);
      var sv = svgEl("svg", { viewBox: "0 0 100 6", preserveAspectRatio: "none", "aria-hidden": "true" }, "wd-bar");
      sv.appendChild(svgEl("rect", { x: 0, y: 0, width: 100, height: 6, rx: 3 }, "wd-track"));
      if (t.bytes > 0) { sv.appendChild(svgEl("rect", { x: 0, y: 0, width: Math.max(1.5, Math.min(1, t.share) * 100), height: 6, rx: 3 }, "wd-fill " + t.cls)); }
      row.appendChild(sv); box.appendChild(row);
    });
  }
  function renderWhereFlow(box, d, sources, targets, W) {
    var charW = 6.9, charW2 = 6.1, barW = 10, rowMin = 34, gap = 8, head = 22, groupGap = 18;
    function longest(list, f) { return list.reduce(function (n, x) { return Math.max(n, f(x).length); }, 0); }
    sources.forEach(function (s) { s.line2 = fmtBytes(s.bytes) + " · " + fmtShare(s.bytes / d.total_bytes); });
    targets.forEach(function (t) { t.line2 = (t.bytes ? fmtBytes(t.bytes) + " · " + fmtShare(t.share) : "empty") + (t.sub ? " · " + t.sub : ""); });
    function need(list) { return Math.max(longest(list, function (x) { return x.name; }) * charW, longest(list, function (x) { return x.line2; }) * charW2) + 14; }
    var labL = Math.round(Math.min(W * 0.22, Math.max(84, need(sources))));
    var labR = Math.round(Math.min(W * 0.34, Math.max(118, need(targets))));
    var xL = labL, xR = W - labR - barW;
    var groups = []; targets.forEach(function (t) { if (!groups.length || groups[groups.length - 1] !== t.group) { groups.push(t.group); } });
    var rightBytes = targets.reduce(function (n, t) { return n + t.bytes; }, 0) || 1;
    var Ht = Math.max(240, Math.min(520, targets.length * 52));
    var fixedR = head + (groups.length - 1) * groupGap + (targets.length - 1) * gap;
    var k = Math.max(0, Ht - fixedR) / rightBytes;
    // Small nodes get a minimum slot for their label; scale down until it fits.
    for (var it = 0; it < 6; it++) {
      var need = fixedR + targets.reduce(function (n, t) { return n + Math.max(rowMin, t.bytes * k); }, 0);
      if (need <= Ht + 1) { break; }
      k *= Math.max(0.5, (Ht - fixedR - rowMin * targets.length * 0.5) / (need - fixedR - rowMin * targets.length * 0.5) || 0.5);
    }
    var y = head, lastGroup = targets.length ? targets[0].group : "", heads = [[targets.length ? targets[0].group : "", y]];
    targets.forEach(function (t, i) {
      if (t.group !== lastGroup) { y += groupGap; lastGroup = t.group; heads.push([t.group, y]); }
      t.h = Math.max(t.bytes > 0 ? 2 : 0, t.bytes * k); t.slot = Math.max(rowMin, t.h); t.top = y + (t.slot - t.h) / 2; t.cy = y + t.slot / 2; t.fill = t.top;
      y += t.slot + (i < targets.length - 1 ? gap : 0);
    });
    var Hr = y;
    sources.forEach(function (s) { s.h = Math.max(2, s.bytes * k); s.slot = Math.max(rowMin, s.h); });
    var leftH = sources.reduce(function (n, s) { return n + s.slot; }, 0) + Math.max(0, sources.length - 1) * gap * 1.5;
    var H = Math.max(Hr, leftH + head) + 6;
    var yl = head + Math.max(0, (H - 6 - head - leftH) / 2);
    sources.forEach(function (s) { s.top = yl + (s.slot - s.h) / 2; s.cy = yl + s.slot / 2; yl += s.slot + gap * 1.5; });
    var nBands = sources.reduce(function (n, s) { return n + Object.keys(s.flows).length; }, 0);
    var svg = svgEl("svg", { width: W, height: H, viewBox: "0 0 " + W + " " + H, role: "img", "aria-label": "Bytes of each folder on each storage and device" }, "wd-svg" + (nBands > 30 ? " dense" : ""));
    var defs = svgEl("defs");
    ["own", "ext", "cold", "carrier", "other"].forEach(function (c) {
      var g = svgEl("linearGradient", { id: "wd-g-" + c, x1: 0, y1: 0, x2: 1, y2: 0 });
      g.appendChild(svgEl("stop", { offset: "0" }, "wd-stop src"));
      g.appendChild(svgEl("stop", { offset: "1" }, "wd-stop " + c));
      defs.appendChild(g);
    });
    svg.appendChild(defs);
    var bands = svgEl("g", {}, "wd-bands"), nodes = svgEl("g"), labels = svgEl("g");
    svg.appendChild(bands); svg.appendChild(nodes); svg.appendChild(labels);
    var byKey = {}; targets.forEach(function (t) { byKey[t.key] = t; });
    var x0 = xL + barW, x1 = xR, mx = (x0 + x1) / 2;
    sources.forEach(function (s, si) {
      var outs = targets.filter(function (t) { return s.flows[t.key] > 0; });
      var sum = outs.reduce(function (n, t) { return n + s.flows[t.key]; }, 0) || 1, ys = s.top;
      outs.forEach(function (t) {
        var v = s.flows[t.key], hs = s.h * v / sum, ht = v * k;
        var a0 = ys, a1 = ys + hs, b0 = t.fill, b1 = t.fill + ht;
        ys = a1; t.fill = b1;
        var p = svgEl("path", { d: "M" + x0 + "," + a0 + " C" + mx + "," + a0 + " " + mx + "," + b0 + " " + x1 + "," + b0 + " L" + x1 + "," + b1 + " C" + mx + "," + b1 + " " + mx + "," + a1 + " " + x0 + "," + a1 + " Z", fill: "url(#wd-g-" + t.cls.split(" ")[0] + ")", "data-s": si, "data-t": t.key }, "wd-band");
        svgTitle(p, s.name + " → " + t.name + ": " + fmtBytes(v) + " (" + fmtShare(v / s.bytes) + " of the folder)");
        bands.appendChild(p);
      });
    });
    function focus(attr, val) {
      svg.classList.toggle("focus", val !== null);
      bands.querySelectorAll(".wd-band").forEach(function (b) { b.classList.toggle("hot", val !== null && b.getAttribute(attr) === String(val)); });
    }
    function txt(x, y, anchor, cls, text) { labels.appendChild(svgEl("text", { x: x, y: y, "text-anchor": anchor }, cls, text)); }
    var charsL = Math.floor((labL - 14) / charW), charsR = Math.floor((labR - 14) / charW);
    var chars2L = Math.floor((labL - 14) / charW2), chars2R = Math.floor((labR - 14) / charW2);
    sources.forEach(function (s, si) {
      var g = svgEl("g", {}, "wd-node src" + (s.warn ? " warn" : ""));
      g.appendChild(svgEl("rect", { x: 0, y: s.cy - s.slot / 2, width: xL + barW, height: s.slot }, "wd-hit"));
      g.appendChild(svgEl("rect", { x: xL, y: s.top, width: barW, height: s.h, rx: Math.min(3, s.h / 2) }, "wd-bar-node"));
      g.appendChild(svgEl("text", { x: xL - 8, y: s.cy - 2, "text-anchor": "end" }, "wd-t1", clip(s.name, charsL)));
      g.appendChild(svgEl("text", { x: xL - 8, y: s.cy + 13, "text-anchor": "end" }, "wd-t2", clip(s.line2, chars2L)));
      svgTitle(g, s.title);
      g.addEventListener("mouseenter", function () { focus("data-s", si); });
      g.addEventListener("mouseleave", function () { focus("data-s", null); });
      nodes.appendChild(g);
    });
    targets.forEach(function (t) {
      var g = svgEl("g", {}, "wd-node " + t.cls + (t.bytes ? "" : " empty"));
      g.appendChild(svgEl("rect", { x: xR, y: t.cy - t.slot / 2, width: W - xR, height: t.slot }, "wd-hit"));
      if (t.h > 0) { g.appendChild(svgEl("rect", { x: xR, y: t.top, width: barW, height: t.h, rx: Math.min(3, t.h / 2) }, "wd-bar-node")); }
      else { g.appendChild(svgEl("rect", { x: xR, y: t.cy - 1, width: barW, height: 2, rx: 1 }, "wd-bar-node")); }
      g.appendChild(svgEl("text", { x: xR + barW + 8, y: t.cy - 2 }, "wd-t1", clip(t.name, charsR)));
      g.appendChild(svgEl("text", { x: xR + barW + 8, y: t.cy + 13 }, "wd-t2", clip(t.line2, chars2R)));
      svgTitle(g, t.title);
      g.addEventListener("mouseenter", function () { focus("data-t", t.key); });
      g.addEventListener("mouseleave", function () { focus("data-t", null); });
      nodes.appendChild(g);
    });
    txt(xL + barW, 12, "end", "wd-head", "Folders");
    heads.forEach(function (h) { txt(xR, h[1] - 10, "start", "wd-head", h[0]); });
    box.appendChild(svg);
  }
  window.addEventListener("resize", function () { if (lastWhere && currentPage === "overview" && $("wd-chart").clientWidth !== whereWidth) { renderWhere(lastWhere); } });
  $("p2pform").onsubmit = function (ev) { ev.preventDefault(); var d = formData(ev.target); d.port = +d.port || 17893; api("POST", "/api/p2p", d).then(function (r) { log("p2p settings saved; " + r.note); loadP2p(); }).catch(function (e) { alertBox(e.message); }); };
  $("storagekind").onchange = function () { var k = this.value; document.querySelectorAll("#addstorage [data-kind]").forEach(function (d) { d.classList.toggle("hidden", d.getAttribute("data-kind") !== k); }); };
  $("acceptshare").onsubmit = function (ev) { ev.preventDefault(); busy(true); api("POST", "/api/share/accept", formData(ev.target)).then(function (r) { ev.target.reset(); log("accepted shared folder " + r.folder + (r.fingerprint ? " (the owner confirmed fingerprint " + r.fingerprint + ")" : "") + "; attach it under Files"); nav("files"); return refreshState(); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); }); };

  // Folder forms: on desktop the directory is pre-filled from the folder root as you type the name;
  // on phones no directory is asked and the service picks <folder_root>/<name> (or the shared
  // storage for plain-file folders).
  function joinRoot(name) { var r = appState.folder_root || ""; if (!r || !name) { return ""; } var sep = r.indexOf("\\") >= 0 && r.indexOf("/") < 0 ? "\\" : "/"; return r.replace(/[\\/]+$/, "") + sep + name; }
  function wirePrefill(form, nameField) {
    var nameInp = form.querySelector("input[name=" + nameField + "]"); var pathInp = form.querySelector("input[name=path]");
    if (!nameInp || !pathInp) { return; }
    pathInp.dataset.auto = "1";
    pathInp.addEventListener("input", function () { pathInp.dataset.auto = pathInp.value ? "0" : "1"; });
    nameInp.addEventListener("input", function () { if (pathInp.dataset.auto !== "0") { pathInp.value = joinRoot(nameInp.value.trim()); } });
    form.addEventListener("reset", function () { setTimeout(function () { pathInp.dataset.auto = "1"; }, 0); });
  }
  wirePrefill($("addfolder"), "name"); wirePrefill($("attachfolder"), "name_or_id");
  // Device mode on phones: "plain files" needs all files access on Android, asked for when chosen.
  function wireModeCards(form) {
    var plain = form.querySelector("input[name=mode][value=plain]"); var encrypted = form.querySelector("input[name=mode][value=encrypted]"); var hint = form.querySelector(".mode-hint");
    if (!plain) { return; }
    plain.addEventListener("change", function () {
      if (!plain.checked || hasAllFiles()) { hint.classList.add("hidden"); return; }
      encrypted.checked = true;
      hint.textContent = droid ? "Android asks for all files access first. Allow it on the settings screen, come back and choose plain files again." : "This device cannot write plain files to the shared storage.";
      hint.classList.remove("hidden");
      if (droid) { try { droid.requestAllFilesAccess(); } catch (e) {} }
    });
  }
  wireModeCards($("addfolder")); wireModeCards($("attachfolder"));
  function modeOf(form) { var m = form.querySelector("input[name=mode]:checked"); return m ? m.value : "encrypted"; }
  function cleanPath(d, form) {
    if (isMobile() || !d.path || !d.path.trim()) { delete d.path; }
    delete d.mode;
    // Only the phone shells choose a mode; desktops keep plain files.
    if (appState.mobile) { d.plain = modeOf(form) === "plain"; }
    return d;
  }
  // A folder of the vault that is not on this device: attach that same folder
  // (never create a new one). Phones ask only how to keep it, desktops where.
  function offerAttach(f) {
    if (isMobile()) {
      dialog({ title: "Add " + f.name + " to this phone?", text: "This folder is on your other devices. It syncs here under the same name.", ok: "Encrypted on this phone", extra: "Plain files" }).then(function (r) {
        if (!r) { return; }
        var plain = r.action === "extra";
        if (plain && !hasAllFiles()) {
          if (droid) { try { droid.requestAllFilesAccess(); } catch (e) {} }
          alertBox("Android asks for all files access first. Allow it on the settings screen, come back and tap the folder again.");
          return;
        }
        attachFolder(f.name, "", plain);
      });
      return;
    }
    dialog({ title: "Attach " + f.name + " on this device?", text: "This folder is on your other devices. It syncs into this directory under the same name.", fields: [{ name: "path", label: "Directory on this device", value: joinRoot(f.name) }], ok: "Attach" }).then(function (r) {
      if (r) { attachFolder(f.name, (r.values.path || "").trim()); }
    });
  }
  function attachFolder(nameOrId, path, plain) {
    var form = $("attachfolder");
    var d = { name_or_id: nameOrId, selective: form.querySelector("input[name=selective]").checked };
    if (path && !isMobile()) { d.path = path; }
    if (appState.mobile) { d.plain = plain === undefined ? modeOf(form) === "plain" : plain; }
    busy(true);
    api("POST", "/api/folder/attach", d).then(function () { log("folder attached: " + nameOrId); return refreshStatus().then(function () { openFolder(nameOrId); }); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); });
  }
  $("addfolder").onsubmit = function (ev) { ev.preventDefault(); var d = cleanPath(formData(ev.target), ev.target); var name = d.name; api("POST", "/api/folder", d).then(function () { ev.target.reset(); log("folder added: " + name + (d.plain === false ? " (encrypted on this phone)" : d.plain ? " (plain files on this phone)" : "")); showFolderForms(false, true); return refreshStatus().then(function () { openFolder(name); }); }).catch(function (e) { alertBox(e.message); }); };
  $("attachfolder").onsubmit = function (ev) { ev.preventDefault(); var d = formData(ev.target); if (!d.name_or_id) { return; } attachFolder(d.name_or_id, d.path); ev.target.reset(); };
  $("addstorage").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/storage", formData(ev.target)).then(function (r) { ev.target.reset(); $("storagekind").onchange.call($("storagekind")); log("storage added; copying the vault to it now in the background"); return refreshStatus(r.status); }).catch(function (e) { alertBox(e.message); }); };

  // Logs (Settings card): how much the service writes to its log on this
  // device, the space it takes, the folder and a bundle to send with a report.
  var logLevels = ["trace", "debug", "info", "warn", "error"];
  function renderLogs(l) {
    var sel = $("log-level");
    var level = l.level || "debug";
    var extra = sel.querySelector("option[data-extra]");
    if (logLevels.indexOf(level) < 0) {
      // A filter spec (from the config, VARSTO_LOG or --log-level): shown as it is.
      if (!extra) { extra = el("option"); extra.dataset.extra = "1"; extra.setAttribute("data-no-i18n", ""); sel.appendChild(extra); }
      extra.value = level; extra.textContent = level;
    } else if (extra) { extra.remove(); }
    sel.value = level;
    var src = $("log-source");
    var over = l.source === "env" ? "The VARSTO_LOG environment variable overrides this setting." : l.source === "flag" ? "The --log-level option the service was started with overrides this setting." : "";
    src.textContent = over; src.classList.toggle("hidden", !over);
    if (l.bytes !== undefined) { $("log-usage").textContent = "Using " + fmtBytes(l.bytes || 0) + " in " + (l.files || 0) + " files"; }
    $("log-open").classList.toggle("hidden", l.can_open === false);
  }
  function loadLogs() {
    if (document.body.dataset.view !== "app") { return; }
    api("GET", "/api/logs").then(renderLogs).catch(function (e) { $("log-usage").textContent = e.message; });
  }
  $("log-level").onchange = function () {
    var v = this.value;
    api("POST", "/api/logs/level", { level: v }).then(function (r) { log("log detail set to " + (r.level || v)); renderLogs(r); loadLogs(); }).catch(function (e) { alertBox(e.message); loadLogs(); });
  };
  $("log-open").onclick = function () { api("POST", "/api/logs/open").catch(function (e) { alertBox(e.message); }); };
  $("log-bundle").onclick = function () {
    var b = this;
    if (droid && droid.shareFile) {
      // The Android shell cannot save a download: the service writes the bundle and the shell shares it.
      api("POST", "/api/logs/bundle", { save: true }).then(function (r) {
        log("log bundle saved: " + r.path);
        return alertBox("The bundle has no keys or passphrases, but it does contain file and folder names, device and storage names. Look through it before you share it.", "Log bundle saved").then(function () { droid.shareFile(r.path); });
      }).catch(function (e) { alertBox(e.message); });
      return;
    }
    b.disabled = true; workBar(true);
    fetch("/api/logs/bundle", { method: "POST", headers: { "X-Varsto-Token": token } }).then(function (r) {
      if (!r.ok) { return r.text().then(function (t) { var j = null; try { j = JSON.parse(t); } catch (x) {} throw new Error((j && j.error) || ("The Varsto service answered " + r.status + " to POST /api/logs/bundle")); }); }
      var m = (r.headers.get("Content-Disposition") || "").match(/filename="?([^";]+)"?/);
      var name = m ? m[1] : "varsto-logs.tar.zst";
      return r.blob().then(function (blob) {
        var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
        log("log bundle saved: " + name);
        return alertBox("The bundle has no keys or passphrases, but it does contain file and folder names, device and storage names. Look through it before you share it.", "Log bundle saved");
      });
    }, function (e) {
      throw new Error("Could not reach the Varsto service (POST /api/logs/bundle): " + e.message + ". It may be restarting or busy; try again in a moment.");
    }).catch(function (e) { alertBox(e.message); }).then(function () { b.disabled = false; workBar(false); loadLogs(); });
  };

  // Android: all files access for "plain files on this phone" folders (Settings card).
  function refreshAllFiles() {
    var android = !!droid || appState.platform === "android";
    $("allfilescard").classList.toggle("hidden", !android);
    if (!android) { return; }
    var ok = hasAllFiles();
    $("allfiles-state").textContent = ok ? "Allowed: plain-file folders go to Internal storage/Varsto." : "Not allowed yet: folders can only be kept encrypted on this phone.";
    $("allfilesbtn").textContent = ok ? "Open the permission settings" : "Allow all files access";
    document.querySelectorAll(".mode-hint").forEach(function (h) { if (ok) { h.classList.add("hidden"); } });
    if (typeof refreshCamera === "function") { refreshCamera(); }
  }
  // Android: camera upload settings (Settings card). The shell keeps them and does the uploading;
  // the page chooses the folder, explains the media permission and shows the status.
  var camNew = "\u0000new";
  function camSettings() { try { return JSON.parse(droid.cameraUpload()); } catch (e) { return null; } }
  function refreshCamera() {
    var cs = droid && droid.cameraUpload ? camSettings() : null;
    $("cameracard").classList.toggle("hidden", !cs);
    if (!cs) { return; }
    var sel = $("cam-folder"); var names = ((lastStatus && lastStatus.folders) || []).filter(function (f) { return f.path; }).map(function (f) { return f.name; });
    sel.innerHTML = "";
    names.forEach(function (n) { var o = document.createElement("option"); o.value = n; o.textContent = n; sel.appendChild(o); });
    if (cs.folder && names.indexOf(cs.folder) < 0) { var o2 = document.createElement("option"); o2.value = cs.folder; o2.textContent = cs.folder + " (not on this phone)"; sel.appendChild(o2); }
    var nw = document.createElement("option"); nw.value = camNew; nw.textContent = "New folder…"; sel.appendChild(nw);
    sel.value = cs.folder || (names.indexOf("Camera") >= 0 ? "Camera" : camNew);
    $("cam-on").checked = cs.enabled; $("cam-wifi").checked = cs.wifi_only; $("cam-charging").checked = cs.charging_only; $("cam-shots").checked = cs.screenshots;
    var line = !cs.enabled ? "Off." : !cs.permission ? "Access to photos and videos is not allowed; turn camera upload off and on again to allow it." : cs.message ? cs.message + "." : "On: new photos and videos go to " + cs.folder + ".";
    if (cs.uploaded) { line += " " + cs.uploaded + " uploaded so far" + (cs.last_upload ? ", last on " + new Date(cs.last_upload * 1000).toLocaleString() : "") + "."; }
    $("cam-state").textContent = line;
  }
  function saveCamera(enabled) {
    droid.setCameraUpload(JSON.stringify({ enabled: enabled, folder: $("cam-folder").value === camNew ? "" : $("cam-folder").value, wifi_only: $("cam-wifi").checked, charging_only: $("cam-charging").checked, screenshots: $("cam-shots").checked }));
    refreshCamera();
  }
  // A new folder for the uploads (kept encrypted on the phone, like any folder added here).
  function cameraFolder() {
    if ($("cam-folder").value !== camNew) { return Promise.resolve($("cam-folder").value); }
    return dialog({ title: "Folder for camera upload", fields: [{ name: "name", label: "Name", value: folderByName("Camera") ? "" : "Camera", required: true }], ok: "Create" }).then(function (r) {
      if (!r) { return null; }
      var name = r.values.name.trim();
      if (folderByName(name)) { return name; }
      return api("POST", "/api/folder", { name: name }).then(function () { log("folder added: " + name); return refreshStatus(); }).then(function () { return name; });
    });
  }
  var camPending = null;
  window.varstoMediaAccess = function (granted, blocked) {
    var then = camPending; camPending = null;
    if (granted) { if (then) { then(); } return; }
    $("cam-on").checked = false; saveCamera(false);
    if (blocked) { confirmBox("Android no longer asks for this permission. Open Varsto's app settings and allow Photos and videos there.", { title: "Access was refused", ok: "Open app settings" }).then(function (yes) { if (yes) { droid.openAppSettings(); } }); }
  };
  $("cam-on").onchange = function () {
    if (!$("cam-on").checked) { saveCamera(false); return; }
    cameraFolder().then(function (name) {
      if (!name) { $("cam-on").checked = false; return refreshCamera(); }
      refreshCamera(); $("cam-folder").value = name; $("cam-on").checked = true;
      if (droid.hasMediaAccess()) { saveCamera(true); return; }
      return dialog({ title: "Allow access to photos and videos?", text: "Camera upload reads new photos and videos on this phone and uploads them to " + name + ", encrypted. Varsto only reads them: the originals are never changed or deleted. Android asks you next.", ok: "Continue" }).then(function (r) {
        if (!r) { $("cam-on").checked = false; return; }
        camPending = function () { saveCamera(true); };
        droid.requestMediaAccess();
      });
    }).catch(function (e) { $("cam-on").checked = false; alertBox(e.message); });
  };
  $("cam-folder").onchange = function () {
    if ($("cam-folder").value === camNew) { cameraFolder().then(function (name) { refreshCamera(); if (name) { $("cam-folder").value = name; saveCamera($("cam-on").checked); } }).catch(function (e) { alertBox(e.message); }); return; }
    saveCamera($("cam-on").checked);
  };
  ["cam-wifi", "cam-charging", "cam-shots"].forEach(function (id) { $(id).onchange = function () { saveCamera($("cam-on").checked); }; });
  $("allfilesbtn").onclick = function () { if (droid) { try { droid.requestAllFilesAccess(); } catch (e) { alertBox(e.message); } } else { alertBox("Only the Android app can ask for this permission."); } };
  // The shell calls this when the activity resumes (back from the settings screen); browsers get visibilitychange.
  // Android: back in the app with the keyboard open on a number field (the
  // pairing code), the WebView reconnects the keyboard as a text keyboard.
  // Focusing the field again makes it ask for the number pad.
  function refocusNumberField() {
    var a = document.activeElement;
    if (!a || a.tagName !== "INPUT" || !(a.type === "tel" || a.inputMode === "numeric")) { return; }
    var pos = a.selectionStart; a.blur();
    setTimeout(function () { a.focus(); try { a.setSelectionRange(pos, pos); } catch (e) { /* not every type has a selection */ } }, 60);
  }
  document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") { refocusNumberField(); } });
  window.varstoResumed = function () { refocusNumberField(); refreshAllFiles(); if (document.body.dataset.view === "app") { refreshStatus(); } takeLink(); };
  window.addEventListener("focus", function () { if (document.body.dataset.view && document.body.dataset.view !== "unlock") { takeLink(); } });
  document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") { refreshAllFiles(); } trafficWatch(); activityWatch(); });

  // Reset: wipes this device's vault configuration after the user typed "reset".
  var resetInput = $("resetform").querySelector("input[name=confirm]");
  $("resetbtn").dataset.keepDisabled = "1";
  resetInput.addEventListener("input", function () { var ok = resetInput.value.trim() === "reset"; $("resetbtn").disabled = !ok; $("resetbtn").dataset.keepDisabled = ok ? "0" : "1"; });
  $("resetform").onsubmit = function (ev) {
    ev.preventDefault();
    if (resetInput.value.trim() !== "reset") { return; }
    confirmBox("Its keys and ledger copy are removed; your files stay. You will need the vault key to join again.", { title: "Reset this device?", ok: "Reset this device", danger: true }).then(function (yes) {
      if (!yes) { return; }
      busy(true);
      return api("POST", "/api/reset", { confirm: "reset" }).then(function (r) { log("device reset: removed " + ((r.removed || []).join(", ") || "nothing")); ev.target.reset(); $("resetbtn").disabled = true; $("resetbtn").dataset.keepDisabled = "1"; lastStatus = null; selectedFile = null; nav("overview"); return refreshState(); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); });
    });
  };

  refreshState();
})();
