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
  function log(msg) { var t = new Date().toLocaleTimeString(); logEl.textContent = "[" + t + "] " + msg + "\n" + logEl.textContent; }
  // Feedback for every action: the button that started a request shows a
  // spinner until it settles (and "Still working…" after a while), and a
  // thin bar at the top shows that something runs. Background polls (GET
  // without a press) stay silent.
  var lastPress = null; var working = 0; var barTimer = null;
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
    if (working === 0) { clearTimeout(barTimer); barTimer = null; $("workbar").classList.remove("on"); }
  }
  // While a pressed button downloads a file, the note under it shows how far.
  function followDownload(b) {
    var stop = false;
    (function tick() {
      if (stop) { return; }
      fetch("/api/progress", { headers: { "X-Varsto-Token": token } }).then(function (r) { return r.json(); }).then(function (j) {
        if (stop) { return; }
        var d = j.download;
        if (d && d.total > 0) {
          var note = b.nextElementSibling && b.nextElementSibling.classList.contains("busy-note") ? b.nextElementSibling : null;
          if (!note) { note = el("span", "busy-note muted small"); b.after(note); }
          note.textContent = "Downloading " + d.path.split("/").pop() + ": " + fmtBytes(d.done) + " of " + fmtBytes(d.total) + " (" + d.percent + " %" + (d.bytes_per_sec > 0 ? ", " + fmtBytes(d.bytes_per_sec) + "/s" : "") + ")";
        }
      }).catch(function () {}).then(function () { if (!stop) { setTimeout(tick, 400); } });
    })();
    return function () { stop = true; };
  }
  function api(method, path, body) {
    var b = pressed(); var loud = !!b || method !== "GET";
    if (b) { markBusy(b, true); }
    if (loud) { workBar(true); }
    var unfollow = b && /^\/api\/(fetch|paths|sync|view)/.test(path) ? followDownload(b) : null;
    var done = function () { if (unfollow) { unfollow(); } if (b) { markBusy(b, false); } if (loud) { workBar(false); } };
    return fetch(path, { method: method, headers: { "X-Varsto-Token": token, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) { throw new Error(j.error || r.statusText); } return j; }); })
      .then(function (j) { done(); return j; }, function (e) { done(); throw e; });
  }
  function show(section) { ["setup", "unlock", "app"].forEach(function (id) { $(id).classList.toggle("hidden", id !== section); }); $("lock").classList.toggle("hidden", section !== "app"); document.body.dataset.view = section; if (section !== "app") { $("pagetitle").textContent = section === "setup" ? "Welcome" : "Locked"; } else { $("pagetitle").textContent = pageTitle(currentPage); } trafficWatch(); }
  function fmtBytes(n) { var u = ["B", "KiB", "MiB", "GiB", "TiB"]; var i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + " " + u[i]; }
  function fmtDate(t) { return t ? new Date(t * 1000).toLocaleDateString() : ""; }
  function formData(form) { var o = {}; new FormData(form).forEach(function (v, k) { o[k] = v; }); form.querySelectorAll("input[type=checkbox]").forEach(function (c) { o[c.name] = c.checked; }); return o; }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined) { e.textContent = text; } return e; }
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
  var modalResolve = null;
  function dialog(o) {
    return new Promise(function (resolve) {
      closeDialog("cancel");
      modalResolve = resolve;
      $("modal-title").textContent = o.title || "Varsto";
      var tx = $("modal-text"); tx.textContent = o.text || ""; tx.classList.toggle("hidden", !o.text);
      var code = $("modal-code"); code.textContent = o.code || ""; code.classList.toggle("hidden", !o.code);
      var fs = $("modal-fields"); fs.innerHTML = "";
      (o.fields || []).forEach(function (f) {
        var lab = el("label", "", f.label); var inp = el("input"); inp.name = f.name; inp.type = f.type || "text"; inp.autocomplete = "off";
        if (f.type === "number") { inp.min = "0"; inp.step = "1"; inp.inputMode = "numeric"; }
        if (f.value !== undefined && f.value !== null) { inp.value = f.value; }
        if (f.placeholder) { inp.placeholder = f.placeholder; }
        if (f.required) { inp.required = true; }
        lab.appendChild(inp); if (f.hint) { lab.appendChild(el("span", "hint muted", f.hint)); } fs.appendChild(lab);
      });
      fs.classList.toggle("hidden", !(o.fields || []).length);
      var ok = $("modal-ok"); ok.textContent = o.ok || "OK"; ok.className = o.danger ? "danger-fill" : "";
      $("modal-cancel").textContent = o.cancel || "Cancel"; $("modal-cancel").classList.toggle("hidden", o.cancel === false);
      var ex = $("modal-extra"); ex.textContent = o.extra || ""; ex.classList.toggle("hidden", !o.extra);
      $("modal").classList.remove("hidden"); document.body.classList.add("modal-open");
      var first = fs.querySelector("input") || ok;
      setTimeout(function () { first.focus(); if (first.select) { first.select(); } }, 30);
    });
  }
  function dialogValues() { var v = {}; $("modal-fields").querySelectorAll("input").forEach(function (i) { v[i.name] = i.value; }); return v; }
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
    closeDialog("ok");
  };
  $("modal-cancel").onclick = function () { closeDialog("cancel"); };
  $("modal-extra").onclick = function () { closeDialog("extra"); };
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
  function miniMap(f) { var m = el("span", "minimap"); var b = folderBlocks(f); var t = blockTotal(b); if (t === 0) { return m; } var per = Math.max(1, Math.ceil(t / 40)); drawBlocks(m, b, per); m.title = t + " block" + (t === 1 ? "" : "s") + (per > 1 ? ", 1 square ≈ " + per + " blocks" : ""); return m; }
  function fileStateKey(f) { return f.state === "placeholder" ? "ph" : f.state === "missing" ? "missing" : f.pinned ? "verified" : "stored"; }
  function fileStateLabel(f) { return f.state === "placeholder" ? "Not on this device" : f.state === "missing" ? "Unavailable" : f.pinned ? "Local, kept here" : "Local"; }
  function stateSquare(f) { var sq = el("i", "blk state-blk s-" + fileStateKey(f)); sq.title = fileStateLabel(f); return sq; }

  // Theme: follows the OS unless the user picked one (persisted).
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  function storedTheme() { try { return localStorage.getItem("varsto-theme") || ""; } catch (e) { return ""; } }
  function applyTheme(t) { if (t === "dark" || t === "light") { document.documentElement.dataset.theme = t; } else { delete document.documentElement.dataset.theme; } var dark = t ? t === "dark" : !!(mq && mq.matches); document.querySelector("#themetoggle .theme-label").textContent = dark ? "Light mode" : "Dark mode"; $("themetoggle").setAttribute("aria-pressed", dark ? "true" : "false"); }
  applyTheme(storedTheme());
  if (mq && mq.addEventListener) { mq.addEventListener("change", function () { applyTheme(storedTheme()); }); }
  function toggleTheme() { var dark = document.documentElement.dataset.theme ? document.documentElement.dataset.theme === "dark" : !!(mq && mq.matches); var next = dark ? "light" : "dark"; try { localStorage.setItem("varsto-theme", next); } catch (e) {} applyTheme(next); }
  $("themetoggle").onclick = toggleTheme;
  $("themetoggle2").onclick = toggleTheme;
  $("themeauto").onclick = function () { try { localStorage.removeItem("varsto-theme"); } catch (e) {} applyTheme(""); log("theme follows the system"); };

  // Navigation between the pages of the app section.
  var titles = { overview: "Overview", files: "Files", shared: "Shared", storages: "Storages", policies: "Policies", peers: "Peers", settings: "Settings", more: "More" };
  var legacyPages = { folders: "files", sharing: "shared" };
  function pageTitle(p) { return titles[p] || "Overview"; }
  var currentPage = (function () { try { var p = sessionStorage.getItem("varsto-page"); p = legacyPages[p] || p; return titles[p] ? p : "overview"; } catch (e) { return "overview"; } })();
  function nav(page) {
    page = legacyPages[page] || page;
    if (!titles[page]) { page = "overview"; }
    if (page === "more" && !isMobile()) { page = "settings"; }
    if (page !== "policies") { policyReturn = null; } else if (!policyEdited()) { policyReturn = null; policyButtons(); }
    currentPage = page;
    try { sessionStorage.setItem("varsto-page", page); } catch (e) {}
    document.querySelectorAll(".page").forEach(function (d) { d.classList.toggle("hidden", d.dataset.page !== page); });
    var tab = page === "shared" || page === "policies" || page === "peers" || page === "settings" ? "more" : page;
    document.querySelectorAll(".sidebar .nav-item[data-nav]").forEach(function (b) { if (b.dataset.nav === page) { b.setAttribute("aria-current", "page"); } else { b.removeAttribute("aria-current"); } });
    document.querySelectorAll(".tabbar .nav-item[data-nav]").forEach(function (b) { if (b.dataset.nav === tab) { b.setAttribute("aria-current", "page"); } else { b.removeAttribute("aria-current"); } });
    if (document.body.dataset.view === "app") { $("pagetitle").textContent = pageTitle(page); }
    if (page === "peers") { loadP2p(); }
    trafficWatch();
    if (page === "files") { ensureFiles(); }
    if (page === "settings" && droid && lastStatus) { refreshAllFiles(); }
    window.scrollTo(0, 0);
  }
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
      if (!st.has_vault) { show("setup"); return; }
      if (!st.unlocked) { show("unlock"); return; }
      show("app");
      return refreshStatus();
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
        body.appendChild(title);
        body.appendChild(el("div", "li-sub", d.revoked
          ? "Removed by " + d.revoked_by + " on " + fmtDate(d.revoked_utc) + (d.wipe_ordered ? ", wipe ordered" : "") + " · " + d.device_id.slice(0, 8)
          : [deviceSystem(d), "added " + fmtDate(d.enrolled_utc), d.device_id.slice(0, 8)].filter(Boolean).join(" · ")));
        li.appendChild(body);
        if (!d.this_device && !d.revoked) {
          var a = el("div", "li-actions"); var b = el("button", "secondary danger", "Remove device…"); b.type = "button";
          b.onclick = function () { removeDevice(d); }; a.appendChild(b); li.appendChild(a);
        }
        ul.appendChild(li);
      });
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
    ["Folder", "Status", "Copies on any storage"].concat(places.map(placeLabel)).concat(["Verified by another device within (days)"]).forEach(function (h) { head.appendChild(el("th", null, h)); });
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
    return Object.keys((lastStatus && lastStatus.devices) || {}).map(function (k) { return lastStatus.devices[k]; }).filter(function (n) { return n !== me; });
  }
  function fillCarrierFor() {
    var sel = $("carrierfor"); var keep = sel.value; sel.innerHTML = "";
    var any = document.createElement("option"); any.value = ""; any.textContent = "any device that lacks the blocks"; sel.appendChild(any);
    otherDeviceNames().forEach(function (n) { var o = document.createElement("option"); o.value = n; o.textContent = n; sel.appendChild(o); });
    sel.value = keep;
  }
  function carrierDestination(name, current) {
    var names = otherDeviceNames();
    dialog({ title: "Where does " + name + " travel?", text: "Name the device (or devices, comma-separated) this transferrer is taken to. It then carries the blocks they still lack and is emptied as they receive them. Leave empty to carry what any device lacks. Your other devices: " + (names.join(", ") || "none yet") + ".", fields: [{ name: "devices", label: "Destination devices", value: current.join(", "), placeholder: names[0] || "" }], ok: "Save" }).then(function (r) {
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
  // Removing a storage: first show what has to be copied elsewhere to keep
  // every block's copies (one, or the folder policy's minimum), then do it.
  function removeStorage(name) {
    api("GET", "/api/storage/remove-plan?name=" + enc(name)).then(function (p) {
      if (p.blocked) { alertBox("Cannot remove " + name + ": " + p.blocked); return null; }
      var text = name + " holds " + p.blocks + " block" + (p.blocks === 1 ? "" : "s") + " of your files. ";
      text += p.copies.length ? p.blocks_ok + " already have enough copies elsewhere; " + p.copies.length + " cop" + (p.copies.length === 1 ? "y" : "ies") + " (" + fmtBytes(p.bytes_to_copy) + ") will first be made on " + p.targets.join(", ") + ". " : "Every block already has enough copies on your other storages. ";
      text += "Then no device counts " + name + " as a copy any more. Remove leaves its data in place; you can also delete it.";
      return dialog({ title: "Remove storage " + name + "?", text: text, ok: "Remove", extra: "Remove and delete data" }).then(function (r) {
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
      text: (f.shared ? "" : "Anyone holding the token can read and write this folder. ") + "Paste the recipient's request code to seal the token to their device, or leave it empty for a plain token that carries the folder key itself.",
      fields: [{ name: "to", label: "Recipient's request code (optional)", placeholder: "vsr1…" }],
      ok: f.shared ? "Create token" : "Share"
    }).then(function (r) {
      if (!r) { return; }
      return api("POST", "/api/share/create", { folder: f.name, to: (r.values.to || "").trim() }).then(function (t) {
        $("sharetoken").textContent = (t.sealed ? "Sealed share token for " + t.folder + " (only the requesting device can open it): " : "Share token for " + t.folder + " (contains the folder key; send over a secure channel): ") + t.token;
        $("sharetoken").classList.remove("hidden"); nav("shared"); refreshStatus();
      });
    }).catch(function (e) { alertBox(e.message); });
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
        text: (keys.length === 1 ? "One key opens this Strongroom; if it is lost, so is the folder. Enrol a backup key and keep it somewhere safe." : keys.length + " keys open this Strongroom; any one of them is enough.") + " To add a backup key, run the command with an enrolled key plugged in; it asks you to swap to the new key.",
        code: lines.join("\n") + "\n\nvarsto strongroom add-key " + shArg(f.name) + " --label safe",
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

  function refreshStatus() {
    return api("GET", "/api/status").then(function (s) {
      lastStatus = s;
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
        if (f.path && f.plain === false) { nameCell.appendChild(document.createTextNode(" ")); nameCell.appendChild(pill("grey", "encrypted here")); }
        var sub = el("span", "sub", f.path || "Not attached on this device"); if (f.path) { sub.title = f.path; } nameCell.appendChild(sub);
        nameCell.appendChild(miniMap(f));
        tr.appendChild(nameCell);
        totalBlocks = addBlocks(totalBlocks, folderBlocks(f));
        td(f.files, "num", "Files"); td(fmtBytes(f.bytes), "num", "Size"); td(f.chunks, "num", "Chunks");
        td(f.chunks_without_storage_copy, "num" + (f.chunks_without_storage_copy > 0 ? " bad" : ""), "Without storage copy"); td(f.chunks_verified_elsewhere, "num", "Verified elsewhere");
        var pc = document.createElement("td"); pc.dataset.policyFor = f.name; pc.appendChild(pill("grey", f.policy ? "Unchecked" : "No policy")); if (f.policy) { var pt = el("span", "policy-text", f.policy); pt.title = f.policy; pc.appendChild(pt); } tr.appendChild(pc);
        var act = document.createElement("td");
        if (f.path) { var b = document.createElement("button"); b.className = "secondary"; b.textContent = "Sync"; b.onclick = function () { runSync(f.name); }; act.appendChild(b); }
        if (!s.member) { var sh = document.createElement("button"); sh.className = "secondary"; sh.textContent = f.shared ? "Token" : "Share"; sh.onclick = function () { shareFolder(f); }; act.appendChild(sh); }
        if (!s.member) { var pb = document.createElement("button"); pb.className = "secondary"; pb.textContent = "Policy"; pb.onclick = function () { openPolicy(f); }; act.appendChild(pb); }
        if (!s.member) { var rmb = document.createElement("button"); rmb.className = "secondary"; rmb.textContent = "Remove"; rmb.onclick = function () { removeFolder(f); }; act.appendChild(rmb); }
        if (f.strongroom && f.strongroom !== "locked") { var lk = document.createElement("button"); lk.className = "secondary"; lk.textContent = "Lock"; lk.onclick = function () { api("POST", "/api/strongroom/lock", { folder: f.name }).then(function () { log("locked " + f.name); return refreshStatus(); }).catch(function (e) { alertBox(e.message); }); }; act.appendChild(lk); }
        if (!s.member && f.path && !f.strongroom && !f.shared) { var cv = document.createElement("button"); cv.className = "secondary"; cv.textContent = "Convert to Strongroom…"; cv.onclick = function () { convertStrongroom(f); }; act.appendChild(cv); }
        if (f.strongroom) { var ks = document.createElement("button"); ks.className = "secondary"; ks.textContent = "Security keys…"; ks.title = "Enrolled security keys; add a backup key"; ks.onclick = function () { strongroomKeys(f); }; act.appendChild(ks); }
        if (f.strongroom === "locked") { var note = document.createElement("span"); note.className = "muted"; note.textContent = "unlock with: varsto strongroom unlock " + f.name; act.appendChild(note); }
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
          var sbody = el("div", "li-body"); var stitle = el("div", "li-title", f.name); stitle.appendChild(pill("accent", "shared")); sbody.appendChild(stitle);
          sbody.appendChild(el("div", "li-sub", f.files + " files · " + fmtBytes(f.bytes) + (f.path ? " · " + f.path : ""))); sli.appendChild(sbody);
          if (!s.member) { var sa = el("div", "li-actions"); var sb = el("button", "secondary", "New token"); sb.type = "button"; sb.onclick = function () { shareFolder(f); }; sa.appendChild(sb); sli.appendChild(sa); }
          shl.appendChild(sli);
        }

        // Policies page: one row per folder, filled in once the reports arrive.
        var pli = el("li"); pli.dataset.policyRow = f.name;
        var pic = el("span", "li-icon"); pic.appendChild(icon("policies")); pli.appendChild(pic);
        var pbody = el("div", "li-body"); var ptitle = el("div", "li-title", f.name); ptitle.appendChild(pill("grey", f.policy ? "Unchecked" : "No policy")); pbody.appendChild(ptitle);
        pbody.appendChild(el("div", "li-sub", f.policy || "No rule set. Files are still written to every storage; a policy adds a minimum that Varsto watches for you."));
        pli.appendChild(pbody);
        if (!s.member) { var pa = el("div", "li-actions"); var pe = el("button", "secondary", f.policy ? "Edit policy" : "Set policy"); pe.type = "button"; pe.onclick = function () { editPolicy(f); }; pa.appendChild(pe); pli.appendChild(pa); }
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
      loadAdvice(); loadAutoVerify();
      $("selectivetoggle").checked = fsel.selectedOptions.length && fsel.selectedOptions[0].dataset.selective === "1";
      var ul = $("storages"); ul.innerHTML = "";
      s.storages.forEach(function (st) {
        var where = st.kind === "s3" ? st.endpoint + " bucket " + st.bucket + (st.prefix ? "/" + st.prefix : "") + (st.storage_class ? ", class " + st.storage_class : "") : (st.kind === "rclone" ? st.remote : st.kind === "pool" ? (st.disks || []).length + " disk" + ((st.disks || []).length === 1 ? "" : "s") + ", " + (st.reserve_percent || 5) + " % kept free" : st.path);
        var li = el("li"); li.dataset.storage = st.name; var ic = el("span", "li-icon"); ic.appendChild(icon("storages")); li.appendChild(ic);
        var body = el("div", "li-body"); var title = el("div", "li-title", st.name);
        title.appendChild(pill("grey", st.kind === "s3" ? "S3" : st.kind === "rclone" ? "rclone" : st.kind === "pool" ? "disk pool" : "directory"));
        var dest = (s.carrier_for || {})[st.name] || [];
        if (st.cold) { title.appendChild(pill("grey", "cold")); } if (st.carrier) { title.appendChild(pill("grey", dest.length ? "transferrer for " + dest.join(", ") : "transferrer")); }
        if (st.place) { title.appendChild(pill("grey", st.place)); }
        body.appendChild(title); body.appendChild(el("div", "li-sub", where || "")); li.appendChild(body);
        if (!s.member) {
          var ra = el("div", "li-actions");
          if (st.carrier) { var cb = el("button", "secondary", "Destination\u2026"); cb.type = "button"; cb.onclick = function () { carrierDestination(st.name, dest); }; ra.appendChild(cb); }
          var rb = el("button", "secondary", "Remove"); rb.type = "button"; rb.onclick = function () { removeStorage(st.name); }; ra.appendChild(rb); li.appendChild(ra);
        }
        ul.appendChild(li);
      });
      $("storages-empty").classList.toggle("hidden", s.storages.length > 0);
      loadStorageCosts();
      renderPools(s.storages);
      var names = Object.keys(s.devices).map(function (k) { return s.devices[k] + " (" + k.slice(0, 8) + ")"; });
      var reps = Object.keys(s.replicas || {}).map(function (k) { return s.replicas[k]; });
      var mems = Object.keys(s.members || {}).map(function (k) { return s.members[k]; });
      $("devices").textContent = (s.member ? "This device is a member of a shared folder. " : "") + "Devices: " + (names.join(", ") || "none yet") + (reps.length ? " · replicas: " + reps.join(", ") : "") + (mems.length ? " · members: " + mems.join(", ") : "") + (s.forked_devices.length ? " · FORKED: " + s.forked_devices.join(", ") : "");
      $("members").textContent = mems.length ? "Members with access to shared folders: " + mems.join(", ") : "";
      loadDevices(s);
      $("replicatoken").classList.toggle("hidden", !!s.member);
      $("replicacard").classList.toggle("hidden", !!s.member);
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
      var row = el("div", "suggestion");
      row.appendChild(el("span", "", s.folder + ": " + s.files + " idle file" + (s.files === 1 ? "" : "s") + " (" + fmtBytes(s.bytes) + ") can be freed on this device; they stay on " + s.keep_on.join(", ") + "."));
      var b = el("button", "secondary", "Free " + s.files + " file" + (s.files === 1 ? "" : "s")); b.type = "button";
      b.onclick = function () { applySuggestion(s); };
      row.appendChild(b); box.appendChild(row);
    });
  }
  function applySuggestion(s) {
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
        var acts = el("div", "li-actions"); var pb = el("button", "secondary", "Price"); pb.type = "button"; pb.onclick = function () { editPrice(e); }; acts.appendChild(pb); li.appendChild(acts);
      });
    }).catch(function () {});
  }
  function editPrice(e) {
    var p = e.price || {};
    var v = function (x) { return x == null ? "" : String(x); };
    dialog({ title: "Prices of " + e.name, text: "Used for the monthly cost and the placement suggestions. Empty means unknown, not free." + (p.source ? " Now: " + p.source + "." : ""), fields: [
      { name: "gb_month", label: "Storage per GB-month", value: v(p.storage_per_gb_month), placeholder: "0.006" },
      { name: "egress", label: "Egress per GB", value: v(p.egress_per_gb), placeholder: "0.01" },
      { name: "retrieval", label: "Retrieval per GB (cold classes)", value: v(p.retrieval_per_gb) },
      { name: "min_days", label: "Minimum storage days (cold classes)", value: v(p.minimum_storage_days) },
      { name: "currency", label: "Currency", value: p.currency || "", placeholder: "EUR" }
    ], ok: "Save", extra: "Clear my prices" }).then(function (r) {
      if (!r) { return; }
      var body = r.action === "extra" ? { name: e.name, clear: true } : { name: e.name, gb_month: r.values.gb_month, egress: r.values.egress, retrieval: r.values.retrieval, min_days: r.values.min_days, currency: r.values.currency };
      return api("POST", "/api/storage/price", body).then(function () { log("prices of " + e.name + " saved"); refreshStatus(); });
    }).catch(function (err) { log("error: " + err.message); });
  }

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
        var ul = el("ul", "list");
        mine.forEach(function (d) {
          var li = el("li"); var ic = el("span", "li-icon"); ic.appendChild(icon("storages")); li.appendChild(ic);
          var body = el("div", "li-body"); var t = el("div", "li-title", d.label);
          t.appendChild(pill(d.attached ? "ok" : "grey", d.attached ? "attached" : "offline")); if (d.retired) { t.appendChild(pill("grey", "retired")); }
          body.appendChild(t);
          var parts = [];
          if (d.attached) { parts.push(d.mount); if (d.free_bytes !== null && d.free_bytes !== undefined) { parts.push(fmtBytes(d.free_bytes) + " free"); } }
          else if (d.mount) { parts.push("last seen at " + d.mount); }
          parts.push(d.objects + " block" + (d.objects === 1 ? "" : "s") + ", " + fmtBytes(d.used_bytes) + " used");
          parts.push("last verified " + (d.last_verified_utc ? fmtDate(d.last_verified_utc) : "never"));
          if (d.pending_deletes) { parts.push(d.pending_deletes + " pending delete" + (d.pending_deletes === 1 ? "" : "s")); }
          body.appendChild(el("div", "li-sub", parts.join(" · ")));
          li.appendChild(body);
          if (!isMobile()) {
            var acts = el("div", "li-actions");
            if (d.attached) {
              var chk = el("button", "secondary", "Check"); chk.type = "button"; chk.title = "Verify sizes, apply pending deletes, add new blocks"; chk.onclick = function () { diskAction("/api/disk/check", { label: d.label, full: false }, "check"); }; acts.appendChild(chk);
              var full = el("button", "secondary", "Check fully"); full.type = "button"; full.title = "Re-hash every block on the disk"; full.onclick = function () { diskAction("/api/disk/check", { label: d.label, full: true }, "full check"); }; acts.appendChild(full);
              var ej = el("button", "secondary", "Eject"); ej.type = "button"; ej.title = "Write the disk index and sync; then unmount it yourself"; ej.onclick = function () { diskAction("/api/disk/eject", { label: d.label }, "eject"); }; acts.appendChild(ej);
            }
            if (!d.retired) { var rt = el("button", "secondary", "Retire"); rt.type = "button"; rt.title = "Nothing new goes to this disk"; rt.onclick = function () { dialog({ title: "Retire disk " + d.label + "?", text: "Nothing new is written to it; what it holds stays readable while attached.", ok: "Retire" }).then(function (yes) { if (yes) { diskAction("/api/disk/retire", { label: d.label }, "retire"); } }); }; acts.appendChild(rt); }
            li.appendChild(acts);
          }
          ul.appendChild(li);
        });
        card.appendChild(ul);
        box.appendChild(card);
      });
    }).catch(function (e) { log("disks: " + e.message); });
  }
  $("adddisk").onsubmit = function (ev) {
    ev.preventDefault(); var d = formData(ev.target); busy(true); log("adding disk " + d.label + " to pool " + d.pool);
    api("POST", "/api/disk/add", d).then(function (r) { ev.target.reset(); log("disk " + r.disk.label + " added to pool " + r.pool + ": " + fmtBytes(r.bytes_added) + " added (" + r.objects_added + " blocks)"); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); return refreshStatus(); });
  };

  function fmtTime(t) { return t ? new Date(t * 1000).toLocaleTimeString() : "never"; }
  function renderService(sv) {
    var state = sv.running ? (sv.paused ? "paused" : "running") : "stopped";
    var txt = sv.running ? "Watching " + sv.watching + " folder(s) · last sync " + fmtTime(sv.last_sync_utc) + (sv.last_result ? " (" + sv.last_result + ")" : "") + (sv.last_error ? " · last error: " + sv.last_error : "") + " · next in " + (sv.next_sync_utc ? Math.max(0, Math.round(sv.next_sync_utc - Date.now() / 1000)) + " s" : "-") : "The background service is not running; nothing syncs until it is started.";
    $("svc-text").textContent = txt;
    var sp = $("svc-pill"); sp.textContent = state === "running" ? "Running" : state === "paused" ? "Paused" : "Not running"; sp.className = "pill " + (state === "running" ? "ok" : state === "paused" ? "risk" : "bad");
    $("svc-dot").dataset.state = state;
    $("pause").textContent = sv.paused ? "Resume" : "Pause";
    $("pause").dataset.paused = sv.paused ? "1" : "0";
  }
  // The tray and menu bar pause and sync through the same service; follow them.
  function pollService() { if (!token || document.visibilityState !== "visible") { return; } api("GET", "/api/service").then(renderService).catch(function () {}); }
  setInterval(pollService, 5000);
  window.addEventListener("focus", pollService);
  $("pause").onclick = function () { api("POST", "/api/service/pause", { paused: $("pause").dataset.paused !== "1" }).then(renderService).catch(function (e) { log("error: " + e.message); }); };
  $("update").onclick = function () {
    busy(true); log("checking for updates");
    api("GET", "/api/update/check").then(function (c) {
      if (!c.available) { log("up to date: " + c.current + " (latest " + c.latest + ")"); busy(false); return; }
      return confirmBox("Update " + c.current + " to " + c.latest + " now? The service restarts afterwards.", { title: "Update Varsto", ok: "Update" }).then(function (yes) {
        if (!yes) { busy(false); return; }
        return api("POST", "/api/update", {}).then(function (r) { log(r.message); if (r.updated) { log("the service is restarting; reopen Varsto in a few seconds"); } busy(false); });
      });
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
      r.forEach(function (x) { log(x.pull.folder + ": pulled " + x.pull.files_updated + " updated, " + x.pull.files_deleted + " deleted, " + x.pull.conflicts + " conflicts; pushed " + x.push.files_changed + " changed, " + x.push.chunks_uploaded + " chunks" + (x.pull.files_unavailable.length ? "; unavailable: " + x.pull.files_unavailable.join(", ") : "") + (x.pull.forked_devices.length ? "; FORKED: " + x.pull.forked_devices.join(", ") : "")); });
    }).catch(function (e) { log("sync failed: " + e.message); }).then(function () { busy(false); return refreshStatus().then(function () { if (currentPage === "files") { loadFiles(); } }); });
  }

  $("sync").onclick = function () { runSync(null); };
  $("refresh").onclick = refreshStatus;
  $("lock").onclick = function () { api("POST", "/api/lock").then(function (r) { (r.freed || []).forEach(function (f) { if (f.freed || f.kept) { log(f.folder + ": removed " + f.freed + " local cop" + (f.freed === 1 ? "y" : "ies") + (f.kept ? ", kept " + f.kept + " not yet stored elsewhere" : "")); } }); return refreshState(); }).catch(function (e) { log("error: " + e.message); }); };
  $("fsck").onclick = function () {
    busy(true); log("fsck started");
    api("POST", "/api/fsck", { verify: $("verify").checked }).then(function (r) {
      log("fsck: " + r.chunks_referenced + " referenced, " + r.chunks_with_storage_copy + " with storage copy, " + r.chunks_verified_elsewhere + " verified elsewhere, " + r.chunks_claimed_only + " claimed only, missing " + r.chunks_missing.length + ", claims without object " + r.claims_without_object + ", unreferenced objects " + r.objects_unreferenced + ", verified now " + r.objects_verified_now + ", corrupt " + r.objects_corrupt.length + (r.forked_devices.length ? ", FORKED " + r.forked_devices.join(",") : ""));
    }).catch(function (e) { log("fsck failed: " + e.message); }).then(function () { busy(false); return refreshStatus(); });
  };

  // Files view: folder header, tree selection, rows, details pane and toolbar. On a phone the
  // card has two screens: the folder list and one folder (#filesmain[data-screen]).
  function setScreen(sc) { $("filesmain").dataset.screen = sc; }
  function showFolderList() { setScreen("list"); clearSelection(); }
  $("files-back").onclick = showFolderList;
  function markTree(name) { document.querySelectorAll("#foldertree .tree-item").forEach(function (b) { if (b.dataset.folder === name && name) { b.setAttribute("aria-current", "true"); } else { b.removeAttribute("aria-current"); } }); }
  // Where the folder's files are on a phone, in the user's words.
  function whereLine(f) {
    if (!f || !isMobile()) { return ""; }
    if (f.plain === false) { return "Encrypted on this phone: files are fetched when you open them and removed when you lock the vault."; }
    if (appState.platform !== "android") { return ""; }
    var p = f.path || "";
    if (p.indexOf("/storage/emulated/0/") === 0 && p.indexOf("/Android/data/") < 0) { return "On this phone: Internal storage/" + p.slice("/storage/emulated/0/".length) + ", visible in My Files."; }
    return "Plain files inside the app's own space only; other apps cannot see them.";
  }
  function updateFilesHead() {
    var f = folderByName($("filesfolder").value);
    $("files-sub").textContent = f ? [f.path, f.files + " file" + (f.files === 1 ? "" : "s"), fmtBytes(f.bytes), f.selective ? "selective sync" : null, f.shared ? "shared" : null].filter(Boolean).join(" · ") : "";
    if (f && isMobile()) { $("files-sub").textContent = [f.files + " file" + (f.files === 1 ? "" : "s"), fmtBytes(f.bytes), f.selective && f.plain !== false ? "selective sync" : null].filter(Boolean).join(" · "); }
    var w = whereLine(f); $("files-where").textContent = w; $("files-where").classList.toggle("hidden", !w);
    $("selectivelabel").classList.toggle("hidden", !!(f && isMobile() && f.plain === false));
    $("files-share").disabled = !f || !!(lastStatus && lastStatus.member);
    $("files-sync").disabled = !f;
    $("files-upload").disabled = !f;
    $("files-mkdir").disabled = !f;
    updateToolbar();
  }
  function openFolder(name) { $("filesfolder").value = name; $("selectivetoggle").checked = $("filesfolder").selectedOptions.length && $("filesfolder").selectedOptions[0].dataset.selective === "1"; markTree(name); updateFilesHead(); showFolderForms(false); setScreen("folder"); nav("files"); loadFiles(); }
  function showFolderForms(on, byUser) { $("folderforms").classList.toggle("hidden", !on); if (byUser) { $("folderforms").dataset.user = on ? "1" : "0"; } if (on && byUser) { var inp = $("addfolder").querySelector("input[name=name]"); setTimeout(function () { inp.focus(); }, 50); } }
  $("treeadd").onclick = function () { nav("files"); showFolderForms(true, true); window.scrollTo(0, document.body.scrollHeight); };
  $("filesadd").onclick = function () { var open = $("folderforms").classList.contains("hidden"); showFolderForms(open, true); if (open) { $("folderforms").scrollIntoView({ block: "start", behavior: "smooth" }); } };
  $("folderlist-add").onclick = function () { showFolderForms(true, true); $("folderforms").scrollIntoView({ block: "start", behavior: "smooth" }); };
  document.querySelectorAll("[data-close-forms]").forEach(function (b) { b.onclick = function () { showFolderForms(false, true); }; });

  // Open or share a file on the phone: fetch it first if it is only a placeholder, then hand the
  // real path to the shell, which builds a content URI and starts the system chooser.
  function openOnPhone(folder, f, share) {
    var ready = f.state === "local" ? Promise.resolve() : (busy(true), api("POST", "/api/fetch", { folder: folder, path: f.path }).then(function () { log("fetched " + f.path); busy(false); }, function (e) { busy(false); throw e; }));
    ready.then(function () {
      if (!droid) { throw new Error("opening files in other apps is not available in this shell yet"); }
      if (share) { droid.shareFile(f.disk); } else { droid.openFile(f.disk); }
      setTimeout(loadFiles, 1500);
    }).catch(function (e) { log((share ? "share" : "open") + " failed: " + e.message); alertBox(e.message); });
  }
  // Folders kept encrypted on the phone: handing a file to another app writes a decrypted copy,
  // so say so once per session before the first one.
  function encryptedHere(folder) { var fs = folderByName(folder); return !!(fs && fs.path && fs.plain === false); }
  var handOffOk = false;
  function handOff(folder, f, share) {
    if (!encryptedHere(folder) || handOffOk) { return openOnPhone(folder, f, share); }
    confirmBox("Varsto writes a decrypted copy of " + f.path.split("/").pop() + " to this phone and gives it to the app you choose. Varsto removes its copy when it locks; the other app may keep its own.", { title: share ? "Share a decrypted copy?" : "Open in another app?", ok: share ? "Share" : "Open" }).then(function (yes) { if (yes) { handOffOk = true; openOnPhone(folder, f, share); } });
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
    $("viewer-name").textContent = f.path.split("/").pop(); $("viewer-name").title = f.path;
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
    $("fd-name").textContent = f.path;
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
    var acts = $("fd-actions"); acts.innerHTML = "";
    fileActions(folder, f, true).forEach(function (b) { acts.appendChild(b); });
    updateToolbar();
  }
  function clearSelection() { selectedFile = null; document.querySelectorAll("#files tbody tr").forEach(function (r) { r.classList.remove("selected"); }); $("filedetails").classList.add("hidden"); document.querySelector(".files-layout").classList.remove("with-details"); updateToolbar(); }
  $("fd-close").onclick = clearSelection;
  function updateToolbar() {
    var f = selectedFile; var folder = folderByName($("filesfolder").value);
    $("files-download").disabled = !f || !(f.state === "placeholder" || f.state === "missing");
    // Without a selection the button frees every fetched file of an "encrypted here" folder.
    var folderWide = !f && !!folder && folder.plain === false && isMobile();
    $("files-free").disabled = f ? f.state !== "local" : !folderWide;
    $("files-free").title = folderWide ? "Remove every fetched copy of this folder from this phone" : "Keep only a placeholder of the selected file here";
  }
  function fetchFile(folder, path) {
    busy(true); $("needsdisk").classList.add("hidden");
    api("POST", "/api/fetch", { folder: folder, path: path }).then(function (r) {
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
  $("files-sync").onclick = function () { var f = $("filesfolder").value; if (f) { runSync(f); } };
  $("files-download").onclick = function () { if (selectedFile) { fetchFile($("filesfolder").value, selectedFile.path); } };
  $("files-free").onclick = function () { var folder = $("filesfolder").value; if (selectedFile) { freeFile(folder, selectedFile.path); } else if (folder) { freeFolder(folder); } };
  $("files-share").onclick = function () { var f = folderByName($("filesfolder").value); if (f) { shareFolder(f); } };

  // Adding files: each chosen file goes up as a raw POST /api/upload body; new subfolders made in
  // this session are shown as rows (the ledger lists files only) so files can be added into them.
  var uploadPrefix = "";
  var newDirs = {};
  $("files-upload").onclick = function () { uploadPrefix = ""; $("fileinput").click(); };
  $("fileinput").onchange = function () { var files = Array.prototype.slice.call($("fileinput").files || []); $("fileinput").value = ""; uploadFiles($("filesfolder").value, files, uploadPrefix); };
  function uploadFiles(folder, files, prefix) {
    if (!folder || !files.length) { return; }
    var prog = $("files-progress"); prog.classList.remove("hidden");
    var done = 0, failed = 0; busy(true);
    function step(i) {
      if (i >= files.length) {
        prog.textContent = failed ? done + " of " + files.length + " files added to " + folder + "; " + failed + " failed" : files.length + " file" + (files.length === 1 ? "" : "s") + " added to " + folder + (prefix ? "/" + prefix : "");
        setTimeout(function () { prog.classList.add("hidden"); }, 4000);
        busy(false); loadFiles();
        return runSync(folder);
      }
      var f = files[i]; var rel = (prefix ? prefix + "/" : "") + f.name;
      prog.textContent = "Adding " + (i + 1) + " of " + files.length + ": " + f.name + " (" + fmtBytes(f.size) + ")";
      return fetch("/api/upload?folder=" + enc(folder) + "&path=" + enc(rel), { method: "POST", headers: { "X-Varsto-Token": token, "Content-Type": "application/octet-stream" }, body: f })
        .then(function (r) { return r.json().then(function (j) { if (!r.ok) { throw new Error(j.error || r.statusText); } done++; log("added " + rel + " (" + fmtBytes(f.size) + ") to " + folder + "; " + j.push.chunks_uploaded + " chunks pushed"); }); })
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
      var tb = $("files").querySelector("tbody"); tb.innerHTML = "";
      var dirs = (newDirs[folder] || []).filter(function (d) { return !rows.some(function (r) { return r.path.indexOf(d + "/") === 0; }); });
      var empty = $("files-empty");
      empty.querySelector(".empty-title").textContent = rows.length || dirs.length ? "" : "This folder is empty";
      empty.querySelector(".muted").textContent = rows.length || dirs.length ? "" : "Add files here, or put them in " + folder + " on any device; they appear after a sync.";
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
      rows.forEach(function (f) {
        var tr = document.createElement("tr"); tr.dataset.path = f.path;
        function td(t, cls, label) { var d = document.createElement("td"); d.textContent = t; if (cls) { d.className = cls; } if (label) { d.dataset.label = label; } tr.appendChild(d); }
        var nameCell = document.createElement("td"); var wrap = el("span", "file-name");
        wrap.appendChild(stateSquare(f));
        if (f.media) { var im = document.createElement("img"); im.className = "thumb"; im.alt = ""; im.loading = "lazy"; im.src = "/api/thumb?folder=" + enc(folder) + "&path=" + enc(f.path) + "&token=" + enc(token); im.onerror = function () { var fi = el("span", "file-icon"); fi.appendChild(icon("image")); im.replaceWith(fi); }; wrap.appendChild(im); }
        else { var fi = el("span", "file-icon"); fi.appendChild(icon("files")); wrap.appendChild(fi); }
        wrap.appendChild(document.createTextNode(f.path)); nameCell.appendChild(wrap); tr.appendChild(nameCell);
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
    }).catch(function (e) { log("error: " + e.message); });
  }
  $("filesload").onclick = loadFiles;
  $("filesfolder").onchange = function () { $("selectivetoggle").checked = $("filesfolder").selectedOptions.length && $("filesfolder").selectedOptions[0].dataset.selective === "1"; markTree($("filesfolder").value); updateFilesHead(); clearSelection(); setScreen("folder"); loadFiles(); };
  $("selectivetoggle").onchange = function () { api("POST", "/api/selective", { folder: $("filesfolder").value, on: $("selectivetoggle").checked }).then(function () { log("selective sync " + ($("selectivetoggle").checked ? "on" : "off")); return refreshStatus(); }).catch(function (e) { log("error: " + e.message); }); };
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
  $("pairstop").onclick = function () { api("POST", "/api/pair/stop", {}).then(function () { if (pairTimer) { clearInterval(pairTimer); pairTimer = null; } $("pairbox").classList.add("hidden"); pairButtons(false); }).catch(function (e) { alertBox(e.message); }); };
  $("join").onsubmit = function (ev) { ev.preventDefault(); busy(true); api("POST", "/api/join", formData(ev.target)).then(function () { ev.target.reset(); log("joined the vault; attach folders under Files"); nav("files"); return refreshState(); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); }); };
  $("replicatoken").onclick = function () { api("GET", "/api/replica/token").then(function (r) { $("replicaout").textContent = "Replica token (give to the device that will hold your encrypted copies without being able to open them): " + r.token; $("replicaout").classList.remove("hidden"); }).catch(function (e) { alertBox(e.message); }); };
  $("sharerequest").onclick = function () { api("POST", "/api/share/request", {}).then(function (r) { $("sharerequestout").textContent = r.request_code; $("sharerequestout").classList.remove("hidden"); }).catch(function (e) { alertBox(e.message); }); };
  function loadP2p() {
    if (document.body.dataset.view !== "app") { return; }
    api("GET", "/api/p2p").then(function (p) {
      var f = $("p2pform");
      f.enabled.checked = !!p.config.enabled; f.port.value = p.config.port || 17893;
      f.public_addrs.value = (p.config.public_addrs || []).join(", ");
      f.stun.value = (p.config.stun || []).join(", ");
      var peers = p.peers || [];
      $("p2pstatus").textContent = (p.listen ? "Listening on " + p.listen + ". " : "Not listening (enable and restart the service). ") + peers.length + " peers known (" + p.lan_peers + " on the LAN), " + p.chunks_from_peers + " blocks received from peers since start.";
      var nat = p.listen ? ("NAT: " + (p.nat || "unknown") + ". " + ((p.public || []).length ? "Public address " + p.public.join(", ") + ". " : "No public address observed. ") + (p.reachable ? "Reachable from the internet; this device relays for the others." : "Not reachable directly" + ((p.relays || []).length ? "; registered with relay " + p.relays.join(", ") + "." : "; no relay yet.")) + (p.cert_sha256 ? " Certificate " + p.cert_sha256.slice(0, 16) + "." : "")) : "";
      $("p2pnat").textContent = nat;
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
  $("p2pbox").ontoggle = function () { if ($("p2pbox").open) { loadP2p(); } };
  // Traffic view (Peers page): /api/p2p/traffic every second while the page is shown.
  // The service answers it without waiting for a sync, so it stays live during long transfers.
  var trafficTimer = null, trafficBusy = false, lastTraffic = null;
  var SVGNS = "http://www.w3.org/2000/svg";
  function trafficWanted() { return currentPage === "peers" && document.body.dataset.view === "app" && document.visibilityState !== "hidden"; }
  function trafficWatch() {
    if (!trafficWanted()) { if (trafficTimer) { clearTimeout(trafficTimer); trafficTimer = null; } return; }
    if (trafficTimer || trafficBusy) { return; }
    trafficBusy = true;
    api("GET", "/api/p2p/traffic").then(renderTraffic).catch(function () {}).then(function () {
      trafficBusy = false;
      if (trafficWanted() && !trafficTimer) { trafficTimer = setTimeout(function () { trafficTimer = null; trafficWatch(); }, 1000); }
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
  $("p2pform").onsubmit = function (ev) { ev.preventDefault(); var d = formData(ev.target); d.port = +d.port || 17893; api("POST", "/api/p2p", d).then(function (r) { log("p2p settings saved; " + r.note); loadP2p(); }).catch(function (e) { alertBox(e.message); }); };
  $("storagekind").onchange = function () { var k = this.value; document.querySelectorAll("#addstorage [data-kind]").forEach(function (d) { d.classList.toggle("hidden", d.getAttribute("data-kind") !== k); }); };
  $("acceptshare").onsubmit = function (ev) { ev.preventDefault(); busy(true); api("POST", "/api/share/accept", formData(ev.target)).then(function (r) { ev.target.reset(); log("accepted shared folder " + r.folder + "; attach it under Files"); nav("files"); return refreshState(); }).catch(function (e) { alertBox(e.message); }).then(function () { busy(false); }); };

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
  $("addstorage").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/storage", formData(ev.target)).then(function () { ev.target.reset(); log("storage added"); return refreshStatus(); }).catch(function (e) { alertBox(e.message); }); };

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
  window.varstoResumed = function () { refreshAllFiles(); if (document.body.dataset.view === "app") { refreshStatus(); } };
  document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") { refreshAllFiles(); } trafficWatch(); });

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
