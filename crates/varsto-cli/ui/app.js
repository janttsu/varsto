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
  function api(method, path, body) {
    return fetch(path, { method: method, headers: { "X-Varsto-Token": token, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) { throw new Error(j.error || r.statusText); } return j; }); });
  }
  function show(section) { ["setup", "unlock", "app"].forEach(function (id) { $(id).classList.toggle("hidden", id !== section); }); $("lock").classList.toggle("hidden", section !== "app"); document.body.dataset.view = section; if (section !== "app") { $("pagetitle").textContent = section === "setup" ? "Welcome" : "Locked"; } else { $("pagetitle").textContent = pageTitle(currentPage); } }
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

  // Block maps: one square per block of encrypted data, coloured by where the block is.
  // Derived only from /api/status: chunks, chunks_without_storage_copy, chunks_verified_elsewhere,
  // placeholders (files) and whether the folder is attached here. A placeholder file's blocks are
  // estimated as its share of the folder's chunks.
  var BLOCK_STATES = ["verified", "stored", "local", "ph", "missing"];
  function folderBlocks(f) {
    var c = f.chunks || 0;
    var verified = Math.min(c, f.chunks_verified_elsewhere || 0);
    var noCopy = Math.min(c - verified, f.chunks_without_storage_copy || 0);
    var stored = c - verified - noCopy;
    var b = { verified: verified, stored: stored, local: 0, ph: 0, missing: 0 };
    if (!f.path) { b.ph = stored + verified; b.verified = 0; b.stored = 0; b.missing = noCopy; return b; }
    b.local = noCopy;
    var want = f.files > 0 && f.placeholders > 0 ? Math.min(c, Math.round(c * f.placeholders / f.files)) : 0;
    var ph = want;
    var take = Math.min(ph, b.stored); b.stored -= take; ph -= take;
    take = Math.min(ph, b.verified); b.verified -= take; ph -= take;
    b.ph = want - ph;
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
      for (var i = 0; i < n; i++) { var sq = document.createElement("i"); sq.className = "blk s-" + k; frag.appendChild(sq); }
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
    currentPage = page;
    try { sessionStorage.setItem("varsto-page", page); } catch (e) {}
    document.querySelectorAll(".page").forEach(function (d) { d.classList.toggle("hidden", d.dataset.page !== page); });
    var tab = page === "shared" || page === "policies" || page === "peers" || page === "settings" ? "more" : page;
    document.querySelectorAll(".sidebar .nav-item[data-nav]").forEach(function (b) { if (b.dataset.nav === page) { b.setAttribute("aria-current", "page"); } else { b.removeAttribute("aria-current"); } });
    document.querySelectorAll(".tabbar .nav-item[data-nav]").forEach(function (b) { if (b.dataset.nav === tab) { b.setAttribute("aria-current", "page"); } else { b.removeAttribute("aria-current"); } });
    if (document.body.dataset.view === "app") { $("pagetitle").textContent = pageTitle(page); }
    if (page === "peers") { loadP2p(); }
    if (page === "files") { ensureFiles(); }
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
      appState.mobile = !!st.mobile; appState.folder_root = st.folder_root || ""; appState.platform = st.platform || "";
      appState.plain_root = st.plain_root || ""; appState.plain_root_writable = st.plain_root_writable !== false;
      applyMobile();
      refreshAllFiles();
      if (!st.has_vault) { show("setup"); return; }
      if (!st.unlocked) { show("unlock"); return; }
      show("app");
      return refreshStatus();
    }).catch(function (e) { log("error: " + e.message); });
  }

  // Policy editor: four minimums; zeros everywhere (or the Clear button) remove the policy.
  function editPolicy(f) {
    api("GET", "/api/policy").then(function (p) {
      var cur = null; (p.policies || []).forEach(function (x) { if (x.folder === f.name) { cur = x.policy; } });
      var places = (cur && cur.min_per_place) || {};
      return dialog({
        title: (cur ? "Policy for " : "Set a policy for ") + f.name,
        text: "Minimums that Varsto checks against the ledger on every sync. 0 means no rule.",
        fields: [
          { name: "min_copies", label: "Copies on any storage", type: "number", value: cur ? cur.min_copies || 0 : 2 },
          { name: "cloud", label: "Copies in place 'cloud'", type: "number", value: cur ? places.cloud || 0 : 1 },
          { name: "home", label: "Copies in place 'home'", type: "number", value: cur ? places.home || 0 : 1 },
          { name: "days", label: "Every block verified by another device within (days)", type: "number", value: cur ? cur.verified_within_days || 0 : 30 }
        ],
        ok: cur ? "Save" : "Set policy", extra: cur ? "Clear policy" : null
      });
    }).then(function (r) {
      if (!r) { return; }
      var v = r.values; var n = function (k) { return Math.max(0, Math.floor(+v[k]) || 0); };
      var clear = r.action === "extra" || (n("min_copies") === 0 && n("cloud") === 0 && n("home") === 0 && n("days") === 0);
      return api("POST", "/api/policy", { folder: f.name, clear: clear, min_copies: n("min_copies"), verified_within_days: n("days"), places: { cloud: n("cloud"), home: n("home") } })
        .then(function () { log(clear ? "policy cleared for " + f.name : "policy set for " + f.name); return refreshStatus(); });
    }).catch(function (e) { alertBox(e.message); });
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
        if (!s.member) { var pb = document.createElement("button"); pb.className = "secondary"; pb.textContent = "Policy"; pb.onclick = function () { editPolicy(f); }; act.appendChild(pb); }
        if (f.strongroom && f.strongroom !== "locked") { var lk = document.createElement("button"); lk.className = "secondary"; lk.textContent = "Lock"; lk.onclick = function () { api("POST", "/api/strongroom/lock", { folder: f.name }).then(function () { log("locked " + f.name); return refreshStatus(); }).catch(function (e) { alertBox(e.message); }); }; act.appendChild(lk); }
        if (f.strongroom === "locked") { var note = document.createElement("span"); note.className = "muted"; note.textContent = "unlock with: varsto strongroom unlock " + f.name; act.appendChild(note); }
        tr.appendChild(act); tb.appendChild(tr);
        var o = document.createElement("option"); o.value = f.name; o.textContent = f.name; sel.appendChild(o);
        if (f.path) { var o2 = document.createElement("option"); o2.value = f.name; o2.textContent = f.name; o2.dataset.selective = f.selective ? "1" : "0"; fsel.appendChild(o2); }

        // Sidebar tree under Files.
        var li = el("li"); var tbtn = el("button", "tree-item" + (f.path ? "" : " detached")); tbtn.type = "button"; tbtn.dataset.folder = f.name; tbtn.title = f.path || "Not attached on this device";
        tbtn.appendChild(icon("folders")); tbtn.appendChild(el("span", "tree-name", f.name));
        if (!f.path) { var dot = el("i", "tree-dot"); dot.title = "Not attached on this device"; tbtn.appendChild(dot); }
        tbtn.onclick = function () { if (f.path) { openFolder(f.name); } else { nav("files"); showFolderForms(true); } };
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
      $("stat-folders").textContent = s.folders.length;
      $("stat-files").textContent = totalFiles;
      $("stat-bytes").textContent = fmtBytes(totalBytes);
      $("stat-devices").textContent = Object.keys(s.devices).length;
      $("stat-storages").textContent = s.storages.length;
      (function () {
        var t = blockTotal(totalBlocks); var per = Math.max(1, Math.ceil(t / 600));
        drawBlocks($("datamap"), totalBlocks, per);
        BLOCK_STATES.forEach(function (k) { $("leg-" + k).textContent = totalBlocks[k] || 0; });
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
        var lines = [];
        (p.reports || []).forEach(function (r) {
          var label = stateLabel(r.state); var cls = stateClass(r.state);
          var cell = document.querySelector('[data-policy-for="' + r.folder + '"]');
          if (cell) { var old = cell.querySelector(".pill"); if (old) { old.replaceWith(pill(cls, label)); } }
          var row = document.querySelector('[data-policy-row="' + r.folder + '"]');
          if (row) { var rp = row.querySelector(".pill"); if (rp) { rp.replaceWith(pill(cls, label)); } var sub = row.querySelector(".li-sub"); var extra = r.reasons.concat(r.warnings).join(" "); if (sub && extra) { sub.textContent = sub.textContent + " — " + extra; } }
          if (r.state !== "ok") { lines.push(r.folder + ": " + label + ". " + r.reasons.concat(r.warnings).join(" ")); }
        });
        $("policybanner").textContent = lines.join(" ");
        $("policybanner").classList.toggle("hidden", lines.length === 0);
      }).catch(function () {});
      loadAdvice();
      $("selectivetoggle").checked = fsel.selectedOptions.length && fsel.selectedOptions[0].dataset.selective === "1";
      var ul = $("storages"); ul.innerHTML = "";
      s.storages.forEach(function (st) {
        var where = st.kind === "s3" ? st.endpoint + " bucket " + st.bucket + (st.prefix ? "/" + st.prefix : "") + (st.storage_class ? ", class " + st.storage_class : "") : (st.kind === "rclone" ? st.remote : st.kind === "pool" ? (st.disks || []).length + " disk" + ((st.disks || []).length === 1 ? "" : "s") + ", " + (st.reserve_percent || 5) + " % kept free" : st.path);
        var li = el("li"); var ic = el("span", "li-icon"); ic.appendChild(icon("storages")); li.appendChild(ic);
        var body = el("div", "li-body"); var title = el("div", "li-title", st.name);
        title.appendChild(pill("grey", st.kind === "s3" ? "S3" : st.kind === "rclone" ? "rclone" : st.kind === "pool" ? "disk pool" : "directory"));
        if (st.cold) { title.appendChild(pill("grey", "cold")); } if (st.carrier) { title.appendChild(pill("grey", "transferrer")); }
        if (st.place) { title.appendChild(pill("grey", st.place)); }
        body.appendChild(title); body.appendChild(el("div", "li-sub", where || "")); li.appendChild(body); ul.appendChild(li);
      });
      $("storages-empty").classList.toggle("hidden", s.storages.length > 0);
      renderPools(s.storages);
      var names = Object.keys(s.devices).map(function (k) { return s.devices[k] + " (" + k.slice(0, 8) + ")"; });
      var reps = Object.keys(s.replicas || {}).map(function (k) { return s.replicas[k]; });
      var mems = Object.keys(s.members || {}).map(function (k) { return s.members[k]; });
      $("devices").textContent = (s.member ? "This device is a member of a shared folder. " : "") + "Devices: " + (names.join(", ") || "none yet") + (reps.length ? " · replicas: " + reps.join(", ") : "") + (mems.length ? " · members: " + mems.join(", ") : "") + (s.forked_devices.length ? " · FORKED: " + s.forked_devices.join(", ") : "");
      $("members").textContent = mems.length ? "Members with access to shared folders: " + mems.join(", ") : "";
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
      b.onclick = function () { if (f.path) { openFolder(f.name); } else { showFolderForms(true, true); $("folderforms").scrollIntoView({ block: "start", behavior: "smooth" }); } };
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
      var tail = " Moving files to another storage class is not automatic yet; the figures are estimates from Varsto's price table.";
      if (hot) { alt.textContent = "Cheapest option that stays instantly readable: " + className(hot) + " at about " + money(hot.monthly_cost, hot.currency) + " a month" + (hot.last_verified ? " (verified " + hot.last_verified + ")" : "") + "." + tail; }
      else { var second = a.estimates[1]; alt.textContent = (second ? "Next: " + className(second) + " at about " + money(second.monthly_cost, second.currency) + " a month" + (second.retrieval_cost_once ? ", " + money(second.retrieval_cost_once, second.currency) + " to retrieve once" : "") + "." : "") + tail; }
      $("advice").classList.remove("hidden");
    }).catch(function () { $("advice").classList.add("hidden"); });
  }

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
  function busy(on) { busyCount = Math.max(0, busyCount + (on ? 1 : -1)); document.querySelectorAll("button").forEach(function (b) { if (b.classList.contains("nav-item") || b.classList.contains("more-item") || b.classList.contains("tree-item") || b.classList.contains("folder-card") || b.closest("#modal")) { return; } if (b.dataset.keepDisabled === "1") { return; } b.disabled = busyCount > 0; }); if (busyCount === 0) { updateToolbar(); } }
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
  function fileActions(folder, f, full) {
    var out = [];
    if (phoneActions()) {
      if (f.state !== "missing") {
        var ob = el("button", "secondary"); ob.type = "button"; if (full) { ob.appendChild(icon("open")); } ob.appendChild(document.createTextNode("Open")); ob.onclick = function (ev) { ev.stopPropagation(); openOnPhone(folder, f, false); }; out.push(ob);
        var sb = el("button", "secondary"); sb.type = "button"; if (full) { sb.appendChild(icon("share")); } sb.appendChild(document.createTextNode("Share")); sb.onclick = function (ev) { ev.stopPropagation(); openOnPhone(folder, f, true); }; out.push(sb);
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
    var copies = [];
    if (fs) {
      var storages = lastStatus ? lastStatus.storages.length : 0;
      copies.push(fs.chunks_without_storage_copy > 0 ? fs.chunks_without_storage_copy + " of the folder's " + fs.chunks + " blocks still lack a storage copy" : "every block of this folder is on " + (storages === 1 ? "the storage" : storages + " storages"));
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
      rows.forEach(function (f) {
        var tr = document.createElement("tr");
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
        tr.onclick = function () { if (selectedFile && selectedFile.path === f.path && tr.classList.contains("selected")) { clearSelection(); } else { selectFile(f, tr); } };
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
  function attachFolder(nameOrId, path) {
    var form = $("attachfolder");
    var d = { name_or_id: nameOrId, selective: form.querySelector("input[name=selective]").checked };
    if (path && !isMobile()) { d.path = path; }
    if (appState.mobile) { d.plain = modeOf(form) === "plain"; }
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
  }
  $("allfilesbtn").onclick = function () { if (droid) { try { droid.requestAllFilesAccess(); } catch (e) { alertBox(e.message); } } else { alertBox("Only the Android app can ask for this permission."); } };
  // The shell calls this when the activity resumes (back from the settings screen); browsers get visibilitychange.
  window.varstoResumed = function () { refreshAllFiles(); if (document.body.dataset.view === "app") { refreshStatus(); } };
  document.addEventListener("visibilitychange", function () { if (document.visibilityState === "visible") { refreshAllFiles(); } });

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
