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

  // App-level state from /api/state (platform, mobile shell, folder root) and the last /api/status.
  var appState = { mobile: false, folder_root: "", platform: "" };
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
  document.querySelectorAll(".nav-item[data-nav], .more-item[data-nav]").forEach(function (b) { b.onclick = function () { nav(b.dataset.nav); }; });
  nav(currentPage);

  function refreshState() {
    return api("GET", "/api/state").then(function (st) {
      $("version").textContent = st.version; $("version2").textContent = st.version;
      appState.mobile = !!st.mobile; appState.folder_root = st.folder_root || ""; appState.platform = st.platform || "";
      applyMobile();
      if (!st.has_vault) { show("setup"); return; }
      if (!st.unlocked) { show("unlock"); return; }
      show("app");
      return refreshStatus();
    }).catch(function (e) { log("error: " + e.message); });
  }

  function editPolicy(f) {
    var mc = prompt("Minimum copies on any storage (0 = no rule):", "2"); if (mc === null) { return; }
    var cloud = prompt("Minimum copies in place 'cloud' (0 = no rule):", "1"); if (cloud === null) { return; }
    var home = prompt("Minimum copies in place 'home' (0 = no rule):", "1"); if (home === null) { return; }
    var days = prompt("Every chunk verified by another device within N days (0 = no rule):", "30"); if (days === null) { return; }
    var clear = (+mc || 0) === 0 && (+cloud || 0) === 0 && (+home || 0) === 0 && (+days || 0) === 0;
    api("POST", "/api/policy", { folder: f.name, clear: clear, min_copies: +mc || 0, verified_within_days: +days || 0, places: { cloud: +cloud || 0, home: +home || 0 } }).then(function () { log(clear ? "policy cleared for " + f.name : "policy set for " + f.name); return refreshStatus(); }).catch(function (e) { alert(e.message); });
  }
  function shareFolder(f) {
    if (!f.shared && !confirm("Share folder \"" + f.name + "\" with another Varsto user? Anyone holding the token can read and write it.")) { return; }
    var to = prompt("Paste the recipient's request code (vsr1…) to seal the token to their device. Leave empty for a plain token that carries the key itself.", "") || "";
    api("POST", "/api/share/create", { folder: f.name, to: to.trim() }).then(function (r) { $("sharetoken").textContent = (r.sealed ? "Sealed share token for " + r.folder + " (only the requesting device can open it): " : "Share token for " + r.folder + " (contains the folder key; send over a secure channel): ") + r.token; $("sharetoken").classList.remove("hidden"); nav("shared"); refreshStatus(); }).catch(function (e) { alert(e.message); });
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
        if (f.strongroom && f.strongroom !== "locked") { var lk = document.createElement("button"); lk.className = "secondary"; lk.textContent = "Lock"; lk.onclick = function () { api("POST", "/api/strongroom/lock", { folder: f.name }).then(function () { log("locked " + f.name); return refreshStatus(); }).catch(function (e) { alert(e.message); }); }; act.appendChild(lk); }
        if (f.strongroom === "locked") { var note = document.createElement("span"); note.className = "muted"; note.textContent = "unlock with: varsto strongroom unlock " + f.name; act.appendChild(note); }
        tr.appendChild(act); tb.appendChild(tr);
        var o = document.createElement("option"); o.value = f.name; o.textContent = f.name; sel.appendChild(o);
        if (f.path) { var o2 = document.createElement("option"); o2.value = f.name; o2.textContent = f.name + (f.selective ? " (selective)" : ""); o2.dataset.selective = f.selective ? "1" : "0"; fsel.appendChild(o2); }

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
        var where = st.kind === "s3" ? st.endpoint + " bucket " + st.bucket + (st.prefix ? "/" + st.prefix : "") + (st.storage_class ? ", class " + st.storage_class : "") : (st.kind === "rclone" ? st.remote : st.path);
        var li = el("li"); var ic = el("span", "li-icon"); ic.appendChild(icon("storages")); li.appendChild(ic);
        var body = el("div", "li-body"); var title = el("div", "li-title", st.name);
        title.appendChild(pill("grey", st.kind === "s3" ? "S3" : st.kind === "rclone" ? "rclone" : "directory"));
        if (st.cold) { title.appendChild(pill("grey", "cold")); } if (st.carrier) { title.appendChild(pill("grey", "transferrer")); }
        if (st.place) { title.appendChild(pill("grey", st.place)); }
        body.appendChild(title); body.appendChild(el("div", "li-sub", where || "")); li.appendChild(body); ul.appendChild(li);
      });
      $("storages-empty").classList.toggle("hidden", s.storages.length > 0);
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
      if (!confirm("Update " + c.current + " to " + c.latest + " now? The service restarts afterwards.")) { busy(false); return; }
      return api("POST", "/api/update", {}).then(function (r) { log(r.message); if (r.updated) { log("the service is restarting; reopen Varsto in a few seconds"); } busy(false); });
    }).catch(function (e) { log("update failed: " + e.message); busy(false); });
  };
  $("quit").onclick = function () {
    if (!confirm("Quit Varsto? Folders stop syncing until the service is started again.")) { return; }
    api("POST", "/api/quit", {}).then(function () { log("the service is shutting down"); $("svc-dot").dataset.state = "stopped"; }).catch(function (e) { log("quit failed: " + e.message); });
  };
  var busyCount = 0;
  function busy(on) { busyCount = Math.max(0, busyCount + (on ? 1 : -1)); document.querySelectorAll("button").forEach(function (b) { if (b.classList.contains("nav-item") || b.classList.contains("more-item") || b.classList.contains("tree-item")) { return; } if (b.dataset.keepDisabled === "1") { return; } b.disabled = busyCount > 0; }); if (busyCount === 0) { updateToolbar(); } }
  function runSync(folder) {
    busy(true); log("sync " + (folder || "all") + " started");
    api("POST", "/api/sync", folder ? { folder: folder } : {}).then(function (r) {
      r.forEach(function (x) { log(x.pull.folder + ": pulled " + x.pull.files_updated + " updated, " + x.pull.files_deleted + " deleted, " + x.pull.conflicts + " conflicts; pushed " + x.push.files_changed + " changed, " + x.push.chunks_uploaded + " chunks" + (x.pull.files_unavailable.length ? "; unavailable: " + x.pull.files_unavailable.join(", ") : "") + (x.pull.forked_devices.length ? "; FORKED: " + x.pull.forked_devices.join(", ") : "")); });
    }).catch(function (e) { log("sync failed: " + e.message); }).then(function () { busy(false); return refreshStatus().then(function () { if (currentPage === "files") { loadFiles(); } }); });
  }

  $("sync").onclick = function () { runSync(null); };
  $("refresh").onclick = refreshStatus;
  $("lock").onclick = function () { api("POST", "/api/lock").then(refreshState); };
  $("fsck").onclick = function () {
    busy(true); log("fsck started");
    api("POST", "/api/fsck", { verify: $("verify").checked }).then(function (r) {
      log("fsck: " + r.chunks_referenced + " referenced, " + r.chunks_with_storage_copy + " with storage copy, " + r.chunks_verified_elsewhere + " verified elsewhere, " + r.chunks_claimed_only + " claimed only, missing " + r.chunks_missing.length + ", claims without object " + r.claims_without_object + ", unreferenced objects " + r.objects_unreferenced + ", verified now " + r.objects_verified_now + ", corrupt " + r.objects_corrupt.length + (r.forked_devices.length ? ", FORKED " + r.forked_devices.join(",") : ""));
    }).catch(function (e) { log("fsck failed: " + e.message); }).then(function () { busy(false); return refreshStatus(); });
  };

  // Files view: folder header, tree selection, rows, details pane and toolbar.
  function markTree(name) { document.querySelectorAll("#foldertree .tree-item").forEach(function (b) { if (b.dataset.folder === name && name) { b.setAttribute("aria-current", "true"); } else { b.removeAttribute("aria-current"); } }); }
  function updateFilesHead() {
    var f = folderByName($("filesfolder").value);
    $("files-sub").textContent = f ? [f.path, f.files + " file" + (f.files === 1 ? "" : "s"), fmtBytes(f.bytes), f.selective ? "selective sync" : null, f.shared ? "shared" : null].filter(Boolean).join(" · ") : "";
    $("files-sub").classList.toggle("desktop-only", false);
    if (f && isMobile()) { $("files-sub").textContent = [f.files + " file" + (f.files === 1 ? "" : "s"), fmtBytes(f.bytes), f.selective ? "selective sync" : null].filter(Boolean).join(" · "); }
    $("files-share").disabled = !f || !!(lastStatus && lastStatus.member);
    $("files-sync").disabled = !f;
  }
  function openFolder(name) { $("filesfolder").value = name; $("selectivetoggle").checked = $("filesfolder").selectedOptions.length && $("filesfolder").selectedOptions[0].dataset.selective === "1"; markTree(name); updateFilesHead(); showFolderForms(false); nav("files"); loadFiles(); }
  function showFolderForms(on, byUser) { $("folderforms").classList.toggle("hidden", !on); if (byUser) { $("folderforms").dataset.user = on ? "1" : "0"; } if (on && byUser) { var inp = $("addfolder").querySelector("input[name=name]"); setTimeout(function () { inp.focus(); }, 50); } }
  $("treeadd").onclick = function () { nav("files"); showFolderForms(true, true); window.scrollTo(0, document.body.scrollHeight); };
  $("filesadd").onclick = function () { var open = $("folderforms").classList.contains("hidden"); showFolderForms(open, true); if (open) { $("folderforms").scrollIntoView({ block: "start", behavior: "smooth" }); } };
  document.querySelectorAll("[data-close-forms]").forEach(function (b) { b.onclick = function () { showFolderForms(false, true); }; });
  function selectFile(f, tr) {
    selectedFile = f;
    document.querySelectorAll("#files tbody tr").forEach(function (r) { r.classList.toggle("selected", r === tr); });
    var folder = $("filesfolder").value; var fs = folderByName(folder);
    var d = $("filedetails"); d.classList.remove("hidden"); document.querySelector(".files-layout").classList.add("with-details");
    var pv = $("fd-preview"); pv.innerHTML = "";
    if (f.media) { var im = document.createElement("img"); im.alt = ""; im.src = "/api/thumb?folder=" + encodeURIComponent(folder) + "&path=" + encodeURIComponent(f.path) + "&token=" + encodeURIComponent(token); im.onerror = function () { im.remove(); pv.appendChild(icon("image")); }; pv.appendChild(im); } else { pv.appendChild(icon("files")); }
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
    if (f.state !== "missing") { var open = document.createElement("a"); open.className = "button secondary"; open.appendChild(icon("open")); open.appendChild(document.createTextNode("Open")); open.href = "/api/open?folder=" + encodeURIComponent(folder) + "&path=" + encodeURIComponent(f.path) + "&token=" + encodeURIComponent(token); open.onclick = function () { setTimeout(loadFiles, 1500); }; acts.appendChild(open); }
    var b = document.createElement("button"); b.type = "button";
    if (f.state === "placeholder" || f.state === "missing") { b.appendChild(icon("download")); b.appendChild(document.createTextNode("Download")); b.onclick = function () { fetchFile(folder, f.path); }; }
    else { b.className = "secondary"; b.appendChild(icon("free")); b.appendChild(document.createTextNode("Free up space")); b.onclick = function () { freeFile(folder, f.path); }; }
    acts.appendChild(b);
    updateToolbar();
  }
  function clearSelection() { selectedFile = null; document.querySelectorAll("#files tbody tr").forEach(function (r) { r.classList.remove("selected"); }); $("filedetails").classList.add("hidden"); document.querySelector(".files-layout").classList.remove("with-details"); updateToolbar(); }
  $("fd-close").onclick = clearSelection;
  function updateToolbar() { var f = selectedFile; $("files-download").disabled = !f || !(f.state === "placeholder" || f.state === "missing"); $("files-free").disabled = !f || f.state !== "local"; }
  function fetchFile(folder, path) { busy(true); api("POST", "/api/fetch", { folder: folder, path: path }).then(function () { log("fetched " + path); }).catch(function (e) { log("fetch failed: " + e.message); }).then(function () { busy(false); loadFiles(); }); }
  function freeFile(folder, path) { api("POST", "/api/free", { folder: folder, path: path }).then(function () { log(path + " is now a placeholder"); }).catch(function (e) { log("free failed: " + e.message); }).then(function () { loadFiles(); refreshStatus(); }); }
  $("files-sync").onclick = function () { var f = $("filesfolder").value; if (f) { runSync(f); } };
  $("files-download").onclick = function () { if (selectedFile) { fetchFile($("filesfolder").value, selectedFile.path); } };
  $("files-free").onclick = function () { if (selectedFile) { freeFile($("filesfolder").value, selectedFile.path); } };
  $("files-share").onclick = function () { var f = folderByName($("filesfolder").value); if (f) { shareFolder(f); } };
  function loadFiles() {
    var folder = $("filesfolder").value; if (!folder) { return; }
    filesLoadedFor = folder;
    var keep = selectedFile ? selectedFile.path : null;
    api("GET", "/api/files?folder=" + encodeURIComponent(folder)).then(function (rows) {
      var tb = $("files").querySelector("tbody"); tb.innerHTML = "";
      var empty = $("files-empty");
      empty.querySelector(".empty-title").textContent = rows.length ? "" : "This folder is empty";
      empty.querySelector(".muted").textContent = rows.length ? "" : "Files you put in " + folder + " on any device appear here after a sync.";
      empty.classList.toggle("hidden", rows.length > 0);
      var reselect = null;
      rows.forEach(function (f) {
        var tr = document.createElement("tr");
        function td(t, cls, label) { var d = document.createElement("td"); d.textContent = t; if (cls) { d.className = cls; } if (label) { d.dataset.label = label; } tr.appendChild(d); }
        var nameCell = document.createElement("td"); var wrap = el("span", "file-name");
        wrap.appendChild(stateSquare(f));
        if (f.media) { var im = document.createElement("img"); im.className = "thumb"; im.alt = ""; im.loading = "lazy"; im.src = "/api/thumb?folder=" + encodeURIComponent(folder) + "&path=" + encodeURIComponent(f.path) + "&token=" + encodeURIComponent(token); im.onerror = function () { var fi = el("span", "file-icon"); fi.appendChild(icon("image")); im.replaceWith(fi); }; wrap.appendChild(im); }
        else { var fi = el("span", "file-icon"); fi.appendChild(icon("files")); wrap.appendChild(fi); }
        wrap.appendChild(document.createTextNode(f.path)); nameCell.appendChild(wrap); tr.appendChild(nameCell);
        td(fmtBytes(f.size), "num");
        var st = document.createElement("td"); st.appendChild(pill(f.state === "placeholder" ? "grey" : f.state === "missing" ? "bad" : "ok", fileStateLabel(f))); tr.appendChild(st);
        td(f.last_accessed_utc ? fmtDate(f.last_accessed_utc) : "Never here", f.last_accessed_utc ? "" : "muted", "Last used");
        var act = document.createElement("td");
        if (f.state !== "missing") { var open = document.createElement("a"); open.className = "button secondary"; open.textContent = "Open"; open.href = "/api/open?folder=" + encodeURIComponent(folder) + "&path=" + encodeURIComponent(f.path) + "&token=" + encodeURIComponent(token); open.onclick = function (ev) { ev.stopPropagation(); setTimeout(loadFiles, 1500); }; act.appendChild(open); }
        var b = document.createElement("button"); b.className = "secondary"; b.type = "button";
        if (f.state === "placeholder" || f.state === "missing") { b.textContent = "Download"; b.onclick = function (ev) { ev.stopPropagation(); fetchFile(folder, f.path); }; }
        else { b.textContent = "Free up space"; b.onclick = function (ev) { ev.stopPropagation(); freeFile(folder, f.path); }; }
        act.appendChild(b); tr.appendChild(act); tb.appendChild(tr);
        tr.onclick = function () { if (selectedFile && selectedFile.path === f.path && tr.classList.contains("selected")) { clearSelection(); } else { selectFile(f, tr); } };
        if (keep && f.path === keep) { reselect = { f: f, tr: tr }; }
      });
      if (reselect) { selectFile(reselect.f, reselect.tr); } else { clearSelection(); }
    }).catch(function (e) { log("error: " + e.message); });
  }
  $("filesload").onclick = loadFiles;
  $("filesfolder").onchange = function () { $("selectivetoggle").checked = $("filesfolder").selectedOptions.length && $("filesfolder").selectedOptions[0].dataset.selective === "1"; markTree($("filesfolder").value); updateFilesHead(); clearSelection(); loadFiles(); };
  $("selectivetoggle").onchange = function () { api("POST", "/api/selective", { folder: $("filesfolder").value, on: $("selectivetoggle").checked }).then(function () { log("selective sync " + ($("selectivetoggle").checked ? "on" : "off")); return refreshStatus(); }).catch(function (e) { log("error: " + e.message); }); };
  $("dupes").onclick = function () {
    api("GET", "/api/dupes?folder=" + encodeURIComponent($("dupefolder").value)).then(function (g) {
      $("dupeout").textContent = g.length ? g.map(function (x) { return fmtBytes(x.size) + ": " + x.paths.join(", "); }).join("\n") : "no duplicates";
    }).catch(function (e) { log("dupes failed: " + e.message); });
  };
  $("unlockform").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/unlock", formData(ev.target)).then(function () { ev.target.reset(); return refreshState(); }).catch(function (e) { alert(e.message); }); };
  $("init").onsubmit = function (ev) {
    ev.preventDefault();
    api("POST", "/api/init", formData(ev.target)).then(function (r) {
      ev.target.reset();
      $("vaultkey").textContent = "Vault key (shown once, write it down and keep it offline): " + r.vault_key;
      $("vaultkey").classList.remove("hidden");
      return refreshState();
    }).catch(function (e) { alert(e.message); });
  };
  $("join").onsubmit = function (ev) { ev.preventDefault(); busy(true); api("POST", "/api/join", formData(ev.target)).then(function () { ev.target.reset(); log("joined the vault; attach folders under Files"); nav("files"); return refreshState(); }).catch(function (e) { alert(e.message); }).then(function () { busy(false); }); };
  $("replicatoken").onclick = function () { api("GET", "/api/replica/token").then(function (r) { $("replicaout").textContent = "Replica token (give to the device that will hold your encrypted copies without being able to open them): " + r.token; $("replicaout").classList.remove("hidden"); }).catch(function (e) { alert(e.message); }); };
  $("sharerequest").onclick = function () { api("POST", "/api/share/request", {}).then(function (r) { $("sharerequestout").textContent = r.request_code; $("sharerequestout").classList.remove("hidden"); }).catch(function (e) { alert(e.message); }); };
  function loadP2p() { if (document.body.dataset.view !== "app") { return; } api("GET", "/api/p2p").then(function (p) { var f = $("p2pform"); f.enabled.checked = !!p.config.enabled; f.port.value = p.config.port || 17893; f.public_addrs.value = (p.config.public_addrs || []).join(", "); $("p2pstatus").textContent = (p.listen ? "Listening on " + p.listen + ". " : "Not listening (enable and restart the service). ") + (p.peers || []).length + " peers known (" + p.lan_peers + " on the LAN), " + p.chunks_from_peers + " blocks received from peers since start." + ((p.peers || []).length ? " Peers: " + p.peers.map(function (x) { return (x.name || x.device.slice(0, 8)) + " " + x.addr; }).join(", ") : ""); }).catch(function () {}); }
  $("p2pbox").ontoggle = function () { if ($("p2pbox").open) { loadP2p(); } };
  $("p2pform").onsubmit = function (ev) { ev.preventDefault(); var d = formData(ev.target); d.port = +d.port || 17893; api("POST", "/api/p2p", d).then(function (r) { log("p2p settings saved; " + r.note); loadP2p(); }).catch(function (e) { alert(e.message); }); };
  $("storagekind").onchange = function () { var k = this.value; document.querySelectorAll("#addstorage [data-kind]").forEach(function (d) { d.classList.toggle("hidden", d.getAttribute("data-kind") !== k); }); };
  $("acceptshare").onsubmit = function (ev) { ev.preventDefault(); busy(true); api("POST", "/api/share/accept", formData(ev.target)).then(function (r) { ev.target.reset(); log("accepted shared folder " + r.folder + "; attach it under Files"); nav("files"); return refreshState(); }).catch(function (e) { alert(e.message); }).then(function () { busy(false); }); };

  // Folder forms: on desktop the directory is pre-filled from the folder root as you type the name;
  // on phones no directory is asked and the service picks <folder_root>/<name>.
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
  function cleanPath(d) { if (isMobile() || !d.path || !d.path.trim()) { delete d.path; } return d; }
  function attachFolder(nameOrId, path) {
    var d = { name_or_id: nameOrId, selective: $("attachfolder").querySelector("input[name=selective]").checked };
    if (path && !isMobile()) { d.path = path; }
    busy(true);
    api("POST", "/api/folder/attach", d).then(function () { log("folder attached: " + nameOrId); return refreshStatus().then(function () { openFolder(nameOrId); }); }).catch(function (e) { alert(e.message); }).then(function () { busy(false); });
  }
  $("addfolder").onsubmit = function (ev) { ev.preventDefault(); var d = cleanPath(formData(ev.target)); var name = d.name; api("POST", "/api/folder", d).then(function () { ev.target.reset(); log("folder added: " + name); showFolderForms(false, true); return refreshStatus().then(function () { openFolder(name); }); }).catch(function (e) { alert(e.message); }); };
  $("attachfolder").onsubmit = function (ev) { ev.preventDefault(); var d = formData(ev.target); if (!d.name_or_id) { return; } attachFolder(d.name_or_id, d.path); ev.target.reset(); };
  $("addstorage").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/storage", formData(ev.target)).then(function () { ev.target.reset(); log("storage added"); return refreshStatus(); }).catch(function (e) { alert(e.message); }); };

  // Reset: wipes this device's vault configuration after the user typed "reset".
  var resetInput = $("resetform").querySelector("input[name=confirm]");
  $("resetbtn").dataset.keepDisabled = "1";
  resetInput.addEventListener("input", function () { var ok = resetInput.value.trim() === "reset"; $("resetbtn").disabled = !ok; $("resetbtn").dataset.keepDisabled = ok ? "0" : "1"; });
  $("resetform").onsubmit = function (ev) {
    ev.preventDefault();
    if (resetInput.value.trim() !== "reset") { return; }
    if (!confirm("Reset this device? Its keys and ledger copy are removed; files stay. You will need the vault key to join again.")) { return; }
    busy(true);
    api("POST", "/api/reset", { confirm: "reset" }).then(function (r) { log("device reset: removed " + ((r.removed || []).join(", ") || "nothing")); ev.target.reset(); $("resetbtn").disabled = true; $("resetbtn").dataset.keepDisabled = "1"; lastStatus = null; selectedFile = null; nav("overview"); return refreshState(); }).catch(function (e) { alert(e.message); }).then(function () { busy(false); });
  };

  refreshState();
})();
