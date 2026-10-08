// Varsto desktop UI. Talks to the local API with a per-session token.
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
  function show(section) { ["setup", "unlock", "app"].forEach(function (id) { $(id).classList.toggle("hidden", id !== section); }); $("lock").classList.toggle("hidden", section !== "app"); }
  function fmtBytes(n) { var u = ["B", "KiB", "MiB", "GiB", "TiB"]; var i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + " " + u[i]; }
  function formData(form) { var o = {}; new FormData(form).forEach(function (v, k) { o[k] = v; }); form.querySelectorAll("input[type=checkbox]").forEach(function (c) { o[c.name] = c.checked; }); return o; }

  function refreshState() {
    return api("GET", "/api/state").then(function (st) {
      $("version").textContent = st.version;
      if (!st.has_vault) { show("setup"); return; }
      if (!st.unlocked) { show("unlock"); return; }
      show("app");
      return refreshStatus();
    }).catch(function (e) { log("error: " + e.message); });
  }

  function refreshStatus() {
    return api("GET", "/api/status").then(function (s) {
      $("who").textContent = "vault " + s.vault_id.slice(0, 8) + " · device " + s.device_name + " · " + s.ledger_batches + " ledger batches";
      var tb = $("folders").querySelector("tbody"); tb.innerHTML = "";
      var sel = $("dupefolder"); sel.innerHTML = "";
      var fsel = $("filesfolder"); var prev = fsel.value; fsel.innerHTML = "";
      s.folders.forEach(function (f) {
        var tr = document.createElement("tr");
        function td(text, cls) { var d = document.createElement("td"); d.textContent = text; if (cls) { d.className = cls; } tr.appendChild(d); }
        td(f.name); td(f.path || "(not attached)"); td(f.files); td(fmtBytes(f.bytes)); td(f.chunks);
        td(f.chunks_without_storage_copy, f.chunks_without_storage_copy > 0 ? "bad" : ""); td(f.chunks_verified_elsewhere);
        var pc = document.createElement("td"); pc.dataset.policyFor = f.name; pc.textContent = f.policy || "none"; tr.appendChild(pc);
        var act = document.createElement("td");
        if (!s.member) { var pb = document.createElement("button"); pb.className = "secondary"; pb.textContent = "Policy…"; pb.onclick = function () {
          var mc = prompt("Minimum copies on any storage (0 = no rule):", "2"); if (mc === null) { return; }
          var cloud = prompt("Minimum copies in place 'cloud' (0 = no rule):", "1"); if (cloud === null) { return; }
          var home = prompt("Minimum copies in place 'home' (0 = no rule):", "1"); if (home === null) { return; }
          var days = prompt("Every chunk verified by another device within N days (0 = no rule):", "30"); if (days === null) { return; }
          var clear = (+mc || 0) === 0 && (+cloud || 0) === 0 && (+home || 0) === 0 && (+days || 0) === 0;
          api("POST", "/api/policy", { folder: f.name, clear: clear, min_copies: +mc || 0, verified_within_days: +days || 0, places: { cloud: +cloud || 0, home: +home || 0 } }).then(function () { log(clear ? "policy cleared for " + f.name : "policy set for " + f.name); return refreshStatus(); }).catch(function (e) { alert(e.message); });
        }; act.appendChild(pb); }
        if (f.path) { var b = document.createElement("button"); b.className = "secondary"; b.textContent = "Sync"; b.onclick = function () { runSync(f.name); }; act.appendChild(b); }
        if (!s.member) { var sh = document.createElement("button"); sh.className = "secondary"; sh.textContent = f.shared ? "Share token" : "Share…"; sh.onclick = function () {
          if (!f.shared && !confirm("Share folder \"" + f.name + "\" with another Varsto user? Anyone holding the token can read and write it.")) { return; }
          var to = prompt("Paste the recipient's request code (vsr1…) to seal the token to their device. Leave empty for a plain token that carries the key itself.", "") || "";
          api("POST", "/api/share/create", { folder: f.name, to: to.trim() }).then(function (r) { $("sharetoken").textContent = (r.sealed ? "Sealed share token for " + r.folder + " (only the requesting device can open it): " : "Share token for " + r.folder + " (contains the folder key; send over a secure channel): ") + r.token; $("sharetoken").classList.remove("hidden"); refreshStatus(); }).catch(function (e) { alert(e.message); });
        }; act.appendChild(sh); }
        tr.appendChild(act); tb.appendChild(tr);
        var o = document.createElement("option"); o.value = f.name; o.textContent = f.name; sel.appendChild(o);
        if (f.path) { var o2 = document.createElement("option"); o2.value = f.name; o2.textContent = f.name + (f.selective ? " (selective)" : ""); o2.dataset.selective = f.selective ? "1" : "0"; fsel.appendChild(o2); }
      });
      if (prev) { fsel.value = prev; }
      api("GET", "/api/policy").then(function (p) {
        var worst = null; var lines = [];
        (p.reports || []).forEach(function (r) {
          var cell = document.querySelector('[data-policy-for="' + r.folder + '"]');
          var label = r.state === "ok" ? "OK" : r.state === "at_risk" ? "at risk" : r.state === "violated" ? "VIOLATED" : "unknown";
          if (cell) { cell.textContent = (r.policy ? r.policy.min_copies ? "" : "" : "") + label + " · " + cell.textContent; cell.className = r.state === "ok" ? "" : "bad"; }
          if (r.state !== "ok") { lines.push(r.folder + ": " + label + ". " + r.reasons.concat(r.warnings).join(" ")); }
          if (!worst || r.state === "violated" || (r.state === "at_risk" && worst !== "violated")) { worst = r.state; }
        });
        $("policybanner").textContent = lines.join(" ");
        $("policybanner").classList.toggle("hidden", lines.length === 0);
      }).catch(function () {});
      $("selectivetoggle").checked = fsel.selectedOptions.length && fsel.selectedOptions[0].dataset.selective === "1";
      (function () {
      });
      var ul = $("storages"); ul.innerHTML = "";
      s.storages.forEach(function (st) { var li = document.createElement("li"); var where = st.kind === "s3" ? st.endpoint + " bucket " + st.bucket + (st.prefix ? "/" + st.prefix : "") + (st.storage_class ? ", class " + st.storage_class : "") : (st.kind === "rclone" ? st.remote : st.path); li.textContent = st.name + " (" + st.kind + ": " + where + (st.cold ? ", cold" : "") + (st.carrier ? ", transferrer" : "") + ")"; ul.appendChild(li); });
      var names = Object.keys(s.devices).map(function (k) { return s.devices[k] + " (" + k.slice(0, 8) + ")"; });
      var reps = Object.keys(s.replicas || {}).map(function (k) { return s.replicas[k]; });
      var mems = Object.keys(s.members || {}).map(function (k) { return s.members[k]; });
      $("devices").textContent = (s.member ? "This device is a member of a shared folder. " : "") + "Devices: " + (names.join(", ") || "none yet") + (reps.length ? " · replicas: " + reps.join(", ") : "") + (mems.length ? " · members: " + mems.join(", ") : "") + (s.forked_devices.length ? " · FORKED: " + s.forked_devices.join(", ") : "");
      $("replicatoken").classList.toggle("hidden", !!s.member);
      return api("GET", "/api/service").then(function (sv) { renderService(sv); return api("GET", "/api/ledger"); }).then(function (l) {
        $("ledger").textContent = l.map(function (e) { return e.device.slice(0, 8) + " #" + e.seq + " lamport " + e.lamport + " events " + e.events; }).join("\n") || "(empty)";
      });
    }).catch(function (e) { log("error: " + e.message); });
  }

  function fmtTime(t) { return t ? new Date(t * 1000).toLocaleTimeString() : "never"; }
  function renderService(sv) {
    var txt = sv.running ? (sv.paused ? "Background service paused" : "Background service running") + " · watching " + sv.watching + " folder(s) · last sync " + fmtTime(sv.last_sync_utc) + (sv.last_result ? " (" + sv.last_result + ")" : "") + (sv.last_error ? " · last error: " + sv.last_error : "") + " · next in " + (sv.next_sync_utc ? Math.max(0, Math.round(sv.next_sync_utc - Date.now() / 1000)) + " s" : "-") : "Background service not running";
    $("svc-text").textContent = txt;
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
  function busy(on) { document.querySelectorAll("button").forEach(function (b) { b.disabled = on; }); }
  function runSync(folder) {
    busy(true); log("sync " + (folder || "all") + " started");
    api("POST", "/api/sync", folder ? { folder: folder } : {}).then(function (r) {
      r.forEach(function (x) { log(x.pull.folder + ": pulled " + x.pull.files_updated + " updated, " + x.pull.files_deleted + " deleted, " + x.pull.conflicts + " conflicts; pushed " + x.push.files_changed + " changed, " + x.push.chunks_uploaded + " chunks" + (x.pull.files_unavailable.length ? "; unavailable: " + x.pull.files_unavailable.join(", ") : "") + (x.pull.forked_devices.length ? "; FORKED: " + x.pull.forked_devices.join(", ") : "")); });
    }).catch(function (e) { log("sync failed: " + e.message); }).then(function () { busy(false); return refreshStatus(); });
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
  function loadFiles() {
    var folder = $("filesfolder").value; if (!folder) { return; }
    api("GET", "/api/files?folder=" + encodeURIComponent(folder)).then(function (rows) {
      var tb = $("files").querySelector("tbody"); tb.innerHTML = "";
      rows.forEach(function (f) {
        var tr = document.createElement("tr");
        function td(t) { var d = document.createElement("td"); d.textContent = t; tr.appendChild(d); }
        var nameCell = document.createElement("td");
        if (f.media) { var im = document.createElement("img"); im.className = "thumb"; im.alt = ""; im.loading = "lazy"; im.src = "/api/thumb?folder=" + encodeURIComponent(folder) + "&path=" + encodeURIComponent(f.path) + "&token=" + encodeURIComponent(token); im.onerror = function () { im.remove(); }; nameCell.appendChild(im); }
        nameCell.appendChild(document.createTextNode(f.path)); tr.appendChild(nameCell);
        td(fmtBytes(f.size)); td(f.state + (f.pinned ? ", kept here" : ""));
        td(f.last_accessed_utc ? new Date(f.last_accessed_utc * 1000).toLocaleDateString() : "never here");
        var act = document.createElement("td");
        if (f.state !== "missing") { var open = document.createElement("a"); open.className = "button secondary"; open.textContent = "Open"; open.href = "/api/open?folder=" + encodeURIComponent(folder) + "&path=" + encodeURIComponent(f.path) + "&token=" + encodeURIComponent(token); open.onclick = function () { setTimeout(loadFiles, 1500); }; act.appendChild(open); act.appendChild(document.createTextNode(" ")); }
        var b = document.createElement("button"); b.className = "secondary";
        if (f.state === "placeholder" || f.state === "missing") { b.textContent = "Download"; b.onclick = function () { busy(true); api("POST", "/api/fetch", { folder: folder, path: f.path }).then(function () { log("fetched " + f.path); }).catch(function (e) { log("fetch failed: " + e.message); }).then(function () { busy(false); loadFiles(); }); }; }
        else { b.textContent = "Free up space"; b.onclick = function () { api("POST", "/api/free", { folder: folder, path: f.path }).then(function () { log(f.path + " is now a placeholder"); }).catch(function (e) { log("free failed: " + e.message); }).then(function () { loadFiles(); refreshStatus(); }); }; }
        act.appendChild(b); tr.appendChild(act); tb.appendChild(tr);
      });
    }).catch(function (e) { log("error: " + e.message); });
  }
  $("filesload").onclick = loadFiles;
  $("filesfolder").onchange = function () { $("selectivetoggle").checked = $("filesfolder").selectedOptions.length && $("filesfolder").selectedOptions[0].dataset.selective === "1"; loadFiles(); };
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
  $("join").onsubmit = function (ev) { ev.preventDefault(); busy(true); api("POST", "/api/join", formData(ev.target)).then(function () { ev.target.reset(); log("joined the vault; attach folders below"); return refreshState(); }).catch(function (e) { alert(e.message); }).then(function () { busy(false); }); };
  $("replicatoken").onclick = function () { api("GET", "/api/replica/token").then(function (r) { $("replicaout").textContent = "Replica token (give to the device that will hold your encrypted copies without being able to open them): " + r.token; $("replicaout").classList.remove("hidden"); }).catch(function (e) { alert(e.message); }); };
  $("sharerequest").onclick = function () { api("POST", "/api/share/request", {}).then(function (r) { $("sharerequestout").textContent = r.request_code; $("sharerequestout").classList.remove("hidden"); }).catch(function (e) { alert(e.message); }); };
  $("storagekind").onchange = function () { var k = this.value; document.querySelectorAll("#addstorage [data-kind]").forEach(function (d) { d.classList.toggle("hidden", d.getAttribute("data-kind") !== k); }); };
  $("acceptshare").onsubmit = function (ev) { ev.preventDefault(); busy(true); api("POST", "/api/share/accept", formData(ev.target)).then(function (r) { ev.target.reset(); log("accepted shared folder " + r.folder + "; attach it below"); return refreshState(); }).catch(function (e) { alert(e.message); }).then(function () { busy(false); }); };
  $("addfolder").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/folder", formData(ev.target)).then(function () { ev.target.reset(); log("folder added"); return refreshStatus(); }).catch(function (e) { alert(e.message); }); };
  $("attachfolder").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/folder/attach", formData(ev.target)).then(function () { ev.target.reset(); log("folder attached"); return refreshStatus(); }).catch(function (e) { alert(e.message); }); };
  $("addstorage").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/storage", formData(ev.target)).then(function () { ev.target.reset(); log("storage added"); return refreshStatus(); }).catch(function (e) { alert(e.message); }); };
  refreshState();
})();
