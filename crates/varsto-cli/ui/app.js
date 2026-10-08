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
      s.folders.forEach(function (f) {
        var tr = document.createElement("tr");
        function td(text, cls) { var d = document.createElement("td"); d.textContent = text; if (cls) { d.className = cls; } tr.appendChild(d); }
        td(f.name); td(f.path || "(not attached)"); td(f.files); td(fmtBytes(f.bytes)); td(f.chunks);
        td(f.chunks_without_storage_copy, f.chunks_without_storage_copy > 0 ? "bad" : ""); td(f.chunks_verified_elsewhere);
        var act = document.createElement("td");
        if (f.path) { var b = document.createElement("button"); b.className = "secondary"; b.textContent = "Sync"; b.onclick = function () { runSync(f.name); }; act.appendChild(b); }
        tr.appendChild(act); tb.appendChild(tr);
        var o = document.createElement("option"); o.value = f.name; o.textContent = f.name; sel.appendChild(o);
      });
      var ul = $("storages"); ul.innerHTML = "";
      s.storages.forEach(function (st) { var li = document.createElement("li"); li.textContent = st.name + " (" + st.kind + ": " + st.path + (st.cold ? ", cold" : "") + ")"; ul.appendChild(li); });
      var names = Object.keys(s.devices).map(function (k) { return s.devices[k] + " (" + k.slice(0, 8) + ")"; });
      $("devices").textContent = "Devices: " + (names.join(", ") || "none yet") + (s.forked_devices.length ? " · FORKED: " + s.forked_devices.join(", ") : "");
      return api("GET", "/api/ledger").then(function (l) {
        $("ledger").textContent = l.map(function (e) { return e.device.slice(0, 8) + " #" + e.seq + " lamport " + e.lamport + " events " + e.events; }).join("\n") || "(empty)";
      });
    }).catch(function (e) { log("error: " + e.message); });
  }

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
  $("addfolder").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/folder", formData(ev.target)).then(function () { ev.target.reset(); log("folder added"); return refreshStatus(); }).catch(function (e) { alert(e.message); }); };
  $("attachfolder").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/folder/attach", formData(ev.target)).then(function () { ev.target.reset(); log("folder attached"); return refreshStatus(); }).catch(function (e) { alert(e.message); }); };
  $("addstorage").onsubmit = function (ev) { ev.preventDefault(); api("POST", "/api/storage", formData(ev.target)).then(function () { ev.target.reset(); log("storage added"); return refreshStatus(); }).catch(function (e) { alert(e.message); }); };
  refreshState();
})();
