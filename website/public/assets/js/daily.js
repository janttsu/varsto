// Daily builds page: fills in the numbers of the newest build from
// /daily/latest.json (written on the server by ops/site/daily-sync.py). The
// page itself is static and its download links are constant; without this
// script they still work. External file so a strict CSP can forbid inline
// scripts. Everything from the JSON goes in as text or as a validated link.
(function () {
  var build = document.getElementById("daily-build");
  if (!build) { return; }
  var pre = build.getAttribute("data-pre") || "";
  var REPO = "https://github.com/janttsu/varsto";

  function fields(root, name) { return root.querySelectorAll('[data-f="' + name + '"]'); }
  function setText(root, name, value) {
    Array.prototype.forEach.call(fields(root, name), function (el) { el.textContent = value; });
  }
  function setLink(root, name, href, text) {
    Array.prototype.forEach.call(fields(root, name), function (el) { el.setAttribute("href", href); el.textContent = text; });
  }
  function str(v, re) { return typeof v === "string" && re.test(v) ? v : ""; }

  function show(j) {
    var id = str(j.id, /^\d{8}-[0-9a-f]{7,40}$/);
    if (!id) { throw new Error("no build id"); }
    setText(build, "id", id);
    setText(build, "date", str(j.date, /^\d{4}-\d{2}-\d{2}$/));
    setText(build, "version", str(j.version, /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,39}$/));
    build.hidden = false;

    var commit = str(j.commit, /^[0-9a-f]{7,40}$/);
    var included = document.getElementById("daily-included");
    if (included) {
      if (commit) { setLink(included, "commit", REPO + "/commit/" + commit, commit.slice(0, 7)); }
      var run = str(j.ci_run, /^https:\/\/github\.com\/janttsu\/varsto\/actions\/runs\/\d+$/);
      if (run) { setLink(included, "ci_run", run, run); }
      included.hidden = false;
    }

    var rows = {};
    (j.platforms || []).forEach(function (p) { if (p && typeof p.file === "string") { rows[p.file] = p; } });
    Array.prototype.forEach.call(document.querySelectorAll("#daily-table tbody tr"), function (tr) {
      var p = rows[tr.getAttribute("data-file")];
      if (!p) { return; }
      if (typeof p.size === "number") { setText(tr, "size", (p.size / 1048576).toFixed(1) + " MB"); }
      var c = str(p.commit, /^[0-9a-f]{7,40}$/);
      if (c) {
        var cell = fields(tr, "commit")[0];
        var a = document.createElement("a");
        a.setAttribute("href", REPO + "/commit/" + c);
        var code = document.createElement("code");
        code.textContent = c.slice(0, 7);
        a.appendChild(code);
        cell.textContent = "";
        cell.appendChild(a);
      }
      var sum = str(p.sha256, /^[0-9a-f]{64}$/);
      if (sum) { setText(tr, "sha256", sum); }
    });

    var list = document.getElementById("daily-history");
    if (list) {
      (j.history || []).forEach(function (h) {
        var hid = h && str(h.id, /^\d{8}-[0-9a-f]{7,40}$/);
        if (!hid) { return; }
        var li = document.createElement("li");
        var a = document.createElement("a");
        a.setAttribute("href", pre + "daily/builds/" + hid + "/");
        a.textContent = hid;
        li.appendChild(a);
        var d = str(h.date, /^\d{4}-\d{2}-\d{2}$/);
        if (d) { li.appendChild(document.createTextNode(" (" + d + ")")); }
        list.appendChild(li);
      });
    }
  }

  function fail() {
    build.textContent = build.getAttribute("data-unavailable") || "";
    build.hidden = false;
  }

  if (!window.fetch) { fail(); return; }
  fetch(pre + "daily/latest.json", { cache: "no-cache" })
    .then(function (r) { if (!r.ok) { throw new Error("HTTP " + r.status); } return r.json(); })
    .then(show)
    .catch(fail);
})();
