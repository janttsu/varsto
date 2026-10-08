// Theme: auto (system) / light / dark. External file so a strict CSP can forbid inline scripts.
(function () {
  var root = document.documentElement;
  var key = "theme";
  function read() { try { return localStorage.getItem(key); } catch (e) { return null; } }
  function write(v) { try { if (v) { localStorage.setItem(key, v); } else { localStorage.removeItem(key); } } catch (e) {} }
  function apply(v) { if (v === "light" || v === "dark") { root.setAttribute("data-theme", v); } else { root.removeAttribute("data-theme"); } }
  apply(read());
  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) { return; }
    function label() {
      var v = read();
      btn.textContent = v === "light" ? "Theme: light" : v === "dark" ? "Theme: dark" : "Theme: auto";
    }
    label();
    btn.addEventListener("click", function () {
      var v = read();
      var next = v === null ? "light" : v === "light" ? "dark" : null;
      write(next); apply(next); label();
    });
  });
})();
