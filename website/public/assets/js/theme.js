// Theme: light (default) / dark / auto (follow the system). External file so a
// strict CSP can forbid inline scripts.
(function () {
  var root = document.documentElement;
  var key = "theme";
  function read() { try { return localStorage.getItem(key); } catch (e) { return null; } }
  function write(v) { try { localStorage.setItem(key, v); } catch (e) {} }
  function apply(v) { root.setAttribute("data-theme", v === "dark" || v === "auto" ? v : "light"); }
  apply(read());
  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) { return; }
    function label() {
      var v = read();
      btn.textContent = v === "dark" ? "Theme: dark" : v === "auto" ? "Theme: auto" : "Theme: light";
    }
    label();
    btn.addEventListener("click", function () {
      var v = read();
      var next = v === "dark" ? "auto" : v === "auto" ? "light" : "dark";
      write(next); apply(next); label();
    });
  });
})();
