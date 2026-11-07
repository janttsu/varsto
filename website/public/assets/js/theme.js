// Theme: dark (default) / light / auto (follow the system). External file so a
// strict CSP can forbid inline scripts. The button shows a sun or a moon; its
// title and aria-label say which theme is on.
(function () {
  var root = document.documentElement;
  var key = "theme";
  function read() { try { return localStorage.getItem(key); } catch (e) { return null; } }
  function write(v) { try { localStorage.setItem(key, v); } catch (e) {} }
  function apply(v) { root.setAttribute("data-theme", v === "light" || v === "auto" ? v : "dark"); }
  apply(read());
  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("theme-toggle");
    if (!btn) { return; }
    function label() {
      var v = read();
      var t = v === "light" ? "Theme: light" : v === "auto" ? "Theme: auto" : "Theme: dark";
      btn.title = t; btn.setAttribute("aria-label", t);
    }
    label();
    btn.addEventListener("click", function () {
      var v = read();
      var next = v === "light" ? "auto" : v === "auto" ? "dark" : "light";
      write(next); apply(next); label();
    });
  });
})();
