// Motion around the content of the home page: headings that settle out of
// block glyphs, windows and cards that rise into place as they reach the
// screen, a light that runs round the product window, a spotlight under the
// cursor on the cards, and the visitor's platform marked in the download row.
// The page is complete without it, and nothing moves for visitors who ask
// for reduced motion.
(function () {
  var root = document.documentElement;
  // The platform row: mark this device's system (no motion involved).
  var ua = navigator.userAgent || "", pf = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
  var os = /iPhone|iPad|iPod/.test(ua) || (/Mac/.test(pf) && navigator.maxTouchPoints > 1) ? "iOS"
    : /Android/.test(ua) ? "Android" : /Win/.test(pf + ua) ? "Windows" : /Mac/.test(pf + ua) ? "macOS" : /Linux|X11/.test(pf + ua) ? "Linux" : "";
  document.querySelectorAll(".platforms a").forEach(function (a) { if (a.textContent.trim() === os) { a.classList.add("here"); } });

  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce || !("IntersectionObserver" in window)) { return; }
  root.classList.add("motion");

  // Headings: each letter starts as a glyph and settles, left to right. The
  // heading keeps its text for assistive technology, and every letter is held
  // at its final width so nothing reflows.
  var GLYPHS = "#%*+=-:;.`/|<>~^";
  function decode(h) {
    if (h.dataset.decoded) { return; }
    h.dataset.decoded = "1";
    var text = h.textContent, cells = [];
    h.setAttribute("aria-label", text);
    var frag = document.createDocumentFragment();
    text.split(/(\s+)/).forEach(function (part) {
      if (!part) { return; }
      if (/^\s+$/.test(part)) { frag.appendChild(document.createTextNode(" ")); return; }
      var word = document.createElement("span");
      word.className = "dc-w"; word.setAttribute("aria-hidden", "true");
      for (var i = 0; i < part.length; i++) {
        var c = document.createElement("span");
        c.className = "dc"; c.dataset.ch = part[i]; c.textContent = part[i];
        word.appendChild(c); cells.push(c);
      }
      frag.appendChild(word);
    });
    h.textContent = ""; h.appendChild(frag);
    cells.forEach(function (c) { c.style.width = c.getBoundingClientRect().width + "px"; });
    var start = performance.now(), n = cells.length, span = Math.min(900, 300 + n * 14);
    function step(now) {
      var p = (now - start) / span, done = true;
      for (var i = 0; i < n; i++) {
        var at = (i / n) * 0.75;
        if (p < at + 0.25) {
          done = false;
          cells[i].textContent = p < at ? "" : GLYPHS[(Math.random() * GLYPHS.length) | 0];
          cells[i].classList.toggle("dc-g", p >= at);
        } else if (cells[i].textContent !== cells[i].dataset.ch) {
          cells[i].textContent = cells[i].dataset.ch; cells[i].classList.remove("dc-g");
        }
      }
      if (!done) { requestAnimationFrame(step); } else { cells.forEach(function (c) { c.style.width = ""; }); }
    }
    requestAnimationFrame(step);
  }

  // Rise into place: windows, figures, cards (staggered within a grid), list items.
  var rising = document.querySelectorAll(".stage, .home > h2, .home .grid > .card, .home > figure, .home > ul > li, .home > p, .dl-card");
  rising.forEach(function (el) {
    el.classList.add("rise");
    var sib = el.parentElement ? Array.prototype.indexOf.call(el.parentElement.children, el) : 0;
    if (el.matches(".card, li, .dl-card")) { el.style.setProperty("--i", String(sib % 6)); }
  });
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (!e.isIntersecting) { return; }
      e.target.classList.add("in");
      if (e.target.matches("h2")) { decode(e.target); }
      io.unobserve(e.target);
    });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.12 });
  rising.forEach(function (el) { io.observe(el); });
  var h1 = document.querySelector(".hero h1");
  if (h1) { decode(h1); }

  // The spotlight on the cards follows the cursor.
  document.querySelectorAll(".home .grid > .card").forEach(function (c) {
    c.addEventListener("pointermove", function (e) {
      var r = c.getBoundingClientRect();
      c.style.setProperty("--mx", (e.clientX - r.left) + "px");
      c.style.setProperty("--my", (e.clientY - r.top) + "px");
    });
  });
})();
