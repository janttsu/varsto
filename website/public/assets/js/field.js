// The home page's block field: a band of characters behind the hero, drawn on
// a canvas. Each cell is a block; brighter glyphs are blocks with more copies,
// and a slow wave of verification passes over them. Decorative only
// (aria-hidden), paused off screen and when the tab is hidden, and a single
// still frame for people who ask for reduced motion.
(function () {
  var canvas = document.getElementById("field");
  if (!canvas || !canvas.getContext) { return; }
  var ctx = canvas.getContext("2d");
  var GLYPHS = " .`-:;=+*#%";
  var cell = 13, cols = 0, rows = 0, dpr = 1, seed = [], t0 = performance.now();
  var still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var visible = true, raf = 0;
  function colors() {
    var s = getComputedStyle(document.documentElement);
    return { a: s.getPropertyValue("--accent").trim() || "#86a4ff", b: s.getPropertyValue("--accent-2").trim() || "#5ee0cf", f: s.getPropertyValue("--faint").trim() || "#687083" };
  }
  var col = colors();
  function size() {
    var r = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.max(1, Math.floor(r.width * dpr));
    canvas.height = Math.max(1, Math.floor(r.height * dpr));
    cols = Math.ceil(r.width / cell); rows = Math.ceil(r.height / cell);
    seed = [];
    for (var i = 0; i < cols * rows; i++) { seed.push(Math.random()); }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.font = "500 11px \"Geist Mono\", ui-monospace, monospace";
    ctx.textBaseline = "middle"; ctx.textAlign = "center";
  }
  function frame(now) {
    var t = (now - t0) / 1000;
    var w = canvas.width / dpr, h = canvas.height / dpr;
    ctx.clearRect(0, 0, w, h);
    for (var y = 0; y < rows; y++) {
      for (var x = 0; x < cols; x++) {
        var nx = x / cols, ny = y / rows;
        // Two drifting ridges make the band; the seed keeps each cell its own.
        var ridge = Math.sin(nx * 7.0 + t * 0.35) * 0.18 + Math.sin(nx * 2.3 - t * 0.2) * 0.22 + 0.5;
        var d = Math.abs(ny - ridge);
        var v = Math.max(0, 1 - d * 3.2) * (0.55 + 0.45 * seed[y * cols + x]);
        // The verification sweep.
        var sweep = Math.max(0, 1 - Math.abs(((t * 0.08) % 1.4) - 0.2 - nx) * 9);
        v = Math.min(1, v + sweep * 0.5 * v);
        if (v < 0.08) { continue; }
        var g = GLYPHS[Math.min(GLYPHS.length - 1, Math.floor(v * GLYPHS.length))];
        ctx.globalAlpha = 0.18 + v * 0.75;
        ctx.fillStyle = sweep > 0.3 ? col.b : v > 0.62 ? col.a : col.f;
        ctx.fillText(g, x * cell + cell / 2, y * cell + cell / 2);
      }
    }
    ctx.globalAlpha = 1;
    if (!still && visible) { raf = requestAnimationFrame(frame); }
  }
  function start() { cancelAnimationFrame(raf); raf = requestAnimationFrame(frame); }
  size(); start();
  window.addEventListener("resize", function () { size(); if (still) { start(); } });
  if ("IntersectionObserver" in window) {
    new IntersectionObserver(function (e) { visible = e[0].isIntersecting; if (visible && !still) { start(); } }).observe(canvas);
  }
  document.addEventListener("visibilitychange", function () { visible = !document.hidden; if (visible && !still) { start(); } });
  // The theme toggle changes the colours.
  new MutationObserver(function () { col = colors(); if (still) { start(); } }).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
})();
