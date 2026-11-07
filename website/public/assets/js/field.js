// Varsto home page: two glyph fields drawn on canvases.
//  - The hero field fills the first screen: drifting ridges of block glyphs,
//    dim behind the headline and the buttons, brighter where a slow
//    verification sweep passes, stirred by the cursor.
//  - The footer wordmark: "varsto" set in the page's type, filled with
//    glyphs that shimmer, a scan passing over them, the cursor scattering
//    the ones it touches.
// Decorative only (aria-hidden). Both sleep off screen and in hidden tabs,
// run at most 30 frames a second, and draw one still frame when the visitor
// asks for reduced motion.
(function () {
  var still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var GLYPHS = " .`-:;=+*#%";
  function palette() {
    var s = getComputedStyle(document.documentElement);
    return { a: s.getPropertyValue("--accent").trim() || "#86a4ff", b: s.getPropertyValue("--accent-2").trim() || "#5ee0cf", f: s.getPropertyValue("--faint").trim() || "#687083", t: s.getPropertyValue("--text").trim() || "#eef0f6" };
  }
  var col = palette();
  new MutationObserver(function () { col = palette(); fields.forEach(function (f) { f.kick(); }); })
    .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

  function hash(x, y) { var h = Math.sin(x * 127.1 + y * 311.7) * 43758.5453; return h - Math.floor(h); }

  // A field on `canvas`, painted by `paint(ctx, w, h, t, mouse)`, sized by `onSize`.
  function Field(canvas, cell, onSize, paint) {
    var ctx = canvas.getContext("2d"), dpr = 1, visible = true, raf = 0, last = 0, t0 = performance.now();
    var mouse = { x: -1e4, y: -1e4, k: 0 }, self = this;
    function size() {
      var r = canvas.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.max(1, Math.floor(r.width * dpr));
      canvas.height = Math.max(1, Math.floor(r.height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.font = "500 " + Math.round(cell * 0.86) + "px \"Geist Mono\", ui-monospace, monospace";
      ctx.textBaseline = "middle"; ctx.textAlign = "center";
      onSize(r.width, r.height);
    }
    function frame(now) {
      raf = 0;
      if (!still && now - last < 32) { raf = requestAnimationFrame(frame); return; }
      last = now;
      var w = canvas.width / dpr, h = canvas.height / dpr;
      ctx.clearRect(0, 0, w, h);
      mouse.k *= 0.94;
      paint(ctx, w, h, (now - t0) / 1000, mouse);
      ctx.globalAlpha = 1;
      if (!still && visible) { raf = requestAnimationFrame(frame); }
    }
    this.kick = function () { if (!raf) { raf = requestAnimationFrame(frame); } };
    size(); this.kick();
    window.addEventListener("resize", function () { size(); self.kick(); });
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (e) { visible = e[0].isIntersecting; if (visible) { self.kick(); } }).observe(canvas);
    }
    document.addEventListener("visibilitychange", function () { visible = !document.hidden; if (visible) { self.kick(); } });
    if (!still) {
      window.addEventListener("pointermove", function (e) {
        var r = canvas.getBoundingClientRect();
        mouse.x = e.clientX - r.left; mouse.y = e.clientY - r.top; mouse.k = 1;
        self.kick();
      }, { passive: true });
    }
  }
  var fields = [];

  // ----- the hero ---------------------------------------------------------------
  var hero = document.getElementById("field");
  if (hero && hero.getContext) {
    var hcell = 14, quiet = [];
    var hf = new Field(hero, hcell, function () {
      // Where the text is: the field stays dim there.
      var base = hero.getBoundingClientRect();
      quiet = [];
      document.querySelectorAll(".hero h1, .hero .lead, .hero .cta, .hero .platforms").forEach(function (el) {
        var r = el.getBoundingClientRect();
        quiet.push([r.left - base.left - 24, r.top - base.top - 16, r.right - base.left + 24, r.bottom - base.top + 16]);
      });
    }, function (ctx, w, h, t, m) {
      var cols = Math.ceil(w / hcell), rows = Math.ceil(h / hcell);
      var sweepX = ((t * 0.07) % 1.5) - 0.25;
      for (var y = 0; y < rows; y++) {
        var py = y * hcell + hcell / 2, ny = py / h;
        for (var x = 0; x < cols; x++) {
          var px = x * hcell + hcell / 2, nx = px / w, s = hash(x, y);
          // Two ridges low on the screen, and a faint scatter everywhere else.
          var r1 = 0.76 + Math.sin(nx * 6.2 + t * 0.32) * 0.08 + Math.sin(nx * 2.1 - t * 0.18) * 0.07;
          var r2 = 0.9 + Math.sin(nx * 4.0 - t * 0.27 + 1.7) * 0.05;
          var v = Math.max(0, 1 - Math.abs(ny - r1) * 5.2) * (0.6 + 0.4 * s);
          v = Math.max(v, Math.max(0, 1 - Math.abs(ny - r2) * 7) * 0.8 * s);
          v = Math.max(v, s > 0.965 ? 0.3 + 0.25 * Math.sin(t * 2 + s * 40) : 0);
          var sweep = Math.max(0, 1 - Math.abs(sweepX - nx) * 10);
          v = Math.min(1, v + sweep * 0.55 * v);
          var dx = px - m.x, dy = py - m.y, near = m.k * Math.max(0, 1 - Math.sqrt(dx * dx + dy * dy) / 170);
          v = Math.min(1, v + near * (0.5 + 0.5 * s));
          for (var q = 0; q < quiet.length; q++) {
            var b = quiet[q];
            if (px > b[0] && px < b[2] && py > b[1] && py < b[3]) { v *= 0.22; break; }
          }
          if (v < 0.07) { continue; }
          var g = GLYPHS[Math.min(GLYPHS.length - 1, Math.floor(v * GLYPHS.length))];
          ctx.globalAlpha = Math.min(1, 0.18 + v * 0.85);
          ctx.fillStyle = near > 0.2 || sweep > 0.3 ? col.b : v > 0.5 ? col.a : col.f;
          ctx.fillText(g, px + (near > 0.4 ? (s - 0.5) * 6 * near : 0), py);
        }
      }
    });
    fields.push(hf);
  }

  // ----- the footer wordmark ------------------------------------------------------
  var host = document.querySelector("[data-foot-mark]");
  if (host) {
    var fc = document.createElement("canvas");
    fc.setAttribute("aria-hidden", "true");
    host.appendChild(fc);
    host.classList.add("live");
    var fcell = 9, mask = null, mw = 0;
    var ff = new Field(fc, fcell, function (w, h) {
      // The word, white on transparent, at the canvas size: the cells inside it light up.
      var off = document.createElement("canvas");
      off.width = Math.ceil(w); off.height = Math.ceil(h);
      var o = off.getContext("2d");
      var size = h * 1.18;
      o.font = "700 " + size + "px Geist, ui-sans-serif, system-ui, sans-serif";
      o.textAlign = "center"; o.textBaseline = "alphabetic";
      if (o.letterSpacing !== undefined) { o.letterSpacing = (-0.07 * size) + "px"; }
      o.fillStyle = "#fff";
      o.fillText("varsto", w / 2, h * 0.93);
      mask = o.getImageData(0, 0, off.width, off.height).data; mw = off.width;
    }, function (ctx, w, h, t, m) {
      if (!mask) { return; }
      var cols = Math.ceil(w / fcell), rows = Math.ceil(h / fcell);
      var scan = ((t * 0.12) % 1.4) - 0.2;
      for (var y = 0; y < rows; y++) {
        var py = y * fcell + fcell / 2;
        for (var x = 0; x < cols; x++) {
          var px = x * fcell + fcell / 2;
          var inside = mask[((Math.floor(py) * mw) + Math.floor(px)) * 4 + 3] > 120;
          var s = hash(x + 17, y + 3);
          var dx = px - m.x, dy = py - m.y, d = Math.sqrt(dx * dx + dy * dy), near = m.k * Math.max(0, 1 - d / 110);
          if (!inside && near < 0.2) { continue; }
          var shimmer = 0.5 + 0.5 * Math.sin(t * 1.6 + s * 30);
          var v = inside ? 0.3 + 0.45 * shimmer * s + 0.25 * Math.max(0, 1 - Math.abs(scan - px / w) * 12) : 0.25 * near * s;
          var ox = 0, oy = 0;
          if (near > 0) { ox = (dx / (d || 1)) * near * 14 * s; oy = (dy / (d || 1)) * near * 14 * s; }
          var g = GLYPHS[Math.min(GLYPHS.length - 1, 2 + Math.floor(v * (GLYPHS.length - 2)))];
          ctx.globalAlpha = Math.min(0.95, 0.16 + v * (inside ? 0.62 : 0.7));
          ctx.fillStyle = near > 0.3 ? col.b : v > 0.62 ? col.a : col.t;
          ctx.fillText(g, px + ox, py + oy);
        }
      }
    });
    fields.push(ff);
  }
})();
