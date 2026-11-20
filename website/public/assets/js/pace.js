// One clip per measured scenario on the Resilio comparison.
// Each figure plays once when it scrolls into view, then stays on the last frame.
// Blocky cubes, no words in the picture. Finish time and the byte count come
// from each figure's data attributes. A note after the unit is not part of the count.
(function () {
  var W = 360, H = 188;
  var SPAN = 8000;

  function mount(fig) {
    var canvas = fig.querySelector("canvas");
    var ctx = canvas && canvas.getContext("2d");
    if (!ctx) { return; }
    var scene = fig.getAttribute("data-scene") || "text";
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var resilioRaw = fig.getAttribute("data-resilio") || "";
    var varstoRaw = fig.getAttribute("data-varsto") || "";
    // The other tool has no finish clock. Draw its end state and do not race it.
    var noFinish = fig.getAttribute("data-nofinish") === "1";
    var rSec = noFinish ? 0 : seconds(resilioRaw);
    var vSec = seconds(varstoRaw);
    var slow = Math.max(rSec, vSec, 0.001);
    var rAt = rSec / slow;
    var vAt = vSec / slow;
    var t0 = 0;
    var running = false;
    var lastP = 0;
    var started = false;
    var queue = [];

    function fit() {
      var dpr = Math.min(window.devicePixelRatio || 1, 3);
      var cssW = canvas.clientWidth;
      if (cssW < 8) { cssW = 960; }
      var bw = Math.max(1, Math.round(cssW * dpr));
      var bh = Math.max(1, Math.round(cssW * H / W * dpr));
      if (canvas.width !== bw || canvas.height !== bh) {
        canvas.width = bw;
        canvas.height = bh;
      }
      ctx.setTransform(bw / W, 0, 0, bh / H, 0, 0);
    }
    function css(name, fallback) {
      var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return v || fallback;
    }
    function mixArr(a, b, t) {
      return [
        (a[0] + (b[0] - a[0]) * t) | 0,
        (a[1] + (b[1] - a[1]) * t) | 0,
        (a[2] + (b[2] - a[2]) * t) | 0
      ];
    }
    function mix(a, b, t) {
      var c = mixArr(a, b, t);
      return "rgb(" + c[0] + "," + c[1] + "," + c[2] + ")";
    }
    function rgb(hex) {
      hex = String(hex).replace("#", "");
      if (hex.length === 3) { hex = hex[0] + hex[0] + hex[1] + hex[1] + hex[2] + hex[2]; }
      var n = parseInt(hex, 16);
      return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
    }
    function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
    function lerp(a, b, t) { return a + (b - a) * t; }
    function P(ox, x, y, z) {
      // Narrower than 26px per step so each lane stays inside the frame,
      // with the same gap on both sides of the centre line.
      return [ox + x * 22 - z * 10, 112 + z * 6 - y * 20];
    }
    function shade(tone) {
      return {
        top: mix(tone, [255, 255, 255], 0.4),
        side: mix(tone, [0, 0, 0], 0.2),
        edge: mix(tone, [0, 0, 0], 0.42)
      };
    }
    function poly(pts, color) {
      ctx.beginPath();
      ctx.moveTo(pts[0][0], pts[0][1]);
      for (var i = 1; i < pts.length; i++) { ctx.lineTo(pts[i][0], pts[i][1]); }
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();
    }
    function box(ox, x, y, z, sx, sy, sz, tone, front) {
      if (sx < 0.05 || sy < 0.05 || sz < 0.05) { return; }
      var c = shade(tone);
      queue.push({
        key: x + z * 0.2 + y * 0.35 + (front ? 30 : 0),
        draw: function () {
          poly([P(ox, x, y, z + sz), P(ox, x + sx, y, z + sz), P(ox, x + sx, y + sy, z + sz), P(ox, x, y + sy, z + sz)], c.edge);
          poly([P(ox, x + sx, y, z), P(ox, x + sx, y, z + sz), P(ox, x + sx, y + sy, z + sz), P(ox, x + sx, y + sy, z)], c.side);
          poly([P(ox, x, y + sy, z), P(ox, x + sx, y + sy, z), P(ox, x + sx, y + sy, z + sz), P(ox, x, y + sy, z + sz)], c.top);
        }
      });
    }
    function flush() {
      queue.sort(function (a, b) { return a.key - b.key; });
      for (var i = 0; i < queue.length; i++) { queue[i].draw(); }
      queue = [];
    }
    function slot(i, x0, s) {
      var step = s + 0.08;
      return [x0 + (i % 2) * step, ((i / 2) | 0) * step, 0.18];
    }
    function hop(i, count, p, start, doneAt) {
      var gap = (doneAt - start) / count;
      var dur = gap * 0.72;
      if (!(dur > 0.02)) { dur = 0.02; }
      return (p - (start + i * gap)) / dur;
    }
    function cubeAt(ox, home, dest, u, s, tone) {
      var t = clamp(u, 0, 1);
      var x = lerp(home[0], dest[0], t);
      var y = lerp(home[1], dest[1], t) + Math.sin(t * Math.PI) * 0.7;
      var z = lerp(home[2], dest[2], t);
      box(ox, x, y, z, s, s, s, tone);
    }
    function travel(ox, home, dest, u, s, tone) {
      if (u < 0) { box(ox, home[0], home[1], home[2], s, s, s, tone); }
      else if (u < 1) { cubeAt(ox, home, dest, u, s, tone); }
      else { box(ox, dest[0], dest[1], dest[2], s, s, s, tone); }
    }
    function runPile(ox, count, size, tone, p, start, doneAt, xHome, xDest) {
      for (var i = 0; i < count; i++) {
        travel(ox, slot(i, xHome, size), slot(i, xDest, size), hop(i, count, p, start, doneAt), size, tone);
      }
    }

    function lane(name, p, ox) {
      if (noFinish && name !== "varsto") {
        var settled = rgb(css("--faint", "#687083"));
        box(ox, 0, -0.2, 0, 1.85, 0.12, 1.25, [86, 92, 104]);
        box(ox, 3.2, -0.2, 0, 1.85, 0.12, 1.25, [86, 92, 104]);
        for (var n = 0; n < 4; n++) {
          var sitting = slot(n, 3.6, 0.58);
          box(ox, sitting[0], sitting[1], sitting[2], 0.58, 0.58, 0.58, settled);
        }
        return false;
      }
      var accent = rgb(css("--accent", "#86a4ff"));
      var stone = [214, 176, 122];
      var grey = [128, 134, 146];
      var pad = [86, 92, 104];
      var tone = name === "varsto" ? accent : stone;
      var bg = rgb(css("--raise", "#14171c"));
      var doneAt = name === "varsto" ? vAt : rAt;
      box(ox, 0, -0.2, 0, 1.85, 0.12, 1.25, pad);
      if (scene === "readers") {
        box(ox, 2.65, -0.2, 0, 1.15, 0.12, 1.05, pad);
        box(ox, 4.05, -0.2, 0.2, 1.15, 0.12, 1.05, pad);
      } else {
        box(ox, 3.2, -0.2, 0, 1.85, 0.12, 1.25, pad);
      }

      if (scene === "text") {
        if (name === "varsto" && p < 0.2) {
          var k = p / 0.2;
          box(ox, -0.05, lerp(2.35, 0.55, k), -0.05, 1.9, 0.12, 1.4, mixArr(tone, [255, 255, 255], 0.25), true);
          for (var i = 0; i < 6; i++) {
            var home = slot(i, 0.12, 0.78);
            var s = i < 2 ? lerp(0.78, 0.46, k) : lerp(0.78, 0.08, k);
            var fade = i < 2 ? tone : mixArr(tone, bg, k);
            if (i >= 2 && k > 0.9) { continue; }
            box(ox, home[0], Math.max(0, home[1] - (i < 2 ? 0 : k * 0.5)), home[2], s, s, s, fade);
          }
          return false;
        }
        if (name === "varsto") { runPile(ox, 2, 0.46, tone, p, 0.2, doneAt, 0.2, 3.45); }
        else { runPile(ox, 6, 0.78, tone, p, 0.02, doneAt, 0.1, 3.28); }
        return p >= doneAt;
      }

      if (scene === "edit") {
        for (var w = 0; w < 8; w++) {
          var col = w % 4;
          var c = grey;
          if (name === "varsto" && p < doneAt) {
            var sweep = (p * 3) % 1;
            if (Math.abs(col / 3 - sweep) < 0.2) { c = mixArr(grey, accent, 0.85); }
          }
          box(ox, 3.28 + col * 0.42, (w / 4 | 0) * 0.42, 0.28, 0.38, 0.38, 0.38, c);
        }
        runPile(ox, 2, 0.5, tone, p, doneAt > 0.75 ? 0.7 : 0.05, doneAt, 0.25, 3.4);
        return p >= doneAt;
      }

      if (scene === "files") {
        runPile(ox, 8, 0.4, tone, p, 0.02, doneAt, 0.08, 3.32);
        return p >= doneAt;
      }

      if (scene === "pair") {
        runPile(ox, 2, 0.92, tone, p, 0.02, doneAt, 0.12, 3.35);
        return p >= doneAt;
      }

      if (scene === "dup") {
        // Varsto carries one half. The other half appears on the reader's pad.
        if (name === "varsto") {
          for (var d = 0; d < 3; d++) {
            var homeD = slot(d, 0.12, 0.5);
            var destD = [3.32 + d * 0.56, 0.02, 0.2];
            var u = hop(d, 3, p, 0.02, doneAt);
            travel(ox, homeD, destD, u, 0.5, tone);
            if (u >= 1) {
              var grown = clamp((u - 1) / 0.35, 0, 1);
              box(ox, destD[0], 0.6, destD[2], 0.5 * grown, 0.5 * grown, 0.5 * grown, mixArr(tone, [255, 255, 255], 0.16));
            }
          }
        } else {
          runPile(ox, 6, 0.55, tone, p, 0.02, doneAt, 0.08, 3.28);
        }
        return p >= doneAt;
      }

      if (scene === "readers") {
        for (var r = 0; r < 4; r++) {
          var homeR = slot(r, 0.1, 0.46);
          var toB = r >= 2;
          var destR = slot(r % 2, toB ? 4.18 : 2.72, 0.46);
          var ur = hop(r, 4, p, 0.04, doneAt);
          if (name === "varsto" && r === 2) {
            var mid = [2.95, 1.15, 0.3];
            var leg = ur * 2;
            if (leg < 1) { travel(ox, homeR, mid, leg, 0.46, tone); }
            else { travel(ox, mid, destR, leg - 1, 0.46, tone); }
          } else {
            travel(ox, homeR, destR, ur, 0.46, tone);
          }
        }
        return p >= doneAt;
      }

      if (scene === "rename") {
        if (name === "varsto") {
          var shift = 0.32 * clamp(p / Math.max(doneAt, 0.05), 0, 1);
          for (var n = 0; n < 4; n++) {
            var sitting = slot(n, 3.28 + shift, 0.58);
            box(ox, sitting[0], sitting[1], sitting[2], 0.58, 0.58, 0.58, tone);
          }
          var speck = clamp(p / Math.max(doneAt, 0.05), 0, 1);
          cubeAt(ox, [0.28, 0.15, 0.85], [4.55, 0.15, 0.85], speck, 0.18, tone);
        } else {
          runPile(ox, 4, 0.62, tone, p, 0.02, doneAt, 0.12, 3.32);
        }
        return p >= doneAt;
      }

      if (scene === "slow") {
        var post = [96, 104, 118];
        // A gap in the link. Cubes that are in it while the link is cut vanish.
        box(ox, 1.55, 0.2, 0.2, 0.1, 0.85, 0.1, post);
        box(ox, 2.55, 0.2, 0.2, 0.1, 0.85, 0.1, post);
        var chop = ((p * 5) % 1) < 0.22;
        for (var s = 0; s < 5; s++) {
          var uSlow = hop(s, 5, p, 0.02, doneAt);
          var inGap = uSlow > 0.38 && uSlow < 0.68;
          var drop = inGap && (chop || s % 2 === 0);
          if (drop) {
            var left = 1 - (uSlow - 0.38) / 0.3;
            var gs = 0.4 * clamp(left, 0.05, 1);
            var ghost = slot(s, 1.85, 0.4);
            box(ox, ghost[0], ghost[1] + (1 - left) * 0.35, ghost[2], gs, gs, gs, mixArr(tone, [160, 64, 64], 0.65));
          } else {
            var again = chop && uSlow >= 0.68 ? uSlow - 0.28 : uSlow;
            travel(ox, slot(s, 0.06, 0.4), slot(s, 2.85, 0.4), again, 0.4, tone);
          }
        }
        return p >= doneAt;
      }

      runPile(ox, 4, 0.6, tone, p, 0.02, doneAt, 0.12, 3.32);
      return p >= doneAt;
    }

    function tick(x, y) {
      ctx.fillStyle = "#8fd4a8";
      ctx.fillRect(x, y + 4, 3, 3);
      ctx.fillRect(x + 3, y + 7, 3, 3);
      ctx.fillRect(x + 6, y, 3, 6);
    }
    function show(side, raw, p, doneAt) {
      var el = fig.querySelector('[data-side="' + side + '"] b');
      if (!el || !raw) { return; }
      var k = clamp(doneAt <= 0 ? 1 : p / doneAt, 0, 1);
      if (k >= 1) { el.textContent = raw; return; }
      var end = parseBytes(raw);
      el.textContent = Math.round(end.s * k) + " s · " + fmtBytes(end.n * k, end) + (end.unit ? " " + end.unit : "");
    }

    function paint(p) {
      lastP = p;
      fit();
      var bg = rgb(css("--raise", "#14171c"));
      ctx.fillStyle = "rgb(" + bg[0] + "," + bg[1] + "," + bg[2] + ")";
      ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = mix(rgb(css("--faint", "#687083")), [0, 0, 0], 0.25);
      ctx.fillRect((W / 2) | 0, 28, 1, H - 56);
      var rDone = lane("resilio", p, 28);
      var vDone = lane("varsto", p, 230);
      flush();
      var tickX = scene === "readers" ? 5.15 : 3.7;
      var tickY = (scene === "files" || scene === "text" || scene === "dup" || scene === "slow") ? 2.7 : 1.65;
      if (rDone) { var rp = P(28, tickX, tickY, 0.2); tick(rp[0], rp[1]); }
      if (vDone) { var vp = P(230, tickX, tickY, 0.2); tick(vp[0], vp[1]); }
      if (noFinish) {
        var held = fig.querySelector('[data-side="resilio"] b');
        if (held) { held.textContent = resilioRaw; }
      } else {
        show("resilio", resilioRaw, p, rAt);
      }
      show("varsto", varstoRaw, p, vAt);
    }
    function frame(now) {
      var p = reduce ? 1 : Math.min(1, (now - t0) / SPAN);
      paint(p);
      if (!reduce && p < 1) { requestAnimationFrame(frame); }
      else { running = false; showPlay(true); }
    }
    var play = document.createElement("button");
    play.type = "button";
    play.className = "pace-play";
    play.textContent = fig.getAttribute("data-play") || "Play";
    fig.appendChild(play);
    function showPlay(on) { play.hidden = !on; }
    function start() {
      if (started) { return; }
      started = true;
      showPlay(false);
      if (reduce) { paint(1); showPlay(true); return; }
      running = true;
      t0 = performance.now();
      requestAnimationFrame(frame);
    }
    function replay() {
      started = false;
      running = false;
      start();
    }
    play.addEventListener("click", replay);
    fig.replay = replay;

    paint(reduce ? 1 : 0);
    showPlay(false);
    if (reduce) { started = true; showPlay(true); }
    else if (!("IntersectionObserver" in window)) { start(); }
    else {
      var io = new IntersectionObserver(function (entries) {
        for (var i = 0; i < entries.length; i++) {
          if (entries[i].isIntersecting) { start(); io.disconnect(); break; }
        }
      }, { threshold: 0.2 });
      io.observe(fig);
    }
    new MutationObserver(function () { if (!running) { paint(lastP); } })
      .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    window.addEventListener("resize", function () { if (!running) { paint(lastP); } });
  }

  function seconds(raw) {
    var m = /(\d+(?:[.,]\d+)?)/.exec(raw || "");
    return m ? parseFloat(m[1].replace(",", ".")) : 0;
  }
  function parseBytes(raw) {
    var m = /(\d+(?:[.,]\d+)?)\s*s\s*·\s*(\d[\d\s.,]*)\s*(\S+)/.exec(raw || "");
    if (!m) { return { s: 0, n: 0, unit: "", dec: 0, comma: false }; }
    var nraw = m[2].replace(/\s/g, "");
    var comma = nraw.indexOf(",") >= 0 && nraw.indexOf(".") < 0;
    var parts = nraw.split(/[.,]/);
    return {
      s: parseFloat(m[1].replace(",", ".")),
      n: parseFloat(nraw.replace(",", ".")),
      unit: m[3].replace(/,$/, ""),
      dec: parts[1] ? parts[1].length : 0,
      comma: comma
    };
  }
  function fmtBytes(n, end) {
    if (!(n > 0.049)) { return "0"; }
    if (end.dec) {
      var s = n.toFixed(end.dec);
      return end.comma ? s.replace(".", ",") : s;
    }
    var whole = String(Math.max(0, Math.round(n)));
    return whole.replace(/\B(?=(\d{3})+(?!\d))/g, " ");
  }

  document.querySelectorAll("figure.pace").forEach(mount);
  document.querySelectorAll(".pace-set").forEach(function (set) {
    var tabs = set.querySelectorAll("[data-tab]");
    var panels = set.querySelectorAll("[data-panel]");
    function show(id) {
      for (var i = 0; i < tabs.length; i++) {
        var on = tabs[i].getAttribute("data-tab") === id;
        tabs[i].setAttribute("aria-selected", on ? "true" : "false");
      }
      for (var j = 0; j < panels.length; j++) {
        var open = panels[j].getAttribute("data-panel") === id;
        panels[j].hidden = !open;
        if (open) {
          var fig = panels[j].querySelector("figure.pace");
          if (fig && fig.replay) { fig.replay(); }
        }
      }
    }
    for (var t = 0; t < tabs.length; t++) {
      tabs[t].addEventListener("click", function () { show(this.getAttribute("data-tab")); });
    }
  });
})();
