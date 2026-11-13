// Opening race on the compare page. Three horizontal transfers, timed from
// the measured finishes on the slow, lossy link (10 000 small files).
// The slowest finish fills the clip. The page stays readable without it.
(function () {
  var DUR = 14000;

  function boot(fig) {
    var canvas = fig.querySelector("canvas");
    var ctx = canvas && canvas.getContext("2d");
    var rows = Array.prototype.slice.call(fig.querySelectorAll("[data-lane]"));
    if (!ctx || !rows.length) { return; }
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var lanes = rows.map(function (row) {
      return {
        row: row,
        sec: parseFloat(row.getAttribute("data-sec")) || 1,
        clock: row.querySelector("b"),
        finalText: (row.querySelector("b") || {}).textContent || ""
      };
    });
    var slow = lanes.reduce(function (m, lane) { return Math.max(m, lane.sec); }, 1);
    var play = fig.querySelector(".qpace-play");
    var running = false;
    var t0 = 0;
    var raf = 0;

    function css(name, fallback) {
      var v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
      return v || fallback;
    }
    function fit() {
      var dpr = Math.min(window.devicePixelRatio || 1, 3);
      var cssW = canvas.clientWidth || 720;
      var bw = Math.max(1, Math.round(cssW * dpr));
      var bh = Math.max(1, Math.round(cssW * (150 / 720) * dpr));
      if (canvas.width !== bw || canvas.height !== bh) {
        canvas.width = bw;
        canvas.height = bh;
      }
      ctx.setTransform(bw / 720, 0, 0, bh / 150, 0, 0);
    }
    function round(x, y, w, h, r) {
      var rr = Math.min(r, w / 2, h / 2);
      ctx.beginPath();
      ctx.moveTo(x + rr, y);
      ctx.arcTo(x + w, y, x + w, y + h, rr);
      ctx.arcTo(x + w, y + h, x, y + h, rr);
      ctx.arcTo(x, y + h, x, y, rr);
      ctx.arcTo(x, y, x + w, y, rr);
      ctx.closePath();
    }
    function paint(progress) {
      fit();
      var colors = [css("--accent-2", "#5ee0cf"), css("--series-1", "#6f97ff"), css("--series-2", "#f07a45")];
      var track = css("--surface-2", "#161a23");
      var paper = css("--raise", "#0e1117");
      var line = css("--border", "#1d222c");
      ctx.clearRect(0, 0, 720, 150);
      ctx.fillStyle = paper;
      ctx.fillRect(0, 0, 720, 150);
      var scenario = progress * slow;
      lanes.forEach(function (lane, i) {
        var p = Math.min(1, scenario / lane.sec);
        var y = 18 + i * 46;
        var x0 = 18;
        var tw = 684;
        var h = 30;
        ctx.fillStyle = track;
        round(x0, y, tw, h, 7);
        ctx.fill();
        ctx.strokeStyle = line;
        ctx.lineWidth = 1;
        ctx.stroke();
        var fw = Math.max(0, tw * p);
        if (fw > 1) {
          ctx.fillStyle = colors[i] || colors[0];
          round(x0, y, Math.max(fw, 8), h, 7);
          ctx.fill();
        }
        if (p >= 1) {
          ctx.fillStyle = colors[i] || colors[0];
          ctx.fillRect(x0 + tw - 4, y - 4, 4, h + 8);
        }
        var shown = p >= 1 ? lane.sec : Math.round(scenario < lane.sec ? scenario : lane.sec);
        if (lane.clock) { lane.clock.textContent = shown + " s"; }
        lane.row.classList.toggle("is-done", p >= 1);
      });
    }
    function stopAtEnd() {
      running = false;
      cancelAnimationFrame(raf);
      paint(1);
      if (play) { play.hidden = false; }
    }
    function frame(now) {
      if (!running) { return; }
      var p = Math.min(1, (now - t0) / DUR);
      paint(p);
      if (p >= 1) { stopAtEnd(); return; }
      raf = requestAnimationFrame(frame);
    }
    function start() {
      cancelAnimationFrame(raf);
      if (reduce) { stopAtEnd(); return; }
      if (play) { play.hidden = true; }
      lanes.forEach(function (lane) {
        if (lane.clock) { lane.clock.textContent = "0 s"; }
        lane.row.classList.remove("is-done");
      });
      running = true;
      t0 = performance.now();
      raf = requestAnimationFrame(frame);
    }
    if (play) {
      play.addEventListener("click", start);
    }
    if (document.fonts && document.fonts.ready) {
      document.fonts.ready.then(start);
    } else {
      start();
    }
  }

  document.querySelectorAll("[data-qpace]").forEach(boot);
})();
