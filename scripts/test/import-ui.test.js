// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Tests of the Import page's pure rules (crates/varsto-cli/ui/app.js): what a
// YouTube address names, which decides the "One video" / "Whole channel or
// playlist" toggle. Plain node, no packages:
//
//     node scripts/test/import-ui.test.js
//
// The page script needs a page; the function is taken out of it by name and
// run on its own.
"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");

const src = fs.readFileSync(path.join(__dirname, "..", "..", "crates", "varsto-cli", "ui", "app.js"), "utf8");

// The source of `function <name>(...) { ... }`, by matching braces.
function take(name) {
  const start = src.indexOf("function " + name + "(");
  assert(start >= 0, "app.js has " + name);
  let i = src.indexOf("{", start), depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === "{") { depth++; }
    if (src[i] === "}") { depth--; if (depth === 0) { break; } }
  }
  return src.slice(start, i + 1);
}
const ytKind = new Function(take("ytKind") + "\nreturn ytKind;")();

const kind = (u) => { const k = ytKind(u); return k && k.kind; };
// Videos.
assert.strictEqual(kind("https://www.youtube.com/watch?v=dQw4w9WgXcQ"), "video");
assert.strictEqual(kind("youtube.com/watch?v=dQw4w9WgXcQ&t=42"), "video");
assert.strictEqual(kind("https://youtu.be/dQw4w9WgXcQ"), "video");
assert.strictEqual(kind("https://m.youtube.com/shorts/abcdefghijk"), "video");
assert.strictEqual(kind("https://www.youtube.com/live/abcdefghijk"), "video");
assert.strictEqual(kind("abcdefghijk"), "video", "a bare video id");
// Playlists and channels.
assert.strictEqual(kind("https://www.youtube.com/playlist?list=PL0123456789"), "playlist");
assert.strictEqual(ytKind("https://www.youtube.com/playlist?list=PL0123456789").list, "PL0123456789");
for (const u of ["https://www.youtube.com/@ExampleChannel", "https://www.youtube.com/@ExampleChannel/videos",
  "https://www.youtube.com/channel/UC0123456789abcdefghij", "https://www.youtube.com/c/Example",
  "https://www.youtube.com/user/example", "music.youtube.com/@Example"]) {
  assert.strictEqual(kind(u), "channel", u);
}
// A video in a playlist: either is meant; the playlist id comes along.
const both = ytKind("https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLabc&index=3");
assert.strictEqual(both.kind, "both");
assert.strictEqual(both.list, "PLabc");
assert.strictEqual(kind("https://youtu.be/dQw4w9WgXcQ?list=PLabc"), "both");
// Not YouTube, or nothing to import.
for (const u of ["", "   ", "https://example.com/watch?v=dQw4w9WgXcQ", "https://www.youtube.com/", "https://www.youtube.com/watch",
  "https://www.youtube.com/playlist", "https://youtu.be/", "not an address at all"]) {
  assert.strictEqual(ytKind(u), null, JSON.stringify(u));
}

// The page wiring the rules feed.
const html = fs.readFileSync(path.join(__dirname, "..", "..", "crates", "varsto-cli", "ui", "index.html"), "utf8");
for (const k of ["dir", "git-annex", "cloud", "torrent", "youtube"]) {
  assert(html.includes(`class="ij-source" data-kind="${k}"`), "a card for " + k);
}
for (const id of ["importjobs", "importjobs-empty", "importdone", "import-unavailable", "import-yt-url", "import-yt-detected", "import-storage", "import-torrent-file"]) {
  assert(html.includes(`id="${id}"`), "page has " + id);
  assert(src.includes(`$("${id}")`), "script uses " + id);
}
for (const v of ['name="sleep" value="25-65"', 'name="sleep_requests" type="number" min="0" step="1" value="2"', 'name="rate" value="600K"', 'name="concurrent_fragments" type="number" min="1" max="16" step="1" value="1"']) {
  assert(html.includes(v), "YouTube default " + v);
}
for (const k of ["/api/import/jobs", "/api/import/start", "\"import.jobs\""]) {
  assert(src.includes(k), "script uses " + k);
}
console.log("import-ui: ok");
