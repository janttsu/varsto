// SPDX-License-Identifier: PolyForm-Shield-1.0.0
// Interface languages: English (the source), Finnish and Swedish. The page is
// written in English; this script translates what it shows, the static page
// and everything app.js adds later, from /i18n/<lang>.json: exact strings
// (`strings`) and patterns for messages built from parts (`patterns`, each
// [regular expression, replacement]). Untranslated text stays English. The
// choice is kept in this browser and sent to the service, so the tray and
// menu-bar follow it.
(function () {
  "use strict";
  var LANGS = [["en", "English"], ["fi", "Suomi"], ["sv", "Svenska"]];
  var KEY = "varsto-lang";
  var lang = "en";
  try { lang = localStorage.getItem(KEY) || "en"; } catch (e) { /* storage blocked */ }
  if (!LANGS.some(function (l) { return l[0] === lang; })) { lang = "en"; }
  document.documentElement.lang = lang;
  var dict = null, patterns = [], parts = [];
  var ATTRS = ["title", "placeholder", "aria-label", "alt"];
  var original = new WeakMap(); // node -> English text, to translate again after app.js rewrites it
  var busy = false;

  function norm(s) { return s.replace(/\s+/g, " ").trim(); }
  function translate(s) {
    if (!dict || !s) { return s; }
    var k = norm(s);
    if (!k) { return s; }
    var t = dict[k];
    if (t === undefined) {
      for (var i = 0; i < patterns.length; i++) {
        if (patterns[i][0].test(k)) { t = k.replace(patterns[i][0], patterns[i][1]); break; }
      }
    }
    // Known phrases inside a longer text (lists the service writes, such as
    // a policy's rules or a sync summary): each is replaced where it occurs.
    if (t === undefined && parts.length) {
      var u = k;
      for (var j = 0; j < parts.length; j++) { u = u.replace(parts[j][0], parts[j][1]); }
      if (u !== k) { t = u; }
    }
    if (t === undefined || t === k) { return s; }
    // Keep the surrounding white space of the original.
    var lead = s.match(/^\s*/)[0], trail = s.match(/\s*$/)[0];
    return lead + t + trail;
  }
  function skip(el) {
    for (var n = el; n && n.nodeType === 1; n = n.parentNode) {
      var tag = n.tagName;
      if (tag === "SCRIPT" || tag === "STYLE" || tag === "CODE" || tag === "PRE" || tag === "TEXTAREA" || (n.hasAttribute && n.hasAttribute("data-no-i18n"))) { return true; }
    }
    return false;
  }
  function doText(node) {
    if (skip(node.parentNode)) { return; }
    var src = node.nodeValue;
    var prev = original.get(node);
    // app.js wrote new text: remember it as the English original.
    if (prev === undefined || (prev.out !== src)) { prev = { en: src, out: src }; }
    var out = translate(prev.en);
    prev.out = out;
    original.set(node, prev);
    if (out !== src) { node.nodeValue = out; }
  }
  function doAttrs(el) {
    if (skip(el)) { return; }
    for (var i = 0; i < ATTRS.length; i++) {
      var a = ATTRS[i];
      if (!el.hasAttribute(a)) { continue; }
      var v = el.getAttribute(a), t = translate(v);
      if (t !== v) { el.setAttribute(a, t); }
    }
  }
  function walk(root) {
    if (root.nodeType === 3) { doText(root); return; }
    if (root.nodeType !== 1) { return; }
    doAttrs(root);
    var w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    var n;
    while ((n = w.nextNode())) { if (n.nodeType === 3) { doText(n); } else { doAttrs(n); } }
  }
  function start() {
    walk(document.body);
    new MutationObserver(function (list) {
      if (busy) { return; }
      busy = true;
      try {
        list.forEach(function (m) {
          if (m.type === "characterData") { doText(m.target); }
          else if (m.type === "attributes") { doAttrs(m.target); }
          else { m.addedNodes.forEach(walk); }
        });
      } finally { busy = false; }
    }).observe(document.body, { childList: true, characterData: true, subtree: true, attributes: true, attributeFilter: ATTRS });
  }
  function pickers() {
    document.querySelectorAll("select.lang-select").forEach(function (sel) {
      sel.innerHTML = "";
      LANGS.forEach(function (l) { var o = document.createElement("option"); o.value = l[0]; o.textContent = l[1]; sel.appendChild(o); });
      sel.value = lang;
      sel.setAttribute("data-no-i18n", "");
      sel.onchange = function () { window.varstoLang.set(sel.value); };
    });
  }
  window.varstoLang = {
    get: function () { return lang; },
    t: translate,
    set: function (l) {
      try { localStorage.setItem(KEY, l); } catch (e) { /* not kept */ }
      // Tell the service, so the tray and the menu bar follow (best effort).
      try {
        var tok = new URLSearchParams(location.search).get("token") || sessionStorage.getItem("varsto-token");
        if (tok) { fetch("/api/ui-language", { method: "POST", headers: { "X-Varsto-Token": tok, "Content-Type": "application/json" }, body: JSON.stringify({ language: l }) }); }
      } catch (e) { /* the page still changes */ }
      setTimeout(function () { location.reload(); }, 150);
    }
  };
  document.addEventListener("DOMContentLoaded", function () {
    pickers();
    if (lang === "en") { return; }
    fetch("/i18n/" + lang + ".json").then(function (r) { return r.json(); }).then(function (j) {
      dict = j.strings || {};
      patterns = (j.patterns || []).map(function (p) { return [new RegExp(p[0]), p[1]]; });
      parts = (j.parts || []).map(function (p) { return [new RegExp(p[0], "g"), p[1]]; });
      start();
    }).catch(function () { /* English stays */ });
  });
})();
