// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `GET /api/viz`: the snapshot behind the live visualization page (spec
//! section 63). Answered on the dispatching thread without waiting for the
//! state lock: the engine parts are computed only when the lock is free and
//! kept for a while (`HEAVY_TTL`, `LIGHT_TTL`); while a sync holds the engine
//! the last ones are served (`"stale": true`) and the live part (tasks,
//! transfers, peer traffic) is always current.

use crate::desktop::Shared;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use varsto_core::viz::{self, Heavy, Light, LiveInput};

/// The ledger passes are repeated at most this often.
pub const HEAVY_TTL: Duration = Duration::from_secs(20);
/// The small state files are read at most this often.
pub const LIGHT_TTL: Duration = Duration::from_secs(3);

#[derive(Default)]
pub struct Cache {
    heavy: Option<(Instant, Arc<Heavy>)>,
    light: Option<(Instant, Arc<Light>)>,
    unlocked: bool,
}

static CACHE: Mutex<Cache> = Mutex::new(Cache {
    heavy: None,
    light: None,
    unlocked: false,
});

/// The snapshot for the page now.
pub fn snapshot(state: &Shared, traffic: &varsto_core::p2p::Traffic) -> Value {
    let (heavy, light, stale) = engine_parts(state);
    let peers = varsto_core::activity::global();
    peers.watch();
    let here = varsto_core::activity::local_here();
    let live = LiveInput {
        now_utc: varsto_core::util::now_utc(),
        this_device: here.device.clone(),
        this_name: here.name.clone(),
        tasks: here.tasks,
        peers: peers.report(),
        traffic: traffic.report(),
        transfers: varsto_core::progress::all(),
    };
    let mut v = viz::compose(heavy.as_deref(), light.as_deref(), &live);
    v["stale"] = json!(stale);
    v
}

fn engine_parts(state: &Shared) -> (Option<Arc<Heavy>>, Option<Arc<Light>>, bool) {
    let mut c = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let need_heavy = c
        .heavy
        .as_ref()
        .is_none_or(|(t, _)| t.elapsed() >= HEAVY_TTL);
    let need_light = c
        .light
        .as_ref()
        .is_none_or(|(t, _)| t.elapsed() >= LIGHT_TTL);
    let mut stale = false;
    if need_heavy || need_light {
        match state.try_lock() {
            Ok(st) => match st.engine.as_ref() {
                Some(engine) => {
                    c.unlocked = true;
                    if need_light {
                        match engine.viz_light() {
                            Ok(l) => c.light = Some((Instant::now(), Arc::new(l))),
                            Err(e) => log::debug!("viz light: {e:#}"),
                        }
                    }
                    if need_heavy {
                        match engine.viz_heavy() {
                            Ok(h) => c.heavy = Some((Instant::now(), Arc::new(h))),
                            Err(e) => log::debug!("viz heavy: {e:#}"),
                        }
                    }
                }
                None => {
                    // Locked or no vault: nothing to show.
                    c.heavy = None;
                    c.light = None;
                    c.unlocked = false;
                }
            },
            Err(_) => stale = c.heavy.is_some(),
        }
    }
    (
        c.heavy.as_ref().map(|(_, h)| h.clone()),
        c.light.as_ref().map(|(_, l)| l.clone()),
        stale,
    )
}

macro_rules! sprites {
    ($($n:literal),* $(,)?) => {
        &[$(
            (concat!("/viz/", $n, ".webp"), include_bytes!(concat!("../ui/viz/", $n, ".webp")) as &[u8]),
            (concat!("/viz/", $n, "@2x.webp"), include_bytes!(concat!("../ui/viz/", $n, "@2x.webp")) as &[u8]),
            (concat!("/viz/", $n, "-dark.webp"), include_bytes!(concat!("../ui/viz/", $n, "-dark.webp")) as &[u8]),
            (concat!("/viz/", $n, "-dark@2x.webp"), include_bytes!(concat!("../ui/viz/", $n, "-dark@2x.webp")) as &[u8]),
        )*]
    };
}

/// The sprites of `website/tools/render/viz_sprites.py` (WebP with alpha, 512
/// and 1024 px, light and dark) and their manifest, served without a token.
const SPRITES: &[(&str, &[u8])] = sprites![
    "laptop",
    "phone",
    "tablet",
    "monitor",
    "nas",
    "nas-warn",
    "shelf",
    "dock",
    "dock-disk",
    "dock-disk-busy",
    "dock-disk-bad",
    "usb",
    "cloud",
    "bucket",
    "archive",
    "lock",
    "coins",
];
const MANIFEST: &str = include_str!("../ui/viz/manifest.json");

/// A static file of the visualization under `/viz/`: its bytes and type.
pub fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    if path == "/viz/manifest.json" {
        return Some((MANIFEST.as_bytes(), "application/json; charset=utf-8"));
    }
    SPRITES
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, b)| (*b, "image/webp"))
}

/// Forget the cached parts (tests).
#[cfg(test)]
pub fn reset() {
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Cache::default();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceState;
    use std::io::{Read, Write};

    fn get(port: u16, target: &str, token: Option<&str>) -> (u16, String, Vec<u8>) {
        let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut req =
            format!("GET {target} HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
        if let Some(t) = token {
            req.push_str(&format!("X-Varsto-Token: {t}\r\n"));
        }
        req.push_str("\r\n");
        c.write_all(req.as_bytes()).unwrap();
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        let at = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
        let head = String::from_utf8_lossy(&out[..at]).to_lowercase();
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, head, out[(at + 4).min(out.len())..].to_vec())
    }

    fn server() -> (u16, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let (server, bound) = crate::desktop::bind(0).unwrap();
        let state: Shared = Arc::new(Mutex::new(crate::desktop::State {
            home: tmp.path().to_path_buf(),
            engine: None,
            token: "viz-test-token".into(),
            bound: bound.clone(),
            traffic: Arc::default(),
            service: ServiceState::default(),
            pair: None,
            link: None,
        }));
        let server = Arc::new(server);
        std::thread::spawn(move || crate::desktop::serve_arc(server, state));
        (bound.rsplit(':').next().unwrap().parse().unwrap(), tmp)
    }

    #[test]
    fn viz_route_needs_the_token_and_assets_are_served() {
        reset();
        let (port, _tmp) = server();
        // The snapshot follows the token rules of the other API routes.
        assert_eq!(get(port, "/api/viz", None).0, 401);
        assert_eq!(get(port, "/api/viz", Some("wrong")).0, 401);
        let (st, head, body) = get(port, "/api/viz", Some("viz-test-token"));
        assert_eq!(st, 200);
        assert!(head.contains("application/json") && head.contains("cache-control: no-store"));
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            (v["v"].as_u64(), v["unlocked"].as_bool()),
            (Some(1), Some(false))
        );
        assert!(v["flows"].as_array().unwrap().is_empty());
        // The page's own files, without a token, like app.js.
        let (st, head, body) = get(port, "/viz.js", None);
        assert_eq!(st, 200);
        assert!(head.contains("text/javascript"));
        assert!(String::from_utf8_lossy(&body).contains("api/viz"));
        let (st, head, _) = get(port, "/viz.css", None);
        assert_eq!((st, head.contains("text/css")), (200, true));
        let (st, head, body) = get(port, "/viz/manifest.json", None);
        assert_eq!(st, 200);
        assert!(head.contains("application/json"));
        let man: Value = serde_json::from_slice(&body).unwrap();
        for (path, _) in SPRITES {
            let name = path
                .trim_start_matches("/viz/")
                .split(['.', '@', '-'])
                .next()
                .unwrap();
            assert!(man.get(name).is_some(), "manifest lacks {name}");
        }
        let (st, head, body) = get(port, "/viz/laptop@2x.webp", None);
        assert_eq!(st, 200);
        assert!(head.contains("image/webp"));
        assert_eq!(&body[..4], b"RIFF");
        assert_eq!(get(port, "/viz/nothing.webp", None).0, 404);
    }

    #[test]
    fn page_is_registered_with_the_same_csp_and_every_sprite_exists() {
        let index = include_str!("../ui/index.html");
        assert!(index.contains(r#"src="/viz.js""#) && index.contains(r#"href="/viz.css""#));
        assert!(index.contains(r#"data-page="viz""#) && index.contains(r#"data-nav="viz""#));
        // Strict CSP: no inline script or style, no third-party address in the new files.
        let js = include_str!("../ui/viz.js");
        let css = include_str!("../ui/viz.css");
        for text in [js, css] {
            assert!(
                !text.contains("http://") && !text.contains("https://"),
                "external address"
            );
            assert!(!text.contains("@import"));
        }
        assert!(
            !js.contains("eval(") && !js.contains("innerHTML") && !js.contains("document.write")
        );
        assert_eq!(SPRITES.len(), 17 * 4);
        for (path, bytes) in SPRITES {
            assert_eq!(&bytes[..4], b"RIFF", "{path}");
            assert!(bytes.len() > 500, "{path}");
        }
    }

    /// The pure rules of the page (particle speed, stable flow labels) hold: run
    /// `scripts/test/viz-rules.test.js` with node when node is installed.
    #[test]
    fn page_rules_hold_in_node() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/test/viz-rules.test.js");
        match std::process::Command::new("node").arg(&script).output() {
            Ok(out) => assert!(
                out.status.success(),
                "viz rules failed:\n{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(_) => eprintln!("node is not installed: the viz rules were not run"),
        }
    }

    /// The example scene of the page (used for the screenshots) is reachable only through the
    /// harness flag: every mention of it sits on the flagged line, nothing falls back to it, and
    /// no URL parameter or stored value is read for it.
    #[test]
    fn page_has_no_demo_scene_entry_points() {
        let js = include_str!("../ui/viz.js");
        let flag = "window.__VARSTO_VIZ_TEST === true";
        let uses: Vec<&str> = js
            .lines()
            .filter(|l| l.contains("demoSnap") && !l.trim_start().starts_with("function demoSnap"))
            .collect();
        assert_eq!(uses.len(), 1, "demoSnap used once: {uses:?}");
        assert!(uses[0].contains(flag), "the only use is behind the flag");
        for bad in [
            "|| demoSnap",
            "snap || ",
            "demo = !",
            "Demo data",
            "__vizScene",
            "location.search",
            "URLSearchParams",
            "location.hash",
        ] {
            assert!(!js.contains(bad), "viz.js must not contain {bad:?}");
        }
        assert_eq!(
            js.matches("feed:").count() + js.matches(".feed =").count(),
            1,
            "one feed hook"
        );
        assert!(
            js.contains("window.varstoViz.feed = ")
                && js
                    .lines()
                    .any(|l| l.contains(flag) && l.contains("varstoViz.feed"))
        );
        // The scene is not read from storage: the only keys the page reads are the background mode and the token.
        for line in js
            .lines()
            .filter(|l| l.contains("localStorage.getItem") || l.contains("sessionStorage.getItem"))
        {
            assert!(
                line.contains("varsto-viz-bg") || line.contains("varsto-token"),
                "unexpected storage read: {line}"
            );
        }
        // Until the first answer nothing is drawn: draw() returns before it builds a model without data.
        assert!(js.contains("if (!snap) {\n      // Nothing real has arrived"));
    }

    /// Full screen asks the shell it runs in for the window's own full-screen mode, and
    /// every shell answers: the names the page uses are the ones the shells define.
    #[test]
    fn full_screen_bridges_match_the_shells() {
        let js = include_str!("../ui/viz.js");
        let css = include_str!("../ui/viz.css");
        for needle in [
            "VarstoAndroid.setFullscreen",
            "messageHandlers.varstoShell",
            "varsto:fullscreen:",
            "window.varstoShellFullscreen",
            "requestFullscreen",
            "popstate",
            "\"Escape\"",
        ] {
            assert!(js.contains(needle), "viz.js lacks {needle}");
        }
        for needle in ["100dvh", "100dvw", "viz-fullscreen", "cursor: none"] {
            assert!(css.contains(needle), "viz.css lacks {needle}");
        }
        let android = include_str!(
            "../../../apps/android/app/src/main/java/in/soderlund/varsto/MainActivity.kt"
        );
        assert!(
            android.contains("fun setFullscreen(on: Boolean)")
                && android.contains("BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE")
        );
        let mac = include_str!("../../../apps/macos/VarstoMenuBar/main.swift");
        assert!(
            mac.contains("\"varstoShell\"")
                && mac.contains("toggleFullScreen")
                && mac.contains("windowDidExitFullScreen")
        );
        let win = include_str!("../../varsto-window/src/app.rs");
        assert!(win.contains("with_ipc_handler") && win.contains("set_fullscreen"));
        let shell = include_str!("../../varsto-window/src/shell.rs");
        assert!(shell.contains("varsto:fullscreen:1") && shell.contains("varstoShellFullscreen"));
    }

    /// Every word the page puts on the screen has a Finnish and a Swedish
    /// translation: the literals given to `T(...)`, the tables of kinds and
    /// phases, and the few names passed around in variables.
    #[test]
    fn page_strings_are_translated() {
        let js = include_str!("../ui/viz.js");
        let mut found: Vec<String> = ["Auto", "Light", "Black", "Visualization"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let lits = |s: &str, found: &mut Vec<String>| {
            let mut rest = s;
            while let Some(q) = rest.find('"') {
                let body = &rest[q + 1..];
                let Some(end) = body.find('"') else { break };
                found.push(body[..end].to_string());
                rest = &body[end + 1..];
            }
        };
        // T( ... ): the literals up to the matching parenthesis.
        let b = js.as_bytes();
        let mut i = 0;
        while i + 2 < b.len() {
            let prev_ok = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            if b[i] == b'T' && b[i + 1] == b'(' && prev_ok {
                let mut depth = 1;
                let mut j = i + 2;
                let mut in_str = false;
                while j < b.len() && depth > 0 {
                    match b[j] {
                        b'"' => in_str = !in_str,
                        b'(' if !in_str => depth += 1,
                        b')' if !in_str => depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                lits(&js[i + 2..j - 1], &mut found);
                i = j;
            } else {
                i += 1;
            }
        }
        // The tables: kinds and phases (values only).
        for (start, end) in [("var KINDS = {", "};"), ("label = {", "}[p]")] {
            let a = js.find(start).unwrap() + start.len();
            let z = a + js[a..].find(end).unwrap();
            for part in js[a..z].split(',') {
                if let Some((_, v)) = part.split_once(':') {
                    lits(v, &mut found);
                }
            }
        }
        // The labels of the rows of the "Is it safe?" legend are literals in pairs.
        found.retain(|s| {
            s.len() > 1
                && s.chars().next().is_some_and(|c| c.is_alphabetic())
                && !s.starts_with("viz-")
                && s != "T"
                // Values the conditions inside T(...) compare with.
                && !["at_risk", "auto", "bad", "light", "ok", "wanted", "warn", "black"].contains(&s.as_str())
        });
        found.sort();
        found.dedup();
        assert!(found.len() > 90, "found only {}", found.len());
        for (lang, dict) in [
            ("fi", include_str!("../ui/i18n/fi.json")),
            ("sv", include_str!("../ui/i18n/sv.json")),
        ] {
            let d: Value = serde_json::from_str(dict).unwrap();
            let missing: Vec<&String> = found
                .iter()
                .filter(|t| d["strings"].get(t.as_str()).is_none())
                .collect();
            assert!(missing.is_empty(), "{lang} lacks {missing:?}");
        }
    }
}
