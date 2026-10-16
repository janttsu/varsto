// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Where the window was last: size, position and whether it was maximised,
//! kept in `window.json` and restored at the next start. A saved position on
//! a monitor that is no longer there is dropped, so the window never opens
//! out of reach.

use serde::{Deserialize, Serialize};
use std::path::Path;

pub const MIN_WIDTH: u32 = 720;
pub const MIN_HEIGHT: u32 = 480;
pub const DEFAULT_WIDTH: u32 = 1100;
pub const DEFAULT_HEIGHT: u32 = 760;

/// Physical pixels, as the window system reports them. The position is that
/// of the outer frame, the size that of the inside.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    #[serde(default)]
    pub maximized: bool,
}

/// A monitor's rectangle: x, y, width, height.
pub type Monitor = (i32, i32, u32, u32);

pub fn load(path: &Path) -> Option<Geometry> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

pub fn save(path: &Path, g: &Geometry) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(text) = serde_json::to_vec_pretty(g) {
        // Written beside the file and renamed: a crash never leaves half a file.
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, text).is_ok() && std::fs::rename(&tmp, path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
}

/// The saved geometry made safe to use: at least the minimum size, and a
/// part of the title bar must lie on some monitor. `None` when it does not
/// (the system then places the window).
pub fn fit(g: Geometry, monitors: &[Monitor]) -> Option<Geometry> {
    let g = Geometry {
        width: g.width.clamp(MIN_WIDTH, 16_384),
        height: g.height.clamp(MIN_HEIGHT, 16_384),
        ..g
    };
    // A 160 x 40 px strip of the title bar must be visible on a monitor.
    let (left, top) = (i64::from(g.x), i64::from(g.y));
    let (right, bottom) = (left + i64::from(g.width), top + 40);
    let visible = monitors.iter().any(|&(mx, my, mw, mh)| {
        let (ml, mt) = (i64::from(mx), i64::from(my));
        let (mr, mb) = (ml + i64::from(mw), mt + i64::from(mh));
        right.min(mr) - left.max(ml) >= 160 && bottom.min(mb) - top.max(mt) >= 40
    });
    visible.then_some(g)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCREEN: Monitor = (0, 0, 1920, 1080);

    fn g(x: i32, y: i32, width: u32, height: u32) -> Geometry {
        Geometry {
            x,
            y,
            width,
            height,
            maximized: false,
        }
    }

    #[test]
    fn a_window_on_a_monitor_is_kept() {
        assert_eq!(
            fit(g(100, 80, 1100, 760), &[SCREEN]),
            Some(g(100, 80, 1100, 760))
        );
    }

    #[test]
    fn a_window_on_a_missing_monitor_is_dropped() {
        assert_eq!(fit(g(2500, 80, 1100, 760), &[SCREEN]), None);
        assert_eq!(fit(g(100, 1200, 1100, 760), &[SCREEN]), None);
        assert_eq!(fit(g(-32000, -32000, 1100, 760), &[SCREEN]), None);
    }

    #[test]
    fn a_window_on_a_second_monitor_to_the_left_is_kept() {
        let left = (-1920, 0, 1920, 1080);
        assert!(fit(g(-1800, 50, 1100, 760), &[SCREEN, left]).is_some());
        assert!(fit(g(-1800, 50, 1100, 760), &[SCREEN]).is_none());
    }

    #[test]
    fn a_tiny_size_grows_to_the_minimum() {
        let f = fit(g(10, 10, 100, 50), &[SCREEN]).unwrap();
        assert_eq!((f.width, f.height), (MIN_WIDTH, MIN_HEIGHT));
    }

    #[test]
    fn saved_geometry_comes_back() {
        let dir = tempdir();
        let path = dir.join("window.json");
        assert_eq!(load(&path), None);
        let want = Geometry {
            maximized: true,
            ..g(5, 6, 900, 700)
        };
        save(&path, &want);
        assert_eq!(load(&path), Some(want));
        std::fs::write(&path, "not json").unwrap();
        assert_eq!(load(&path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempdir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "varsto-window-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
