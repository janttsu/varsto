// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Progress of the file download running now, readable without the engine
//! (the service answers it while a fetch holds the engine), so the interface
//! can show "Downloading 1.2 of 5.0 MiB" under the button that started it.

use serde::Serialize;
use std::sync::Mutex;
use std::time::Instant;

struct Current {
    folder: String,
    path: String,
    done: u64,
    total: u64,
    started: Instant,
}

static CURRENT: Mutex<Option<Current>> = Mutex::new(None);

#[derive(Clone, Debug, Serialize)]
pub struct Progress {
    pub folder: String,
    pub path: String,
    pub done: u64,
    pub total: u64,
    pub percent: u32,
    pub bytes_per_sec: u64,
}

/// Marks a download for its lifetime: progress is cleared when it is
/// dropped, also when the download fails.
pub struct Download;

impl Download {
    pub fn begin(folder: &str, path: &str, total: u64) -> Download {
        *CURRENT.lock().unwrap() = Some(Current {
            folder: folder.to_string(),
            path: path.to_string(),
            done: 0,
            total,
            started: Instant::now(),
        });
        Download
    }

    pub fn advance(&self, bytes: u64) {
        if let Some(c) = CURRENT.lock().unwrap().as_mut() {
            c.done += bytes;
        }
    }
}

impl Drop for Download {
    fn drop(&mut self) {
        *CURRENT.lock().unwrap() = None;
    }
}

/// The download running now, if any.
pub fn current() -> Option<Progress> {
    let g = CURRENT.lock().unwrap();
    let c = g.as_ref()?;
    let secs = c.started.elapsed().as_secs_f64().max(0.001);
    Some(Progress {
        folder: c.folder.clone(),
        path: c.path.clone(),
        done: c.done,
        total: c.total,
        percent: (c.done * 100)
            .checked_div(c.total)
            .map_or(100, |p| p.min(100) as u32),
        bytes_per_sec: (c.done as f64 / secs) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_follows_one_download_and_clears() {
        assert!(current().is_none());
        {
            let d = Download::begin("docs", "a.bin", 200);
            d.advance(50);
            let p = current().unwrap();
            assert_eq!((p.done, p.total, p.percent), (50, 200, 25));
        }
        assert!(current().is_none());
    }
}
