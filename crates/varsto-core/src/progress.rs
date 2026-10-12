// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Transfers running now, readable without the engine (the service answers
//! while a sync holds the engine): the file being downloaded, so the
//! interface can show "Downloading 1.2 of 5.0 MiB" under the button that
//! started it, and every upload and download for `varsto transfers`.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

struct Current {
    id: u64,
    kind: &'static str,
    folder: String,
    path: String,
    done: u64,
    total: u64,
    started: Instant,
}

static ACTIVE: Mutex<Vec<Current>> = Mutex::new(Vec::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Serialize)]
pub struct Progress {
    /// "download" or "upload".
    pub kind: String,
    pub folder: String,
    pub path: String,
    pub done: u64,
    pub total: u64,
    pub percent: u32,
    pub bytes_per_sec: u64,
    pub elapsed_secs: u64,
}

/// Marks one transfer for its lifetime: it is removed from the list when
/// dropped, also when the transfer fails.
pub struct Transfer {
    id: u64,
}

/// The download of one file (the name the interface code uses).
pub type Download = Transfer;

impl Transfer {
    fn start(kind: &'static str, folder: &str, path: &str, total: u64) -> Transfer {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        ACTIVE.lock().unwrap().push(Current {
            id,
            kind,
            folder: folder.to_string(),
            path: path.to_string(),
            done: 0,
            total,
            started: Instant::now(),
        });
        Transfer { id }
    }

    /// A file coming from storages or peers.
    pub fn begin(folder: &str, path: &str, total: u64) -> Transfer {
        Self::start("download", folder, path, total)
    }

    /// A file whose blocks go to the storages.
    pub fn upload(folder: &str, path: &str, total: u64) -> Transfer {
        Self::start("upload", folder, path, total)
    }

    pub fn advance(&self, bytes: u64) {
        if let Some(c) = ACTIVE.lock().unwrap().iter_mut().find(|c| c.id == self.id) {
            c.done += bytes;
        }
    }
}

impl Drop for Transfer {
    fn drop(&mut self) {
        ACTIVE.lock().unwrap().retain(|c| c.id != self.id);
    }
}

fn view(c: &Current) -> Progress {
    let secs = c.started.elapsed().as_secs_f64().max(0.001);
    Progress {
        kind: c.kind.to_string(),
        folder: c.folder.clone(),
        path: c.path.clone(),
        done: c.done,
        total: c.total,
        percent: (c.done * 100)
            .checked_div(c.total)
            .map_or(100, |p| p.min(100) as u32),
        bytes_per_sec: (c.done as f64 / secs) as u64,
        elapsed_secs: secs as u64,
    }
}

/// The download running now (the latest one started), if any.
pub fn current() -> Option<Progress> {
    let g = ACTIVE.lock().unwrap();
    g.iter().rev().find(|c| c.kind == "download").map(view)
}

/// Every transfer running now, oldest first.
pub fn all() -> Vec<Progress> {
    ACTIVE.lock().unwrap().iter().map(view).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_follows_transfers_and_clears() {
        assert!(current().is_none());
        {
            let d = Download::begin("docs", "a.bin", 200);
            d.advance(50);
            let p = current().unwrap();
            assert_eq!((p.done, p.total, p.percent), (50, 200, 25));
            let u = Transfer::upload("docs", "b.bin", 10);
            u.advance(10);
            let a = all();
            assert_eq!(a.len(), 2);
            assert_eq!((a[1].kind.as_str(), a[1].percent), ("upload", 100));
            assert_eq!(current().unwrap().path, "a.bin");
        }
        assert!(current().is_none());
        assert!(all().is_empty());
    }
}
