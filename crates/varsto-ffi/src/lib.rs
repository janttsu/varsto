// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! C ABI for the mobile apps: start the local service in-process and get the
//! URL of the embedded interface. Everything else goes through that HTTP API.
//!
//! ```c
//! int   varsto_start(const char *home_dir, unsigned short port);  // 0 on success
//! char *varsto_url(void);           // "http://127.0.0.1:PORT/?token=..." or NULL; free with varsto_free
//! void  varsto_free(char *s);
//! void  varsto_log(int level, const char *msg);  // 1 error … 5 trace, into the core's log
//! ```
//! The service code is shared with the CLI through the `service` module path
//! included below, so the mobile apps run exactly the same server.

#![allow(dead_code)]

use std::ffi::{c_char, CStr, CString};
use std::path::PathBuf;
use std::sync::Mutex;

#[path = "../../varsto-cli/src/desktop.rs"]
mod desktop;
#[path = "../../varsto-cli/src/drive_mount.rs"]
mod drive_mount;
#[path = "../../varsto-cli/src/filemanager.rs"]
mod filemanager;
#[path = "../../varsto-cli/src/mcp_keys.rs"]
mod mcp_keys;
#[path = "../../varsto-cli/src/service.rs"]
mod service;
#[path = "../../varsto-cli/src/update.rs"]
mod update;
#[path = "../../varsto-cli/src/view.rs"]
mod view;

static HOME: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Start the service on a background thread. Returns 0 on success.
///
/// # Safety
/// `home_dir` must be null or point to a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn varsto_start(home_dir: *const c_char, port: u16) -> i32 {
    if home_dir.is_null() {
        return 1;
    }
    let home = unsafe { CStr::from_ptr(home_dir) }
        .to_string_lossy()
        .to_string();
    let home = PathBuf::from(home);
    // Mobile shell: folders live next to the vault directory, chosen by the interface.
    std::env::set_var("VARSTO_MOBILE", "1");
    if std::env::var_os("VARSTO_FOLDER_ROOT").is_none() {
        let root = home
            .parent()
            .map(|p| p.join("Folders"))
            .unwrap_or_else(|| home.join("Folders"));
        let _ = std::fs::create_dir_all(&root);
        std::env::set_var("VARSTO_FOLDER_ROOT", root);
    }
    // The core's debug log: <home>/logs/varsto-ffi-<os>.log, phone-sized.
    let component = if cfg!(target_os = "ios") {
        "ffi-ios"
    } else if cfg!(target_os = "android") {
        "ffi-android"
    } else {
        "ffi"
    };
    let mut o = varsto_core::logging::Options::new(&home, component);
    o.rotation = varsto_core::logging::Rotation::MOBILE;
    let _ = varsto_core::logging::init(o);
    log::info!(version = env!("CARGO_PKG_VERSION"), port = port; "varsto_start");
    *HOME.lock().unwrap() = Some(home.clone());
    std::thread::Builder::new()
        .name("varsto-service".into())
        .spawn(move || {
            if let Err(e) = service::run(service::Options {
                home,
                port,
                interval_secs: 300,
                open_browser: false,
            }) {
                log::error!("service stopped: {e:#}");
            }
            varsto_core::logging::flush();
        })
        .map(|_| 0)
        .unwrap_or(2)
}

/// URL of the local interface, once the service has written its service file.
#[no_mangle]
pub extern "C" fn varsto_url() -> *mut c_char {
    let Some(home) = HOME.lock().unwrap().clone() else {
        return std::ptr::null_mut();
    };
    match service::read_service_file(&home) {
        Some(f) => CString::new(format!("http://127.0.0.1:{}/?token={}", f.port, f.token))
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// Free a string returned by this library.
///
/// # Safety
/// `s` must come from `varsto_url` and be freed once.
#[no_mangle]
pub unsafe extern "C" fn varsto_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Write one line from the app into the core's log (module `app`).
/// `level`: 1 error, 2 warn, 3 info, 4 debug, 5 trace. Ignored before
/// `varsto_start`.
///
/// # Safety
/// `msg` must be null or point to a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn varsto_log(level: std::ffi::c_int, msg: *const c_char) {
    if msg.is_null() {
        return;
    }
    let text = unsafe { CStr::from_ptr(msg) }.to_string_lossy();
    let level = match level {
        1 => log::Level::Error,
        2 => log::Level::Warn,
        3 => log::Level::Info,
        5 => log::Level::Trace,
        _ => log::Level::Debug,
    };
    log::log!(target: "app", level, "{text}");
}
