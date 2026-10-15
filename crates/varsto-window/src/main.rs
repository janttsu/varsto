// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto-window`: Varsto's own window on Windows. It shows the local web
//! interface that the background service serves on 127.0.0.1 in a WebView2
//! view (the same page the browser gets, the way the macOS app shows it in a
//! WebKit view), so Varsto has an icon, a taskbar button and a window of its
//! own instead of a browser tab. Closing the window leaves the service and
//! the tray running; the tray's "Open Varsto" starts this program again.
//!
//! `varsto-window [--home DIR] [--browser] [--background] [--version]`
//!
//! * one window per user: a second launch brings the first to the front;
//! * `--background` (the login starter) starts the tray app and the service
//!   without a window or a console;
//! * size, position and maximised state come back at the next start;
//! * without the WebView2 runtime the interface opens in the default browser
//!   and a message says how to install the runtime.

#![cfg_attr(windows, windows_subsystem = "windows")]
// On other systems only the tests of the portable modules run.
#![cfg_attr(not(windows), allow(dead_code))]

mod geometry;
mod service;

#[cfg(windows)]
mod app;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        // A GUI-subsystem program has no console of its own: attach to the
        // parent's so that `varsto-window --version` prints in a terminal.
        #[cfg(windows)]
        app::attach_console();
        println!("varsto-window {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    #[cfg(windows)]
    app::run(&args);
    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("varsto-window is the native window of the Windows app; on this system run `varsto tray --open` or `varsto desktop`");
        std::process::exit(2);
    }
}
