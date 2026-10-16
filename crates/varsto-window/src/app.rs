// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The Windows window: single instance, WebView2 view, saved geometry.

use crate::{geometry, service, shell};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tao::dpi::{LogicalSize, PhysicalPosition, PhysicalSize};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tao::platform::windows::{IconExtWindows, WindowBuilderExtWindows, WindowExtWindows};
use tao::window::{Fullscreen, Icon, WindowBuilder};
use windows_sys::Win32::Foundation::{GetLastError, BOOL, ERROR_ALREADY_EXISTS, HWND, LPARAM};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetPropW, IsIconic, MessageBoxW, SetForegroundWindow, SetPropW, ShowWindow, IDYES,
    MB_ICONINFORMATION, MB_OK, MB_YESNO, SW_RESTORE, SW_SHOWNORMAL,
};
use wry::{NewWindowResponse, PermissionKind, PermissionResponse, WebContext, WebViewBuilder};

/// The page that installs the WebView2 runtime (Microsoft's Evergreen bootstrapper).
const WEBVIEW2_DOWNLOAD: &str = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";
/// Marks the main window for a second launch to find.
const WINDOW_PROP: &str = "VarstoMainWindow";
const MUTEX_NAME: &str = "Local\\VarstoWindow";

const LOADING_HTML: &str = r#"<!doctype html><meta charset="utf-8"><title>Varsto</title>
<style>:root{color-scheme:light dark}body{font:15px system-ui,"Segoe UI",sans-serif;margin:0;height:100vh;display:grid;place-items:center;background:Canvas;color:CanvasText}
div{text-align:center;opacity:.75}</style>
<div><h2>Starting Varsto&hellip;</h2><p>The window fills in a moment.</p></div>"#;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Let `varsto-window --version` print into the terminal that started it.
pub fn attach_console() {
    use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    // SAFETY: AttachConsole has no preconditions; failure just means no parent console.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

/// Open an address in the default browser (or a file with its program).
fn shell_open(target: &str) {
    // SAFETY: both strings are NUL-terminated and outlive the call.
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wide("open").as_ptr(),
            wide(target).as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

fn message(text: &str, ask: bool) -> bool {
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let r = unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            wide(text).as_ptr(),
            wide("Varsto").as_ptr(),
            MB_ICONINFORMATION | if ask { MB_YESNO } else { MB_OK },
        )
    };
    r == IDYES
}

/// Held for the life of the process: the one-window-per-user mutex.
struct Instance;

/// `None` when another Varsto window already runs.
fn single_instance() -> Option<Instance> {
    // SAFETY: a named mutex with default security; the handle is kept open
    // for the life of the process on purpose (the mutex is the lock).
    unsafe {
        let h = CreateMutexW(std::ptr::null(), 0, wide(MUTEX_NAME).as_ptr());
        if h.is_null() {
            return Some(Instance); // cannot tell: show a window rather than none
        }
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return None;
        }
    }
    Some(Instance)
}

unsafe extern "system" fn find_main(hwnd: HWND, found: LPARAM) -> BOOL {
    if !GetPropW(hwnd, wide(WINDOW_PROP).as_ptr()).is_null() {
        *(found as *mut HWND) = hwnd;
        return 0; // stop
    }
    1
}

/// Bring the window of the running instance to the front. The first
/// instance may still be starting, so look for a few seconds.
fn focus_existing() {
    for _ in 0..20 {
        let mut found: HWND = std::ptr::null_mut();
        // SAFETY: the callback only writes through the pointer we pass, which lives through the call.
        unsafe {
            EnumWindows(Some(find_main), &mut found as *mut HWND as LPARAM);
            if !found.is_null() {
                if IsIconic(found) != 0 {
                    ShowWindow(found, SW_RESTORE);
                }
                SetForegroundWindow(found);
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Start the tray app (which runs the service) when no service answers.
fn start_service(home: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let varsto = exe.with_file_name("varsto.exe");
    if !varsto.exists() {
        return Err(format!("{} is missing", varsto.display()));
    }
    std::process::Command::new(varsto)
        .arg("--home")
        .arg(home)
        .arg("tray")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Wait until a service answers, starting the tray app first when needed.
fn wait_for_service(home: &Path) -> Result<service::ServiceFile, String> {
    if let Some(f) = service::alive(home) {
        return Ok(f);
    }
    start_service(home)?;
    let until = Instant::now() + Duration::from_secs(40);
    while Instant::now() < until {
        if let Some(f) = service::alive(home) {
            return Ok(f);
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    Err("the background service did not start. Look at service.log in the Varsto data folder, or run varsto.exe service run in a terminal.".into())
}

/// Without a WebView2 view: the interface in the default browser.
fn browser_fallback(home: &Path, why: &str) {
    let opened = wait_for_service(home)
        .and_then(|f| service::boot_url(&f))
        .map(|url| shell_open(&url));
    let mut text = format!("{why}\n\n");
    match opened {
        Ok(()) => text.push_str("Varsto opened in your default browser instead.\n\n"),
        Err(e) => text.push_str(&format!("Varsto could not open its interface: {e}\n\n")),
    }
    text.push_str("Install the Microsoft Edge WebView2 Runtime (free, from Microsoft) to get Varsto's own window. Open the download page now?");
    if message(&text, true) {
        shell_open(WEBVIEW2_DOWNLOAD);
    }
}

fn state_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(|p| PathBuf::from(p).join("Varsto"))
        .unwrap_or_else(|| std::env::temp_dir().join("Varsto"))
}

fn is_local(url: &str) -> bool {
    [
        "http://127.0.0.1:",
        "http://localhost:",
        "about:",
        "data:",
        "blob:",
    ]
    .iter()
    .any(|p| url.starts_with(p))
}

enum Ev {
    Navigate(String),
    Failed(String),
    /// The page asked for the whole window in full screen (or back).
    Fullscreen(bool),
}

fn failed_html(why: &str) -> String {
    let esc = why.replace('&', "&amp;").replace('<', "&lt;");
    format!(
        r#"<!doctype html><meta charset="utf-8"><style>:root{{color-scheme:light dark}}body{{font:15px system-ui,"Segoe UI",sans-serif;margin:3em;background:Canvas;color:CanvasText}}</style><h2>Varsto cannot start</h2><p>{esc}</p>"#
    )
}

pub fn run(args: &[String]) {
    let mut home_arg = None;
    let mut force_browser = false;
    let mut background = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--home" => home_arg = it.next().map(PathBuf::from),
            "--browser" => force_browser = true,
            "--background" => background = true,
            _ => {}
        }
    }
    let Some(home) = service::home(home_arg) else {
        message(
            "Varsto cannot find its data folder (APPDATA is not set).",
            false,
        );
        return;
    };
    if background {
        // The login starter: the tray app and the service, no window and no
        // console. (Started again while they run, it does nothing.)
        if service::alive(&home).is_none() {
            let _ = start_service(&home);
        }
        return;
    }
    let Some(_instance) = single_instance() else {
        focus_existing();
        return;
    };
    if force_browser {
        browser_fallback(&home, "Started with --browser.");
        return;
    }
    if let Err(e) = wry::webview_version() {
        browser_fallback(
            &home,
            &format!("The Microsoft Edge WebView2 Runtime is not installed ({e})."),
        );
        return;
    }
    if let Err(e) = window(&home) {
        browser_fallback(&home, &format!("Varsto's window could not start ({e})."));
    }
}

fn window(home: &Path) -> Result<(), String> {
    let state_file = state_dir().join("window.json");
    let event_loop = EventLoopBuilder::<Ev>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let ipc_proxy = event_loop.create_proxy();

    let monitors: Vec<geometry::Monitor> = event_loop
        .available_monitors()
        .map(|m| {
            (
                m.position().x,
                m.position().y,
                m.size().width,
                m.size().height,
            )
        })
        .collect();
    let saved = geometry::load(&state_file).and_then(|g| geometry::fit(g, &monitors));

    // The icon is resource 1 of this exe (build.rs); without it the system default shows.
    let small = Icon::from_resource(1, Some(PhysicalSize::new(32, 32))).ok();
    let large = Icon::from_resource(1, Some(PhysicalSize::new(256, 256))).ok();
    let mut wb = WindowBuilder::new()
        .with_title("Varsto")
        .with_min_inner_size(LogicalSize::new(geometry::MIN_WIDTH, geometry::MIN_HEIGHT))
        .with_window_icon(small)
        .with_taskbar_icon(large);
    wb = match saved {
        Some(g) => wb
            .with_inner_size(PhysicalSize::new(g.width, g.height))
            .with_position(PhysicalPosition::new(g.x, g.y))
            .with_maximized(g.maximized),
        None => wb.with_inner_size(LogicalSize::new(
            geometry::DEFAULT_WIDTH,
            geometry::DEFAULT_HEIGHT,
        )),
    };
    let window = wb.build(&event_loop).map_err(|e| e.to_string())?;
    // SAFETY: the handle is this window's own, valid until it is destroyed.
    unsafe {
        SetPropW(
            window.hwnd() as HWND,
            wide(WINDOW_PROP).as_ptr(),
            std::ptr::dangling_mut::<std::ffi::c_void>(),
        );
    }

    // A private data folder for WebView2, and in-private mode: the session
    // token and the page's own storage never reach the disk.
    let mut ctx = WebContext::new(Some(state_dir().join("WebView2")));
    let webview = WebViewBuilder::new_with_web_context(&mut ctx)
        .with_incognito(true)
        .with_html(LOADING_HTML)
        // Only the local interface loads here; every other address goes to the browser.
        .with_navigation_handler(|url| {
            if is_local(&url) {
                true
            } else {
                shell_open(&url);
                false
            }
        })
        .with_new_window_req_handler(|url, _| {
            if !is_local(&url) {
                shell_open(&url);
            }
            NewWindowResponse::Deny
        })
        // The QR scanner of the interface uses the camera; nothing else is allowed.
        .with_permission_handler(|kind| match kind {
            PermissionKind::Camera => PermissionResponse::Allow,
            PermissionKind::ClipboardRead => PermissionResponse::Default,
            _ => PermissionResponse::Deny,
        })
        .with_clipboard(true)
        // The visualization page asks for real full screen: the window itself, not only the page in it.
        .with_ipc_handler(move |req| {
            if let Some(on) = shell::fullscreen_request(req.body()) {
                let _ = ipc_proxy.send_event(Ev::Fullscreen(on));
            }
        })
        .build(&window)
        .map_err(|e| e.to_string())?;

    // Waits for the service (starting it when needed), opens the interface,
    // and opens it again with a fresh boot code when the service restarts
    // (after an update): the old session token is gone then.
    let home = home.to_path_buf();
    std::thread::spawn(move || {
        let mut shown: Option<service::ServiceFile> = None;
        match wait_for_service(&home) {
            Ok(_) => {}
            Err(e) => {
                let _ = proxy.send_event(Ev::Failed(e));
                return;
            }
        }
        loop {
            if let Some(f) = service::alive(&home) {
                if shown.as_ref() != Some(&f) {
                    if let Ok(url) = service::boot_url(&f) {
                        if proxy.send_event(Ev::Navigate(url)).is_err() {
                            return;
                        }
                        shown = Some(f);
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    });

    // The last placement while the window is neither maximised nor minimised.
    let mut normal = saved.unwrap_or(geometry::Geometry {
        x: 0,
        y: 0,
        width: geometry::DEFAULT_WIDTH,
        height: geometry::DEFAULT_HEIGHT,
        maximized: false,
    });
    let mut have_position = saved.is_some();
    let mut last_save = Instant::now();
    event_loop.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        let _keep = (&webview, &ctx);
        match event {
            Event::UserEvent(Ev::Navigate(url)) => {
                let _ = webview.load_url(&url);
                let _ = webview.focus();
            }
            Event::UserEvent(Ev::Failed(why)) => {
                let _ = webview.load_html(&failed_html(&why));
            }
            Event::UserEvent(Ev::Fullscreen(on)) => {
                window.set_fullscreen(on.then_some(Fullscreen::Borderless(None)));
                let _ = webview.evaluate_script(&shell::fullscreen_notice(on));
                let _ = webview.focus();
            }
            Event::WindowEvent { event, .. } => match event {
                WindowEvent::Moved(_) | WindowEvent::Resized(_) => {
                    // A full-screen size is not the window's own: keep the last normal placement.
                    if window.fullscreen().is_none()
                        && !window.is_maximized()
                        && !window.is_minimized()
                    {
                        if let Ok(p) = window.outer_position() {
                            let s = window.inner_size();
                            normal = geometry::Geometry {
                                x: p.x,
                                y: p.y,
                                width: s.width,
                                height: s.height,
                                maximized: false,
                            };
                            have_position = true;
                        }
                    }
                    if last_save.elapsed() > Duration::from_millis(700) && have_position {
                        last_save = Instant::now();
                        geometry::save(
                            &state_file,
                            &geometry::Geometry {
                                maximized: window.is_maximized(),
                                ..normal
                            },
                        );
                    }
                }
                WindowEvent::CloseRequested => {
                    if have_position {
                        geometry::save(
                            &state_file,
                            &geometry::Geometry {
                                maximized: window.is_maximized(),
                                ..normal
                            },
                        );
                    }
                    // Only the window goes; the service and the tray keep running.
                    *flow = ControlFlow::Exit;
                }
                _ => {}
            },
            _ => {}
        }
    });
}
