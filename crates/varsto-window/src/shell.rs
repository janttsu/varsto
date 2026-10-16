// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! What the page may ask the window for. The visualization page posts
//! `varsto:fullscreen:1` / `varsto:fullscreen:0` through `window.ipc` to put
//! the whole window (not just the page inside it) into full screen and back.

/// `Some(true)` to enter and `Some(false)` to leave full screen; anything
/// else is not a request this window knows.
pub fn fullscreen_request(message: &str) -> Option<bool> {
    match message.trim() {
        "varsto:fullscreen:1" => Some(true),
        "varsto:fullscreen:0" => Some(false),
        _ => None,
    }
}

/// The script that tells the page the window's full-screen state, so that
/// its button and Esc handling follow it.
pub fn fullscreen_notice(on: bool) -> String {
    format!("window.varstoShellFullscreen&&window.varstoShellFullscreen({on})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fullscreen_messages() {
        assert_eq!(fullscreen_request("varsto:fullscreen:1"), Some(true));
        assert_eq!(fullscreen_request(" varsto:fullscreen:0\n"), Some(false));
        assert_eq!(fullscreen_request("varsto:fullscreen:2"), None);
        assert_eq!(fullscreen_request("fullscreen"), None);
        assert_eq!(fullscreen_request(""), None);
        assert_eq!(
            fullscreen_notice(true),
            "window.varstoShellFullscreen&&window.varstoShellFullscreen(true)"
        );
    }
}
