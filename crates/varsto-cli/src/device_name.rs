// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! This computer's name, for devices joined without `--name` and for the
//! push notifications before the vault is open. Shared with the mobile
//! shells (`varsto-ffi` includes this file by path).

/// This computer's name, for devices joined without `--name`.
pub(crate) fn default_device_name() -> String {
    let name = if cfg!(target_os = "macos") {
        std::process::Command::new("scutil")
            .args(["--get", "ComputerName"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else if cfg!(windows) {
        std::env::var("COMPUTERNAME").ok()
    } else {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .or_else(|_| std::fs::read_to_string("/etc/hostname"))
            .ok()
            .map(|h| h.trim().to_string())
    };
    name.filter(|n| !n.is_empty() && !n.contains('.'))
        .or_else(name_before_dot)
        .unwrap_or_else(|| "this-device".into())
}

fn name_before_dot() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .and_then(|h| h.trim().split('.').next().map(|s| s.to_string()))
        .filter(|s| !s.is_empty())
}
