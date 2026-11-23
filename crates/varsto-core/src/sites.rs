// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Sites group whole devices into one geographic failure domain. Two laptops
//! in the same house are not two copies: a fire there takes both. A device
//! that has published no site is its own domain.

/// Longest site name, in bytes. The same bound as a device detail field.
pub const MAX_SITE: usize = 64;

/// A site name as stored: trimmed, or empty when the device has none.
/// Empty, a slash and control characters are refused; empty input clears.
pub fn normalize_site(raw: &str) -> Result<String, String> {
    let site = raw.trim();
    if site.is_empty() {
        return Ok(String::new());
    }
    if site.len() > MAX_SITE {
        return Err(format!("a site name is at most {MAX_SITE} bytes"));
    }
    if site.chars().any(|c| c.is_control() || c == '/') {
        return Err("a site name cannot contain a slash or a control character".into());
    }
    Ok(site.to_string())
}

/// The failure domain of one device. Devices with the same non-empty site
/// share a key; a device with no site does not share a domain with anyone.
pub fn domain_key(device_id: &str, site: &str) -> String {
    let site = site.trim();
    if site.is_empty() {
        format!("device:{device_id}")
    } else {
        format!("site:{site}")
    }
}

/// The site a domain key names, or empty when the key is one unnamed device.
pub fn site_of_key(key: &str) -> &str {
    key.strip_prefix("site:").unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_devices_at_one_site_are_one_domain() {
        assert_eq!(domain_key("laptop", "home"), domain_key("phone", "home"));
        assert_ne!(domain_key("laptop", "home"), domain_key("nas", "office"));
        assert_ne!(domain_key("a", ""), domain_key("b", ""));
        assert_ne!(domain_key("a", ""), domain_key("a", "home"));
        assert_eq!(site_of_key(&domain_key("laptop", "home")), "home");
        assert_eq!(site_of_key(&domain_key("a", "")), "");
    }

    #[test]
    fn a_site_name_is_trimmed_and_bounded() {
        assert_eq!(normalize_site("  home ").unwrap(), "home");
        assert_eq!(normalize_site("   ").unwrap(), "");
        assert!(normalize_site("a/b").is_err());
        assert!(normalize_site(&"x".repeat(MAX_SITE + 1)).is_err());
        assert!(normalize_site(&"x".repeat(MAX_SITE)).is_ok());
    }
}
