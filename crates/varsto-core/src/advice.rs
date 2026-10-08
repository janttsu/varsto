// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! "Where is this cheapest to keep?" Cost estimates for files that have not
//! been used for a while, from the open, dated price data in `data/providers`.
//! The data set is embedded at build time so the estimate works offline; each
//! figure carries its source URL and verification date, and nothing here is
//! a quote.

use serde::Serialize;

const PROVIDERS: &[&str] = &[
    include_str!("../../../data/providers/aws-s3.json"),
    include_str!("../../../data/providers/scaleway-object-storage.json"),
    include_str!("../../../data/providers/hetzner-storage-box.json"),
];

#[derive(Clone, Debug, Serialize)]
pub struct IdleFile {
    pub folder: String,
    pub path: String,
    pub size: u64,
    pub last_accessed_utc: Option<i64>,
    pub idle_days: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClassEstimate {
    pub provider: String,
    pub class: String,
    pub kind: String,
    pub currency: String,
    pub storage_price_per_gb_month: f64,
    pub monthly_cost: f64,
    pub retrieval_price_per_gb: Option<f64>,
    pub retrieval_cost_once: Option<f64>,
    pub minimum_storage_days: Option<u64>,
    pub typical_delay: Option<String>,
    pub source_url: String,
    pub last_verified: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Advice {
    pub idle_days_threshold: i64,
    pub idle_files: Vec<IdleFile>,
    pub idle_bytes: u64,
    pub idle_gb: f64,
    /// Cheapest first.
    pub estimates: Vec<ClassEstimate>,
    pub notes: Vec<String>,
}

fn num(v: &serde_json::Value) -> Option<f64> {
    v.as_f64()
}

/// Estimate what the idle files would cost per month in every known storage
/// class. `files` are (folder, path, size, last_accessed_utc, modified_utc).
pub fn storage_advice(
    files: &[(String, String, u64, Option<i64>, i64)],
    idle_days_threshold: i64,
    now_utc: i64,
) -> Advice {
    let mut idle = Vec::new();
    let mut bytes = 0u64;
    for (folder, path, size, accessed, modified) in files {
        let last = accessed.unwrap_or(*modified).max(*modified);
        let idle_days = (now_utc - last) / 86_400;
        if idle_days >= idle_days_threshold {
            bytes += size;
            idle.push(IdleFile {
                folder: folder.clone(),
                path: path.clone(),
                size: *size,
                last_accessed_utc: *accessed,
                idle_days,
            });
        }
    }
    idle.sort_by_key(|f| std::cmp::Reverse(f.size));
    let gb = bytes as f64 / 1_073_741_824.0;
    let mut estimates = Vec::new();
    let mut notes = vec![
        "Prices come from the open data set in the repository (data/providers), each with a source URL and the date it was verified; they are estimates, not quotes, and exclude request fees, egress and tax unless stated.".to_string(),
        "Last-accessed times are what Varsto recorded on this device (fetch, open, read) plus the filesystem access time seen at scan; other devices' use is not included yet.".to_string(),
    ];
    for raw in PROVIDERS {
        let Ok(doc) = serde_json::from_str::<serde_json::Value>(raw) else {
            continue;
        };
        let provider = doc["name"].as_str().unwrap_or("?").to_string();
        let currency = doc["currency"].as_str().unwrap_or("?").to_string();
        for class in doc["storage_classes"].as_array().into_iter().flatten() {
            let Some(tiers) = class["storage_price_per_gb_month"].as_array() else {
                notes.push(format!(
                    "{provider}: {} is not priced per GB in the data set and is left out.",
                    class["name"].as_str().unwrap_or("?")
                ));
                continue;
            };
            let Some(first) = tiers.first() else { continue };
            let Some(price) = num(&first["price"]["value"]) else {
                continue;
            };
            let retrieval = num(&class["retrieval"]["price_per_gb"]["value"]);
            estimates.push(ClassEstimate {
                provider: provider.clone(),
                class: class["name"].as_str().unwrap_or("?").to_string(),
                kind: class["kind"].as_str().unwrap_or("?").to_string(),
                currency: currency.clone(),
                storage_price_per_gb_month: price,
                monthly_cost: gb * price,
                retrieval_price_per_gb: retrieval,
                retrieval_cost_once: retrieval.map(|r| gb * r),
                minimum_storage_days: class["minimum_storage_duration_days"]["value"].as_u64(),
                typical_delay: class["retrieval"]["typical_delay"]["value"]
                    .as_str()
                    .map(|s| s.to_string()),
                source_url: first["price"]["source_url"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
                last_verified: first["price"]["last_verified"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    estimates.sort_by(|a, b| a.monthly_cost.partial_cmp(&b.monthly_cost).unwrap());
    Advice {
        idle_days_threshold,
        idle_files: idle,
        idle_bytes: bytes,
        idle_gb: gb,
        estimates,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advice_lists_idle_files_and_prices_cheapest_first() {
        let now = 1_800_000_000;
        let files = vec![
            (
                "v".to_string(),
                "old.mp4".to_string(),
                2 * 1_073_741_824,
                Some(now - 400 * 86_400),
                now - 500 * 86_400,
            ),
            (
                "v".to_string(),
                "fresh.txt".to_string(),
                10,
                Some(now - 2 * 86_400),
                now - 3 * 86_400,
            ),
            (
                "v".to_string(),
                "never-opened.iso".to_string(),
                1_073_741_824,
                None,
                now - 200 * 86_400,
            ),
        ];
        let a = storage_advice(&files, 90, now);
        assert_eq!(a.idle_files.len(), 2);
        assert_eq!(a.idle_files[0].path, "old.mp4");
        assert!((a.idle_gb - 3.0).abs() < 1e-9);
        assert!(a.estimates.len() >= 5);
        assert!(a
            .estimates
            .windows(2)
            .all(|w| w[0].monthly_cost <= w[1].monthly_cost));
        assert!(a
            .estimates
            .iter()
            .all(|e| !e.source_url.is_empty() && !e.last_verified.is_empty()));
        assert!(a.estimates[0].kind == "archive");
    }
}
