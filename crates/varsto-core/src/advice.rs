// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! "Where is this cheapest to keep?" Cost estimates for files that have not
//! been used for a while, from the open, dated price data in `data/providers`.
//! The data set is embedded at build time so the estimate works offline; each
//! figure carries its source URL and verification date, and nothing here is
//! a quote.

use crate::price::StoragePrice;
use serde::Serialize;
use std::collections::BTreeMap;

const PROVIDERS: &[&str] = &[
    include_str!("../../../data/providers/aws-s3.json"),
    include_str!("../../../data/providers/scaleway-object-storage.json"),
    include_str!("../../../data/providers/hetzner-storage-box.json"),
];

/// The embedded provider profiles, parsed (profiles that fail to parse are left out).
pub fn provider_profiles() -> Vec<serde_json::Value> {
    PROVIDERS
        .iter()
        .filter_map(|raw| serde_json::from_str(raw).ok())
        .collect()
}

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
    /// The storages configured on this device with their prices and what the
    /// idle files cost there (filled by `Engine::placement_advice`).
    #[serde(default)]
    pub storages: Vec<StorageEstimate>,
    /// Monthly cost per folder from the storages' prices.
    #[serde(default)]
    pub folders: Vec<FolderCost>,
    /// Placement changes that can be carried out (`Engine::apply_suggestion`).
    #[serde(default)]
    pub suggestions: Vec<Suggestion>,
}

/// Amounts by currency: storages may be priced in different currencies and
/// are never converted.
pub type Costs = BTreeMap<String, f64>;

/// Add `amount` in `currency` to `costs`.
pub fn add_cost(costs: &mut Costs, currency: &str, amount: f64) {
    let cur = if currency.is_empty() { "?" } else { currency };
    *costs.entry(cur.to_string()).or_default() += amount;
}

/// One configured storage, its price and what it holds.
#[derive(Clone, Debug, Serialize)]
pub struct StorageEstimate {
    pub name: String,
    pub kind: String,
    pub cold: bool,
    pub carrier: bool,
    pub price: Option<StoragePrice>,
    /// Bytes the ledger records on this storage (every folder).
    pub bytes: u64,
    /// Monthly cost of `bytes`, when the storage price is known.
    pub monthly_cost: Option<f64>,
    /// Monthly cost of the idle files' share on this storage.
    pub idle_monthly_cost: Option<f64>,
    pub currency: String,
}

/// What a folder's current files cost per month on the storages that hold them.
#[derive(Clone, Debug, Serialize)]
pub struct FolderCost {
    pub folder: String,
    pub bytes: u64,
    pub idle_bytes: u64,
    pub monthly: Costs,
    pub idle_monthly: Costs,
    /// Storages holding the folder that have no storage price yet.
    pub unpriced_storages: Vec<String>,
}

/// A placement change Varsto can carry out: keep a folder's idle files only
/// on the storages (cheapest first) and free their copies on this device
/// (`free-idle`), or move their blocks to a cheaper cold storage
/// (`cold-idle`).
#[derive(Clone, Debug, Serialize)]
pub struct Suggestion {
    /// Stable id for `varsto advice apply` and the API: `free-idle:<folder>`
    /// or `cold-idle:<folder>`.
    pub id: String,
    /// "free-idle" or "cold-idle".
    pub kind: String,
    /// For a move: the storage the blocks leave and the one they go to.
    pub move_from: Option<String>,
    pub move_to: Option<String>,
    /// For a move: what the storage bill goes down by per month.
    pub monthly_saving: Costs,
    /// For a move: reading blocks this device lacks from the old storage once.
    pub one_time_cost: Costs,
    pub folder: String,
    /// Idle files that are on this device and not pinned.
    pub files: u64,
    pub bytes: u64,
    /// A few of the paths, largest first.
    pub examples: Vec<String>,
    /// Storages that keep the data, cheapest first.
    pub keep_on: Vec<String>,
    /// The cheapest of them by the price model, if any price is known.
    pub cheapest: Option<String>,
    /// What keeping the files on those storages costs per month (unchanged by the action).
    pub monthly_cost: Costs,
    /// Reading every file back once from the cheapest readable storage.
    pub read_back_cost: Costs,
    /// Bytes not yet verified on any readable storage; they are downloaded
    /// and hash-checked before the local copy goes.
    pub verify_first_bytes: u64,
    /// Files that cannot be freed now, with the reason.
    pub blocked: Vec<(String, String)>,
    /// What the action does, for the confirmation.
    pub summary: String,
    pub warnings: Vec<String>,
}

/// Prefix of a "free idle files" suggestion id.
pub const FREE_IDLE_PREFIX: &str = "free-idle:";
/// Prefix of a "move idle files to cold storage" suggestion id.
pub const COLD_IDLE_PREFIX: &str = "cold-idle:";

/// What carrying out a suggestion did.
#[derive(Clone, Debug, Serialize, Default)]
pub struct ApplyReport {
    pub id: String,
    pub folder: String,
    pub files_freed: u64,
    pub bytes_freed: u64,
    /// Blocks downloaded and hash-checked first because no readable copy had been verified.
    pub blocks_verified: u64,
    /// Files left on this device, with the reason.
    pub skipped: Vec<(String, String)>,
    /// What a `cold-idle` move did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub moved: Option<crate::placement::MoveReport>,
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
        storages: Vec::new(),
        folders: Vec::new(),
        suggestions: Vec::new(),
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
