// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Per-storage price model: what a GB costs per month on a storage, what
//! reading it back costs (egress and, for cold classes, retrieval), and the
//! minimum storage duration a cold class bills for. The user sets the figures
//! per storage (`varsto storage price`); a storage whose provider, region and
//! class are in the open price data (`data/providers`) gets those figures as
//! defaults. Prices are kept in `config.json` on this device; they are
//! estimates, not quotes.

use crate::storage::StorageSpec;
use serde::{Deserialize, Serialize};

const GB: f64 = 1_073_741_824.0;

/// Prices of one storage. Every figure is optional: `None` means unknown,
/// not free.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct StoragePrice {
    /// Storage per GB-month.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_per_gb_month: Option<f64>,
    /// Data transfer out per GB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_per_gb: Option<f64>,
    /// Retrieval (restore) per GB, for cold classes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_per_gb: Option<f64>,
    /// Minimum storage duration billed by the class (early deletion is
    /// charged for the remaining days).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_storage_days: Option<u32>,
    #[serde(default)]
    pub currency: String,
    /// Where the figures come from: "set by you" or the built-in profile with
    /// its verification date.
    #[serde(default)]
    pub source: String,
}

impl StoragePrice {
    pub fn is_empty(&self) -> bool {
        self.storage_per_gb_month.is_none()
            && self.egress_per_gb.is_none()
            && self.retrieval_per_gb.is_none()
            && self.minimum_storage_days.is_none()
    }

    /// Monthly cost of keeping `bytes` here.
    pub fn monthly_cost(&self, bytes: u64) -> Option<f64> {
        self.storage_per_gb_month.map(|p| bytes as f64 / GB * p)
    }

    /// Cost of reading `bytes` back once (egress plus retrieval); `None`
    /// when neither figure is known.
    pub fn read_cost(&self, bytes: u64) -> Option<f64> {
        if self.egress_per_gb.is_none() && self.retrieval_per_gb.is_none() {
            return None;
        }
        let per_gb = self.egress_per_gb.unwrap_or(0.0) + self.retrieval_per_gb.unwrap_or(0.0);
        Some(bytes as f64 / GB * per_gb)
    }

    /// What deleting `bytes` after `days_stored` days still costs because of
    /// the minimum storage duration (billed pro rata, 30-day months).
    pub fn early_deletion_cost(&self, bytes: u64, days_stored: u32) -> Option<f64> {
        let min = self.minimum_storage_days?;
        let price = self.storage_per_gb_month?;
        let remaining = min.saturating_sub(days_stored);
        Some(bytes as f64 / GB * price * remaining as f64 / 30.0)
    }

    /// One line for listings: "0.0245 USD/GB-month, egress 0.09, retrieval 0.03, min 90 days".
    pub fn describe(&self) -> String {
        if self.is_empty() {
            return "no price set".to_string();
        }
        let cur = if self.currency.is_empty() {
            String::new()
        } else {
            format!(" {}", self.currency)
        };
        let mut parts = Vec::new();
        match self.storage_per_gb_month {
            Some(p) => parts.push(format!("{p}{cur}/GB-month")),
            None => parts.push("storage price unknown".to_string()),
        }
        if let Some(e) = self.egress_per_gb {
            parts.push(format!("egress {e}{cur}/GB"));
        }
        if let Some(r) = self.retrieval_per_gb {
            parts.push(format!("retrieval {r}{cur}/GB"));
        }
        if let Some(d) = self.minimum_storage_days {
            parts.push(format!("minimum {d} days"));
        }
        parts.join(", ")
    }

    /// The user's figures over the built-in ones: every figure the user set
    /// wins, the others come from `builtin`.
    pub fn merged(user: Option<&StoragePrice>, builtin: Option<StoragePrice>) -> Option<Self> {
        match (user, builtin) {
            (None, b) => b,
            (Some(u), None) => Some(StoragePrice {
                source: "set by you".to_string(),
                ..u.clone()
            }),
            (Some(u), Some(b)) => {
                let from_builtin = (u.storage_per_gb_month.is_none()
                    && b.storage_per_gb_month.is_some())
                    || (u.egress_per_gb.is_none() && b.egress_per_gb.is_some())
                    || (u.retrieval_per_gb.is_none() && b.retrieval_per_gb.is_some())
                    || (u.minimum_storage_days.is_none() && b.minimum_storage_days.is_some());
                Some(StoragePrice {
                    storage_per_gb_month: u.storage_per_gb_month.or(b.storage_per_gb_month),
                    egress_per_gb: u.egress_per_gb.or(b.egress_per_gb),
                    retrieval_per_gb: u.retrieval_per_gb.or(b.retrieval_per_gb),
                    minimum_storage_days: u.minimum_storage_days.or(b.minimum_storage_days),
                    currency: if u.currency.is_empty() {
                        b.currency.clone()
                    } else {
                        u.currency.clone()
                    },
                    source: if from_builtin {
                        format!("set by you; other figures from {}", b.source)
                    } else {
                        "set by you".to_string()
                    },
                })
            }
        }
    }
}

/// Which provider profile and storage class an S3 endpoint and class name
/// map to: (profile id, class id).
fn recognise(endpoint: &str, storage_class: Option<&str>) -> Option<(&'static str, &'static str)> {
    let host = endpoint.to_ascii_lowercase();
    let class = storage_class.unwrap_or("STANDARD").to_ascii_uppercase();
    if host.contains("amazonaws.com") {
        let id = match class.as_str() {
            "STANDARD" => "standard",
            "STANDARD_IA" => "standard-ia",
            "GLACIER_IR" => "glacier-instant-retrieval",
            "GLACIER" => "glacier-flexible-retrieval",
            "DEEP_ARCHIVE" => "glacier-deep-archive",
            _ => return None,
        };
        return Some(("aws-s3", id));
    }
    if host.contains("scw.cloud") {
        let id = match class.as_str() {
            "STANDARD" => "standard-multi-az",
            "ONEZONE_IA" => "standard-one-zone",
            "GLACIER" => "glacier",
            _ => return None,
        };
        return Some(("scaleway-object-storage", id));
    }
    None
}

fn region_applies(v: &serde_json::Value, region: &str) -> bool {
    v["applies_to_regions"]
        .as_array()
        .is_some_and(|a| a.iter().any(|r| r.as_str() == Some(region)))
}

/// Built-in prices for a storage whose provider, region and class are in the
/// open price data. Only regions the data was verified for are priced.
pub fn builtin_for(spec: &StorageSpec) -> Option<StoragePrice> {
    let StorageSpec::S3 {
        endpoint,
        region,
        storage_class,
        ..
    } = spec
    else {
        return None;
    };
    let (profile, class_id) = recognise(endpoint, storage_class.as_deref())?;
    let doc = crate::advice::provider_profiles()
        .into_iter()
        .find(|d| d["id"].as_str() == Some(profile))?;
    let class = doc["storage_classes"]
        .as_array()?
        .iter()
        .find(|c| c["id"].as_str() == Some(class_id))?;
    if !region_applies(class, region) {
        return None;
    }
    let first = class["storage_price_per_gb_month"].as_array()?.first()?;
    let egress = if region_applies(&doc["egress"], region) {
        doc["egress"]["price_per_gb"]
            .as_array()
            .and_then(|t| t.first())
            .and_then(|t| t["price"]["value"].as_f64())
    } else {
        None
    };
    Some(StoragePrice {
        storage_per_gb_month: first["price"]["value"].as_f64(),
        egress_per_gb: egress,
        retrieval_per_gb: class["retrieval"]["price_per_gb"]["value"].as_f64(),
        minimum_storage_days: class["minimum_storage_duration_days"]["value"]
            .as_u64()
            .map(|d| d as u32),
        currency: doc["currency"].as_str().unwrap_or("").to_string(),
        source: format!(
            "built-in price data: {} {}, {} (verified {})",
            doc["name"].as_str().unwrap_or("?"),
            class["name"].as_str().unwrap_or("?"),
            region,
            first["price"]["last_verified"].as_str().unwrap_or("?")
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s3(endpoint: &str, region: &str, class: Option<&str>) -> StorageSpec {
        StorageSpec::S3 {
            name: "b".into(),
            endpoint: endpoint.into(),
            region: region.into(),
            bucket: "x".into(),
            prefix: String::new(),
            access_key_id: "k".into(),
            secret_ref: String::new(),
            path_style: true,
            storage_class: class.map(str::to_string),
            cold: false,
            place: String::new(),
        }
    }

    #[test]
    fn cost_math() {
        let p = StoragePrice {
            storage_per_gb_month: Some(0.004),
            egress_per_gb: Some(0.09),
            retrieval_per_gb: Some(0.01),
            minimum_storage_days: Some(90),
            currency: "USD".into(),
            source: String::new(),
        };
        let ten_gb = 10 * 1_073_741_824;
        assert!((p.monthly_cost(ten_gb).unwrap() - 0.04).abs() < 1e-12);
        assert!((p.read_cost(ten_gb).unwrap() - 1.0).abs() < 1e-12);
        // 30 days stored of 90: 60 days (two months) still billed.
        assert!((p.early_deletion_cost(ten_gb, 30).unwrap() - 0.08).abs() < 1e-12);
        assert_eq!(p.early_deletion_cost(ten_gb, 120), Some(0.0));
        let unknown = StoragePrice::default();
        assert_eq!(unknown.monthly_cost(ten_gb), None);
        assert_eq!(unknown.read_cost(ten_gb), None);
        assert_eq!(unknown.early_deletion_cost(ten_gb, 0), None);
        let egress_only = StoragePrice {
            egress_per_gb: Some(0.01),
            ..Default::default()
        };
        assert!((egress_only.read_cost(ten_gb).unwrap() - 0.1).abs() < 1e-12);
    }

    #[test]
    fn builtin_prices_follow_provider_class_and_region() {
        let aws = builtin_for(&s3(
            "https://s3.eu-central-1.amazonaws.com",
            "eu-central-1",
            None,
        ))
        .unwrap();
        assert_eq!(aws.storage_per_gb_month, Some(0.0245));
        assert_eq!(aws.egress_per_gb, Some(0.09));
        assert_eq!(aws.currency, "USD");
        assert!(aws.source.contains("verified 2026-"), "{}", aws.source);
        let deep = builtin_for(&s3(
            "https://s3.eu-central-1.amazonaws.com",
            "eu-central-1",
            Some("DEEP_ARCHIVE"),
        ))
        .unwrap();
        assert_eq!(deep.minimum_storage_days, Some(180));
        assert!(deep.retrieval_per_gb.is_some());
        let scw = builtin_for(&s3(
            "https://s3.fr-par.scw.cloud",
            "fr-par",
            Some("GLACIER"),
        ))
        .unwrap();
        assert_eq!(scw.currency, "EUR");
        assert!(scw.retrieval_per_gb.is_some());
        // A region the data was not verified for, and an unknown endpoint: no defaults.
        assert!(
            builtin_for(&s3("https://s3.us-west-2.amazonaws.com", "us-west-2", None)).is_none()
        );
        assert!(builtin_for(&s3("https://minio.example", "us-east-1", None)).is_none());
    }

    #[test]
    fn user_figures_win_over_builtin_ones() {
        let builtin = StoragePrice {
            storage_per_gb_month: Some(0.02),
            egress_per_gb: Some(0.09),
            currency: "USD".into(),
            source: "built-in".into(),
            ..Default::default()
        };
        let user = StoragePrice {
            storage_per_gb_month: Some(0.006),
            ..Default::default()
        };
        let m = StoragePrice::merged(Some(&user), Some(builtin.clone())).unwrap();
        assert_eq!(m.storage_per_gb_month, Some(0.006));
        assert_eq!(m.egress_per_gb, Some(0.09));
        assert_eq!(m.currency, "USD");
        assert!(m
            .source
            .starts_with("set by you; other figures from built-in"));
        assert_eq!(
            StoragePrice::merged(None, Some(builtin.clone())),
            Some(builtin)
        );
        assert_eq!(StoragePrice::merged(None, None), None);
        assert!(m.describe().contains("0.006 USD/GB-month"));
    }
}
