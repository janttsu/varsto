// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The open provider price data (`data/providers`), embedded at build time so
//! it works offline, and a summary of each S3-compatible provider for the Add
//! storage form: its regions with endpoints and addressing style, and the
//! headline prices of its default storage class. Every figure keeps its
//! source URL and verification date; a figure the data does not know stays
//! unknown (`null`), never zero.

use serde::Serialize;
use serde_json::{json, Value};

/// File name and contents of every embedded profile. A test checks that this
/// list matches the files in `data/providers`.
macro_rules! profile {
    ($file:literal) => {
        (
            $file,
            include_str!(concat!("../../../data/providers/", $file)),
        )
    };
}

pub const PROFILES: &[(&str, &str)] = &[
    profile!("aws-s3.json"),
    profile!("backblaze-b2.json"),
    profile!("cleura-object-storage.json"),
    profile!("cloudflare-r2.json"),
    profile!("contabo-object-storage.json"),
    profile!("digitalocean-spaces.json"),
    profile!("exoscale-sos.json"),
    profile!("filebase.json"),
    profile!("google-cloud-storage.json"),
    profile!("hetzner-object-storage.json"),
    profile!("hetzner-storage-box.json"),
    profile!("idrive-e2.json"),
    profile!("impossible-cloud.json"),
    profile!("ionos-object-storage.json"),
    profile!("linode-object-storage.json"),
    profile!("minio.json"),
    profile!("ovhcloud-object-storage.json"),
    profile!("safespring-storage.json"),
    profile!("scaleway-object-storage.json"),
    profile!("stackit-object-storage.json"),
    profile!("storj.json"),
    profile!("synology-c2-object-storage.json"),
    profile!("tigris.json"),
    profile!("upcloud-object-storage.json"),
    profile!("wasabi.json"),
];

/// Prices older than this many days are flagged as stale.
pub const STALE_AFTER_DAYS: i64 = 90;

/// The embedded profiles, parsed (a profile that fails to parse is left out;
/// the tests make sure none does).
pub fn profiles() -> Vec<Value> {
    PROFILES
        .iter()
        .filter_map(|(_, raw)| serde_json::from_str(raw).ok())
        .collect()
}

/// One S3 endpoint of a provider, ready for the form.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct EndpointSummary {
    /// Region code to send in requests.
    pub region: String,
    /// City or label to show.
    pub label: String,
    /// ISO country code, when the region is listed.
    pub country: Option<String>,
    /// Endpoint URL; may contain `{placeholders}` the user fills in.
    pub endpoint: String,
    pub has_placeholder: bool,
    /// Use path-style requests (`false`: virtual-hosted style).
    pub path_style: bool,
    /// The headline prices were verified for this region.
    pub prices_verified: bool,
    /// When this region's prices are in a class of their own
    /// (`<default class id>-<region>`): its headline figures, which replace
    /// the provider's for this endpoint.
    pub region_prices: Option<Value>,
    pub note: Option<String>,
}

/// One provider's headline facts. Each price is the profile's own fact
/// object: `{value, source_url, last_verified, note}`, with `value: null`
/// when unknown.
#[derive(Clone, Debug, Serialize)]
pub struct ProviderSummary {
    pub id: String,
    pub name: String,
    /// "service" or "self_hosted".
    pub kind: String,
    pub website_url: Option<String>,
    pub signup_url: Option<String>,
    pub pricing_url: Option<String>,
    pub currency: Option<String>,
    pub prices_include_tax: Option<bool>,
    pub tax_note: Option<String>,
    /// The storage class the headline prices are for: {id, name, kind}.
    pub class: Option<Value>,
    /// Regions the headline prices were verified for.
    pub price_regions: Vec<String>,
    pub storage_per_gb_month: Value,
    /// The storage price has more volume bands than the first one.
    pub storage_tiered: bool,
    /// For flat-rate plans: the first plan, {id, capacity_gb, monthly_price}.
    pub plan: Option<Value>,
    pub egress_free_gb_per_month: Value,
    pub egress_free_scope: Option<String>,
    /// Egress per GB after the free allowance (first band).
    pub egress_per_gb: Value,
    pub egress_tiered: bool,
    pub egress_fair_use: Value,
    pub put_per_1000: Value,
    pub get_per_1000: Value,
    pub list_per_1000: Value,
    pub retrieval_per_gb: Value,
    pub minimum_storage_days: Value,
    pub minimum_object_kb: Value,
    pub free_tier: Value,
    pub object_lock: Value,
    pub endpoints: Vec<EndpointSummary>,
    /// The oldest verification date among the headline figures.
    pub last_verified: Option<String>,
    /// Where the headline storage price comes from.
    pub source_url: Option<String>,
    /// `last_verified` is more than `STALE_AFTER_DAYS` days old.
    pub stale: bool,
    pub notes: Vec<String>,
}

fn text(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

/// A fact object as it is in the profile, or an "unknown" one.
fn fact(v: &Value, missing: &str) -> Value {
    if v.is_object() && v.get("value").is_some() {
        v.clone()
    } else {
        json!({"value": null, "note": missing})
    }
}

/// The class whose prices are the headline: `default_storage_class`, else the first.
fn default_class(doc: &Value) -> Option<&Value> {
    let classes = doc["storage_classes"].as_array()?;
    doc["default_storage_class"]
        .as_str()
        .and_then(|id| classes.iter().find(|c| c["id"].as_str() == Some(id)))
        .or_else(|| classes.first())
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(text).collect())
        .unwrap_or_default()
}

/// The storage price band to show and estimate with: the first band, or,
/// when a plan includes the first gigabytes (a first band priced 0 next to a
/// plan fee), the first band after it.
pub fn headline_band(class: &Value) -> &Value {
    static NONE: Value = Value::Null;
    let Some(tiers) = class["storage_price_per_gb_month"].as_array() else {
        return &NONE;
    };
    let has_plan = class["plans"].as_array().is_some_and(|p| !p.is_empty());
    match tiers.first() {
        Some(first)
            if has_plan && first["price"]["value"].as_f64() == Some(0.0) && tiers.len() > 1 =>
        {
            &tiers[1]
        }
        Some(first) => first,
        None => &NONE,
    }
}

/// The class holding `class_id`'s prices in `region`: the class itself when
/// it lists the region, else a regional variant with id `<class_id>-<region>`.
pub fn class_in_region<'a>(doc: &'a Value, class_id: &str, region: &str) -> Option<&'a Value> {
    let classes = doc["storage_classes"].as_array()?;
    let applies = |c: &Value| {
        strings(&c["applies_to_regions"])
            .iter()
            .any(|r| r == region)
    };
    let variant = format!("{class_id}-{region}");
    classes
        .iter()
        .find(|c| c["id"].as_str() == Some(class_id) && applies(c))
        .or_else(|| {
            classes
                .iter()
                .find(|c| c["id"].as_str() == Some(variant.as_str()) && applies(c))
        })
}

/// `YYYY-MM-DD` of the day `STALE_AFTER_DAYS` before `now` (Unix seconds).
fn stale_cutoff(now: i64) -> String {
    crate::util::format_date(now - STALE_AFTER_DAYS * 86_400)
}

/// Summarise one profile; `now` is the current Unix time (for staleness).
pub fn summarise(doc: &Value, now: i64) -> ProviderSummary {
    let self_hosted = doc["kind"].as_str() == Some("self_hosted");
    let unknown = if self_hosted {
        "Self-hosted: there is no provider price."
    } else {
        "Not in the price data."
    };
    let class = default_class(doc);
    let none = Value::Null;
    let c = class.unwrap_or(&none);
    let first_band = |tiers: &Value| -> Value { fact(&tiers[0]["price"], unknown) };
    let storage = fact(&headline_band(c)["price"], unknown);
    let egress = &doc["egress"];
    let egress_price = first_band(&egress["price_per_gb"]);
    let price_regions = strings(&c["applies_to_regions"]);
    let plan = c["plans"].as_array().and_then(|p| p.first()).cloned();

    let regions = doc["regions"].as_array().cloned().unwrap_or_default();
    let endpoints = doc["s3_endpoints"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| {
            let region = text(&e["region"])?;
            let endpoint = text(&e["endpoint"])?;
            // The region whose prices apply (the signing region may differ).
            let priced = text(&e["price_region"]).unwrap_or_else(|| region.clone());
            let listed = regions.iter().find(|r| r["code"].as_str() == Some(&priced));
            let label = text(&e["label"])
                .or_else(|| listed.and_then(|r| text(&r["city"])))
                .unwrap_or_else(|| priced.clone());
            let variant = class
                .and_then(|c| c["id"].as_str())
                .and_then(|id| class_in_region(doc, id, &priced))
                .filter(|v| !std::ptr::eq(*v, c));
            let region_prices = variant.map(|v| {
                json!({
                    "class": {"id": v["id"], "name": v["name"], "kind": v["kind"]},
                    "storage_per_gb_month": fact(&headline_band(v)["price"], unknown),
                    "storage_tiered": v["storage_price_per_gb_month"].as_array().is_some_and(|t| t.len() > 1),
                    "put_per_1000": fact(&v["requests"]["put_per_1000"], unknown),
                    "get_per_1000": fact(&v["requests"]["get_per_1000"], unknown),
                    "list_per_1000": fact(&v["requests"]["list_per_1000"], unknown),
                    "minimum_storage_days": fact(&v["minimum_storage_duration_days"], unknown),
                    "minimum_object_kb": fact(&v["minimum_billable_object_size_kb"], unknown),
                })
            });
            Some(EndpointSummary {
                has_placeholder: endpoint.contains('{') || region.contains('{'),
                prices_verified: price_regions.contains(&priced) || region_prices.is_some(),
                region_prices,
                country: listed.and_then(|r| text(&r["country"])),
                path_style: e["path_style"].as_bool().unwrap_or(true),
                note: text(&e["note"]),
                region,
                label,
                endpoint,
            })
        })
        .collect();

    let headline = [
        &storage,
        &egress_price,
        &doc["egress"]["free_allowance_gb_per_month"],
        &c["requests"]["put_per_1000"],
        &c["requests"]["get_per_1000"],
        &c["minimum_storage_duration_days"],
        &c["minimum_billable_object_size_kb"],
    ];
    let mut dates: Vec<&str> = headline
        .iter()
        .filter(|f| !f["value"].is_null())
        .filter_map(|f| f["last_verified"].as_str())
        .collect();
    if let Some(p) = &plan {
        dates.extend(p["monthly_price"]["last_verified"].as_str());
    }
    let last_verified = dates.into_iter().min().map(str::to_string);
    let stale = last_verified
        .as_deref()
        .is_some_and(|d| d < stale_cutoff(now).as_str());
    let source_url = text(&storage["source_url"])
        .or_else(|| {
            plan.as_ref()
                .and_then(|p| text(&p["monthly_price"]["source_url"]))
        })
        .or_else(|| text(&doc["pricing_url"]));

    ProviderSummary {
        id: text(&doc["id"]).unwrap_or_default(),
        name: text(&doc["name"]).unwrap_or_default(),
        kind: if self_hosted {
            "self_hosted"
        } else {
            "service"
        }
        .to_string(),
        website_url: text(&doc["website_url"]),
        signup_url: text(&doc["signup_url"]),
        pricing_url: text(&doc["pricing_url"]),
        currency: text(&doc["currency"]),
        prices_include_tax: doc["prices_include_tax"].as_bool(),
        tax_note: text(&doc["tax_note"]),
        class: class.map(|c| json!({"id": c["id"], "name": c["name"], "kind": c["kind"]})),
        price_regions,
        storage_tiered: c["storage_price_per_gb_month"]
            .as_array()
            .is_some_and(|t| t.len() > 1),
        storage_per_gb_month: storage,
        plan,
        egress_free_gb_per_month: fact(&egress["free_allowance_gb_per_month"], unknown),
        egress_free_scope: text(&egress["free_allowance_scope"]),
        egress_tiered: egress["price_per_gb"]
            .as_array()
            .is_some_and(|t| t.len() > 1),
        egress_per_gb: egress_price,
        egress_fair_use: fact(&doc["egress_fair_use"], unknown),
        put_per_1000: fact(&c["requests"]["put_per_1000"], unknown),
        get_per_1000: fact(&c["requests"]["get_per_1000"], unknown),
        list_per_1000: fact(&c["requests"]["list_per_1000"], unknown),
        retrieval_per_gb: fact(&c["retrieval"]["price_per_gb"], unknown),
        minimum_storage_days: fact(&c["minimum_storage_duration_days"], unknown),
        minimum_object_kb: fact(&c["minimum_billable_object_size_kb"], unknown),
        free_tier: fact(&doc["free_tier"], unknown),
        object_lock: fact(&doc["object_lock"], unknown),
        endpoints,
        last_verified,
        source_url,
        stale,
        notes: strings(&doc["notes"]),
    }
}

/// Every embedded provider that speaks S3, sorted by name.
pub fn s3_providers(now: i64) -> Vec<ProviderSummary> {
    let mut out: Vec<ProviderSummary> = profiles()
        .iter()
        .filter(|d| strings(&d["protocols"]).iter().any(|p| p == "s3"))
        .filter(|d| d["s3_endpoints"].is_array())
        .map(|d| summarise(d, now))
        .collect();
    out.sort_by_key(|p| p.name.to_lowercase());
    out
}

/// The host of an endpoint URL, lower case, without scheme, port or path.
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit_once('@').map_or(host, |(_, h)| h);
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    host.to_ascii_lowercase()
}

/// Whether `host` matches an endpoint template host such as
/// `{account_id}.r2.cloudflarestorage.com` (a placeholder matches one or
/// more characters of a host name).
fn host_matches(template: &str, host: &str) -> bool {
    let t = host_of(template);
    let mut parts = Vec::new();
    let mut rest = t.as_str();
    while let Some(open) = rest.find('{') {
        parts.push(&rest[..open]);
        match rest[open..].find('}') {
            Some(close) => rest = &rest[open + close + 1..],
            None => return false,
        }
    }
    parts.push(rest);
    if parts.len() == 1 {
        return parts[0] == host;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !host.starts_with(first) || !host.ends_with(last) || host.len() < first.len() + last.len() {
        return false;
    }
    let mut middle = &host[first.len()..host.len() - last.len()];
    // Every placeholder takes at least one character.
    for lit in &parts[1..parts.len() - 1] {
        let Some(at) = middle.get(1..).and_then(|m| m.find(lit)) else {
            return false;
        };
        middle = &middle[1 + at + lit.len()..];
    }
    !middle.is_empty()
}

/// The embedded profile whose S3 endpoints match `endpoint`, if any, with
/// the price region of the matching endpoint entry (`price_region`, else its
/// `region`).
pub fn profile_for_endpoint(endpoint: &str) -> Option<(Value, String)> {
    let host = host_of(endpoint);
    if host.is_empty() {
        return None;
    }
    profiles().into_iter().find_map(|d| {
        if d["kind"].as_str() == Some("self_hosted") {
            return None;
        }
        let entry = d["s3_endpoints"].as_array()?.iter().find(|e| {
            e["endpoint"]
                .as_str()
                .is_some_and(|t| host_matches(t, &host))
        })?;
        let region = text(&entry["price_region"]).or_else(|| text(&entry["region"]))?;
        Some((d, region))
    })
}

/// The class id in `doc` for an S3 storage-class name: none or `STANDARD`
/// is the default class; otherwise a class whose id equals the name in
/// lower case with `-` for `_`.
pub fn class_for(doc: &Value, storage_class: Option<&str>) -> Option<String> {
    match storage_class.map(str::trim).filter(|s| !s.is_empty()) {
        None => default_class(doc).and_then(|c| text(&c["id"])),
        Some(s) if s.eq_ignore_ascii_case("STANDARD") => {
            default_class(doc).and_then(|c| text(&c["id"]))
        }
        Some(s) => {
            let want = s.to_ascii_lowercase().replace('_', "-");
            doc["storage_classes"]
                .as_array()?
                .iter()
                .filter_map(|c| text(&c["id"]))
                .find(|id| *id == want)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Walk a profile and check that every fact with a value has a source
    /// and a date, and every unknown one says why.
    fn check_facts(v: &Value, path: &str, errors: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                if m.contains_key("value") {
                    let has = |k: &str| {
                        m.get(k)
                            .and_then(Value::as_str)
                            .is_some_and(|s| !s.is_empty())
                    };
                    if m["value"].is_null() {
                        if !has("note") {
                            errors.push(format!("{path}: null without a note"));
                        }
                    } else {
                        if !has("source_url")
                            || !m["source_url"].as_str().unwrap().starts_with("https://")
                        {
                            errors.push(format!("{path}: value without an https source_url"));
                        }
                        let date = m.get("last_verified").and_then(Value::as_str).unwrap_or("");
                        if date.len() != 10
                            || date.as_bytes()[4] != b'-'
                            || date.as_bytes()[7] != b'-'
                        {
                            errors
                                .push(format!("{path}: value without a YYYY-MM-DD last_verified"));
                        }
                    }
                }
                for (k, x) in m {
                    check_facts(x, &format!("{path}/{k}"), errors);
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter().enumerate() {
                    check_facts(x, &format!("{path}/{i}"), errors);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn every_profile_in_the_data_set_is_embedded_and_parses() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/providers");
        let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.ends_with(".json") && n != "schema.json")
            .collect();
        let embedded: BTreeSet<String> = PROFILES.iter().map(|(n, _)| n.to_string()).collect();
        assert_eq!(on_disk, embedded, "data/providers and PROFILES differ");
        for (name, raw) in PROFILES {
            let doc: Value = serde_json::from_str(raw).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                format!("{}.json", doc["id"].as_str().unwrap()),
                *name,
                "file name and id differ"
            );
        }
        assert_eq!(profiles().len(), PROFILES.len());
    }

    #[test]
    fn profiles_keep_the_data_rules() {
        let mut errors = Vec::new();
        for (name, raw) in PROFILES {
            let doc: Value = serde_json::from_str(raw).unwrap();
            check_facts(&doc, name, &mut errors);
            let self_hosted = doc["kind"].as_str() == Some("self_hosted");
            if !self_hosted {
                let cur = doc["currency"].as_str().unwrap_or("");
                if cur.len() != 3 || !cur.chars().all(|c| c.is_ascii_uppercase()) {
                    errors.push(format!("{name}: currency {cur:?}"));
                }
            }
            let codes: BTreeSet<&str> = doc["regions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| r["code"].as_str())
                .collect();
            for class in doc["storage_classes"].as_array().into_iter().flatten() {
                for r in strings(&class["applies_to_regions"]) {
                    if !codes.contains(r.as_str()) {
                        errors.push(format!(
                            "{name}: class {} applies to unknown region {r}",
                            class["id"]
                        ));
                    }
                }
            }
            if let Some(id) = doc["default_storage_class"].as_str() {
                if default_class(&doc).and_then(|c| c["id"].as_str()) != Some(id) {
                    errors.push(format!("{name}: default_storage_class {id} is not a class"));
                }
            }
            for e in doc["s3_endpoints"].as_array().into_iter().flatten() {
                let r = e["price_region"]
                    .as_str()
                    .or(e["region"].as_str())
                    .unwrap_or("");
                if !self_hosted && !codes.contains(r) {
                    errors.push(format!("{name}: endpoint region {r} is not in regions"));
                }
                let url = e["endpoint"].as_str().unwrap_or("");
                if !self_hosted && !url.starts_with("https://") {
                    errors.push(format!("{name}: endpoint {url} is not https"));
                }
            }
        }
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn s3_providers_are_sorted_and_carry_headline_prices() {
        let now = 1_791_849_600; // 2026-10-13
        let list = s3_providers(now);
        assert!(list.len() >= 2);
        let names: Vec<String> = list.iter().map(|p| p.name.to_lowercase()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        for p in &list {
            assert!(!p.endpoints.is_empty(), "{} has no endpoints", p.name);
            for f in [
                &p.storage_per_gb_month,
                &p.egress_per_gb,
                &p.put_per_1000,
                &p.get_per_1000,
            ] {
                assert!(f.get("value").is_some(), "{}: {f}", p.name);
            }
            if p.kind == "service" {
                assert!(p.currency.is_some(), "{}", p.name);
            }
        }
        let aws = list.iter().find(|p| p.id == "aws-s3").unwrap();
        assert_eq!(aws.storage_per_gb_month["value"].as_f64(), Some(0.0245));
        assert_eq!(aws.currency.as_deref(), Some("USD"));
        assert!(aws.storage_tiered);
        assert!(aws.last_verified.is_some());
        let fra = aws
            .endpoints
            .iter()
            .find(|e| e.region == "eu-central-1")
            .unwrap();
        assert!(fra.prices_verified);
        assert!(fra.region_prices.is_none());
        assert!(!fra.path_style);
        if let Some(sto) = aws.endpoints.iter().find(|e| e.region == "eu-north-1") {
            let rp = sto.region_prices.as_ref().expect("Stockholm prices");
            assert!(rp["storage_per_gb_month"]["value"].is_number());
            assert!(sto.prices_verified);
        }
        // Storage Box is not S3 and is left out.
        assert!(!list.iter().any(|p| p.id == "hetzner-storage-box"));
        // Far in the future every dated figure is stale.
        let later = s3_providers(now + 400 * 86_400);
        assert!(later
            .iter()
            .filter(|p| p.last_verified.is_some())
            .all(|p| p.stale));
        assert!(list.iter().all(|p| !p.stale), "a profile is already stale");
    }

    #[test]
    fn endpoint_templates_match_hosts() {
        assert!(host_matches(
            "https://{account_id}.r2.cloudflarestorage.com",
            "abc123.r2.cloudflarestorage.com"
        ));
        assert!(!host_matches(
            "https://{account_id}.r2.cloudflarestorage.com",
            ".r2.cloudflarestorage.com"
        ));
        assert!(host_matches(
            "https://s3.{region}.example.com",
            "s3.eu-1.example.com"
        ));
        assert!(!host_matches(
            "https://s3.{region}.example.com",
            "s3.eu-1.example.org"
        ));
        assert!(host_matches(
            "https://s3.eu-central-1.amazonaws.com",
            "s3.eu-central-1.amazonaws.com"
        ));
        assert_eq!(
            host_of("https://User@Host.example.com:9000/path"),
            "host.example.com"
        );
        assert!(profile_for_endpoint("https://s3.fr-par.scw.cloud").is_some());
        assert!(profile_for_endpoint("http://localhost:9000").is_none());
        let (aws, region) = profile_for_endpoint("https://s3.eu-central-1.amazonaws.com").unwrap();
        assert_eq!(region, "eu-central-1");
        assert_eq!(class_for(&aws, None).as_deref(), Some("standard"));
        assert_eq!(
            class_for(&aws, Some("standard_ia")).as_deref(),
            Some("standard-ia")
        );
        assert_eq!(class_for(&aws, Some("NOPE")), None);
    }
}
