// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The live visualization snapshot (`/api/viz`, spec section 63) from a
//! fixture vault: two storages (one at home, one in the cloud place with a
//! price), a disk pool with one docked disk, a folder with data on all of
//! them and an upload task running now. The fixture is deterministic: the
//! running task is given to `compose` by hand, with a known rate.

use std::fs;
use varsto_core::activity::{TaskView, Unit};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::Engine;
use varsto_core::pool::{self, DiskSpace};
use varsto_core::price::StoragePrice;
use varsto_core::storage::StorageSpec;
use varsto_core::viz::{self, LiveInput};

const PASS: &str = "correct horse battery staple";
const GIB: u64 = 1 << 30;

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s & 0xff) as u8
        })
        .collect()
}

fn dir(root: &std::path::Path, name: &str, place: &str) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: root.join(name),
        cold: false,
        carrier: false,
        place: place.into(),
        min_free: None,
    }
}

#[test]
fn snapshot_joins_storages_disks_costs_and_a_running_upload() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let mounts = root.join("mounts");
    fs::create_dir_all(&mounts).unwrap();
    let (mut e, _) = Engine::init(&root.join("home"), "laptop", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.add_storage(dir(&root, "box", "home")).unwrap();
    e.add_storage(dir(&root, "cloud", "cloud")).unwrap();
    e.add_storage(StorageSpec::Pool {
        name: "shelf".into(),
        place: "shelf".into(),
        reserve_percent: 5,
        min_reserve_bytes: 2 * GIB,
        disks: vec![],
        scan_roots: vec![mounts.clone()],
        copies: 1,
        verify_after_days: pool::DEFAULT_VERIFY_AFTER_DAYS,
    })
    .unwrap();
    let d1 = mounts.join("d1");
    fs::create_dir_all(&d1).unwrap();
    pool::set_fake_space(
        &d1,
        Some(DiskSpace {
            free: 50 * GIB,
            total: 100 * GIB,
        }),
    );
    e.disk_add(&d1, "shelf", "data-01").unwrap();
    e.set_storage_price(
        "cloud",
        Some(StoragePrice {
            storage_per_gb_month: Some(0.02),
            egress_per_gb: Some(0.09),
            currency: "EUR".into(),
            ..Default::default()
        }),
    )
    .unwrap();
    e.add_folder("docs", &root.join("docs")).unwrap();
    fs::write(root.join("docs/a.bin"), pseudo_random(200_000, 7)).unwrap();
    e.push("docs").unwrap();

    let heavy = e.viz_heavy().unwrap();
    let light = e.viz_light().unwrap();
    assert_eq!(heavy.this_device, e.device_id().to_string());
    assert_eq!(heavy.total_bytes, 200_000);
    assert_eq!(heavy.storages.len(), 3);
    let cloud = heavy.storages.iter().find(|s| s.name == "cloud").unwrap();
    assert_eq!(cloud.kind, "directory");
    assert_eq!(cloud.place, "cloud");
    assert_eq!(cloud.data_bytes, heavy.total_bytes);
    let price = cloud.price.as_ref().unwrap();
    assert_eq!(
        (price.currency.as_str(), price.egress_per_gb),
        ("EUR", Some(0.09))
    );
    let month = cloud.monthly_cost.unwrap();
    assert!((month - cloud.data_bytes as f64 / GIB as f64 * 0.02).abs() < 1e-12);
    assert!(cloud.read_all_cost.unwrap() > 0.0);
    let docs = heavy.folders.iter().find(|f| f.name == "docs").unwrap();
    assert!(
        docs.targets.contains(&"box".to_string()) && docs.targets.contains(&"cloud".to_string())
    );
    assert_eq!(docs.missing_blocks, 0);
    assert_eq!(heavy.devices.len(), 1);
    assert_eq!(heavy.devices[0].role, "this");

    assert_eq!(light.disks.len(), 1);
    assert_eq!(light.disks[0].label, "data-01");
    assert!(light.disks[0].docked);
    assert_eq!(light.disks[0].capacity_bytes, 100 * GIB);

    // An upload of 10 MB, 4 MB done, 2 MB/s: finishes in 3 s.
    let now = 1_800_000_000;
    let task = TaskView {
        id: 1,
        kind: "upload".into(),
        phase: String::new(),
        subject: "docs".into(),
        detail: None,
        done: 4_000_000,
        total: 10_000_000,
        unit: Unit::Bytes,
        percent: Some(40),
        started_utc: now - 10,
        updated_utc: now,
        rate: 2_000_000,
        eta_utc: None,
    };
    let fill = TaskView {
        id: 2,
        kind: "disk_check".into(),
        subject: "data-01".into(),
        unit: Unit::Items,
        done: 30,
        total: 100,
        percent: Some(30),
        rate: 0,
        ..task.clone()
    };
    let live = LiveInput {
        now_utc: now,
        this_device: heavy.this_device.clone(),
        this_name: "laptop".into(),
        tasks: vec![task, fill],
        ..Default::default()
    };
    let v = viz::compose(Some(&heavy), Some(&light), &live);
    assert_eq!(v["v"], 1);
    assert_eq!(v["unlocked"], true);
    let flows = v["flows"].as_array().unwrap();
    let ups: Vec<_> = flows.iter().filter(|f| f["kind"] == "upload").collect();
    assert_eq!(ups.len(), 3, "one flow per write target: {flows:?}");
    let to_cloud = ups.iter().find(|f| f["to"] == "s:cloud").unwrap();
    assert_eq!(to_cloud["from"], format!("d:{}", heavy.this_device));
    assert_eq!(to_cloud["folder"], "docs");
    assert_eq!(
        to_cloud["bps"], 666_666,
        "the task's rate shared by the targets"
    );
    assert_eq!(to_cloud["eta_utc"], now + 3);
    assert_eq!(to_cloud["remaining"], 6_000_000);
    let jobs = v["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 2);
    // A disk check on the docked disk shows as its phase and progress.
    let disk = &v["disks"]["list"][0];
    assert_eq!(disk["phase"], "verify");
    assert_eq!(disk["progress"], 30);
    assert_eq!(v["disks"]["docked"][0], "data-01");
    assert_eq!(v["disks"]["working_on"], "data-01");
    // The cost: only the priced storage, marked as an estimate.
    assert_eq!(v["cost"]["estimate"], true);
    let total = v["cost"]["month"]["EUR"].as_f64().unwrap();
    assert!((total - month).abs() < 1e-12);
    assert_eq!(v["health"]["overall"], "ok");
    // Pure: the same input gives the same JSON.
    assert_eq!(v, viz::compose(Some(&heavy), Some(&light), &live));
}

#[test]
fn snapshot_without_data_is_empty_but_well_formed() {
    let v = viz::compose(None, None, &LiveInput::default());
    assert_eq!(v["unlocked"], false);
    for k in ["devices", "storages", "folders", "flows", "jobs", "alerts"] {
        assert_eq!(v[k].as_array().unwrap().len(), 0, "{k}");
    }
    assert_eq!(v["disks"]["count"], 0);
    assert_eq!(v["health"]["overall"], "ok");
}

#[test]
fn flows_of_a_device_with_itself_are_filtered() {
    use varsto_core::ids::DeviceId;
    use varsto_core::p2p::traffic::{PeerTraffic, RelayTraffic, TrafficReport};
    let me = DeviceId::from_bytes(&[1u8; 16]);
    let other = DeviceId::from_bytes(&[2u8; 16]);
    let peer = |device: &DeviceId| PeerTraffic {
        device: device.clone(),
        rx_bps: 500,
        tx_bps: 700,
        ..Default::default()
    };
    let live = LiveInput {
        now_utc: 1_000,
        this_device: me.to_string(),
        traffic: TrafficReport {
            peers: vec![peer(&me), peer(&other)],
            relays: vec![RelayTraffic {
                from: other.clone(),
                to: other.clone(),
                bps: 9,
                ..Default::default()
            }],
            ..Default::default()
        },
        ..Default::default()
    };
    let v = viz::compose(None, None, &live);
    let flows = v["flows"].as_array().unwrap();
    assert_eq!(flows.len(), 2, "{flows:?}");
    for f in flows {
        assert_ne!(f["from"], f["to"], "{f}");
        assert!(f["id"].as_str().unwrap().contains(&other.to_string()));
    }
}
