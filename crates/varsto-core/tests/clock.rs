// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The logical clock: handed out from memory, reserved on disk in blocks,
//! never the same value twice, even from two processes on one device.

use std::collections::HashSet;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

#[test]
fn ten_thousand_ticks_write_the_clock_file_a_few_times() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let (mut engine, _) = Engine::init(&home, "laptop", PASS).unwrap();
    let mut last = 0;
    for _ in 0..10_000 {
        let v = engine.tick_clock().unwrap();
        assert!(v > last, "clock went from {last} to {v}");
        last = v;
    }
    assert!(
        engine.clock_writes() < 20,
        "clock.json written {} times for 10 000 ticks",
        engine.clock_writes()
    );
    // A restart goes on after the reserved end, never behind a value handed out.
    drop(engine);
    let mut again = Engine::open(&home, PASS).unwrap();
    assert!(again.tick_clock().unwrap() > last);
}

#[test]
fn two_engines_on_one_home_never_hand_out_the_same_value() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let (mut a, _) = Engine::init(&home, "laptop", PASS).unwrap();
    // The background service and the command line open the same directory.
    let mut b = Engine::open(&home, PASS).unwrap();
    let mut seen = HashSet::new();
    // Runs of different lengths, so both cross reservation ends several times.
    for round in 0..40u64 {
        let (first, n) = if round % 2 == 0 {
            (&mut a, 300 + round * 7)
        } else {
            (&mut b, 150 + round * 11)
        };
        for _ in 0..n {
            let v = first.tick_clock().unwrap();
            assert!(seen.insert(v), "value {v} handed out twice");
        }
    }
    // A third process started now continues after both.
    let mut c = Engine::open(&home, PASS).unwrap();
    let v = c.tick_clock().unwrap();
    assert!(seen.iter().all(|s| *s < v), "{v} not after every value");
}

/// Two processes reserving at the same time. Each crosses several
/// reservation ends, so both rewrite `clock.json` while the other ticks.
#[test]
fn parallel_reservations_never_hand_out_the_same_value() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let (engine, _) = Engine::init(&home, "laptop", PASS).unwrap();
    drop(engine);
    let spawn = |home: std::path::PathBuf| {
        std::thread::spawn(move || {
            let mut engine = Engine::open(&home, PASS).unwrap();
            let mut out = Vec::with_capacity(2_500);
            for _ in 0..2_500 {
                out.push(engine.tick_clock().unwrap());
            }
            out
        })
    };
    let left = spawn(home.clone());
    let right = spawn(home);
    let mut all = left.join().expect("left engine");
    all.extend(right.join().expect("right engine"));
    let distinct: HashSet<u64> = all.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        all.len(),
        "a Lamport value was handed out twice"
    );
}
