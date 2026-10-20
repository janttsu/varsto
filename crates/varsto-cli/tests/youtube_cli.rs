// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto import youtube`, `import jobs` and `import youtube-scan` through the binary, with a fake yt-dlp (a shell script;
//! nothing goes to the network): add runs the job until it waits, status,
//! scan, pause, resume and remove.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn run(home: &Path, root: &Path, args: &[&str]) -> (bool, serde_json::Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(home)
        .arg("--json")
        .args(args)
        .env("VARSTO_PASSPHRASE", "test passphrase")
        .env("VARSTO_FOLDER_ROOT", root.join("folders"))
        .env_remove("VARSTO_YTDLP")
        .output()
        .expect("run varsto");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v = serde_json::from_str(&stdout).unwrap_or(serde_json::Value::String(stdout));
    (
        out.status.success(),
        v,
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn ok(home: &Path, root: &Path, args: &[&str]) -> serde_json::Value {
    let (success, v, err) = run(home, root, args);
    assert!(success, "varsto {args:?} failed: {err}");
    v
}

/// Lists two videos; downloads write `<id>.mp4` and `<id>.info.json`.
fn fake(root: &Path) -> String {
    let script = format!(
        r#"#!/usr/bin/env bash
echo "$*" >> '{root}/calls.log'
mode=download; out=''; prev=''
for a in "$@"; do
  case "$a" in --flat-playlist) mode=list ;; --skip-download) mode=probe ;; esac
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
url="${{@: -1}}"; id="${{url##*v=}}"
case "$mode" in
  list) printf 'cliAAAAAAA1\thttps://www.youtube.com/watch?v=cliAAAAAAA1\tOne\ncliBBBBBBB2\thttps://www.youtube.com/watch?v=cliBBBBBBB2\tTwo\n'; exit 0 ;;
  probe) echo 1000; exit 0 ;;
esac
base="${{out%%\%(id)s.\%(ext)s}}"
printf 'video %s' "$id" > "$base$id.mp4"
printf '{{"id":"%s","title":"Episode %s","channel":"Example Workshop","upload_date":"20230405"}}' "$id" "$id" > "$base$id.info.json"
"#,
        root = root.display()
    );
    let p = root.join("fake-yt-dlp");
    fs::write(&p, script).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    p.display().to_string()
}

#[test]
fn youtube_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("a");
    let ytdlp = fake(root);
    ok(&home, root, &["init", "--name", "laptop"]);
    ok(
        &home,
        root,
        &[
            "storage",
            "add-local",
            "box",
            root.join("storage").to_str().unwrap(),
        ],
    );
    // A refused extra argument and a refused address.
    let (success, _, err) = run(
        &home,
        root,
        &[
            "import",
            "youtube",
            "https://www.youtube.com/@ExampleWorkshop",
            "--extra-arg=-o",
        ],
    );
    assert!(!success && err.contains("-o cannot be passed"), "{err}");
    let (success, _, _) = run(&home, root, &["import", "youtube", "https://example.com/x"]);
    assert!(!success);

    let job = ok(
        &home,
        root,
        &[
            "import",
            "youtube",
            "https://www.youtube.com/@ExampleWorkshop",
            "--folder",
            "workshop",
            "--storage",
            "box",
            "--download-dir",
            root.join("dl").to_str().unwrap(),
            "--rate",
            "1M",
            "--sleep",
            "30-90",
            "--ytdlp-path",
            &ytdlp,
        ],
    );
    assert_eq!(job["state"], "up_to_date", "{job:#}");
    assert_eq!(job["folder"], "workshop");
    assert_eq!(
        job["url"],
        "https://www.youtube.com/@ExampleWorkshop/videos"
    );
    let calls = fs::read_to_string(root.join("calls.log")).unwrap();
    assert!(
        calls.contains(
            "--sleep-interval 30 --max-sleep-interval 90 --sleep-requests 2 --limit-rate 1M"
        ),
        "{calls}"
    );
    let id = job["id"].as_str().unwrap()[..8].to_string();

    let st = ok(&home, root, &["import", "jobs", "status"]);
    let videos = st[0]["videos"].as_array().unwrap();
    assert_eq!(videos.len(), 2);
    assert!(videos.iter().all(|v| v["status"] == "stored"), "{st:#}");
    assert_eq!(st[0]["job_kind"], "youtube");
    let full = job["id"].as_str().unwrap().to_string();
    assert_eq!(st[0]["job"], format!("youtube:{full}"));
    // The same list as torrent jobs: uniform rows with the kind.
    let list = ok(&home, root, &["import", "jobs", "list"]);
    let rows = list.as_array().unwrap();
    assert_eq!(rows.len(), 1, "{list:#}");
    assert_eq!(rows[0]["id"], format!("youtube:{full}"));
    assert_eq!(rows[0]["kind"], "youtube");
    assert_eq!(rows[0]["unit"], "videos");
    assert_eq!(rows[0]["done"], 2);
    assert_eq!(rows[0]["total"], 2);
    assert_eq!(rows[0]["already_stored"], 0);
    assert_eq!(rows[0]["state"], "up_to_date");
    assert_eq!(rows[0]["actions"], serde_json::json!(["pause", "remove"]));
    // One job by its prefixed id, by its folder.
    let one = ok(
        &home,
        root,
        &[
            "import",
            "jobs",
            "status",
            &format!("youtube:{}", &full[..6]),
        ],
    );
    assert_eq!(one["folder"], "workshop");
    let one = ok(&home, root, &["import", "jobs", "status", "workshop"]);
    assert_eq!(one["job"], format!("youtube:{full}"));
    let files = ok(&home, root, &["folder", "files", "workshop"]);
    let text = files.to_string();
    assert!(
        text.contains("Example Workshop/2023-04-05 Episode cliAAAAAAA1 [cliAAAAAAA1].mp4"),
        "{text}"
    );

    // A directory with a video under yt-dlp's default name.
    let mine = root.join("mine");
    fs::create_dir_all(&mine).unwrap();
    fs::write(mine.join("Old [cliCCCCCCC3].mkv"), b"x").unwrap();
    let scan = ok(
        &home,
        root,
        &["import", "youtube-scan", mine.to_str().unwrap()],
    );
    assert_eq!(scan["videos"], 1);

    let p = ok(&home, root, &["import", "jobs", "pause", &id]);
    assert_eq!(p["state"], "paused");
    let list = ok(&home, root, &["import", "jobs", "list"]);
    assert_eq!(list[0]["actions"], serde_json::json!(["resume", "remove"]));
    let (success, _, err) = run(
        &home,
        root,
        &["import", "jobs", "remove", &id, "--keep-in-transmission"],
    );
    assert!(!success && err.contains("torrent"), "{err}");
    let r = ok(&home, root, &["import", "jobs", "resume", &id]);
    assert_eq!(r["user_paused"], false);
    let removed = ok(&home, root, &["import", "jobs", "remove", &id]);
    assert_eq!(removed["folder"], "workshop");
    let st = ok(&home, root, &["import", "jobs", "status"]);
    assert!(st.as_array().unwrap().is_empty());
    assert!(ok(&home, root, &["import", "jobs", "list"])
        .as_array()
        .unwrap()
        .is_empty());
}
