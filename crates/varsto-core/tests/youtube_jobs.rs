// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! YouTube jobs against a fake yt-dlp (a shell script; nothing goes to the
//! network): a channel of five videos, one private (it fails, is recorded
//! and tried again later without stopping the job), one already in another
//! folder of the vault (never downloaded), downloads that stop halfway and
//! carry on, a step that dies between download and import, a disk that is
//! too full for the next video, and a later listing that brings only the
//! new video.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{
    VideoStatus, YoutubeAddOptions, YoutubeEnv, YoutubeJob, YtState, DEFAULT_YT_FREE_MIN,
};
use varsto_core::pool::DiskSpace;
use varsto_core::storage::StorageSpec;
use varsto_core::youtube::Throttle;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const CHANNEL: &str = "https://www.youtube.com/@ExampleMakers";
const A: &str = "vidAAAAAAA1";
const B: &str = "vidBBBBBBB2";
const C: &str = "vidCCCCCCC3";
const D: &str = "vidDDDDDDD4";
const E: &str = "vidEEEEEEE5";
const F: &str = "vidFFFFFFF6";

/// The fake: lists `listing.txt`; a probe prints 4000 bytes, or fails for
/// the private video; a download writes `<id>.mp4` and `<id>.info.json`
/// where `-o` says. The first download of B stops halfway (a `.part` file
/// and an error); the next one finds the part and finishes it. Every call
/// is logged.
fn fake_ytdlp(root: &Path) -> PathBuf {
    let script = format!(
        r#"#!/usr/bin/env bash
root='{root}'
echo "$*" >> "$root/calls.log"
mode=download
out=''
prev=''
for a in "$@"; do
  case "$a" in
    --flat-playlist) mode=list ;;
    --skip-download) mode=probe ;;
  esac
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
url="${{@: -1}}"
id="${{url##*v=}}"
case "$mode" in
  list)
    cat "$root/listing.txt"
    exit 0 ;;
  probe)
    if [ "$id" = "{c}" ]; then
      echo "ERROR: [youtube] $id: Private video. Sign in if you've been granted access to this video" >&2
      exit 1
    fi
    echo 4000
    exit 0 ;;
esac
if [ "$id" = "{c}" ]; then
  echo "ERROR: [youtube] $id: Private video" >&2
  exit 1
fi
base="${{out%%\%(id)s.\%(ext)s}}"
if [ -e "$root/slow" ]; then sleep 3; fi
media="$base$id.mp4"
if [ "$id" = "{b}" ] && [ ! -e "$media.part" ] && [ ! -e "$root/b-resumed" ]; then
  printf 'first half of %s ' "$id" > "$media.part"
  echo "ERROR: unable to download video data: The read operation timed out" >&2
  exit 1
fi
if [ -e "$media.part" ]; then
  touch "$root/b-resumed"
  cat "$media.part" > "$media.tmp"
  printf 'second half' >> "$media.tmp"
  rm "$media.part"
  mv "$media.tmp" "$media"
else
  for i in $(seq 1 200); do printf 'frame %s of %s\n' "$i" "$id"; done > "$media"
fi
printf '{{"id":"%s","title":"Title of %s","channel":"Example Makers","upload_date":"20240102"}}' "$id" "$id" > "$base$id.info.json"
exit 0
"#,
        root = root.display(),
        b = B,
        c = C,
    );
    let p = root.join("bin").join("fake-yt-dlp");
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, script).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn listing(ids: &[&str]) -> String {
    ids.iter()
        .map(|id| format!("{id}\thttps://www.youtube.com/watch?v={id}\tTitle of {id}\n"))
        .collect()
}

struct TestEnv {
    now: i64,
    space: DiskSpace,
    crash_at: Option<&'static str>,
    /// false: like the background service, yt-dlp runs between steps.
    block: bool,
}

impl YoutubeEnv for TestEnv {
    fn space(&mut self, _dir: &Path) -> Option<DiskSpace> {
        Some(self.space)
    }
    fn now(&mut self) -> i64 {
        self.now
    }
    fn checkpoint(&mut self, at: &str) -> anyhow::Result<()> {
        if self.crash_at == Some(at) {
            self.crash_at = None;
            anyhow::bail!("simulated crash at {at}");
        }
        Ok(())
    }
    fn blocking(&self) -> bool {
        self.block
    }
}

const ROOMY: DiskSpace = DiskSpace {
    free: 900_000_000,
    total: 1_000_000_000,
};

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    a: Engine,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let (mut a, _key) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    })
    .unwrap();
    // A video the user archived earlier, in another folder.
    let old = root.join("old");
    fs::create_dir_all(&old).unwrap();
    a.add_folder("old", &old).unwrap();
    fs::write(old.join(format!("Earlier upload [{D}].mp4")), b"old copy").unwrap();
    a.push("old").unwrap();
    fs::write(root.join("listing.txt"), listing(&[A, B, C, D, E])).unwrap();
    Lab { _tmp: tmp, root, a }
}

fn add(lab: &mut Lab) -> YoutubeJob {
    let ytdlp = fake_ytdlp(&lab.root);
    lab.a
        .youtube_add(&YoutubeAddOptions {
            url: CHANNEL.into(),
            folder: Some("makers".into()),
            storages: vec!["box".into()],
            free_min: DEFAULT_YT_FREE_MIN,
            download_dir: lab.root.join("downloads"),
            folder_parent: lab.root.join("folders"),
            min_copies: Some(1),
            throttle: Throttle::default(),
            thumbnails: false,
            subtitles: String::new(),
            refresh_hours: 24,
            ytdlp: Some(ytdlp),
        })
        .unwrap()
}

/// Step until the job waits for something; the last state.
fn run(lab: &mut Lab, id: &str, env: &mut TestEnv) -> YoutubeJob {
    let mut last = None;
    for _ in 0..40 {
        let j = lab.a.youtube_tick(id, env, true).unwrap().unwrap();
        let waits = matches!(
            j.state,
            YtState::UpToDate
                | YtState::Complete
                | YtState::WaitingRetry
                | YtState::WaitingSpace
                | YtState::WaitingPolicy
        );
        last = Some(j);
        if waits {
            break;
        }
    }
    last.unwrap()
}

fn calls(root: &Path) -> Vec<String> {
    fs::read_to_string(root.join("calls.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn downloads_of(root: &Path, id: &str) -> usize {
    calls(root)
        .iter()
        .filter(|c| !c.contains("--skip-download") && !c.contains("--flat-playlist"))
        .filter(|c| c.ends_with(&format!("v={id}")))
        .count()
}

fn status(j: &YoutubeJob, id: &str) -> VideoStatus {
    j.videos.iter().find(|v| v.id == id).unwrap().status
}

fn path_of(id: &str, ext: &str) -> String {
    format!("Example Makers/2024-01-02 Title of {id} [{id}].{ext}")
}

#[test]
fn channel_is_archived_politely_once() {
    let mut lab = lab();
    let job = add(&mut lab);
    let id = job.id.clone();
    let spool = job.spool_dir.clone();
    let mut env = TestEnv {
        now: 1_000_000,
        space: ROOMY,
        crash_at: None,
        block: true,
    };

    // The first steps: the listing, then A (probe, download, import).
    let j = lab.a.youtube_tick(&id, &mut env, true).unwrap().unwrap();
    assert_eq!(j.videos.len(), 5, "{j:#?}");
    assert!(calls(&lab.root)[0].starts_with("--flat-playlist"));
    // The download of A goes through, then the step dies before the
    // import: the next step imports the file in the spool, nothing is
    // downloaded again.
    env.crash_at = Some("downloaded");
    let mut crashed = false;
    for _ in 0..4 {
        if lab.a.youtube_tick(&id, &mut env, true).is_err() {
            crashed = true;
            break;
        }
    }
    assert!(crashed, "the simulated crash happened");
    assert_eq!(downloads_of(&lab.root, A), 1);
    let j = run(&mut lab, &id, &mut env);
    assert_eq!(downloads_of(&lab.root, A), 1, "A is not downloaded again");
    assert_eq!(status(&j, A), VideoStatus::Stored, "{j:#?}");

    // The download arguments are the polite defaults, one video per call.
    let dl = calls(&lab.root)
        .into_iter()
        .find(|c| c.ends_with(&format!("v={A}")) && !c.contains("--skip-download"))
        .unwrap();
    assert!(
        dl.starts_with("--sleep-interval 25 --max-sleep-interval 65 --sleep-requests 2 --limit-rate 600K --concurrent-fragments 1 --ignore-errors --no-abort-on-error"),
        "{dl}"
    );

    // B stopped halfway: it failed once and waits; C is private; D is in
    // the vault already; E is stored.
    assert_eq!(status(&j, B), VideoStatus::Failed, "{j:#?}");
    assert_eq!(status(&j, C), VideoStatus::Failed);
    let c = j.videos.iter().find(|v| v.id == C).unwrap();
    assert!(
        c.last_error
            .as_deref()
            .unwrap()
            .starts_with("Private video"),
        "{c:?}"
    );
    assert_eq!(status(&j, D), VideoStatus::AlreadyStored);
    assert!(j
        .videos
        .iter()
        .find(|v| v.id == D)
        .unwrap()
        .found_in
        .as_deref()
        .unwrap()
        .contains("folder old"));
    assert_eq!(status(&j, E), VideoStatus::Stored);
    assert_eq!(j.state, YtState::WaitingRetry, "{}", j.text);
    assert!(
        !calls(&lab.root)
            .iter()
            .any(|c| c.ends_with(&format!("v={D}"))),
        "the video in the vault is never probed or downloaded"
    );

    // An hour later B carries on from its part; C fails again.
    env.now += 3601;
    let j = run(&mut lab, &id, &mut env);
    assert_eq!(status(&j, B), VideoStatus::Stored, "{j:#?}");
    assert_eq!(downloads_of(&lab.root, B), 2);
    assert_eq!(
        lab.a.read_file("makers", &path_of(B, "mp4")).unwrap(),
        format!("first half of {B} second half").as_bytes()
    );
    let c = j.videos.iter().find(|v| v.id == C).unwrap();
    assert_eq!((c.status, c.attempts), (VideoStatus::Failed, 2));

    // The folder has the videos with their info files; the spool is empty.
    for v in [A, B, E] {
        let info = lab.a.read_file("makers", &path_of(v, "info.json")).unwrap();
        assert!(String::from_utf8_lossy(&info).contains(v));
        assert!(!spool.join(path_of(v, "mp4")).exists());
    }
    // `import verify` covers every video file the job imported.
    let verify = lab.a.import_verify("makers").unwrap();
    assert_eq!(verify.files_total, 6, "{verify:#?}");
    assert!(verify.complete, "{verify:#?}");
    let counts = j.counts();
    assert_eq!(
        (counts.stored, counts.already_stored, counts.failed),
        (3, 1, 1)
    );
    // Every stored id is in the vault's index (the folder's book).
    let index = lab.a.youtube_index().unwrap();
    for v in [A, B, D, E] {
        assert!(index.contains_key(v), "{v} in {index:?}");
    }
    assert!(!index.contains_key(C));

    // A day later the channel is listed again and has one new video:
    // only that one is downloaded.
    fs::write(lab.root.join("listing.txt"), listing(&[F, A, B, C, D, E])).unwrap();
    env.now += 25 * 3600;
    let before = calls(&lab.root).len();
    let j = run(&mut lab, &id, &mut env);
    assert_eq!(status(&j, F), VideoStatus::Stored, "{j:#?}");
    let new_calls: Vec<String> = calls(&lab.root).split_off(before);
    for v in [A, B, D, E] {
        assert!(
            !new_calls.iter().any(|c| c.ends_with(&format!("v={v}"))),
            "{v} again: {new_calls:#?}"
        );
    }
    assert_eq!(downloads_of(&lab.root, F), 1);

    // A second job for the same channel is refused.
    let again = lab.a.youtube_add(&YoutubeAddOptions {
        url: "https://youtube.com/@ExampleMakers/videos".into(),
        folder: Some("other".into()),
        storages: Vec::new(),
        free_min: DEFAULT_YT_FREE_MIN,
        download_dir: lab.root.join("downloads"),
        folder_parent: lab.root.join("folders"),
        min_copies: None,
        throttle: Throttle::default(),
        thumbnails: false,
        subtitles: String::new(),
        refresh_hours: 24,
        ytdlp: None,
    });
    assert!(again.is_err());
}

#[test]
fn waits_for_space_before_a_video() {
    let mut lab = lab();
    fs::write(lab.root.join("listing.txt"), listing(&[A])).unwrap();
    let job = add(&mut lab);
    let id = job.id;
    // The reserve is 15 % of 1 MB: 150 000 bytes. A needs about 4 200.
    let mut env = TestEnv {
        now: 1_000_000,
        space: DiskSpace {
            free: 100_000,
            total: 1_000_000,
        },
        crash_at: None,
        block: true,
    };
    let j = run(&mut lab, &id, &mut env);
    assert_eq!(j.state, YtState::WaitingSpace, "{j:#?}");
    assert_eq!(j.need_bytes, 50_000);
    // Above the reserve, but not by the video's size.
    env.space.free = 152_000;
    let j = run(&mut lab, &id, &mut env);
    assert_eq!(j.state, YtState::WaitingSpace, "{}", j.text);
    assert!(j.text.contains(A), "{}", j.text);
    assert_eq!(downloads_of(&lab.root, A), 0);
    env.space.free = 160_000;
    let j = run(&mut lab, &id, &mut env);
    assert_eq!(status(&j, A), VideoStatus::Stored, "{j:#?}");
    assert_eq!(j.state, YtState::UpToDate);
}

#[test]
fn scanned_files_are_not_downloaded() {
    let mut lab = lab();
    fs::write(lab.root.join("listing.txt"), listing(&[A, E])).unwrap();
    // A directory outside Varsto with A in it under yt-dlp's default name.
    let mine = lab.root.join("my-videos");
    fs::create_dir_all(&mine).unwrap();
    fs::write(mine.join(format!("Some title [{A}].webm")), b"x").unwrap();
    let scan = lab.a.youtube_scan(mine.to_str().unwrap()).unwrap();
    assert_eq!(
        (scan.kind.as_str(), scan.videos, scan.new_videos),
        ("directory", 1, 1)
    );
    // The folder scan records D with the folder for every device.
    let scan = lab.a.youtube_scan("old").unwrap();
    assert_eq!((scan.kind.as_str(), scan.videos), ("folder", 1));
    let job = add(&mut lab);
    let mut env = TestEnv {
        now: 1_000_000,
        space: ROOMY,
        crash_at: None,
        block: true,
    };
    let j = run(&mut lab, &job.id, &mut env);
    assert_eq!(status(&j, A), VideoStatus::AlreadyStored, "{j:#?}");
    assert_eq!(status(&j, E), VideoStatus::Stored);
    assert_eq!(downloads_of(&lab.root, A), 0);
    // The scanned folder's book is an index only: no import to report.
    assert!(lab.a.import_status(Some("old")).is_err());
    assert_eq!(lab.a.import_status(Some("makers")).unwrap().len(), 1);
    // A scanned folder can take a job's videos; another folder that holds
    // other data cannot.
    fs::write(lab.root.join("listing.txt"), listing(&[F])).unwrap();
    let mut opts = YoutubeAddOptions {
        url: "https://www.youtube.com/playlist?list=PLexample01".into(),
        folder: Some("makers".into()),
        storages: Vec::new(),
        free_min: DEFAULT_YT_FREE_MIN,
        download_dir: lab.root.join("downloads"),
        folder_parent: lab.root.join("folders"),
        min_copies: None,
        throttle: Throttle::default(),
        thumbnails: false,
        subtitles: String::new(),
        refresh_hours: 0,
        ytdlp: Some(lab.root.join("bin").join("fake-yt-dlp")),
    };
    assert!(lab.a.youtube_add(&opts).is_err(), "makers is another job's");
    opts.folder = Some("old".into());
    let into_old = lab.a.youtube_add(&opts).unwrap();
    assert_eq!(into_old.folder, "old");
    lab.a
        .set_policy(
            "old",
            Some(varsto_core::policy::Policy {
                min_copies: 1,
                ..Default::default()
            }),
        )
        .unwrap();
    let j = run(&mut lab, &into_old.id, &mut env);
    assert_eq!(status(&j, F), VideoStatus::Stored, "{j:#?}");
    assert_eq!(j.state, YtState::Complete);
    assert!(lab
        .a
        .read_file("old", &path_of(F, "mp4"))
        .unwrap()
        .starts_with(b"frame 1 of"));
}

#[test]
fn the_service_leaves_ytdlp_running_and_stops_it_when_the_disk_fills() {
    let mut lab = lab();
    fs::write(lab.root.join("listing.txt"), listing(&[A])).unwrap();
    fs::write(lab.root.join("slow"), b"").unwrap();
    let job = add(&mut lab);
    let id = job.id;
    let mut env = TestEnv {
        now: 1_000_000,
        space: ROOMY,
        crash_at: None,
        block: false,
    };
    let wait_until = |lab: &mut Lab, env: &mut TestEnv, want: &dyn Fn(&YoutubeJob) -> bool| {
        for _ in 0..400 {
            let j = lab.a.youtube_tick(&id, env, true).unwrap().unwrap();
            if want(&j) {
                return j;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("the job did not get there");
    };
    let root = lab.root.clone();
    let j = wait_until(&mut lab, &mut env, &|j| {
        j.state == YtState::Downloading && j.running.is_some() && downloads_of(&root, A) == 1
    });
    assert!(j.text.starts_with("downloading"), "{}", j.text);
    // The disk fills meanwhile: the download is stopped (its process, by
    // its PID) and waits; that is not a failure of the video.
    env.space.free = 1000;
    let j = lab.a.youtube_tick(&id, &mut env, true).unwrap().unwrap();
    assert_eq!(j.state, YtState::WaitingSpace, "{j:#?}");
    assert!(j.running.is_none());
    assert_eq!(j.videos[0].attempts, 0);
    assert_eq!(j.videos[0].status, VideoStatus::Pending);
    // Nothing of it was finished (the fake writes only after its pause).
    std::thread::sleep(std::time::Duration::from_secs(4));
    assert!(!j
        .spool_dir
        .join(".varsto-work")
        .join(format!("{A}.mp4"))
        .exists());
    env.space = ROOMY;
    let j = wait_until(&mut lab, &mut env, &|j| j.state == YtState::UpToDate);
    assert_eq!(status(&j, A), VideoStatus::Stored, "{j:#?}");
    assert_eq!(downloads_of(&lab.root, A), 2, "{:#?}", calls(&lab.root));
}
