// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Ignore rules: which paths of a folder Varsto leaves alone.
//!
//! Rules come from `.varstoignore` files inside the folder (synced like any
//! other file, so every device shares them; a file in a subdirectory applies
//! to that subtree) and from patterns kept in this device's configuration
//! only (`FolderMount::ignore_local`). The syntax and meaning are those of
//! gitignore: one pattern per line; blank lines and lines starting with `#`
//! are skipped; `!` re-includes; a leading or middle `/` anchors the pattern
//! to the directory of its file (otherwise it matches a name at any depth);
//! a trailing `/` matches directories only; `*` and `?` match within one path
//! component, `[...]` is a character class, `**` matches any number of
//! directories; `\` escapes the next character. The last matching pattern
//! decides. Precedence, highest first: the device's own patterns, then the
//! `.varstoignore` of the deepest directory up to the folder root. A path
//! inside an ignored directory is ignored whatever the patterns say about
//! it (as in git, it cannot be re-included). Matching is case-sensitive.
//!
//! Written here rather than taken from the `ignore` crate: that crate brings
//! regex, globset and crossbeam with it, and the matcher is small.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// The name of the synced ignore file.
pub const IGNORE_FILE: &str = ".varstoignore";

/// Patterns the interface suggests (never applied unless the user adds them).
pub const SUGGESTED: &[&str] = &[
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    "~$*",
    "*.tmp",
    ".~lock.*#",
];

/// Longest pattern line taken; longer lines are skipped (they cannot be
/// meant, and matching stays cheap).
const MAX_PATTERN: usize = 1024;
/// Largest ignore file read; the rest is not.
const MAX_FILE: u64 = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    Lit(char),
    /// `*`: any run of characters within a component.
    Star,
    /// `?`: one character.
    One,
    /// `[...]`: (negated, ranges).
    Class(bool, Vec<(char, char)>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Seg {
    /// `**`: zero or more components.
    AnyDirs,
    /// A trailing `/**`: one or more components (everything inside).
    Inside,
    Glob(Vec<Tok>),
}

/// One pattern line.
#[derive(Clone, Debug)]
pub struct Pattern {
    /// The line as written (for explanations).
    pub text: String,
    /// 1-based line number in its file (or position in the local list).
    pub line: usize,
    negated: bool,
    dir_only: bool,
    segs: Vec<Seg>,
}

impl Pattern {
    /// Parse one line; None for blank lines, comments and lines that hold
    /// no pattern.
    pub fn parse(line: &str, number: usize) -> Option<Pattern> {
        let raw = line.strip_suffix('\r').unwrap_or(line);
        if raw.is_empty() || raw.starts_with('#') || raw.len() > MAX_PATTERN {
            return None;
        }
        // Trailing spaces are dropped unless escaped with a backslash.
        let mut s = raw.to_string();
        while s.ends_with(' ') && !s.ends_with("\\ ") {
            s.pop();
        }
        let mut rest: &str = &s;
        let mut negated = false;
        if let Some(r) = rest.strip_prefix('!') {
            negated = true;
            rest = r;
        }
        let mut dir_only = false;
        while rest.ends_with('/') && !rest.ends_with("\\/") {
            dir_only = true;
            rest = &rest[..rest.len() - 1];
        }
        if rest.is_empty() {
            return None;
        }
        let anchored = rest.trim_start_matches('/') != rest || rest.contains('/');
        let body = rest.trim_start_matches('/');
        if body.is_empty() {
            return None;
        }
        let mut segs = Vec::new();
        for part in body.split('/') {
            if part.is_empty() {
                continue; // "a//b" is "a/b"
            }
            if part == "**" {
                if segs.last() != Some(&Seg::AnyDirs) {
                    segs.push(Seg::AnyDirs);
                }
            } else {
                segs.push(Seg::Glob(tokens(part)));
            }
        }
        if segs.is_empty() {
            return None;
        }
        if segs.len() > 1 && segs.last() == Some(&Seg::AnyDirs) {
            *segs.last_mut().unwrap() = Seg::Inside;
        }
        if !anchored && segs.first() != Some(&Seg::AnyDirs) {
            segs.insert(0, Seg::AnyDirs);
        }
        Some(Pattern {
            text: raw.to_string(),
            line: number,
            negated,
            dir_only,
            segs,
        })
    }

    /// Whether the pattern matches `comps` (components relative to the
    /// directory of the pattern's file).
    fn matches(&self, comps: &[&str], is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        match_segs(&self.segs, comps)
    }

    /// Whether a match re-includes (`!`) rather than ignores.
    pub fn negated(&self) -> bool {
        self.negated
    }
}

fn tokens(part: &str) -> Vec<Tok> {
    let chars: Vec<char> = part.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' if i + 1 < chars.len() => {
                out.push(Tok::Lit(chars[i + 1]));
                i += 2;
            }
            '*' => {
                if out.last() != Some(&Tok::Star) {
                    out.push(Tok::Star);
                }
                i += 1;
            }
            '?' => {
                out.push(Tok::One);
                i += 1;
            }
            '[' => match class(&chars, i) {
                Some((tok, next)) => {
                    out.push(tok);
                    i = next;
                }
                None => {
                    out.push(Tok::Lit('['));
                    i += 1;
                }
            },
            c => {
                out.push(Tok::Lit(c));
                i += 1;
            }
        }
    }
    out
}

/// A character class starting at `chars[start] == '['`: the token and the
/// index after its `]`, or None when it is not closed (then `[` is literal).
fn class(chars: &[char], start: usize) -> Option<(Tok, usize)> {
    let mut i = start + 1;
    let mut negated = false;
    if i < chars.len() && (chars[i] == '!' || chars[i] == '^') {
        negated = true;
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    while i < chars.len() {
        let mut c = chars[i];
        if c == ']' && !first {
            return Some((Tok::Class(negated, ranges), i + 1));
        }
        first = false;
        if c == '\\' && i + 1 < chars.len() {
            i += 1;
            c = chars[i];
        }
        if i + 2 < chars.len() && chars[i + 1] == '-' && chars[i + 2] != ']' {
            let mut hi = chars[i + 2];
            let mut skip = 3;
            if hi == '\\' && i + 3 < chars.len() {
                hi = chars[i + 3];
                skip = 4;
            }
            ranges.push((c, hi));
            i += skip;
        } else {
            ranges.push((c, c));
            i += 1;
        }
    }
    None
}

fn match_segs(segs: &[Seg], comps: &[&str]) -> bool {
    match segs.first() {
        None => comps.is_empty(),
        Some(Seg::AnyDirs) => (0..=comps.len()).any(|k| match_segs(&segs[1..], &comps[k..])),
        Some(Seg::Inside) => !comps.is_empty(),
        Some(Seg::Glob(toks)) => {
            !comps.is_empty() && match_glob(toks, comps[0]) && match_segs(&segs[1..], &comps[1..])
        }
    }
}

/// Glob match of one component, iterative with backtracking on the last `*`.
fn match_glob(toks: &[Tok], name: &str) -> bool {
    let s: Vec<char> = name.chars().collect();
    let (mut t, mut i) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while i < s.len() {
        let ok = match toks.get(t) {
            Some(Tok::Lit(c)) => *c == s[i],
            Some(Tok::One) => true,
            Some(Tok::Class(neg, ranges)) => {
                ranges.iter().any(|(lo, hi)| *lo <= s[i] && s[i] <= *hi) != *neg
            }
            Some(Tok::Star) => {
                star = Some((t, i));
                t += 1;
                continue;
            }
            None => false,
        };
        if ok {
            t += 1;
            i += 1;
        } else if let Some((st, si)) = star {
            t = st + 1;
            i = si + 1;
            star = Some((st, si + 1));
        } else {
            return false;
        }
    }
    toks[t..].iter().all(|k| *k == Tok::Star)
}

/// The patterns of one source (a file, or the local list), in order.
#[derive(Clone, Debug, Default)]
pub struct RuleSet {
    pub patterns: Vec<Pattern>,
}

impl RuleSet {
    pub fn parse(text: &str) -> RuleSet {
        RuleSet {
            patterns: text
                .lines()
                .enumerate()
                .filter_map(|(i, l)| Pattern::parse(l, i + 1))
                .collect(),
        }
    }

    pub fn from_lines(lines: &[String]) -> RuleSet {
        RuleSet {
            patterns: lines
                .iter()
                .enumerate()
                .filter_map(|(i, l)| Pattern::parse(l, i + 1))
                .collect(),
        }
    }

    /// The last pattern that matches, if any.
    fn decide(&self, comps: &[&str], is_dir: bool) -> Option<&Pattern> {
        self.patterns
            .iter()
            .rev()
            .find(|p| p.matches(comps, is_dir))
    }
}

/// Why a path is (or is not) ignored.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Verdict {
    pub ignored: bool,
    /// The deciding pattern as written, if a pattern decided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Where it is: a `.varstoignore` path within the folder, or "local".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// The deciding path: the path itself or an ignored directory above it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_path: Option<String>,
}

/// The rules of one folder on this device. `.varstoignore` files are read
/// from disk the first time a path below their directory is asked about.
pub struct Matcher {
    root: Option<PathBuf>,
    local: RuleSet,
    /// Directory (manifest path, "" for the root) -> its file's rules.
    sets: BTreeMap<String, RuleSet>,
    loaded: HashSet<String>,
}

impl Matcher {
    /// Rules of the folder at `root` (None: only `local`).
    pub fn new(root: Option<&Path>, local: &[String]) -> Matcher {
        Matcher {
            root: root.map(Path::to_path_buf),
            local: RuleSet::from_lines(local),
            sets: BTreeMap::new(),
            loaded: HashSet::new(),
        }
    }

    /// Rules given as text per directory (tests, previews).
    pub fn from_texts(files: &[(&str, &str)], local: &[String]) -> Matcher {
        let mut m = Matcher::new(None, local);
        for (dir, text) in files {
            m.sets.insert(dir.to_string(), RuleSet::parse(text));
            m.loaded.insert(dir.to_string());
        }
        m
    }

    /// Use `text` as the root `.varstoignore` instead of the file on disk
    /// (a preview of an edit).
    pub fn override_root(&mut self, text: &str) {
        self.sets.insert(String::new(), RuleSet::parse(text));
        self.loaded.insert(String::new());
    }

    /// Whether any rule exists at all (a cheap skip when there are none is
    /// not possible before the files are read; this answers for what is
    /// loaded).
    pub fn is_empty_loaded(&self) -> bool {
        self.local.patterns.is_empty() && self.sets.values().all(|s| s.patterns.is_empty())
    }

    fn ensure(&mut self, dir: &str) {
        if !self.loaded.insert(dir.to_string()) {
            return;
        }
        let Some(root) = &self.root else {
            return;
        };
        let file = if dir.is_empty() {
            root.join(IGNORE_FILE)
        } else {
            root.join(dir).join(IGNORE_FILE)
        };
        // Never through a link: `symlink_metadata` says what the name is.
        let Ok(md) = std::fs::symlink_metadata(&file) else {
            return;
        };
        if !md.file_type().is_file() {
            return;
        }
        use std::io::Read;
        let mut text = String::new();
        if let Ok(f) = std::fs::File::open(&file) {
            let _ = f.take(MAX_FILE).read_to_string(&mut text);
        }
        let set = RuleSet::parse(&text);
        if !set.patterns.is_empty() {
            self.sets.insert(dir.to_string(), set);
        }
    }

    /// The decision for `path` itself, its directories assumed not ignored.
    fn decide_one(&mut self, path: &str, is_dir: bool) -> Option<Verdict> {
        let comps: Vec<&str> = path.split('/').collect();
        if let Some(p) = self.local.decide(&comps, is_dir) {
            return Some(verdict(p, "local".into(), path));
        }
        // Deepest directory first: "a/b/c" asks "a/b", "a", "".
        for depth in (0..comps.len()).rev() {
            let dir = comps[..depth].join("/");
            self.ensure(&dir);
            if let Some(set) = self.sets.get(&dir) {
                if let Some(p) = set.decide(&comps[depth..], is_dir) {
                    let source = if dir.is_empty() {
                        IGNORE_FILE.to_string()
                    } else {
                        format!("{dir}/{IGNORE_FILE}")
                    };
                    return Some(verdict(p, source, path));
                }
            }
        }
        None
    }

    /// Whether a path met during a walk from the root is ignored. The walk
    /// does not enter ignored directories, so only the path itself counts.
    pub fn walk_ignored(&mut self, path: &str, is_dir: bool) -> bool {
        self.decide_one(path, is_dir).is_some_and(|v| v.ignored)
    }

    /// Whether `path` (a manifest path) is ignored, its directories included.
    pub fn is_ignored(&mut self, path: &str, is_dir: bool) -> bool {
        self.explain(path, is_dir).ignored
    }

    /// The decision for `path` and what made it.
    pub fn explain(&mut self, path: &str, is_dir: bool) -> Verdict {
        let path = path.trim_matches('/');
        if path.is_empty() {
            return Verdict::default();
        }
        let comps: Vec<&str> = path.split('/').collect();
        for i in 1..comps.len() {
            let dir = comps[..i].join("/");
            if let Some(v) = self.decide_one(&dir, true) {
                if v.ignored {
                    return v;
                }
            }
        }
        self.decide_one(path, is_dir).unwrap_or_default()
    }
}

fn verdict(p: &Pattern, source: String, path: &str) -> Verdict {
    Verdict {
        ignored: !p.negated,
        pattern: Some(p.text.clone()),
        source: Some(source),
        line: Some(p.line),
        matched_path: Some(path.to_string()),
    }
}

/// `text` with `pattern` added as a line (unless it is there already).
pub fn add_line(text: &str, pattern: &str) -> (String, bool) {
    let pattern = pattern.trim_end_matches(['\r', '\n']);
    if text.lines().any(|l| l.trim_end() == pattern) {
        return (text.to_string(), false);
    }
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(pattern);
    out.push('\n');
    (out, true)
}

/// `text` without the lines that are `pattern`.
pub fn remove_line(text: &str, pattern: &str) -> (String, bool) {
    let mut removed = false;
    let mut out = String::new();
    for l in text.lines() {
        if l.trim_end() == pattern {
            removed = true;
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    (out, removed)
}

/// Refuse a pattern that cannot be one line of an ignore file.
pub fn check_pattern(pattern: &str) -> anyhow::Result<()> {
    if pattern.trim().is_empty() {
        anyhow::bail!("an ignore pattern must not be empty");
    }
    if pattern.contains(['\n', '\r', '\0']) || pattern.len() > MAX_PATTERN {
        anyhow::bail!("an ignore pattern is one line of at most {MAX_PATTERN} bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(root: &str) -> Matcher {
        Matcher::from_texts(&[("", root)], &[])
    }

    #[test]
    fn names_match_at_any_depth() {
        let mut r = m("*.tmp\n.DS_Store\n");
        assert!(r.is_ignored("a.tmp", false));
        assert!(r.is_ignored("x/y/a.tmp", false));
        assert!(r.is_ignored("x/.DS_Store", false));
        assert!(!r.is_ignored("a.tmpx", false));
        assert!(!r.is_ignored("tmp", false));
        // A directory named like the pattern hides what is inside it.
        assert!(r.is_ignored("dir.tmp/inner.txt", false));
    }

    #[test]
    fn comments_blanks_and_escapes() {
        let mut r = m("# a comment\n\n\\#hash\n\\!bang\ntrailing   \nkeep\\ \n");
        assert!(!r.is_ignored("# a comment", false));
        assert!(r.is_ignored("#hash", false));
        assert!(r.is_ignored("!bang", false));
        assert!(r.is_ignored("trailing", false));
        assert!(r.is_ignored("keep ", false));
        assert!(!r.is_ignored("keep", false));
    }

    #[test]
    fn negation_re_includes_and_last_match_wins() {
        let mut r = m("*.log\n!important.log\n");
        assert!(r.is_ignored("debug.log", false));
        assert!(!r.is_ignored("important.log", false));
        assert!(!r.is_ignored("sub/important.log", false));
        let mut r = m("!important.log\n*.log\n");
        assert!(r.is_ignored("important.log", false), "a later pattern wins");
    }

    #[test]
    fn a_file_in_an_ignored_directory_cannot_be_re_included() {
        let mut r = m("build/\n!build/keep.txt\n");
        assert!(r.is_ignored("build", true));
        assert!(r.is_ignored("build/keep.txt", false));
        // Ignoring the contents but not the directory allows it.
        let mut r = m("build/*\n!build/keep.txt\n");
        assert!(!r.is_ignored("build", true));
        assert!(r.is_ignored("build/other.txt", false));
        assert!(!r.is_ignored("build/keep.txt", false));
    }

    #[test]
    fn anchoring() {
        let mut r = m("/todo.txt\ndocs/*.pdf\n");
        assert!(r.is_ignored("todo.txt", false));
        assert!(!r.is_ignored("sub/todo.txt", false));
        assert!(r.is_ignored("docs/a.pdf", false));
        assert!(
            !r.is_ignored("docs/sub/a.pdf", false),
            "* stays in one component"
        );
        assert!(
            !r.is_ignored("other/docs/a.pdf", false),
            "a middle slash anchors"
        );
    }

    #[test]
    fn double_star() {
        let mut r = m("**/cache\nlogs/**\na/**/z\n");
        assert!(r.is_ignored("cache", true));
        assert!(r.is_ignored("x/y/cache", false));
        assert!(r.is_ignored("logs/one.txt", false));
        assert!(r.is_ignored("logs/deep/two.txt", false));
        assert!(!r.is_ignored("logs", true), "logs/** is what is inside");
        assert!(r.is_ignored("a/z", false));
        assert!(r.is_ignored("a/b/c/z", false));
        assert!(!r.is_ignored("b/a/z", false));
    }

    #[test]
    fn directory_only_patterns() {
        let mut r = m("out/\n");
        assert!(r.is_ignored("out", true));
        assert!(!r.is_ignored("out", false), "a file named out stays");
        assert!(r.is_ignored("src/out/x.o", false));
    }

    #[test]
    fn wildcards_and_classes() {
        let mut r = m("~$*\n.~lock.*#\nfile?.txt\n[abc]x\n[!0-9]y\n[\n");
        assert!(r.is_ignored("~$report.docx", false));
        assert!(r.is_ignored(".~lock.notes.odt#", false));
        assert!(r.is_ignored("file1.txt", false));
        assert!(!r.is_ignored("file10.txt", false));
        assert!(r.is_ignored("bx", false));
        assert!(!r.is_ignored("dx", false));
        assert!(r.is_ignored("ay", false));
        assert!(!r.is_ignored("5y", false));
        assert!(r.is_ignored("[", false), "an unclosed [ is literal");
        let mut r = m("a*b*c\n");
        assert!(r.is_ignored("abc", false));
        assert!(r.is_ignored("aXXbYYc", false));
        assert!(!r.is_ignored("aXXbYY", false));
    }

    #[test]
    fn nested_files_apply_to_their_subtree() {
        let mut r = Matcher::from_texts(
            &[
                ("", "*.bak\n"),
                ("photos", "/raw/\n!keep.bak\n"),
                ("photos/x", "*.jpg\n"),
            ],
            &[],
        );
        assert!(r.is_ignored("a.bak", false));
        assert!(r.is_ignored("docs/a.bak", false));
        assert!(
            !r.is_ignored("photos/keep.bak", false),
            "deeper file overrides"
        );
        assert!(r.is_ignored("photos/other.bak", false));
        assert!(r.is_ignored("photos/raw/1.cr2", false));
        assert!(!r.is_ignored("raw/1.cr2", false), "anchored to photos/");
        assert!(r.is_ignored("photos/x/a.jpg", false));
        assert!(!r.is_ignored("photos/a.jpg", false));
        let v = r.explain("photos/raw/1.cr2", false);
        assert_eq!(v.source.as_deref(), Some("photos/.varstoignore"));
        assert_eq!(v.pattern.as_deref(), Some("/raw/"));
        assert_eq!(v.matched_path.as_deref(), Some("photos/raw"));
    }

    #[test]
    fn local_rules_come_first() {
        let mut r = Matcher::from_texts(
            &[("", "*.iso\n")],
            &["big/".to_string(), "!keep.iso".to_string()],
        );
        assert!(r.is_ignored("big/a.txt", false));
        assert!(!r.is_ignored("keep.iso", false));
        assert!(r.is_ignored("other.iso", false));
        assert_eq!(r.explain("big", true).source.as_deref(), Some("local"));
    }

    #[test]
    fn files_are_read_from_disk_lazily() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("sub")).unwrap();
        std::fs::write(tmp.path().join(IGNORE_FILE), "*.o\n").unwrap();
        std::fs::write(tmp.path().join("sub").join(IGNORE_FILE), "!keep.o\n").unwrap();
        let mut r = Matcher::new(Some(tmp.path()), &[]);
        assert!(r.is_ignored("x.o", false));
        assert!(!r.is_ignored("sub/keep.o", false));
        assert!(r.is_ignored("sub/x.o", false));
    }

    #[test]
    fn editing_lines() {
        let (t, added) = add_line("a\nb", "c");
        assert!(added);
        assert_eq!(t, "a\nb\nc\n");
        assert!(!add_line(&t, "b").1);
        let (t, removed) = remove_line(&t, "b");
        assert!(removed);
        assert_eq!(t, "a\nc\n");
        assert!(check_pattern("x\ny").is_err());
        assert!(check_pattern(" ").is_err());
    }
}
