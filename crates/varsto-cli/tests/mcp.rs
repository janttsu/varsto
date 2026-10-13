// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The MCP server end to end: a vault with one folder, grants, then a client
//! speaking JSON-RPC over the binary's stdin/stdout.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const PASS: &str = "correct horse battery staple";

fn varsto(home: &std::path::Path, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env("VARSTO_PASSPHRASE", PASS)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "varsto {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn mcp_server_answers_with_granted_access_only() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let store = tmp.path().join("store");
    let docs = tmp.path().join("docs");
    let secret = tmp.path().join("secret");
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::create_dir_all(&secret).unwrap();
    std::fs::write(
        docs.join("notes.md"),
        "# plan\nmove old videos to cold storage\n",
    )
    .unwrap();
    std::fs::write(secret.join("taxes.txt"), "not for assistants").unwrap();
    varsto(&home, &["init", "--name", "laptop"]);
    varsto(
        &home,
        &["storage", "add-local", "box", store.to_str().unwrap()],
    );
    varsto(&home, &["folder", "add", "docs", docs.to_str().unwrap()]);
    varsto(
        &home,
        &["folder", "add", "secret", secret.to_str().unwrap()],
    );
    varsto(&home, &["sync"]);
    varsto(&home, &["mcp", "grant", "docs", "--write"]);
    let grants = varsto(&home, &["--json", "mcp", "list"]);
    assert!(grants.contains("\"docs\": \"rw\""));
    let grants = varsto(&home, &["mcp", "list"]);
    assert!(grants.contains("docs: rw (read-write"), "{grants}");

    let mut child = Command::new(env!("CARGO_BIN_EXE_varsto"))
        .arg("--home")
        .arg(&home)
        .arg("mcp")
        .env("VARSTO_PASSPHRASE", PASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut next_id = 0;
    let mut call = |method: &str, params: serde_json::Value| -> serde_json::Value {
        next_id += 1;
        let req = serde_json::json!({"jsonrpc": "2.0", "id": next_id, "method": method, "params": params});
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).expect("json line");
        assert_eq!(v["id"], next_id);
        v
    };
    let init = call(
        "initialize",
        serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "varsto");
    let tools = call("tools/list", serde_json::json!({}));
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"varsto_files") && names.contains(&"varsto_storage_advice"));

    let folders = call(
        "tools/call",
        serde_json::json!({"name": "varsto_folders", "arguments": {}}),
    );
    let text = folders["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("\"docs\"") && !text.contains("\"secret\""),
        "only granted folders are visible: {text}"
    );

    let denied = call(
        "tools/call",
        serde_json::json!({"name": "varsto_files", "arguments": {"folder": "secret"}}),
    );
    assert_eq!(denied["result"]["isError"], true);

    let files = call(
        "tools/call",
        serde_json::json!({"name": "varsto_files", "arguments": {"folder": "docs"}}),
    );
    let text = files["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("notes.md") && text.contains("last_accessed_utc"));

    // Contents are not handed out: the assistant reads the synced file from
    // its local path with its own tools.
    let listed: serde_json::Value = serde_json::from_str(text).unwrap();
    let local = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "notes.md")
        .and_then(|f| f["local_path"].as_str())
        .expect("a synced plain file has a local_path")
        .to_string();
    assert!(fs::read_to_string(&local).unwrap().contains("cold storage"));
    let read = call(
        "tools/call",
        serde_json::json!({"name": "varsto_read", "arguments": {"folder": "docs", "path": "notes.md"}}),
    );
    assert_eq!(
        read["result"]["isError"], true,
        "there is no read tool: {read}"
    );

    let moved = call(
        "tools/call",
        serde_json::json!({"name": "varsto_move", "arguments": {"folder": "docs", "from": "notes.md", "to": "2026/notes.md"}}),
    );
    assert_ne!(moved["result"]["isError"], true, "{moved}");
    assert!(docs.join("2026/notes.md").exists());

    // Nothing is ever replaced: writing to an existing name and moving onto
    // one are refused, a new name works, and there is no delete tool.
    let original = fs::read(docs.join("2026/notes.md")).unwrap();
    let overwrite = call(
        "tools/call",
        serde_json::json!({"name": "varsto_write", "arguments": {"folder": "docs", "path": "2026/notes.md", "text": "replaced"}}),
    );
    assert_eq!(overwrite["result"]["isError"], true, "{overwrite}");
    assert_eq!(fs::read(docs.join("2026/notes.md")).unwrap(), original);
    let index = call(
        "tools/call",
        serde_json::json!({"name": "varsto_write", "arguments": {"folder": "docs", "path": "INDEX.md", "text": "notes.md -> 2026/"}}),
    );
    assert_ne!(index["result"]["isError"], true, "{index}");
    let onto = call(
        "tools/call",
        serde_json::json!({"name": "varsto_move", "arguments": {"folder": "docs", "from": "INDEX.md", "to": "2026/notes.md"}}),
    );
    assert_eq!(onto["result"]["isError"], true, "{onto}");
    assert_eq!(fs::read(docs.join("2026/notes.md")).unwrap(), original);
    assert!(docs.join("INDEX.md").exists());
    let tools = call("tools/list", serde_json::json!({}));
    assert!(
        !tools.to_string().contains("delete"),
        "no delete tool: {tools}"
    );

    let advice = call(
        "tools/call",
        serde_json::json!({"name": "varsto_storage_advice", "arguments": {"idle_days": 0}}),
    );
    let text = advice["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("estimates") && text.contains("source_url"));

    drop(stdin);
    let _ = child.wait();
}

/// A JSON-RPC client of `varsto mcp` over the child's stdin and stdout.
struct Client {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl Client {
    fn start(home: &std::path::Path, extra_env: &[(&str, &str)], with_pass: bool) -> Client {
        let mut c = Command::new(env!("CARGO_BIN_EXE_varsto"));
        c.arg("--home").arg(home).arg("mcp");
        if with_pass {
            c.env("VARSTO_PASSPHRASE", PASS);
        } else {
            c.env_remove("VARSTO_PASSPHRASE");
        }
        for (k, v) in extra_env {
            c.env(k, v);
        }
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut cl = Client {
            child,
            stdin,
            stdout,
            next_id: 0,
        };
        cl.call(
            "initialize",
            serde_json::json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}),
        );
        cl
    }
    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let req = serde_json::json!({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params});
        writeln!(self.stdin, "{req}").unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).expect("json line");
        assert_eq!(v["id"], self.next_id);
        v
    }
    /// A tool's result: (is an error, text).
    fn tool(&mut self, name: &str, args: serde_json::Value) -> (bool, String) {
        let v = self.call(
            "tools/call",
            serde_json::json!({"name": name, "arguments": args}),
        );
        (
            v["result"]["isError"] == true,
            v["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        )
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A vault with folders "docs" (two files) and "other" (one), synced.
fn vault_with_docs(tmp: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let home = tmp.join("home");
    let docs = tmp.join("docs");
    let other = tmp.join("other");
    fs::create_dir_all(&docs).unwrap();
    fs::create_dir_all(&other).unwrap();
    fs::write(
        docs.join("receipt.txt"),
        "Hardware store: screws, 12.40 EUR",
    )
    .unwrap();
    fs::write(docs.join("trip.txt"), "Train to Lyon on 9 December").unwrap();
    fs::write(other.join("x.txt"), "other").unwrap();
    varsto(&home, &["init", "--name", "laptop"]);
    let store = tmp.join("store");
    varsto(
        &home,
        &["storage", "add-local", "box", store.to_str().unwrap()],
    );
    varsto(&home, &["folder", "add", "docs", docs.to_str().unwrap()]);
    varsto(&home, &["folder", "add", "other", other.to_str().unwrap()]);
    varsto(&home, &["sync"]);
    (home, docs)
}

#[test]
fn an_analyse_grant_records_analyses_but_moves_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (home, docs) = vault_with_docs(tmp.path());
    varsto(&home, &["mcp", "grant", "docs", "--analyse"]);
    varsto(&home, &["mcp", "grant", "other"]);
    assert!(varsto(&home, &["mcp", "list"]).contains("docs: an (analyse"));
    let mut c = Client::start(&home, &[], true);
    let tools = c.call("tools/list", serde_json::json!({}));
    for t in [
        "varsto_set_analysis",
        "varsto_get_analysis",
        "varsto_search_analyses",
        "varsto_clear_analysis",
    ] {
        assert!(tools.to_string().contains(t), "{t}");
    }
    let (_, folders) = c.tool("varsto_folders", serde_json::json!({}));
    assert!(folders.contains("\"analyse\""), "{folders}");

    let (err, text) = c.tool(
        "varsto_set_analysis",
        serde_json::json!({"folder": "docs", "path": "receipt.txt", "analysis": "A hardware store receipt: screws for 12.40 EUR.", "tags": ["receipt", "hardware"], "by": "test-model"}),
    );
    assert!(!err, "{text}");
    c.tool(
        "varsto_set_analysis",
        serde_json::json!({"folder": "docs", "path": "trip.txt", "analysis": "Train ticket, Lyon, December.", "tags": ["travel"]}),
    );
    // Read-only folder: no analyses; analyse grant: no moves, no new files.
    let (err, _) = c.tool(
        "varsto_set_analysis",
        serde_json::json!({"folder": "other", "path": "x.txt", "analysis": "x"}),
    );
    assert!(err);
    let (err, _) = c.tool(
        "varsto_move",
        serde_json::json!({"folder": "docs", "from": "trip.txt", "to": "t.txt"}),
    );
    assert!(err);
    let (err, _) = c.tool(
        "varsto_write",
        serde_json::json!({"folder": "docs", "path": "new.txt", "text": "x"}),
    );
    assert!(err);
    assert!(docs.join("trip.txt").exists() && !docs.join("new.txt").exists());
    // Too long.
    let (err, text) = c.tool(
        "varsto_set_analysis",
        serde_json::json!({"folder": "docs", "path": "trip.txt", "analysis": "x".repeat(17_000)}),
    );
    assert!(err && text.contains("16384"), "{text}");

    // Listed with the files.
    let (_, files) = c.tool("varsto_files", serde_json::json!({"folder": "docs"}));
    let files: serde_json::Value = serde_json::from_str(&files).unwrap();
    let r = files
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "receipt.txt")
        .unwrap();
    assert!(r["analysis"].as_str().unwrap().contains("screws"));
    assert_eq!(
        r["analysis_tags"],
        serde_json::json!(["receipt", "hardware"])
    );
    assert_eq!(r["analysis_by"], "test-model");
    let (_, bare) = c.tool(
        "varsto_files",
        serde_json::json!({"folder": "docs", "with_analysis": false}),
    );
    assert!(!bare.contains("analysis"), "{bare}");
    let (_, full) = c.tool(
        "varsto_get_analysis",
        serde_json::json!({"folder": "docs", "path": "receipt.txt"}),
    );
    assert!(
        full.contains("12.40 EUR") && full.contains("\"stale\": false"),
        "{full}"
    );

    // Search by text and by tag, with the local path to read.
    let (_, found) = c.tool(
        "varsto_search_analyses",
        serde_json::json!({"query": "SCREWS"}),
    );
    let found: serde_json::Value = serde_json::from_str(&found).unwrap();
    assert_eq!(found["total"], 1, "{found}");
    let hit = &found["hits"][0];
    assert_eq!(hit["path"], "receipt.txt");
    assert_eq!(hit["folder"], "docs");
    assert!(hit["snippet"].as_str().unwrap().contains("screws"));
    let local = hit["local_path"].as_str().unwrap();
    assert!(fs::read_to_string(local).unwrap().contains("Hardware"));
    assert!(hit.get("disk").is_none());
    let (_, by_tag) = c.tool(
        "varsto_search_analyses",
        serde_json::json!({"folder": "docs", "tags": ["travel"]}),
    );
    assert!(
        by_tag.contains("trip.txt") && !by_tag.contains("receipt.txt"),
        "{by_tag}"
    );
    let (err, _) = c.tool(
        "varsto_search_analyses",
        serde_json::json!({"folder": "secret-nope", "query": "x"}),
    );
    assert!(err);

    // Clearing.
    let (err, text) = c.tool(
        "varsto_clear_analysis",
        serde_json::json!({"folder": "docs", "path": "trip.txt"}),
    );
    assert!(!err && text.contains("cleared"), "{text}");
    let (_, none) = c.tool(
        "varsto_get_analysis",
        serde_json::json!({"folder": "docs", "path": "trip.txt"}),
    );
    assert_eq!(none.trim(), "null");
}
