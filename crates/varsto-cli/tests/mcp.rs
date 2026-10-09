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
    let grants = varsto(&home, &["mcp", "list"]);
    assert!(grants.contains("\"docs\": \"rw\""));

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

    let read = call(
        "tools/call",
        serde_json::json!({"name": "varsto_read", "arguments": {"folder": "docs", "path": "notes.md"}}),
    );
    assert!(read["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("cold storage"));

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
