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

/// `varsto` with HOME and the XDG directories in the test directory, so a
/// running service touches nothing of the user's.
fn isolated(root: &std::path::Path, home: &std::path::Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_varsto"));
    c.arg("--home")
        .arg(home)
        .env("VARSTO_PASSPHRASE", PASS)
        .env("VARSTO_NO_INSTALL", "1")
        .env("VARSTO_NO_PORT_MAPPING", "1")
        .env("HOME", root)
        .env("XDG_DATA_HOME", root.join("xdg-data"))
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("DBUS_SESSION_BUS_ADDRESS", "disabled:")
        .env_remove("VARSTO_MCP_KEY")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    c
}

/// One request to the local service with an MCP key: (status, body).
fn with_key(port: u16, key: &str, method: &str, path: &str, body: &str) -> (u16, String) {
    use std::io::Read;
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        s,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Varsto-Mcp-Key: {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = String::new();
    s.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, body.to_string())
}

struct Kill(std::process::Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_scoped_key_reaches_only_its_folders_through_the_service() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (home, docs) = vault_with_docs(root);
    let run = |args: &[&str]| -> String {
        let out = isolated(root, &home).args(args).output().unwrap();
        assert!(
            out.status.success(),
            "varsto {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    // No grants yet: a key needs folders.
    let out = isolated(root, &home)
        .args(["mcp", "key", "create"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let created: serde_json::Value = serde_json::from_str(&run(&[
        "--json",
        "mcp",
        "key",
        "create",
        "--name",
        "llm",
        "--folders",
        "docs",
        "--analyse",
    ]))
    .unwrap();
    let key = created["key"].as_str().unwrap().to_string();
    assert!(key.starts_with("vmk_"));
    let listed = run(&["mcp", "key", "list"]);
    assert!(
        listed.contains("llm (") && listed.contains("docs: an") && listed.contains("never used"),
        "{listed}"
    );
    assert!(!listed.contains(&key));
    assert!(!fs::read_to_string(home.join("mcp-keys.json"))
        .unwrap()
        .contains(&key));
    let config = run(&["mcp", "config", "--client", "opencode"]);
    assert!(
        config.contains("\"VARSTO_MCP_KEY\"") && config.contains("\"mcp\""),
        "{config}"
    );

    // Without the service a key opens nothing.
    let mut c = Client::start(&home, &[("VARSTO_MCP_KEY", key.as_str())], false);
    let (err, text) = c.tool("varsto_folders", serde_json::json!({}));
    assert!(err && text.contains("service is not running"), "{text}");
    drop(c);

    let _service = Kill(
        isolated(root, &home)
            .args(["service", "run", "--port", "0", "--interval", "3600"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let t0 = std::time::Instant::now();
    let port = loop {
        let out = isolated(root, &home)
            .args(["--json", "service", "status"])
            .output()
            .unwrap();
        if out.status.success() {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                if let Some(p) = v["port"].as_u64() {
                    break p as u16;
                }
            }
        }
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(30),
            "the service did not come up"
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    };

    // The service enforces the scope.
    let (st, body) = with_key(port, &key, "GET", "/api/files?folder=docs", "");
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("receipt.txt"));
    let (st, _) = with_key(port, &key, "GET", "/api/files?folder=other", "");
    assert_eq!(st, 403);
    let (st, body) = with_key(port, &key, "GET", "/api/folders", "");
    assert_eq!(st, 200);
    assert!(
        body.contains("\"docs\"") && !body.contains("\"other\""),
        "{body}"
    );
    let (st, _) = with_key(port, &key, "GET", "/api/devices", "");
    assert_eq!(st, 403, "not an MCP route");
    let (st, _) = with_key(port, &key, "POST", "/api/storage", "{}");
    assert_eq!(st, 403);
    let (st, _) = with_key(
        port,
        &key,
        "POST",
        "/api/move",
        r#"{"folder":"docs","from":"trip.txt","to":"t.txt"}"#,
    );
    assert_eq!(st, 403, "an analyse key moves nothing");
    let (st, _) = with_key(port, "vmk_0000", "GET", "/api/folders", "");
    assert_eq!(st, 401);
    // The status of a scoped key holds its folders and nothing about the
    // vault's devices, storages or paths.
    let (st, body) = with_key(port, &key, "GET", "/api/status", "");
    assert_eq!(st, 200, "{body}");
    let status: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        status.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["folders"],
        "{body}"
    );
    let names: Vec<&str> = status["folders"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["name"].as_str())
        .collect();
    assert_eq!(names, ["docs"], "{body}");
    assert!(!body.contains("laptop"), "no device names: {body}");

    // The MCP server without a key refuses to run while the service does:
    // the session token would give the assistant everything.
    let mut keyless = Client::start(&home, &[], false);
    let (err, text) = keyless.tool("varsto_folders", serde_json::json!({}));
    assert!(
        err && text.contains("needs an MCP key") && text.contains("mcp key create"),
        "{text}"
    );
    drop(keyless);

    // MCP end to end with the key and no passphrase.
    let mut c = Client::start(&home, &[("VARSTO_MCP_KEY", key.as_str())], false);
    let (err, folders) = c.tool("varsto_folders", serde_json::json!({}));
    assert!(!err, "{folders}");
    assert!(
        folders.contains("\"docs\"")
            && !folders.contains("\"other\"")
            && folders.contains("\"analyse\""),
        "{folders}"
    );
    let (err, text) = c.tool(
        "varsto_set_analysis",
        serde_json::json!({"folder": "docs", "path": "receipt.txt", "analysis": "Screws receipt", "tags": ["receipt"], "by": "test"}),
    );
    assert!(!err, "{text}");
    let (_, found) = c.tool(
        "varsto_search_analyses",
        serde_json::json!({"query": "screws"}),
    );
    assert!(
        found.contains("receipt.txt") && found.contains("local_path"),
        "{found}"
    );
    let (err, _) = c.tool(
        "varsto_move",
        serde_json::json!({"folder": "docs", "from": "trip.txt", "to": "t.txt"}),
    );
    assert!(err);
    let (err, _) = c.tool("varsto_files", serde_json::json!({"folder": "other"}));
    assert!(err);
    assert!(docs.join("trip.txt").exists());
    drop(c);
    assert!(run(&["mcp", "key", "list"]).contains("last used"));
    // The use is recorded apart from the keys, which a use never rewrites.
    assert!(home.join("mcp-keys-used.json").exists());
    let keys: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.join("mcp-keys.json")).unwrap()).unwrap();
    assert!(keys["keys"][0]["last_used_utc"].is_null(), "{keys}");

    // Expired, then revoked: 401.
    let raw = fs::read_to_string(home.join("mcp-keys.json")).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    v["keys"][0]["expires_utc"] = serde_json::json!(1);
    fs::write(home.join("mcp-keys.json"), v.to_string()).unwrap();
    let (st, body) = with_key(port, &key, "GET", "/api/folders", "");
    assert_eq!(st, 401);
    assert!(body.contains("expired"), "{body}");
    v["keys"][0]["expires_utc"] = serde_json::Value::Null;
    fs::write(home.join("mcp-keys.json"), v.to_string()).unwrap();
    assert_eq!(with_key(port, &key, "GET", "/api/folders", "").0, 200);
    run(&["mcp", "key", "revoke", "llm"]);
    assert_eq!(with_key(port, &key, "GET", "/api/folders", "").0, 401);
}
