//! Wire-level integration tests for the D-230 wiring tool
//! (`code.feedback`) against the real `seahawk` binary and a
//! fake stdio tooling server (`tests/fixtures/fake_tooling.py`)
//! standing in for theodolite/periscope — the theodolite
//! `fake_lsp.rs` precedent: test doubles live in-tree.
//!
//! The battery keeps the estate's validation/adversarial split:
//! clean and dirty diagnostics round-trip with exact counts;
//! unconfigured tooling, unregistered workspaces, escaping
//! file paths, forced routes that cannot serve a check, and
//! the episode bound all refuse with their exact typed codes.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

const AGENT_TOKEN: &str = "wire-agent-token";

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fake_tooling.py")
}

struct Scratch {
    dir: PathBuf,
    workspace: PathBuf,
}

impl Scratch {
    /// Builds a scratch tree: a broker config plus a registered
    /// workspace holding `src/good.rs` and `src/bad.rs`.
    /// `tooling` is the raw `[[tooling]]`/`[feedback]` TOML tail.
    fn new(tooling_tail: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seahawk-feedback-wire-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let workspace = dir.join("project");
        std::fs::create_dir_all(workspace.join("src")).expect("mkdir workspace");
        std::fs::write(workspace.join("src").join("good.rs"), "fn main() {}\n").expect("good.rs");
        std::fs::write(workspace.join("src").join("bad.rs"), "fn broken( {}\n").expect("bad.rs");
        std::fs::write(
            workspace.join("src").join("unformatted.rs"),
            "fn   main( ) {}\n",
        )
        .expect("unformatted.rs");
        let body = format!(
            "[server]\nagent_token = \"{AGENT_TOKEN}\"\n\
             [downstream]\nurl = \"http://127.0.0.1:9/mcp\"\ntimeout_secs = 5\n\
             {tooling_tail}\n\
             [oplog]\npath = \"{}\"\n",
            dir.join("oplog.jsonl").display()
        );
        std::fs::write(dir.join("seahawk.toml"), body).expect("write config");
        Scratch { dir, workspace }
    }

    fn oplog_text(&self) -> String {
        std::fs::read_to_string(self.dir.join("oplog.jsonl")).unwrap_or_default()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    buffered: Vec<Value>,
    next_id: i64,
    scratch: Scratch,
}

impl Session {
    fn spawn(tooling_tail: &str) -> Self {
        let scratch = Scratch::new(tooling_tail);
        let mut child = Command::new(env!("CARGO_BIN_EXE_seahawk"))
            .arg(scratch.dir.join("seahawk.toml"))
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn seahawk");
        let stdin = child.stdin.take().expect("stdin");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let mut session = Session {
            child,
            stdin,
            lines: rx,
            buffered: Vec::new(),
            next_id: 0,
            scratch,
        };
        session.rpc(
            "server/discover",
            json!({"_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "feedback-wire", "version": "0"},
                "io.modelcontextprotocol/clientCapabilities": {},
            }}),
        );
        session
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{frame}").expect("write frame");
        self.stdin.flush().expect("flush");
        if let Some(pos) = self
            .buffered
            .iter()
            .position(|value| value.get("id").and_then(Value::as_i64) == Some(id))
        {
            return self.buffered.remove(pos);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(25);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero(), "timeout waiting for id {id}");
            let line = self.lines.recv_timeout(remaining).expect("channel");
            let value: Value = serde_json::from_str(&line).expect("json line");
            if value.get("id").and_then(Value::as_i64) == Some(id) {
                return value;
            }
            self.buffered.push(value);
        }
    }

    fn call(&mut self, name: &str, arguments: Value) -> Value {
        self.rpc(
            "tools/call",
            json!({
                "name": name,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "feedback-wire", "version": "0"},
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "seahawk/agent_token": AGENT_TOKEN,
                }
            }),
        )
    }

    fn feedback(&mut self, arguments: Value) -> Value {
        self.call("code.feedback", arguments)
    }

    fn workspace(&self) -> String {
        self.scratch.workspace.display().to_string()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn structured(frame: &Value) -> Value {
    frame
        .get("result")
        .and_then(|r| r.get("structuredContent"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn error_code(frame: &Value) -> Option<String> {
    structured(frame)
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn theodolite_tail(workspace: &Path) -> String {
    format!(
        "[[tooling]]\nid = \"theodolite\"\ncommand = \"python3\"\n\
         args = [\"{}\", \"theodolite\"]\ntimeout_secs = 30\n\
         diagnostics_servers = {{ rs = \"bacon-ls\" }}\n\
         [feedback]\nproject_roots = [\"{}\"]\n",
        fixture_path().display(),
        workspace.display()
    )
}

fn both_tail(workspace: &Path) -> String {
    format!(
        "[[tooling]]\nid = \"theodolite\"\ncommand = \"python3\"\n\
         args = [\"{}\", \"theodolite\"]\ntimeout_secs = 30\n\
         diagnostics_servers = {{ rs = \"bacon-ls\" }}\n\
         [[tooling]]\nid = \"periscope\"\ncommand = \"python3\"\n\
         args = [\"{}\", \"periscope\"]\ntimeout_secs = 30\n\
         [feedback]\nproject_roots = [\"{}\"]\n",
        fixture_path().display(),
        fixture_path().display(),
        workspace.display()
    )
}

/// A session whose workspace is registered, with a tail built
/// against that workspace (configs name the root, so spawn in
/// two steps: probe scratch for the path, then build the real
/// one). Simpler: tails take the workspace of a throwaway
/// scratch — but roots must match the session's own workspace,
/// so build the tail from a first scratch's layout: all
/// scratches share the same relative layout, but not the path.
/// Instead, spawn with a placeholder and rebuild: this helper
/// creates the scratch first, then the config, by hand.
fn spawn_with(tail_for: fn(&Path) -> String) -> Session {
    // Session::spawn builds its own scratch internally; to give
    // the config the right project root we exploit that Scratch
    // paths differ only in the counter — so instead we create
    // the session in the same shape manually here.
    let scratch = Scratch::new("");
    let tail = tail_for(&scratch.workspace);
    let body = format!(
        "[server]\nagent_token = \"{AGENT_TOKEN}\"\n\
         [downstream]\nurl = \"http://127.0.0.1:9/mcp\"\ntimeout_secs = 5\n\
         {tail}\n\
         [oplog]\npath = \"{}\"\n",
        scratch.dir.join("oplog.jsonl").display()
    );
    std::fs::write(scratch.dir.join("seahawk.toml"), body).expect("write config");
    let mut child = Command::new(env!("CARGO_BIN_EXE_seahawk"))
        .arg(scratch.dir.join("seahawk.toml"))
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn seahawk");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut session = Session {
        child,
        stdin,
        lines: rx,
        buffered: Vec::new(),
        next_id: 0,
        scratch,
    };
    session.rpc(
        "server/discover",
        json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "feedback-wire", "version": "0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }}),
    );
    session
}

#[test]
fn feedback_tool_is_listed_read_only() {
    let mut session = Session::spawn("");
    let frame = session.rpc(
        "tools/list",
        json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "feedback-wire", "version": "0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }}),
    );
    let tools = frame["result"]["tools"].as_array().expect("tools array");
    let feedback = tools
        .iter()
        .find(|tool| tool["name"] == "code.feedback")
        .expect("code.feedback listed");
    assert_eq!(feedback["annotations"]["readOnlyHint"], true);
    assert_eq!(feedback["annotations"]["destructiveHint"], false);
    assert_eq!(feedback["inputSchema"]["type"], "object");
}

#[test]
fn unconfigured_tooling_refuses_typed_not_clean() {
    let mut session = spawn_with(|workspace| {
        format!(
            "[feedback]\nproject_roots = [\"{}\"]\n",
            workspace.display()
        )
    });
    let workspace = session.workspace();
    let frame = session.feedback(json!({"workspace": workspace, "files": ["src/good.rs"]}));
    assert_eq!(
        error_code(&frame).as_deref(),
        Some("seahawk_tooling_unavailable")
    );
}

#[test]
fn unregistered_workspace_is_refused() {
    let mut session = spawn_with(theodolite_tail);
    let frame = session.feedback(json!({"workspace": "/tmp", "files": ["x.rs"]}));
    assert_eq!(error_code(&frame).as_deref(), Some("seahawk_bad_arguments"));
}

#[test]
fn escaping_file_paths_are_refused() {
    let mut session = spawn_with(theodolite_tail);
    let workspace = session.workspace();
    for bad in ["../outside.rs", "/etc/passwd", "src/../../secret.rs"] {
        let frame = session.feedback(json!({"workspace": workspace, "files": [bad]}));
        assert_eq!(
            error_code(&frame).as_deref(),
            Some("seahawk_bad_arguments"),
            "{bad}"
        );
    }
}

#[test]
fn diagnostics_round_trip_clean_and_dirty_with_exact_counts() {
    let mut session = spawn_with(theodolite_tail);
    let workspace = session.workspace();
    let frame = session.feedback(json!({
        "workspace": workspace,
        "files": ["src/good.rs", "src/bad.rs"],
        "checks": ["diagnostics"],
    }));
    assert_eq!(error_code(&frame), None, "{frame}");
    let data = structured(&frame);
    assert_eq!(data["counts"]["errors"], 1);
    assert_eq!(data["counts"]["warnings"], 0);
    assert_eq!(data["dirty"], true);
    let files = data["files"].as_array().expect("files");
    let good = &files[0];
    assert_eq!(good["diagnostics"]["status"], "ok");
    assert_eq!(good["diagnostics"]["count"], 0);
    assert_eq!(good["file_sha256"].as_str().map(str::len), Some(64));
    let bad = &files[1];
    assert_eq!(bad["diagnostics"]["count"], 1);
    assert_eq!(bad["diagnostics"]["diagnostics"][0]["severity"], "error");
    assert_eq!(bad["diagnostics"]["diagnostics"][0]["source"], "bacon-ls");
    // The op log carries the feedback summary (SPEC §3.3).
    let log = session.scratch.oplog_text();
    assert!(log.contains("\"feedback\""), "{log}");
    assert!(log.contains("code.feedback"), "{log}");
}

#[test]
fn forced_route_that_cannot_serve_refuses() {
    let mut session = spawn_with(both_tail);
    let workspace = session.workspace();
    // theodolite has no lint by design: forcing it for lint is
    // a typed unavailability, never a silent reroute.
    let frame = session.feedback(json!({
        "workspace": workspace,
        "files": ["src/good.rs"],
        "checks": ["lint"],
        "route": "theodolite",
    }));
    assert_eq!(
        error_code(&frame).as_deref(),
        Some("seahawk_tooling_unavailable")
    );
}

#[test]
fn periscope_lint_and_format_checks_answer() {
    let mut session = spawn_with(both_tail);
    let workspace = session.workspace();
    let frame = session.feedback(json!({
        "workspace": workspace,
        "files": ["src/unformatted.rs"],
        "checks": ["lint", "format"],
    }));
    assert_eq!(error_code(&frame), None, "{frame}");
    let data = structured(&frame);
    let file = &data["files"][0];
    assert_eq!(file["lint"]["status"], "ok");
    assert_eq!(file["lint"]["linters"][0]["name"], "clippy");
    assert_eq!(file["format"]["changed"], true);
    assert_eq!(file["format"]["written"], false);
    assert_eq!(data["counts"]["format_changed"], 1);
    // The catalog snapshot rode along (periscope configured).
    assert_eq!(
        data["catalog"]["provenance"].as_str().map(str::len),
        Some(64)
    );
}

#[test]
fn episode_bound_refuses_the_fourth_dirty_call() {
    let mut session = spawn_with(theodolite_tail);
    let workspace = session.workspace();
    let args = json!({
        "workspace": workspace,
        "files": ["src/bad.rs"],
        "checks": ["diagnostics"],
    });
    for iteration in 1..=3 {
        let frame = session.feedback(args.clone());
        assert_eq!(error_code(&frame), None, "call {iteration}: {frame}");
        assert_eq!(structured(&frame)["iteration"], iteration);
    }
    let frame = session.feedback(args);
    assert_eq!(
        error_code(&frame).as_deref(),
        Some("seahawk_code_feedback_unresolved")
    );
}

#[test]
fn gdscript_diagnostics_without_periscope_are_unavailable() {
    let mut session = spawn_with(theodolite_tail);
    // Add a .gd file to the registered workspace.
    std::fs::write(
        session.scratch.workspace.join("src").join("main.gd"),
        "extends Node\n",
    )
    .expect("gd file");
    let workspace = session.workspace();
    let frame = session.feedback(json!({
        "workspace": workspace,
        "files": ["src/main.gd"],
        "checks": ["diagnostics"],
    }));
    assert_eq!(
        error_code(&frame).as_deref(),
        Some("seahawk_tooling_unavailable")
    );
}
