//! Wire-level tests for tool-surface profiles (D-934) against
//! the real `seahawk` binary with a dead downstream (port 9:
//! connection refused, so the brokered surface is empty and
//! tools/list is exactly the native surface the profile
//! serves).
//!
//! Half validation / half adversarial, per the estate split:
//! profile selection by config / env / arg with precedence,
//! per-pack list shapes, calls outside the profile refused as
//! unknown tools — and the security invariants under profiles:
//! the guard's token refusal is unchanged, and a malformed
//! profile spec fails startup closed under every selector.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const AGENT_TOKEN: &str = "agent-secret";
const OPERATOR_TOKEN: &str = "operator-secret";

const CORE: [&str; 3] = ["seahawk_oplog", "seahawk_status", "seahawk_surface"];

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    /// `server_extra` is inserted into the `[server]` section
    /// (e.g. a `tool_profile = "..."` line); `tail` is appended
    /// to the whole file (e.g. `[[gui.apps]]` registrations).
    fn new(server_extra: &str, tail: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seahawk-profile-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir scratch");
        let body = format!(
            "[server]\nagent_token = \"{AGENT_TOKEN}\"\noperator_token = \"{OPERATOR_TOKEN}\"\n\
             {server_extra}\
             [downstream]\nurl = \"http://127.0.0.1:9/mcp\"\ntimeout_secs = 5\n\
             [oplog]\npath = \"{}\"\n{tail}",
            dir.join("oplog.jsonl").display()
        );
        std::fs::write(dir.join("seahawk.toml"), body).expect("write config");
        Scratch { dir }
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("seahawk.toml")
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
    _scratch: Scratch,
}

/// Spawns the binary against a fresh scratch config.
/// `env_profile` sets SEAHAWK_TOOL_PROFILE; `arg_profile`
/// appends `--profile <spec>` after the config path.
fn spawn(
    server_extra: &str,
    tail: &str,
    env_profile: Option<&str>,
    arg_profile: Option<&str>,
) -> Session {
    let scratch = Scratch::new(server_extra, tail);
    let mut command = Command::new(env!("CARGO_BIN_EXE_seahawk"));
    command
        .arg(scratch.config_path())
        .env_remove("SEAHAWK_TOOL_PROFILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(spec) = env_profile {
        command.env("SEAHAWK_TOOL_PROFILE", spec);
    }
    if let Some(spec) = arg_profile {
        command.arg("--profile").arg(spec);
    }
    let mut child = command.spawn().expect("spawn seahawk");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        return;
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
        _scratch: scratch,
    };
    session.handshake();
    session
}

impl Session {
    fn send(&mut self, frame: &Value) {
        let mut line = serde_json::to_string(frame).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv_for(&mut self, id: i64) -> Value {
        if let Some(pos) = self
            .buffered
            .iter()
            .position(|f| f.get("id").and_then(Value::as_i64) == Some(id))
        {
            return self.buffered.remove(pos);
        }
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "timeout waiting for id {id}");
            let line = self
                .lines
                .recv_timeout(remaining)
                .expect("channel closed waiting for response");
            let frame: Value = serde_json::from_str(&line)
                .unwrap_or_else(|_| panic!("non-JSON frame from seahawk: {line}"));
            if frame.get("id").and_then(Value::as_i64) == Some(id) {
                return frame;
            }
            self.buffered.push(frame);
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        self.recv_for(id)
    }

    fn handshake(&mut self) {
        let response = self.rpc("server/discover", json!({"_meta": meta()}));
        assert!(
            response.get("result").is_some(),
            "discover failed: {response}"
        );
    }

    fn list_names(&mut self) -> Vec<String> {
        let response = self.rpc("tools/list", json!({"_meta": meta()}));
        let tools = response["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list shape: {response}"));
        let mut names: Vec<String> = tools
            .iter()
            .map(|t| t["name"].as_str().expect("tool name").to_string())
            .collect();
        names.sort();
        names
    }

    fn call(&mut self, name: &str, arguments: Value, token: Option<&str>) -> Value {
        let mut meta_map = meta().as_object().unwrap().clone();
        if let Some(token) = token {
            meta_map.insert("seahawk/agent_token".to_string(), json!(token));
        }
        self.rpc(
            "tools/call",
            json!({"name": name, "arguments": arguments, "_meta": Value::Object(meta_map)}),
        )
    }

    fn status_profile(&mut self) -> String {
        let response = self.call("seahawk_status", json!({}), Some(AGENT_TOKEN));
        response["result"]["structuredContent"]["tool_profile"]
            .as_str()
            .unwrap_or_else(|| panic!("status lacks tool_profile: {response}"))
            .to_string()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "seahawk-profile-test", "version": "0.1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

fn sorted(names: &[&str]) -> Vec<String> {
    let mut names: Vec<String> = names.iter().map(|name| name.to_string()).collect();
    names.sort();
    names
}

fn core_plus(extra: &[&str]) -> Vec<String> {
    let mut names = sorted(&CORE);
    names.extend(extra.iter().map(|name| name.to_string()));
    names.sort();
    names
}

fn structured_error_code(response: &Value) -> Option<String> {
    response
        .get("result")
        .and_then(|r| r.get("structuredContent"))
        .and_then(|s| s.get("error"))
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// Validation: profile shapes and precedence
// ---------------------------------------------------------------------------

#[test]
fn default_profile_serves_core_only() {
    let mut s = spawn("", "", None, None);
    assert_eq!(s.list_names(), sorted(&CORE));
    assert_eq!(s.status_profile(), "core");
}

#[test]
fn full_profile_serves_all_native_tools() {
    let mut s = spawn("", "", Some("full"), None);
    assert_eq!(
        s.list_names(),
        core_plus(&[
            "code.feedback",
            "gui.act_verified",
            "gui.ground",
            "gui.observe",
            "seahawk_acquire",
        ])
    );
    assert_eq!(s.status_profile(), "full");
}

#[test]
fn each_pack_serves_its_family_plus_core() {
    let cases: [(&str, &[&str]); 5] = [
        ("acquire", &["seahawk_acquire"]),
        ("broker", &[]),
        ("feedback", &["code.feedback"]),
        ("gui", &[]),
        ("vision", &["gui.act_verified", "gui.ground", "gui.observe"]),
    ];
    for (pack, extra) in cases {
        let mut s = spawn("", "", None, Some(pack));
        assert_eq!(s.list_names(), core_plus(extra), "pack {pack}");
        assert_eq!(s.status_profile(), pack, "pack {pack}");
    }
}

#[test]
fn gui_pack_serves_registered_app_tools() {
    let tail = "[[gui.apps]]\nname = \"blender\"\ndisplay_name = \"Blender\"\nwindow_match = [\"Blender\"]\n";
    let mut s = spawn("", tail, None, Some("gui"));
    assert_eq!(
        s.list_names(),
        core_plus(&["gui.blender.actuate", "gui.blender.observe"])
    );
    // Without the pack, the same registration serves nothing.
    let mut s = spawn("", tail, None, None);
    assert_eq!(s.list_names(), sorted(&CORE));
}

#[test]
fn packs_combine() {
    let mut s = spawn("", "", None, Some("acquire,feedback"));
    assert_eq!(
        s.list_names(),
        core_plus(&["code.feedback", "seahawk_acquire"])
    );
    assert_eq!(s.status_profile(), "acquire,feedback");
}

#[test]
fn precedence_arg_beats_env_beats_config() {
    // Config alone.
    let mut s = spawn("tool_profile = \"acquire\"\n", "", None, None);
    assert_eq!(s.status_profile(), "acquire");
    // Env beats config.
    let mut s = spawn("tool_profile = \"acquire\"\n", "", Some("vision"), None);
    assert_eq!(s.status_profile(), "vision");
    // Arg beats env and config.
    let mut s = spawn(
        "tool_profile = \"acquire\"\n",
        "",
        Some("vision"),
        Some("feedback"),
    );
    assert_eq!(s.status_profile(), "feedback");
    assert_eq!(s.list_names(), core_plus(&["code.feedback"]));
}

// ---------------------------------------------------------------------------
// Adversarial: scoping is real, startup fails closed, auth intact
// ---------------------------------------------------------------------------

#[test]
fn call_outside_profile_is_refused_as_unknown_tool() {
    let mut s = spawn("", "", None, None);
    for name in ["seahawk_acquire", "gui.observe", "code.feedback"] {
        let response = s.call(name, json!({}), Some(AGENT_TOKEN));
        assert_eq!(
            structured_error_code(&response).as_deref(),
            Some("seahawk_unknown_tool"),
            "{name}: {response}"
        );
    }
    // A case variant of an unserved name is refused identically:
    // classification follows the dispatch case discipline.
    let response = s.call("GUI.OBSERVE", json!({}), Some(AGENT_TOKEN));
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_unknown_tool")
    );
    // A served core tool still answers under the same profile.
    let response = s.call("seahawk_status", json!({}), Some(AGENT_TOKEN));
    assert_eq!(
        response["result"]["structuredContent"]["server"],
        json!("seahawk")
    );
}

/// Spawns with stderr captured and asserts the process refuses
/// to start: non-zero exit, quickly, naming the failure and the
/// valid packs.
fn assert_startup_refused(
    scratch: &Scratch,
    env_profile: Option<&str>,
    arg_profile: Option<&str>,
    failure_fragment: &str,
) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_seahawk"));
    command
        .arg(scratch.config_path())
        .env_remove("SEAHAWK_TOOL_PROFILE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(spec) = env_profile {
        command.env("SEAHAWK_TOOL_PROFILE", spec);
    }
    if let Some(spec) = arg_profile {
        command.arg("--profile").arg(spec);
    }
    let mut child = command.spawn().expect("spawn seahawk");
    let deadline = Instant::now() + Duration::from_secs(25);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break status,
            None => {
                assert!(
                    Instant::now() < deadline,
                    "server with a bad profile did not exit"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    assert!(!status.success(), "bad profile must refuse startup");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(
        stderr.contains(failure_fragment),
        "stderr names the failure: {stderr}"
    );
    assert!(
        stderr.contains("core, full, acquire, broker, feedback, gui, vision"),
        "stderr lists the valid packs: {stderr}"
    );
}

#[test]
fn unknown_pack_fails_closed_under_every_selector() {
    // Via --profile.
    let scratch = Scratch::new("", "");
    assert_startup_refused(&scratch, None, Some("visionn"), "unknown pack");
    // Via the environment.
    let scratch = Scratch::new("", "");
    assert_startup_refused(&scratch, Some("broker,gihub"), None, "unknown pack");
    // Via the config file (validated at load, so startup fails
    // even though nothing overrides it).
    let scratch = Scratch::new("tool_profile = \"ful\"\n", "");
    assert_startup_refused(&scratch, None, None, "unknown pack");
    // `full` combined with a pack is malformed, not generous.
    let scratch = Scratch::new("", "");
    assert_startup_refused(&scratch, None, Some("full,broker"), "combines 'full'");
}

#[test]
fn guard_token_refusal_is_unchanged_under_profiles() {
    for env_profile in [None, Some("full")] {
        let mut s = spawn("", "", env_profile, None);
        // No token at all: guard refusal, JSON-RPC error -32001.
        let response = s.call("seahawk_status", json!({}), None);
        assert_eq!(response["error"]["code"], json!(-32001), "{response}");
        assert_eq!(
            response["error"]["data"]["code"],
            json!("seahawk_unauthorized")
        );
        assert_eq!(response["error"]["data"]["reason"], json!("missing_token"));
        // Wrong token: same refusal, bad_token reason.
        let response = s.call("seahawk_status", json!({}), Some("wrong-token"));
        assert_eq!(response["error"]["code"], json!(-32001), "{response}");
        assert_eq!(response["error"]["data"]["reason"], json!("bad_token"));
        // The operator token is not the agent token.
        let response = s.call("seahawk_status", json!({}), Some(OPERATOR_TOKEN));
        assert_eq!(response["error"]["code"], json!(-32001), "{response}");
    }
}
