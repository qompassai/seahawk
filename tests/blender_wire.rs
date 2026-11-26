//! Wire-level tests for the Blender stroke provider surface
//! (DESIGN, seahawk-blender-20261124) against the real `seahawk`
//! binary and a mock provider: a std-TcpListener HTTP server
//! that speaks the provider's JSON-RPC dialect, checks the
//! provider-secret header, and records every request — so the
//! adversarial tests can prove a refusal happened *before* the
//! downstream was contacted (the mock's request log stays
//! empty), not merely that the caller saw an error.
//!
//! Half validation / half adversarial, per the estate split:
//! listing shape under the blender profile, a read round-trip,
//! a write round-trip, broker-local artifact validation — and
//! the guard proofs: execute without an operator token,
//! execute not enabled in policy, a path outside the roots, an
//! excluded-feature artifact, a tampered hash, an unknown
//! blender name.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const AGENT_TOKEN: &str = "agent-secret";
const OPERATOR_TOKEN: &str = "operator-secret";
const PROVIDER_SECRET: &str = "provider-secret";

const CORE: [&str; 4] = [
    "seahawk_oplog",
    "seahawk_status",
    "seahawk_surface",
    "target.list",
];

const BLENDER_TOOLS: [&str; 26] = [
    "blender.artifact_validate",
    "blender.blend_save",
    "blender.contact_sheet",
    "blender.curve_apply",
    "blender.curve_capture",
    "blender.gp_capture",
    "blender.gp_capture_range",
    "blender.gp_replay",
    "blender.gp_replay_range",
    "blender.image_export_png",
    "blender.paint_apply",
    "blender.pose_apply",
    "blender.pose_capture",
    "blender.proof_render",
    "blender.rig_apply",
    "blender.scene_census",
    "blender.scene_open",
    "blender.session_status",
    "blender.shells_along_flow",
    "blender.sim_bake",
    "blender.stroke_to_shell",
    "blender.take_apply",
    "blender.take_capture",
    "blender.take_export",
    "blender.take_render",
    "blender.take_validate",
];

// ---------------------------------------------------------------------------
// The mock provider
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    /// (method, params) of every request the provider received.
    requests: Vec<(String, Value)>,
}

struct Mock {
    port: u16,
    state: Arc<Mutex<MockState>>,
}

fn mock_provider() -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let port = listener.local_addr().expect("addr").port();
    let state = Arc::new(Mutex::new(MockState::default()));
    let thread_state = state.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let state = thread_state.clone();
            std::thread::spawn(move || {
                let _ = handle_connection(&mut stream, &state);
            });
        }
    });
    Mock { port, state }
}

fn handle_connection(
    stream: &mut std::net::TcpStream,
    state: &Arc<Mutex<MockState>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut content_length = 0usize;
    let mut secret_ok = false;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
        if lower.starts_with("x-seahawk-provider-secret:") {
            secret_ok = line
                .split_once(':')
                .map(|(_, v)| v.trim() == PROVIDER_SECRET)
                .unwrap_or(false);
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    let respond = |stream: &mut std::net::TcpStream, status: u16, payload: &str| {
        let frame = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n{payload}",
            payload.len()
        );
        let _ = stream.write_all(frame.as_bytes());
        let _ = stream.flush();
    };
    if !secret_ok {
        respond(stream, 403, "missing or wrong provider secret");
        return Ok(());
    }
    let frame: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let method = frame
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let params = frame.get("params").cloned().unwrap_or(Value::Null);
    let id = frame.get("id").cloned().unwrap_or(Value::Null);
    state
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .requests
        .push((method.clone(), params.clone()));
    let result = match method.as_str() {
        "initialize" => json!({
            "session_id": "mock-session-1",
            "blender_version": "5.3.0",
            "provider": "seahawk-mock",
        }),
        "session_status" => json!({
            "blender_version": "5.3.0",
            "provider": "seahawk-mock",
            "scene_open": false,
        }),
        "paint_apply" => json!({"applied": true}),
        "image_export_png" => {
            json!({"path": params.get("path").cloned().unwrap_or(Value::Null), "bytes": 3})
        }
        "scene_open" => json!({"opened": params.get("path").cloned().unwrap_or(Value::Null)}),
        _ => json!({}),
    };
    let payload = json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string();
    respond(stream, 200, &payload);
    Ok(())
}

impl Mock {
    fn request_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .requests
            .len()
    }

    fn methods(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .requests
            .iter()
            .map(|(method, _)| method.clone())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Scratch config + session harness (profile_wire's shape)
// ---------------------------------------------------------------------------

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    /// Builds a config whose [blender] section points at the
    /// mock on `port` (or, when `port` is None, has no [blender]
    /// section at all). All four path roots are the scratch dir.
    /// `policy_extra` is appended after the [policy] header the
    /// template writes.
    fn new(port: Option<u16>, policy_extra: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seahawk-blender-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir scratch");
        let blender = match port {
            Some(port) => format!(
                "[blender]\nurl = \"http://127.0.0.1:{port}/blender\"\ntimeout_secs = 10\n\
                 provider_secret = \"{PROVIDER_SECRET}\"\nexpected_blender = \"5.3.0\"\n\
                 [blender.paths]\nopen_roots = [\"{0}\"]\nsave_roots = [\"{0}\"]\n\
                 export_roots = [\"{0}\"]\nrender_roots = [\"{0}\"]\n",
                dir.display()
            ),
            None => String::new(),
        };
        let body = format!(
            "[server]\nagent_token = \"{AGENT_TOKEN}\"\noperator_token = \"{OPERATOR_TOKEN}\"\n\
             [downstream]\nurl = \"http://127.0.0.1:9/mcp\"\ntimeout_secs = 5\n\
             [policy]\nexecute_enabled = [\"blender.scene_open\", \"blender.image_export_png\"]\n\
             {policy_extra}\
             [oplog]\npath = \"{}\"\n{blender}",
            dir.join("oplog.jsonl").display()
        );
        std::fs::write(dir.join("seahawk.toml"), body).expect("write config");
        Scratch { dir }
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("seahawk.toml")
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

fn spawn(scratch: Scratch) -> Session {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seahawk"))
        .arg(scratch.config_path())
        .arg("--profile")
        .arg("blender")
        .env_remove("SEAHAWK_TOOL_PROFILE")
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
        scratch,
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

    /// Calls a tool. `operator` adds the per-call operator
    /// token to _meta (the agent token always rides).
    fn call(&mut self, name: &str, arguments: Value, operator: bool) -> Value {
        let mut meta_map = meta().as_object().unwrap().clone();
        meta_map.insert("seahawk/agent_token".to_string(), json!(AGENT_TOKEN));
        if operator {
            meta_map.insert("seahawk/operator_token".to_string(), json!(OPERATOR_TOKEN));
        }
        self.rpc(
            "tools/call",
            json!({"name": name, "arguments": arguments, "_meta": Value::Object(meta_map)}),
        )
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
        "io.modelcontextprotocol/clientInfo": {"name": "seahawk-blender-test", "version": "0.1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    })
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

fn structured(response: &Value) -> Value {
    response["result"]["structuredContent"].clone()
}

/// A small valid paint artifact, hash-stamped through the
/// broker's own public canonicalization (the same code the
/// gate runs).
fn paint_artifact() -> Value {
    let mut artifact = json!({
        "schema": "seahawk.stroke/v1",
        "kind": "paint_batch",
        "id": "wire-blush-1",
        "created_by": "blender_wire test",
        "target": {"image": "PrimaFace"},
        "brush": {
            "colour": [0.85, 0.45, 0.4, 1.0],
            "radius_px": 24,
            "falloff": "smooth",
            "spacing": 0.25,
            "blend": "mix",
            "opacity": 0.6
        },
        "strokes": [{
            "points": [
                {"p": ["0.300000", "0.400000"], "pressure": "1.000000", "radius": "1.000000"},
                {"p": ["0.340000", "0.410000"], "pressure": "1.000000", "radius": "1.000000"}
            ]
        }]
    });
    let hash = seahawk::stroke::content_hash(&artifact).expect("hashable");
    artifact["sha256"] = json!(hash);
    artifact
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn blender_profile_lists_the_twenty_six_provider_tools() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(Some(mock.port), ""));
    let mut expected: Vec<String> = CORE.iter().map(|n| n.to_string()).collect();
    expected.extend(BLENDER_TOOLS.iter().map(|n| n.to_string()));
    expected.sort();
    assert_eq!(s.list_names(), expected);
}

#[test]
fn without_a_blender_section_the_tools_are_not_listed() {
    let _mock = mock_provider();
    let mut s = spawn(Scratch::new(None, ""));
    let mut expected: Vec<String> = CORE.iter().map(|n| n.to_string()).collect();
    expected.sort();
    assert_eq!(s.list_names(), expected);
}

#[test]
fn session_status_round_trips_through_the_provider() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(Some(mock.port), ""));
    let response = s.call("blender.session_status", json!({}), false);
    let body = structured(&response);
    assert_eq!(body["blender_version"], "5.3.0", "{response}");
    assert_eq!(body["provider"], "seahawk-mock");
    assert_eq!(mock.methods(), ["initialize", "session_status"]);
}

#[test]
fn paint_apply_round_trips_with_the_artifact_intact() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(Some(mock.port), ""));
    let artifact = paint_artifact();
    let response = s.call(
        "blender.paint_apply",
        json!({"artifact": artifact.clone()}),
        false,
    );
    assert_eq!(structured(&response)["applied"], true, "{response}");
    // The provider received the artifact with its hash intact.
    let state = mock.state.lock().unwrap_or_else(|p| p.into_inner());
    let (_, params) = state
        .requests
        .iter()
        .find(|(method, _)| method == "paint_apply")
        .expect("provider saw paint_apply");
    assert_eq!(params["artifact"]["sha256"], artifact["sha256"]);
    assert_eq!(params["artifact"]["id"], "wire-blush-1");
}

#[test]
fn artifact_validate_is_broker_local() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(Some(mock.port), ""));
    let response = s.call(
        "blender.artifact_validate",
        json!({"artifact": paint_artifact()}),
        false,
    );
    let body = structured(&response);
    assert_eq!(body["valid"], true, "{response}");
    assert_eq!(body["kind"], "paint_batch");
    assert_eq!(body["strokes"], 1);
    assert_eq!(
        mock.request_count(),
        0,
        "validation must not contact the provider"
    );
}

#[test]
fn scene_open_with_operator_token_reaches_the_provider() {
    let mock = mock_provider();
    let scratch = Scratch::new(Some(mock.port), "");
    let path = scratch.dir.join("scene.blend");
    let mut s = spawn(scratch);
    let response = s.call(
        "blender.scene_open",
        json!({"path": path.display().to_string()}),
        true,
    );
    assert_eq!(
        structured(&response)["opened"],
        path.display().to_string(),
        "{response}"
    );
    assert!(mock.methods().contains(&"scene_open".to_string()));
}

// ---------------------------------------------------------------------------
// Adversarial: the guard proofs
// ---------------------------------------------------------------------------

#[test]
fn execute_without_operator_token_is_refused_and_logged() {
    let mock = mock_provider();
    let scratch = Scratch::new(Some(mock.port), "");
    let path = scratch.dir.join("out.png");
    let mut s = spawn(scratch);
    let response = s.call(
        "blender.image_export_png",
        json!({"image": "PrimaFace", "path": path.display().to_string()}),
        false, // no operator token
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );
    assert_eq!(
        mock.request_count(),
        0,
        "a refused execute must not reach the provider"
    );
    let log = s.scratch.oplog_text();
    assert!(
        log.contains("blender.image_export_png")
            && log.contains("refused:seahawk_operator_required"),
        "the refusal is op-logged: {log}"
    );
}

#[test]
fn execute_not_enabled_in_policy_is_refused_even_with_the_token() {
    let mock = mock_provider();
    let scratch = Scratch::new(Some(mock.port), "");
    // blend_save is deliberately absent from execute_enabled.
    let path = scratch.dir.join("work.blend");
    let mut s = spawn(scratch);
    let response = s.call(
        "blender.blend_save",
        json!({"path": path.display().to_string()}),
        true,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_execute_disabled"),
        "{response}"
    );
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn path_outside_roots_is_refused_before_downstream() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(Some(mock.port), ""));
    let response = s.call(
        "blender.scene_open",
        json!({"path": "/etc/passwd.blend"}),
        true,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_blender_path_refused"),
        "{response}"
    );
    assert_eq!(
        mock.request_count(),
        0,
        "the path gate fires before downstream contact"
    );
}

#[test]
fn excluded_feature_artifact_is_refused_by_name_before_downstream() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(Some(mock.port), ""));
    let mut artifact = paint_artifact();
    artifact["brush"]["jitter"] = json!("0.500000");
    // Re-stamp so only the exclusion can refuse it.
    let hash = seahawk::stroke::content_hash(&artifact).expect("hashable");
    artifact["sha256"] = json!(hash);
    let response = s.call("blender.paint_apply", json!({"artifact": artifact}), false);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_blender_artifact_invalid"),
        "{response}"
    );
    let message = response["result"]["structuredContent"]["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_string();
    assert!(
        message.contains("jitter"),
        "the refusal names the excluded feature: {message}"
    );
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn tampered_hash_artifact_is_refused_before_downstream() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(Some(mock.port), ""));
    let mut artifact = paint_artifact();
    artifact["brush"]["opacity"] = json!("0.900000");
    let response = s.call("blender.paint_apply", json!({"artifact": artifact}), false);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_blender_artifact_invalid"),
        "{response}"
    );
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn unknown_blender_tool_is_refused_without_downstream() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(Some(mock.port), ""));
    let response = s.call("blender.exfiltrate", json!({}), true);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_unknown_tool"),
        "{response}"
    );
    assert_eq!(mock.request_count(), 0);
}
