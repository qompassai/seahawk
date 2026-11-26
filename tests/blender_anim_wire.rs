//! Wire-level tests for the Blender animation surface
//! (DESIGN-ANIM §2, ops 13–25) against the real `seahawk`
//! binary and a mock provider, in the shape of
//! `blender_wire.rs`: the mock records every request, so the
//! adversarial tests prove a refusal happened *before* the
//! downstream was contacted.
//!
//! Half validation / half adversarial: the 25-tool listing,
//! broker-local take validation, a take apply round-trip, the
//! broker-side take_export transform — and the guard proofs:
//! execute without an operator token, an excluded-construct
//! take refused by name, a tampered take hash, an
//! unresolvable GP reference, a contact-sheet frame outside
//! the render roots, an export path outside the export roots.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const AGENT_TOKEN: &str = "agent-token-for-tests";
const OPERATOR_TOKEN: &str = "operator-token-for-tests";
const PROVIDER_SECRET: &str = "provider-secret-for-tests";

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
        "take_apply" => json!({"applied": true, "channels": 1}),
        "pose_apply" => json!({"applied": true}),
        "rig_apply" => json!({"applied": true, "bones_created": 1}),
        "pose_capture" => json!({"pose": {"schema": "seahawk.pose/v2", "id": "mock-pose"}}),
        "take_render" => json!({"frames": ["f0001.png"], "count": 1}),
        "take_export" => {
            json!({"path": params.get("path").cloned().unwrap_or(Value::Null), "bytes": 10})
        }
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

    fn params_of(&self, method: &str) -> Option<Value> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .requests
            .iter()
            .find(|(m, _)| m == method)
            .map(|(_, params)| params.clone())
    }
}

// ---------------------------------------------------------------------------
// Scratch config + session harness (blender_wire's shape; the
// execute-enabled set names the animation execute ops)
// ---------------------------------------------------------------------------

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(port: u16) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seahawk-blender-anim-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir scratch");
        let body = format!(
            "[server]\nagent_token = \"{AGENT_TOKEN}\"\noperator_token = \"{OPERATOR_TOKEN}\"\n\
             [downstream]\nurl = \"http://127.0.0.1:9/mcp\"\ntimeout_secs = 5\n\
             [policy]\nexecute_enabled = [\"blender.scene_open\", \"blender.take_render\", \
             \"blender.contact_sheet\", \"blender.sim_bake\", \"blender.take_export\"]\n\
             [oplog]\npath = \"{}\"\n\
             [blender]\nurl = \"http://127.0.0.1:{port}/blender\"\ntimeout_secs = 10\n\
             provider_secret = \"{PROVIDER_SECRET}\"\n\
             [blender.paths]\nopen_roots = [\"{1}\"]\nsave_roots = [\"{1}\"]\n\
             export_roots = [\"{1}\"]\nrender_roots = [\"{1}\"]\n",
            dir.join("oplog.jsonl").display(),
            dir.display(),
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
    assert!(
        session.scratch.config_path().is_file(),
        "the broker config must exist before the broker starts"
    );
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
        "io.modelcontextprotocol/clientInfo": {"name": "seahawk-blender-anim-test", "version": "0.1.0"},
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

fn error_message(response: &Value) -> String {
    response["result"]["structuredContent"]["error"]["message"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn structured(response: &Value) -> Value {
    response["result"]["structuredContent"].clone()
}

const SCENE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// A small valid take, hash-stamped through the broker's own
/// public canonicalization.
fn valid_take() -> Value {
    let mut take = json!({
        "schema": "seahawk.take/v2",
        "id": "wire-take-1",
        "created_by": "blender_anim_wire test",
        "target": {"scene_sha256": SCENE, "rig": "Rig"},
        "frames": {"start": 1, "end": 12, "fps_num": 24, "fps_base": "1.000000"},
        "channels": [{
            "id": {"type": "OBJECT", "name": "Rig"},
            "slot": null,
            "path": "pose.bones[\"Head\"].rotation_quaternion",
            "index": 0,
            "extrapolation": "CONSTANT",
            "keys": [
                {"frame": "1.000000", "value": "1.000000", "interp": "LINEAR",
                 "easing": null, "handle_left": null, "handle_right": null,
                 "handle_left_type": null, "handle_right_type": null,
                 "back": null, "amplitude": null, "period": null},
                {"frame": "12.000000", "value": "0.990000", "interp": "LINEAR",
                 "easing": null, "handle_left": null, "handle_right": null,
                 "handle_left_type": null, "handle_right_type": null,
                 "back": null, "amplitude": null, "period": null}
            ]
        }],
        "gp_tracks": [],
        "bake": null
    });
    let hash = seahawk::stroke::content_hash(&take).expect("hashable");
    take["sha256"] = json!(hash);
    take
}

fn valid_rigbuild() -> Value {
    let mut doc = json!({
        "schema": "seahawk.rigbuild/v1",
        "id": "wire-rigbuild-1",
        "created_by": "blender_anim_wire test",
        "target": {"scene_sha256": SCENE, "armature": "Rig"},
        "bones": [{
            "name": "Hair_01", "parent": "Head",
            "head": ["0.000000", "0.100000", "1.600000"],
            "tail": ["0.000000", "0.160000", "1.520000"],
            "roll": "0.000000", "deform": true
        }],
        "constraints": [{
            "bone": "Hair_01", "type": "DAMPED_TRACK", "name": null,
            "target": null, "subtarget": "", "chain_count": null,
            "influence": "1.000000"
        }],
        "weights": [{
            "mesh": "Body", "group": "Hair_01",
            "vertices": [0, 1, 2], "weight": "0.750000"
        }]
    });
    let hash = seahawk::stroke::content_hash(&doc).expect("hashable");
    doc["sha256"] = json!(hash);
    doc
}

fn valid_pose() -> Value {
    let mut pose = json!({
        "schema": "seahawk.pose/v2",
        "id": "wire-pose-1",
        "created_by": "blender_anim_wire test",
        "target": {"scene_sha256": SCENE},
        "frame": 6,
        "channels": [{
            "id": {"type": "OBJECT", "name": "Rig"},
            "slot": null,
            "path": "pose.bones[\"Head\"].rotation_quaternion",
            "index": 0,
            "value": "0.995000"
        }],
        "insert": {"interp": "LINEAR"}
    });
    let hash = seahawk::stroke::content_hash(&pose).expect("hashable");
    pose["sha256"] = json!(hash);
    pose
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn blender_profile_lists_all_twenty_six_provider_tools() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let mut expected: Vec<String> = CORE.iter().map(|n| n.to_string()).collect();
    expected.extend(BLENDER_TOOLS.iter().map(|n| n.to_string()));
    expected.sort();
    assert_eq!(s.list_names(), expected);
}

#[test]
fn take_validate_is_broker_local() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let take = valid_take();
    let response = s.call(
        "blender.take_validate",
        json!({"take": take.clone()}),
        false,
    );
    let body = structured(&response);
    assert_eq!(body["valid"], true, "{response}");
    assert_eq!(body["kind"], "take");
    assert_eq!(body["channels"], 1);
    assert_eq!(body["keys"], 2);
    assert_eq!(body["sha256"], take["sha256"]);
    assert_eq!(body["action_digest"].as_str().map(str::len), Some(64));
    assert_eq!(
        mock.request_count(),
        0,
        "take validation must not contact the provider"
    );
}

#[test]
fn take_apply_round_trips_with_the_take_intact() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let take = valid_take();
    let response = s.call("blender.take_apply", json!({"take": take.clone()}), false);
    assert_eq!(structured(&response)["applied"], true, "{response}");
    let params = mock
        .params_of("take_apply")
        .expect("provider saw take_apply");
    assert_eq!(params["take"]["sha256"], take["sha256"]);
    assert_eq!(params["take"]["id"], "wire-take-1");
}

#[test]
fn pose_apply_and_capture_round_trip() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let response = s.call("blender.pose_apply", json!({"pose": valid_pose()}), false);
    assert_eq!(structured(&response)["applied"], true, "{response}");
    let response = s.call("blender.pose_capture", json!({"frame": 6}), false);
    assert_eq!(
        structured(&response)["pose"]["id"],
        "mock-pose",
        "{response}"
    );
}

#[test]
fn rig_apply_round_trip() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let doc = valid_rigbuild();
    let response = s.call("blender.rig_apply", json!({"rigbuild": doc.clone()}), false);
    assert_eq!(structured(&response)["applied"], true, "{response}");
    assert_eq!(structured(&response)["bones_created"], 1, "{response}");
    let params = mock.params_of("rig_apply").expect("provider saw rig_apply");
    assert_eq!(params["rigbuild"]["sha256"], doc["sha256"]);
    assert_eq!(params["rigbuild"]["id"], "wire-rigbuild-1");
}

#[test]
fn rig_apply_refuses_a_bad_hash_before_the_provider() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let mut doc = valid_rigbuild();
    doc["sha256"] = json!("0000000000000000000000000000000000000000000000000000000000000000");
    let response = s.call("blender.rig_apply", json!({"rigbuild": doc}), false);
    let text = format!("{response}");
    assert!(
        text.contains("seahawk_blender_artifact_invalid"),
        "{response}"
    );
    assert!(
        mock.params_of("rig_apply").is_none(),
        "provider must not be contacted"
    );
}

#[test]
fn take_export_transform_is_computed_broker_side() {
    let mock = mock_provider();
    let scratch = Scratch::new(mock.port);
    let path = scratch.dir.join("take-export.json");
    let mut s = spawn(scratch);
    let take = valid_take();
    let response = s.call(
        "blender.take_export",
        json!({"take": take.clone(), "path": path.display().to_string()}),
        true,
    );
    assert_eq!(
        structured(&response)["path"],
        path.display().to_string(),
        "{response}"
    );
    // The provider received the finished export document, not
    // the take: the transform is the broker's, the write is
    // the provider's.
    let params = mock
        .params_of("take_export")
        .expect("provider saw take_export");
    assert_eq!(params["export"]["schema"], "seahawk.take-export/v2");
    assert_eq!(params["export"]["take"]["sha256"], take["sha256"]);
    assert_eq!(params["export"]["channels"][0]["target"]["kind"], "bone");
    assert!(
        params.get("take").is_none(),
        "raw take must not ride: {params}"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: the guard proofs
// ---------------------------------------------------------------------------

#[test]
fn take_render_without_operator_token_is_refused() {
    let mock = mock_provider();
    let scratch = Scratch::new(mock.port);
    let prefix = scratch.dir.join("frames/frame_");
    let mut s = spawn(scratch);
    let response = s.call(
        "blender.take_render",
        json!({"take": valid_take(), "path": prefix.display().to_string()}),
        false,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn take_with_excluded_construct_is_refused_by_name() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let mut take = valid_take();
    take["channels"][0]["modifiers"] = json!(["CYCLES"]);
    let hash = seahawk::stroke::content_hash(&take).expect("hashable");
    take["sha256"] = json!(hash);
    let response = s.call("blender.take_apply", json!({"take": take}), false);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_blender_artifact_invalid"),
        "{response}"
    );
    assert!(
        error_message(&response).contains("modifiers"),
        "the refusal names the construct: {response}"
    );
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn tampered_take_hash_is_refused_before_downstream() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let mut take = valid_take();
    take["channels"][0]["keys"][0]["value"] = json!("0.500000");
    let response = s.call("blender.take_apply", json!({"take": take}), false);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_blender_artifact_invalid"),
        "{response}"
    );
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn gp_replay_range_with_unresolvable_reference_is_refused() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let track = json!({
        "object": "Locks", "layer": "Sketch",
        "frames": [{"frame": 1, "artifact": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
    });
    let response = s.call(
        "blender.gp_replay_range",
        json!({"track": track, "artifacts": {}}),
        false,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_blender_artifact_invalid"),
        "{response}"
    );
    assert!(
        error_message(&response).contains("not supplied"),
        "{response}"
    );
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn contact_sheet_frame_outside_render_roots_is_refused() {
    let mock = mock_provider();
    let scratch = Scratch::new(mock.port);
    let out = scratch.dir.join("sheet.png");
    let mut s = spawn(scratch);
    let response = s.call(
        "blender.contact_sheet",
        json!({"frames": ["/etc/frame.png"], "path": out.display().to_string()}),
        true,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_blender_path_refused"),
        "{response}"
    );
    assert_eq!(mock.request_count(), 0);
}

#[test]
fn take_export_path_outside_roots_is_refused() {
    let mock = mock_provider();
    let mut s = spawn(Scratch::new(mock.port));
    let response = s.call(
        "blender.take_export",
        json!({"take": valid_take(), "path": "/etc/take-export.json"}),
        true,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_blender_path_refused"),
        "{response}"
    );
    assert_eq!(mock.request_count(), 0);
}
