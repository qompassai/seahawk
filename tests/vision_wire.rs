//! Wire-level integration tests for the S5 vision-grounding
//! tools (`gui.observe`, `gui.ground`, `gui.act_verified`),
//! against the real `seahawk` binary with the four registered
//! media-GUI apps and a **dead** downstream. The child runs with
//! DISPLAY stripped, so calls that pass every gate fail closed
//! at the backend with `seahawk_gui_unavailable` — the headless
//! proof that the gate opened. The live grounding/actuation
//! proof runs on primo under Xvfb (GATE-REPORT-S5).
//!
//! The battery keeps the estate's validation/adversarial split:
//! grounding must grant no permission — unregistered apps,
//! unknown frames, execute-shaped actions, missing machine
//! checks, and unverifiable expectations all refuse *before* any
//! actuation, and the actuate two-key gate is byte-identical to
//! S4's.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

const AGENT_TOKEN: &str = "agent-secret";
const OPERATOR_TOKEN: &str = "operator-secret";

fn config_text(actuate_enabled: bool, vision: &str, oplog_path: &std::path::Path) -> String {
    let enabled = if actuate_enabled {
        "actuate_enabled = [\"gui.blender.actuate\"]"
    } else {
        ""
    };
    format!(
        "[server]\nagent_token = \"{AGENT_TOKEN}\"\noperator_token = \"{OPERATOR_TOKEN}\"\n\
         [downstream]\nurl = \"http://127.0.0.1:9/mcp\"\ntimeout_secs = 5\n\
         [policy]\n{enabled}\n\
         [[gui.apps]]\nname = \"blender\"\ndisplay_name = \"Blender\"\nwindow_match = [\"Blender\"]\n\
         [[gui.apps]]\nname = \"unity\"\ndisplay_name = \"Unity\"\nwindow_match = [\"Unity\", \"unityhub\", \"Unity Hub\"]\n\
         [[gui.apps]]\nname = \"comfyui\"\ndisplay_name = \"ComfyUI\"\nwindow_match = [\"ComfyUI\"]\n\
         [[gui.apps]]\nname = \"aseprite\"\ndisplay_name = \"Aseprite\"\nwindow_match = [\"Aseprite\"]\n\
         {vision}\
         [oplog]\npath = \"{}\"\n",
        oplog_path.display()
    )
}

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(actuate_enabled: bool, vision: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seahawk-vision-wire-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir scratch");
        let body = config_text(actuate_enabled, vision, &dir.join("oplog.jsonl"));
        std::fs::write(dir.join("seahawk.toml"), body).expect("write config");
        Scratch { dir }
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
    fn spawn(actuate_enabled: bool) -> Self {
        Self::spawn_vision(actuate_enabled, "")
    }

    fn spawn_vision(actuate_enabled: bool, vision: &str) -> Self {
        let scratch = Scratch::new(actuate_enabled, vision);
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
                    Ok(0) | Err(_) => return,
                    Ok(_) => {
                        if tx.send(line).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        Session {
            child,
            stdin,
            lines: rx,
            buffered: Vec::new(),
            next_id: 0,
            scratch,
        }
    }

    fn send(&mut self, frame: &Value) {
        let mut line = serde_json::to_string(frame).unwrap();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn recv_for(&mut self, id: i64) -> Value {
        fn matches(frame: &Value, id: i64) -> bool {
            frame.get("id").and_then(Value::as_i64) == Some(id)
                || (id == 0 && frame.get("id").is_some_and(Value::is_null))
        }
        if let Some(pos) = self.buffered.iter().position(|f| matches(f, id)) {
            return self.buffered.remove(pos);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(25);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero(), "timeout waiting for id {id}");
            let line = self
                .lines
                .recv_timeout(remaining)
                .expect("channel closed waiting for response");
            let frame: Value = serde_json::from_str(&line)
                .unwrap_or_else(|_| panic!("non-JSON frame from seahawk: {line}"));
            if matches(&frame, id) {
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

    fn call(&mut self, name: &str, arguments: Value, operator: Option<&str>) -> Value {
        let mut meta_map = meta().as_object().unwrap().clone();
        meta_map.insert("seahawk/agent_token".to_string(), json!(AGENT_TOKEN));
        if let Some(operator) = operator {
            meta_map.insert("seahawk/operator_token".to_string(), json!(operator));
        }
        self.rpc(
            "tools/call",
            json!({"name": name, "arguments": arguments, "_meta": Value::Object(meta_map)}),
        )
    }

    fn oplog_text(&self) -> String {
        self.scratch.oplog_text()
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
        "io.modelcontextprotocol/clientInfo": {"name": "seahawk-vision-wire-test", "version": "0.1.0"},
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

fn fake_sha() -> String {
    "ab".repeat(32)
}

// ---------------------------------------------------------------------------
// Surface: the three tools, their annotations, status reporting
// ---------------------------------------------------------------------------

#[test]
fn vision_tools_are_listed_with_their_contracts() {
    let mut s = Session::spawn(false);
    s.handshake();
    let response = s.rpc("tools/list", json!({"_meta": meta()}));
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for name in ["gui.observe", "gui.ground", "gui.act_verified"] {
        assert!(names.contains(&name), "missing {name}: {names:?}");
    }
    let observe = tools.iter().find(|t| t["name"] == "gui.observe").unwrap();
    assert_eq!(observe["annotations"]["readOnlyHint"], true);
    assert_eq!(observe["inputSchema"]["required"], json!(["app"]));
    let ground = tools.iter().find(|t| t["name"] == "gui.ground").unwrap();
    assert_eq!(ground["annotations"]["readOnlyHint"], true);
    assert_eq!(
        ground["inputSchema"]["required"],
        json!(["frame_sha256", "target"])
    );
    let act = tools
        .iter()
        .find(|t| t["name"] == "gui.act_verified")
        .unwrap();
    assert_eq!(act["annotations"]["readOnlyHint"], false);
    assert_eq!(act["annotations"]["destructiveHint"], true);
    let description = act["description"].as_str().unwrap();
    assert!(description.contains("actuate-class"), "{description}");
    assert!(description.contains("default-deny"), "{description}");
    assert!(
        description.contains("seahawk_gui_verify_mismatch"),
        "{description}"
    );
}

#[test]
fn status_reports_the_vision_configuration() {
    let mut s = Session::spawn(false);
    s.handshake();
    let response = s.call("seahawk_status", json!({}), None);
    let vision = &response["result"]["structuredContent"]["vision"];
    assert_eq!(vision["grounder"], "agent", "{vision}");
    assert_eq!(vision["grounder_ready"], false, "{vision}");
    assert_eq!(vision["frames_stored"], 0, "{vision}");
}

#[test]
fn ollama_route_broker_starts_and_reports_its_route() {
    // Regression (found live on primo, S5): the local grounder's
    // blocking HTTP client must live on a dedicated worker
    // thread — building it inside the tokio runtime panicked the
    // broker at startup with this exact configuration, while
    // agent-route configs (no client) started fine. The broker
    // must start, list tools, and report the route even with the
    // model server dead (port 9): construction must not depend
    // on reachability.
    let mut s = Session::spawn_vision(
        false,
        "[vision]\ngrounder = \"ollama\"\nollama_url = \"http://127.0.0.1:9\"\n\
         ollama_model = \"no-such-model\"\n",
    );
    s.handshake();
    let response = s.rpc("tools/list", json!({"_meta": meta()}));
    let tools = response["result"]["tools"].as_array().expect("tools array");
    assert!(
        tools.iter().any(|t| t["name"] == "gui.ground"),
        "broker with an ollama grounder must still list the vision tools"
    );
    // The worker builds its client asynchronously; poll briefly
    // for readiness rather than racing the thread.
    let mut vision = Value::Null;
    for _ in 0..20 {
        let response = s.call("seahawk_status", json!({}), None);
        vision = response["result"]["structuredContent"]["vision"].clone();
        if vision["grounder_ready"] == true {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(vision["grounder"], "ollama", "{vision}");
    assert_eq!(vision["grounder_ready"], true, "{vision}");
    assert_eq!(vision["ollama_model"], "no-such-model", "{vision}");
}

// ---------------------------------------------------------------------------
// Observe: registration is the whole surface
// ---------------------------------------------------------------------------

#[test]
fn observe_of_an_unregistered_app_is_unknown() {
    let mut s = Session::spawn(false);
    s.handshake();
    let response = s.call("gui.observe", json!({"app": "godot"}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_unknown_tool"),
        "{response}"
    );
    // A missing app argument is a shape refusal, not a dispatch.
    let response = s.call("gui.observe", json!({}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_bad_arguments"),
        "{response}"
    );
}

#[test]
fn observe_of_a_registered_app_passes_the_gate_headless() {
    let mut s = Session::spawn(false);
    s.handshake();
    // Read-class gate opens under the agent token; the backend
    // then fails closed with no display — distinct codes prove
    // gate vs backend, as in S4.
    let response = s.call("gui.observe", json!({"app": "blender"}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_gui_unavailable"),
        "{response}"
    );
    // Case variants reach the same handler, not a bypass.
    let response = s.call("GUI.OBSERVE", json!({"app": "aseprite"}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_gui_unavailable"),
        "{response}"
    );
    let log = s.oplog_text();
    assert!(log.contains("\"tool\":\"gui.observe\""), "{log}");
}

// ---------------------------------------------------------------------------
// Ground: frames are references, not vibes
// ---------------------------------------------------------------------------

#[test]
fn ground_against_an_unknown_frame_is_refused() {
    let mut s = Session::spawn(false);
    s.handshake();
    let response = s.call(
        "gui.ground",
        json!({"frame_sha256": fake_sha(), "target": "the Queue button"}),
        None,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_gui_no_frame"),
        "{response}"
    );
    // An agent answer cannot conjure a frame into existence.
    let response = s.call(
        "gui.ground",
        json!({
            "frame_sha256": fake_sha(),
            "target": "the Queue button",
            "route": "agent",
            "agent_answer": {"x": 10, "y": 10, "confidence": 0.9},
        }),
        None,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_gui_no_frame"),
        "{response}"
    );
    let log = s.oplog_text();
    assert!(log.contains("refused:seahawk_gui_no_frame"), "{log}");
}

#[test]
fn ground_route_validation_is_strict() {
    let mut s = Session::spawn(false);
    s.handshake();
    // A route that does not exist refuses as an argument error —
    // there is no silent fallback to some other grounder.
    let response = s.call(
        "gui.ground",
        json!({"frame_sha256": fake_sha(), "target": "x", "route": "cloud"}),
        None,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_bad_arguments"),
        "{response}"
    );
    // Missing target: shape refusal.
    let response = s.call("gui.ground", json!({"frame_sha256": fake_sha()}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_bad_arguments"),
        "{response}"
    );
}

#[test]
fn ground_with_grounding_disabled_by_policy_is_unavailable() {
    let mut s = Session::spawn_vision(false, "[vision]\ngrounder = \"none\"\n");
    s.handshake();
    let response = s.call(
        "gui.ground",
        json!({"frame_sha256": fake_sha(), "target": "the Queue button"}),
        None,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_gui_grounder_unavailable"),
        "{response}"
    );
}

// ---------------------------------------------------------------------------
// Act-verified: the gate is S4's, unchanged; checks are mandatory
// ---------------------------------------------------------------------------

#[test]
fn act_verified_on_an_unregistered_app_is_unknown() {
    let mut s = Session::spawn(true);
    s.handshake();
    let response = s.call(
        "gui.act_verified",
        json!({"app": "godot", "action": "click", "x": 1, "y": 1, "expect": {"changed": true}}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_unknown_tool"),
        "{response}"
    );
}

#[test]
fn act_verified_uses_the_s4_two_key_gate_verbatim() {
    // Not enabled in policy: refused even with the operator key.
    let mut s = Session::spawn(false);
    s.handshake();
    let response = s.call(
        "gui.act_verified",
        json!({"app": "blender", "action": "click", "x": 1, "y": 1, "expect": {"changed": true}}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_actuate_disabled"),
        "{response}"
    );
    // Enabled but no operator token on the call.
    let mut s = Session::spawn(true);
    s.handshake();
    let response = s.call(
        "gui.act_verified",
        json!({"app": "blender", "action": "click", "x": 1, "y": 1, "expect": {"changed": true}}),
        None,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );
    // The gate fires BEFORE expectation parsing: a malformed
    // expect cannot launder a gated call into a different refusal.
    let response = s.call(
        "gui.act_verified",
        json!({"app": "blender", "action": "click", "expect": {"bogus": true}}),
        None,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );
    let log = s.oplog_text();
    assert!(log.contains("\"tool\":\"gui.act_verified\""), "{log}");
    assert!(log.contains("refused:seahawk_operator_required"), "{log}");
}

#[test]
fn act_verified_requires_a_machine_check() {
    let mut s = Session::spawn(true);
    s.handshake();
    // No expect at all.
    let response = s.call(
        "gui.act_verified",
        json!({"app": "blender", "action": "click", "x": 1, "y": 1}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_bad_arguments"),
        "{response}"
    );
    // A description is documentation, not verification.
    let response = s.call(
        "gui.act_verified",
        json!({"app": "blender", "action": "click", "x": 1, "y": 1, "expect": {"description": "the menu opens"}}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_bad_arguments"),
        "{response}"
    );
    // Unknown check names refuse rather than being ignored.
    let response = s.call(
        "gui.act_verified",
        json!({"app": "blender", "action": "click", "x": 1, "y": 1, "expect": {"pixel_vibes": true}}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_bad_arguments"),
        "{response}"
    );
}

#[test]
fn act_verified_refuses_checks_it_cannot_evaluate_before_acting() {
    // Default policy route is "agent" — no local grounder — so a
    // text_visible expectation cannot be evaluated and the call
    // refuses up front instead of acting unverified.
    let mut s = Session::spawn(true);
    s.handshake();
    let response = s.call(
        "gui.act_verified",
        json!({"app": "blender", "action": "type", "text": "hello", "expect": {"text_visible": "hello"}}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_gui_verify_unavailable"),
        "{response}"
    );
    let log = s.oplog_text();
    assert!(
        log.contains("refused:seahawk_gui_verify_unavailable"),
        "{log}"
    );
}

#[test]
fn act_verified_execute_shaped_action_dies_in_the_vocabulary() {
    let mut s = Session::spawn(true);
    s.handshake();
    for action in ["run_command", "execute", "shell"] {
        let response = s.call(
            "gui.act_verified",
            json!({"app": "blender", "action": action, "text": "id", "expect": {"changed": true}}),
            Some(OPERATOR_TOKEN),
        );
        assert_eq!(
            structured_error_code(&response).as_deref(),
            Some("seahawk_gui_unknown_action"),
            "{action}: {response}"
        );
    }
}

#[test]
fn act_verified_grounding_grants_no_permission() {
    // A perfectly formed grounding-shaped call (target + route)
    // against a policy that never enabled actuation is refused
    // at the same gate as a raw call: the description of a
    // target is not a key.
    let mut s = Session::spawn(false);
    s.handshake();
    let response = s.call(
        "gui.act_verified",
        json!({
            "app": "blender",
            "action": "click",
            "target": "the Render menu",
            "route": "local",
            "expect": {"changed": true},
        }),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_actuate_disabled"),
        "{response}"
    );
}
