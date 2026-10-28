//! Wire-level integration tests for the S4 host-GUI provider,
//! against the real `seahawk` binary with policy registering the
//! four media-GUI applications (Blender, Unity, ComfyUI,
//! Aseprite) and a **dead** downstream (no editor: GUI behavior
//! must not depend on the Unreal surface). The child runs with
//! DISPLAY stripped, so a call that passes every gate fails
//! closed at the backend with `seahawk_gui_unavailable` — which
//! is exactly what distinguishes "the gate opened" from "the
//! gate refused" in a headless test environment. The live
//! allowed-path proof runs on primo under Xvfb (GATE-REPORT-S4).
//!
//! Half the battery is adversarial, per the estate split: the
//! actuate gate must be unreachable around — unregistered app,
//! unregistered action class (execute-shaped actions through an
//! actuate registration), no agent token, missing/wrong operator
//! token, case-variant names, pipelined bursts, and a policy
//! file rewritten under the running server.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

const AGENT_TOKEN: &str = "agent-secret";
const OPERATOR_TOKEN: &str = "operator-secret";

fn config_text(actuate_enabled: bool, extra_apps: &str, oplog_path: &std::path::Path) -> String {
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
         {extra_apps}\
         [oplog]\npath = \"{}\"\n",
        oplog_path.display()
    )
}

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(actuate_enabled: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seahawk-gui-wire-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir scratch");
        let body = config_text(actuate_enabled, "", &dir.join("oplog.jsonl"));
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

impl Session {
    fn spawn(actuate_enabled: bool) -> Self {
        let scratch = Scratch::new(actuate_enabled);
        let mut child = Command::new(env!("CARGO_BIN_EXE_seahawk"))
            .arg(scratch.config_path())
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

    fn send_raw(&mut self, raw: &str) {
        self.stdin.write_all(raw.as_bytes()).unwrap();
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

    fn call_no_token(&mut self, name: &str, arguments: Value) -> Value {
        self.rpc(
            "tools/call",
            json!({"name": name, "arguments": arguments, "_meta": meta()}),
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
        "io.modelcontextprotocol/clientInfo": {"name": "seahawk-gui-wire-test", "version": "0.1.0"},
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

// ---------------------------------------------------------------------------
// Registration surface
// ---------------------------------------------------------------------------

#[test]
fn gui_tools_listed_for_the_four_registered_apps() {
    let mut s = Session::spawn(false);
    s.handshake();
    let response = s.rpc("tools/list", json!({"_meta": meta()}));
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for app in ["blender", "unity", "comfyui", "aseprite"] {
        for kind in ["observe", "actuate"] {
            let name = format!("gui.{app}.{kind}");
            assert!(names.contains(&name.as_str()), "missing {name}: {names:?}");
        }
    }
    assert!(
        !names.iter().any(|n| n.contains("godot")),
        "unregistered app must not appear: {names:?}"
    );
    let observe = tools
        .iter()
        .find(|t| t["name"] == "gui.blender.observe")
        .unwrap();
    assert_eq!(observe["annotations"]["readOnlyHint"], true);
    assert_eq!(observe["inputSchema"]["type"], "object");
    let actuate = tools
        .iter()
        .find(|t| t["name"] == "gui.blender.actuate")
        .unwrap();
    assert_eq!(actuate["annotations"]["destructiveHint"], true);
    assert_eq!(actuate["annotations"]["readOnlyHint"], false);
    let description = actuate["description"].as_str().unwrap();
    assert!(description.contains("actuate-class"), "{description}");
    assert!(description.contains("default-deny"), "{description}");
}

// ---------------------------------------------------------------------------
// Adversarial: unregistered apps, classes, and actions
// ---------------------------------------------------------------------------

#[test]
fn unregistered_app_and_invented_gui_tools_are_unknown() {
    let mut s = Session::spawn(true);
    s.handshake();
    for name in [
        "gui.godot.actuate",
        "gui.godot.observe",
        "gui.blender.execute",
        "gui.blender.observe2",
        "gui.blender",
    ] {
        let response = s.call(name, json!({"action": "focus"}), Some(OPERATOR_TOKEN));
        assert_eq!(
            structured_error_code(&response).as_deref(),
            Some("seahawk_unknown_tool"),
            "{name}: {response}"
        );
    }
    let log = s.oplog_text();
    assert!(log.contains("refused:seahawk_unknown_tool"), "{log}");
}

#[test]
fn execute_shaped_action_through_actuate_registration_is_refused() {
    // The actuate registration is fully enabled and the operator
    // token is correct — the gate opens — and an execute-shaped
    // action still dies in the closed action vocabulary, before
    // any backend exists to touch.
    let mut s = Session::spawn(true);
    s.handshake();
    for action in ["run_command", "execute", "shell"] {
        let response = s.call(
            "gui.blender.actuate",
            json!({"action": action, "text": "id"}),
            Some(OPERATOR_TOKEN),
        );
        assert_eq!(
            structured_error_code(&response).as_deref(),
            Some("seahawk_gui_unknown_action"),
            "{action}: {response}"
        );
    }
    let log = s.oplog_text();
    assert!(log.contains("unknown actuate action"), "{log}");
}

// ---------------------------------------------------------------------------
// Adversarial: the actuate two-key gate
// ---------------------------------------------------------------------------

#[test]
fn actuation_without_agent_token_is_refused_at_the_guard() {
    let mut s = Session::spawn(true);
    s.handshake();
    let response = s.call_no_token("gui.blender.actuate", json!({"action": "focus"}));
    assert_eq!(response["error"]["code"], -32001, "{response}");
    assert_eq!(response["error"]["data"]["code"], "seahawk_unauthorized");
    let log = s.oplog_text();
    assert!(log.contains("refused:seahawk_unauthorized"), "{log}");
}

#[test]
fn actuate_is_default_deny_without_policy_enablement() {
    let mut s = Session::spawn(false);
    s.handshake();
    // Even with the correct operator token, a tool that policy
    // did not enable is refused: enablement is the first key.
    let response = s.call(
        "gui.blender.actuate",
        json!({"action": "focus"}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_actuate_disabled"),
        "{response}"
    );
    let log = s.oplog_text();
    assert!(log.contains("refused:seahawk_actuate_disabled"), "{log}");
}

#[test]
fn actuate_operator_gate_cycle() {
    let mut s = Session::spawn(true);
    s.handshake();

    // Enabled, but no operator token on the call.
    let response = s.call("gui.blender.actuate", json!({"action": "focus"}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );
    // Wrong operator token.
    let response = s.call(
        "gui.blender.actuate",
        json!({"action": "focus"}),
        Some("operator-wrong"),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );
    // The agent token is not an operator token.
    let response = s.call(
        "gui.blender.actuate",
        json!({"action": "focus"}),
        Some(AGENT_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );
    // Correct operator token: the gate opens — and the backend
    // then fails closed because the test child has no display.
    // That distinct code is the proof the decide() gate passed.
    let response = s.call(
        "gui.blender.actuate",
        json!({"action": "focus"}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_gui_unavailable"),
        "{response}"
    );
    let log = s.oplog_text();
    assert!(log.contains("refused:seahawk_operator_required"), "{log}");
    assert!(log.contains("\"class\":\"actuate\""), "{log}");
}

#[test]
fn case_variant_actuate_name_hits_the_same_gate() {
    let mut s = Session::spawn(false);
    s.handshake();
    // Downstream lookup in this estate is case-insensitive; the
    // GUI namespace is matched case-insensitively too, so a
    // shouted name lands on the same decide() gate rather than
    // slipping past as an unknown tool or, worse, dispatching.
    let response = s.call(
        "GUI.BLENDER.ACTUATE",
        json!({"action": "focus"}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_actuate_disabled"),
        "{response}"
    );
}

// ---------------------------------------------------------------------------
// Observe: passes under the agent token, fails closed headless
// ---------------------------------------------------------------------------

#[test]
fn observe_passes_the_gate_and_fails_closed_without_a_display() {
    let mut s = Session::spawn(false);
    s.handshake();
    for action in ["screenshot", "windows", "state"] {
        let response = s.call("gui.aseprite.observe", json!({"action": action}), None);
        assert_eq!(
            structured_error_code(&response).as_deref(),
            Some("seahawk_gui_unavailable"),
            "{action}: {response}"
        );
    }
    // And without the agent token the guard refuses observe too.
    let response = s.call_no_token("gui.aseprite.observe", json!({"action": "windows"}));
    assert_eq!(response["error"]["code"], -32001, "{response}");
}

// ---------------------------------------------------------------------------
// Adversarial: pipelined burst + policy tampering
// ---------------------------------------------------------------------------

#[test]
fn pipelined_burst_actuation_cannot_skip_the_gate() {
    let mut s = Session::spawn(true);
    s.handshake();
    // Three frames in ONE write: an unauthenticated actuation, an
    // authenticated actuation missing the operator key, and an
    // observe that passes the guard. Every frame is answered and
    // every gate fires, in order.
    let burst = format!(
        "{}\n{}\n{}\n",
        json!({"jsonrpc": "2.0", "id": 41, "method": "tools/call",
               "params": {"name": "gui.blender.actuate", "arguments": {"action": "focus"}}}),
        json!({"jsonrpc": "2.0", "id": 42, "method": "tools/call",
               "params": {"name": "gui.blender.actuate", "arguments": {"action": "focus"},
                          "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                    "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "0"},
                                    "io.modelcontextprotocol/clientCapabilities": {},
                                    "seahawk/agent_token": AGENT_TOKEN}}}),
        json!({"jsonrpc": "2.0", "id": 43, "method": "tools/call",
               "params": {"name": "gui.blender.observe", "arguments": {"action": "state"},
                          "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                    "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "0"},
                                    "io.modelcontextprotocol/clientCapabilities": {},
                                    "seahawk/agent_token": AGENT_TOKEN}}}),
    );
    s.send_raw(&burst);
    let r41 = s.recv_for(41);
    let r42 = s.recv_for(42);
    let r43 = s.recv_for(43);
    assert_eq!(r41["error"]["code"], -32001, "{r41}");
    assert_eq!(
        structured_error_code(&r42).as_deref(),
        Some("seahawk_operator_required"),
        "{r42}"
    );
    assert_eq!(
        structured_error_code(&r43).as_deref(),
        Some("seahawk_gui_unavailable"),
        "{r43}"
    );
}

#[test]
fn policy_tamper_mid_run_is_inert() {
    // The config is read once at startup and never re-read, and
    // there is no registration tool: rewriting the policy file
    // under a running server — enabling actuation and inventing
    // a new app — changes nothing until a restart, when the edit
    // is the operator's own policy act. This test proves the
    // running server's behavior is unchanged by the rewrite.
    let mut s = Session::spawn(false);
    s.handshake();
    let tampered = config_text(
        true,
        "[[gui.apps]]\nname = \"godot\"\nwindow_match = [\"Godot\"]\n",
        &s.scratch.dir.join("oplog.jsonl"),
    );
    std::fs::write(s.scratch.config_path(), tampered).expect("rewrite config");

    let response = s.call(
        "gui.blender.actuate",
        json!({"action": "focus"}),
        Some(OPERATOR_TOKEN),
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_actuate_disabled"),
        "mid-run policy edit took effect: {response}"
    );
    let response = s.call("gui.godot.observe", json!({"action": "windows"}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_unknown_tool"),
        "{response}"
    );
    let response = s.rpc("tools/list", json!({"_meta": meta()}));
    let tools = response["result"]["tools"].as_array().expect("tools array");
    assert!(
        !tools.iter().any(|t| t["name"] == "gui.godot.observe"),
        "mid-run registration appeared in tools/list"
    );
}
