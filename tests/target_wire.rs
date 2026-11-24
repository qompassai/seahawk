//! Wire-level tests for the target-adapter surface
//! (generalization, 2026-11-24) against the real `seahawk`
//! binary: the `target.list` declarations, the Unity and Godot
//! adapters over fake CLI/engine binaries (shell scripts in the
//! scratch dir that print a banner and exit 0 — the adapters
//! only ever spawn them as argv arrays), and the generic-GUI
//! floor's tool shape.
//!
//! Half validation / half adversarial, per the estate split.
//! Validation: listing shape under `full`, honest declarations,
//! status/inspect/run round-trips through the fakes, profile
//! scoping. Adversarial: execute without an operator token, a
//! shell-shaped Unity method name, a Godot script escaping its
//! project, an out-of-vocabulary floor action, an unwrapped
//! verb name, and a call against an unconfigured adapter.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const AGENT_TOKEN: &str = "target-wire-agent-token";
const OPERATOR_TOKEN: &str = "target-wire-operator-token";

const CORE: [&str; 4] = [
    "seahawk_oplog",
    "seahawk_status",
    "seahawk_surface",
    "target.list",
];

const ADAPTER_TOOLS: [&str; 10] = [
    "godot.inspect",
    "godot.run_script",
    "godot.status",
    "gui.floor_act",
    "gui.floor_screenshot",
    "gui.floor_windows",
    "unity.inspect",
    "unity.projects",
    "unity.run_method",
    "unity.status",
];

// ---------------------------------------------------------------------------
// Scratch config + session harness (blender_wire's shape)
// ---------------------------------------------------------------------------

struct Scratch {
    dir: PathBuf,
    project: PathBuf,
}

impl Scratch {
    /// Builds a config with fake unity/godot binaries and a
    /// minimal Godot project in the scratch dir. `sections`
    /// selects which adapter sections are written; `execute`
    /// and `actuate` are the policy enablement lists.
    fn new(sections: &[&str], execute: &[&str], actuate: &[&str]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seahawk-target-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir scratch");
        let fake_unity = dir.join("fake-unity");
        std::fs::write(
            &fake_unity,
            "#!/bin/sh\necho \"unity-cli 1.0.0-wire-test\"\nexit 0\n",
        )
        .expect("write fake unity");
        let fake_godot = dir.join("fake-godot");
        std::fs::write(
            &fake_godot,
            "#!/bin/sh\necho \"godot-wire 4.7.2.stable\"\nexit 0\n",
        )
        .expect("write fake godot");
        for fake in [&fake_unity, &fake_godot] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(fake, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake");
        }
        // A minimal Godot project: identity in project.godot,
        // one scene, one script.
        let project = dir.join("godot-project");
        std::fs::create_dir_all(&project).expect("mkdir project");
        std::fs::write(
            project.join("project.godot"),
            "; Engine configuration file.\n\n[application]\n\n\
             config/name=\"WireProject\"\n\
             run/main_scene=\"res://main.tscn\"\n\
             config/features=PackedStringArray(\"4.7\", \"GL Compatibility\")\n",
        )
        .expect("write project.godot");
        std::fs::write(project.join("main.tscn"), "[gd_scene format=3]\n").expect("write scene");
        std::fs::write(
            project.join("main.gd"),
            "extends SceneTree\n\nfunc _init() -> void:\n\tprint(\"wire\")\n\tquit()\n",
        )
        .expect("write script");

        let mut body = format!(
            "[server]\nagent_token = \"{AGENT_TOKEN}\"\noperator_token = \"{OPERATOR_TOKEN}\"\n\
             [downstream]\nurl = \"http://127.0.0.1:9/mcp\"\ntimeout_secs = 5\n\
             [policy]\nexecute_enabled = [{}]\nactuate_enabled = [{}]\n\
             [oplog]\npath = \"{}\"\n",
            execute
                .iter()
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(", "),
            actuate
                .iter()
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(", "),
            dir.join("oplog.jsonl").display()
        );
        if sections.contains(&"unity") {
            body.push_str(&format!(
                "[unity]\ncli_path = \"{}\"\ntimeout_secs = 60\n",
                fake_unity.display()
            ));
        }
        if sections.contains(&"godot") {
            body.push_str(&format!(
                "[godot]\nbinary = \"{}\"\ntimeout_secs = 60\n",
                fake_godot.display()
            ));
        }
        if sections.contains(&"floor") {
            body.push_str(&format!(
                "[floor]\nydotool_socket = \"{}\"\nruntime_dir = \"{}\"\n",
                dir.join("no-ydotool.sock").display(),
                dir.display()
            ));
        }
        std::fs::write(dir.join("seahawk.toml"), body).expect("write config");
        Scratch { dir, project }
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

fn spawn(scratch: Scratch, profile: &str) -> Session {
    let mut child = Command::new(env!("CARGO_BIN_EXE_seahawk"))
        .arg(scratch.config_path())
        .arg("--profile")
        .arg(profile)
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

    fn list_tools(&mut self) -> Vec<Value> {
        let response = self.rpc("tools/list", json!({"_meta": meta()}));
        response["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list shape: {response}"))
            .clone()
    }

    fn list_names(&mut self) -> Vec<String> {
        let mut names: Vec<String> = self
            .list_tools()
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
        "io.modelcontextprotocol/clientInfo": {"name": "seahawk-target-test", "version": "0.1.0"},
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

fn full_scratch() -> Scratch {
    Scratch::new(
        &["unity", "godot", "floor"],
        &["unity.run_method", "godot.run_script"],
        &["gui.floor_act"],
    )
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn full_profile_lists_the_adapter_tools_with_object_schemas() {
    let mut s = spawn(full_scratch(), "full");
    let tools = s.list_tools();
    let mut names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name").to_string())
        .collect();
    names.sort();
    for expected in CORE.iter().chain(ADAPTER_TOOLS.iter()) {
        assert!(
            names.contains(&expected.to_string()),
            "missing {expected}: {names:?}"
        );
    }
    // No blender section in this config: no blender tools.
    assert!(
        !names.iter().any(|name| name.starts_with("blender.")),
        "{names:?}"
    );
    for tool in &tools {
        if ADAPTER_TOOLS.contains(&tool["name"].as_str().unwrap_or("")) {
            assert_eq!(
                tool["inputSchema"]["type"], "object",
                "{} schema must be an object schema",
                tool["name"]
            );
        }
    }
}

#[test]
fn target_list_reports_honest_declarations() {
    let mut s = spawn(full_scratch(), "full");
    let response = s.call("target.list", json!({}), false);
    let body = structured(&response);
    let targets = body["targets"].as_array().expect("targets array");
    let by_id = |id: &str| {
        targets
            .iter()
            .find(|target| target["id"] == id)
            .unwrap_or_else(|| panic!("target {id} missing: {body}"))
            .clone()
    };
    // No [blender] section: the Blender adapter is not declared.
    assert!(
        !targets.iter().any(|target| target["id"] == "blender"),
        "{body}"
    );
    let unreal = by_id("unreal");
    assert_eq!(unreal["depth"], "scripted-deep");
    assert_eq!(unreal["capabilities"]["execute"], true);
    let unity = by_id("unity");
    assert_eq!(unity["depth"], "scripted-deep");
    assert_eq!(unity["capabilities"]["execute"], true);
    assert_eq!(unity["capabilities"]["actuate"], false);
    let godot = by_id("godot");
    assert_eq!(godot["depth"], "scripted-deep");
    // The floor declares its limits: generic depth, no execute.
    let floor = by_id("gui-floor");
    assert_eq!(floor["depth"], "generic-floor");
    assert_eq!(floor["capabilities"]["execute"], false);
    assert_eq!(floor["capabilities"]["actuate"], true);
    assert_eq!(floor["capabilities"]["observe"], true);
    let ops = floor["ops"].as_array().expect("floor ops");
    assert!(!ops.iter().any(|op| op == "execute"), "{floor}");
}

#[test]
fn status_carries_the_target_declarations() {
    let mut s = spawn(full_scratch(), "full");
    let response = s.call("seahawk_status", json!({}), false);
    let body = structured(&response);
    let targets = body["targets"].as_array().expect("status targets");
    assert_eq!(targets.len(), 4, "{body}");
}

#[test]
fn unity_status_round_trips_through_the_cli() {
    let mut s = spawn(full_scratch(), "full");
    let response = s.call("unity.status", json!({}), false);
    let body = structured(&response);
    assert!(
        body["cli_version"]
            .as_str()
            .unwrap_or("")
            .contains("unity-cli"),
        "{response}"
    );
    assert!(body["editors_installed"].is_array(), "{response}");
}

#[test]
fn godot_status_inspect_and_run_round_trip() {
    let mut s = spawn(full_scratch(), "full");
    let response = s.call("godot.status", json!({}), false);
    let body = structured(&response);
    assert!(
        body["version"].as_str().unwrap_or("").contains("4.7.2"),
        "{response}"
    );
    let project = s.scratch.project.display().to_string();
    let response = s.call("godot.inspect", json!({"project": project}), false);
    let body = structured(&response);
    assert_eq!(body["name"], "WireProject", "{response}");
    assert_eq!(body["scene_files"], 1, "{response}");
    assert_eq!(body["script_files"], 1, "{response}");
    // The run is execute-class: operator token rides.
    let response = s.call(
        "godot.run_script",
        json!({"project": project, "script": "main.gd"}),
        true,
    );
    let body = structured(&response);
    assert_eq!(body["exit_code"], 0, "{response}");
    assert!(
        body["stdout"].as_str().unwrap_or("").contains("godot-wire"),
        "{response}"
    );
}

#[test]
fn adapter_packs_scope_the_listing() {
    let mut s = spawn(full_scratch(), "godot");
    let names = s.list_names();
    for expected in CORE.iter() {
        assert!(names.contains(&expected.to_string()), "{names:?}");
    }
    assert!(names.contains(&"godot.run_script".to_string()), "{names:?}");
    assert!(!names.contains(&"unity.status".to_string()), "{names:?}");
    assert!(!names.contains(&"gui.floor_act".to_string()), "{names:?}");
}

// ---------------------------------------------------------------------------
// Adversarial
// ---------------------------------------------------------------------------

#[test]
fn unity_run_method_without_operator_token_is_refused() {
    let mut s = spawn(full_scratch(), "full");
    let project = s.scratch.project.display().to_string();
    let response = s.call(
        "unity.run_method",
        json!({"project": project, "method": "Some.Class"}),
        false,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );
}

#[test]
fn unity_run_method_with_a_shell_shaped_method_is_refused() {
    let mut s = spawn(full_scratch(), "full");
    let project = s.scratch.project.display().to_string();
    for method in ["Foo.Bar; rm -rf /", "Foo.Bar$(id)", "../Foo.Bar"] {
        let response = s.call(
            "unity.run_method",
            json!({"project": project, "method": method}),
            true,
        );
        assert_eq!(
            structured_error_code(&response).as_deref(),
            Some("seahawk_bad_arguments"),
            "{method}: {response}"
        );
    }
}

#[test]
fn godot_run_script_escaping_the_project_is_refused() {
    let mut s = spawn(full_scratch(), "full");
    let project = s.scratch.project.display().to_string();
    for script in ["../escape.gd", "/etc/passwd.gd", "sub/../../escape.gd"] {
        let response = s.call(
            "godot.run_script",
            json!({"project": project, "script": script}),
            true,
        );
        assert_eq!(
            structured_error_code(&response).as_deref(),
            Some("seahawk_target_capability"),
            "{script}: {response}"
        );
    }
}

#[test]
fn floor_act_outside_the_vocabulary_is_refused() {
    let mut s = spawn(full_scratch(), "full");
    let response = s.call(
        "gui.floor_act",
        json!({"action": "scroll", "x": 1, "y": 2}),
        true,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_gui_unknown_action"),
        "{response}"
    );
    // And without the operator token the actuate gate fires first.
    let response = s.call(
        "gui.floor_act",
        json!({"action": "click", "x": 1, "y": 2}),
        false,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );
}

#[test]
fn unwrapped_verbs_and_unconfigured_adapters_refuse_typed() {
    // unity.eval is deliberately not a wrapped verb (the
    // connector's standing rule): unknown tool, typed.
    let mut s = spawn(full_scratch(), "full");
    let response = s.call("unity.eval", json!({"code": "1"}), true);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_unknown_tool"),
        "{response}"
    );
    // No [godot] section: the call refuses as unavailable, not
    // as a downstream error.
    let scratch = Scratch::new(&["unity"], &["godot.run_script"], &[]);
    let mut s = spawn(scratch, "full");
    let response = s.call(
        "godot.run_script",
        json!({"project": "/tmp", "script": "x.gd"}),
        true,
    );
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_target_unavailable"),
        "{response}"
    );
}
