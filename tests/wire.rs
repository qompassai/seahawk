//! Wire-level integration tests against the real `seahawk` binary
//! with a stub Epic downstream (a raw-TCP fake of the editor's MCP
//! server speaking the measured legacy surface: initialize +
//! session header, list_toolsets / describe_toolset / call_tool).
//!
//! The battery is roughly half adversarial, per the estate split:
//! the execute gate must be unreachable around — no token, wrong
//! token, operator token missing/wrong, case-variant names (the
//! downstream lookup is case-insensitive), renamed tools,
//! unclassified tools, pipelined bursts, malformed frames.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde_json::{Value, json};

const AGENT_TOKEN: &str = "agent-secret";
const OPERATOR_TOKEN: &str = "operator-secret";
const READ_TOOL: &str = "EditorToolset.EditorAppToolset.GetSelectedActors";
const WRITE_TOOL: &str = "EditorToolset.EditorAppToolset.SelectActors";
const EXEC_TOOL: &str =
    "editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script";
const UNCLASSIFIED_TOOL: &str = "Fake.NewToolset.MysteryTool";

// ---------------------------------------------------------------------------
// Stub downstream (Epic's editor server, faked at the wire)
// ---------------------------------------------------------------------------

struct Stub {
    port: u16,
    dispatches: Arc<Mutex<Vec<Value>>>,
}

fn stub_respond(stream: &mut std::net::TcpStream, status: u16, session: bool, body: &str) {
    let mut response = format!(
        "HTTP/1.1 {status} OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n",
        body.len()
    );
    if session {
        response.push_str("Mcp-Session-Id: stub-session-1\r\n");
    }
    response.push_str("\r\n");
    response.push_str(body);
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn stub_handle(stream: &mut std::net::TcpStream, dispatches: &Arc<Mutex<Vec<Value>>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let Ok(request) = serde_json::from_slice::<Value>(&body) else {
        return;
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if method == "notifications/initialized" {
        stub_respond(stream, 202, false, "");
        return;
    }
    if method == "initialize" {
        let result = json!({
            "jsonrpc": "2.0", "id": id,
            "result": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "serverInfo": {"name": "", "version": ""}}
        });
        stub_respond(stream, 200, true, &result.to_string());
        return;
    }
    if method != "tools/call" {
        let result = json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": "stub: unknown method"}});
        stub_respond(stream, 200, false, &result.to_string());
        return;
    }
    let params = &request["params"];
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
    let result_body = match name {
        "list_toolsets" => json!({
            "jsonrpc": "2.0", "id": id,
            "result": {"content": [{"type": "text", "text":
                "Available toolsets:\n  - EditorToolset.EditorAppToolset: app tools\n  - editor_toolset.toolsets.programmatic.ProgrammaticToolset: programmatic\n  - Fake.NewToolset: fake\n"}]}
        }),
        "describe_toolset" => {
            let toolset = arguments
                .get("toolset_name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let described = match toolset {
                "EditorToolset.EditorAppToolset" => json!({
                    "name": "EditorToolset.EditorAppToolset", "version": "1.0",
                    "description": "app tools",
                    "tools": [
                        {"name": READ_TOOL, "description": "Gets the selected actors",
                         "inputSchema": {"type": "object", "properties": {}}},
                        {"name": WRITE_TOOL, "description": "Selects actors",
                         "inputSchema": {"type": "object", "properties": {"actors": {"type": "array", "items": {"type": "string"}}}}}
                    ]
                }),
                "editor_toolset.toolsets.programmatic.ProgrammaticToolset" => json!({
                    "name": "editor_toolset.toolsets.programmatic.ProgrammaticToolset",
                    "version": "1.0", "description": "programmatic",
                    "tools": [
                        {"name": EXEC_TOOL, "description": "Execute a Python script against the toolset APIs",
                         "inputSchema": {"type": "object", "properties": {"script": {"type": "string"}}}}
                    ]
                }),
                "Fake.NewToolset" => json!({
                    "name": "Fake.NewToolset", "version": "1.0", "description": "fake",
                    "tools": [
                        {"name": UNCLASSIFIED_TOOL, "description": "A tool the census never classified",
                         "inputSchema": {"type": "object", "properties": {}}}
                    ]
                }),
                _ => {
                    let result = json!({"jsonrpc": "2.0", "id": id,
                        "result": {"content": [{"type": "text", "text": "error: toolset not found"}], "isError": true}});
                    stub_respond(stream, 200, false, &result.to_string());
                    return;
                }
            };
            json!({"jsonrpc": "2.0", "id": id,
                "result": {"content": [{"type": "text", "text": described.to_string()}]}})
        }
        "call_tool" => {
            dispatches
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(arguments.clone());
            let tool_name = arguments
                .get("tool_name")
                .and_then(Value::as_str)
                .unwrap_or("?");
            json!({"jsonrpc": "2.0", "id": id,
                "result": {"content": [{"type": "text", "text": format!("called {tool_name}")}], "isError": false}})
        }
        _ => json!({"jsonrpc": "2.0", "id": id,
            "error": {"code": -32602, "message": "stub: unknown meta-tool"}}),
    };
    stub_respond(stream, 200, false, &result_body.to_string());
}

fn start_stub() -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let port = listener.local_addr().expect("addr").port();
    let dispatches = Arc::new(Mutex::new(Vec::new()));
    let thread_dispatches = dispatches.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => stub_handle(&mut stream, &thread_dispatches),
                Err(_) => return,
            }
        }
    });
    Stub { port, dispatches }
}

impl Stub {
    fn dispatch_count(&self) -> usize {
        self.dispatches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }
    fn dispatches(&self) -> Vec<Value> {
        self.dispatches
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

// ---------------------------------------------------------------------------
// Session: the real binary + a generated config, in a scratch dir
// ---------------------------------------------------------------------------

struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(port: u16, execute_enabled: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seahawk-wire-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir scratch");
        let enabled = if execute_enabled {
            format!("execute_enabled = [\"{EXEC_TOOL}\"]")
        } else {
            String::new()
        };
        let body = format!(
            "[server]\nagent_token = \"{AGENT_TOKEN}\"\noperator_token = \"{OPERATOR_TOKEN}\"\n\
             [downstream]\nurl = \"http://127.0.0.1:{port}/mcp\"\ntimeout_secs = 10\n\
             [policy]\n{enabled}\n\
             [oplog]\npath = \"{}\"\n",
            dir.join("oplog.jsonl").display()
        );
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
    _scratch: Scratch,
}

impl Session {
    fn spawn(execute_enabled: bool) -> (Self, Stub) {
        let stub = start_stub();
        let scratch = Scratch::new(stub.port, execute_enabled);
        let mut child = Command::new(env!("CARGO_BIN_EXE_seahawk"))
            .arg(scratch.dir.join("seahawk.toml"))
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
        (
            Session {
                child,
                stdin,
                lines: rx,
                buffered: Vec::new(),
                next_id: 0,
                _scratch: scratch,
            },
            stub,
        )
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

    /// Reads frames until one carries `id`; returns it. Frames
    /// for other ids are buffered, never dropped — callers may
    /// await ids in any order.
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

    /// A tools/call with the agent token (and optionally an operator
    /// token) in `_meta`.
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

    /// A tools/call with NO token at all.
    fn call_no_token(&mut self, name: &str, arguments: Value) -> Value {
        self.rpc(
            "tools/call",
            json!({"name": name, "arguments": arguments, "_meta": meta()}),
        )
    }

    fn oplog_text(&self) -> String {
        self._scratch.oplog_text()
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
        "io.modelcontextprotocol/clientInfo": {"name": "seahawk-wire-test", "version": "0.1.0"},
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

fn result_text(response: &Value) -> String {
    response
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Era guard battery
// ---------------------------------------------------------------------------

#[test]
fn legacy_initialize_refused_32022_and_connection_survives() {
    let (mut s, _stub) = Session::spawn(false);
    let response = s.rpc(
        "initialize",
        json!({"protocolVersion": "2025-03-26", "capabilities": {},
               "clientInfo": {"name": "legacy", "version": "0"}}),
    );
    let error = &response["error"];
    assert_eq!(error["code"], -32022, "legacy initialize: {response}");
    assert_eq!(error["data"]["requested"], "2025-03-26");
    assert_eq!(error["data"]["supported"], json!(["2026-07-28"]));
    // The connection stays up: a modern discover still answers.
    s.handshake();
}

#[test]
fn discover_reports_seahawk_and_modern_version() {
    let (mut s, _stub) = Session::spawn(false);
    let response = s.rpc("server/discover", json!({"_meta": meta()}));
    let result = &response["result"];
    assert_eq!(
        result["supportedVersions"],
        json!(["2026-07-28"]),
        "{response}"
    );
    assert_eq!(
        result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "seahawk",
        "{response}"
    );
}

#[test]
fn malformed_and_non_object_frames_draw_parse_errors() {
    let (mut s, _stub) = Session::spawn(false);
    s.send_raw("this is not json\n");
    let frame = s.recv_for(0);
    assert_eq!(frame["error"]["code"], -32700);
    s.send_raw("[1, 2, 3]\n");
    let frame = s.recv_for(0);
    assert_eq!(frame["error"]["code"], -32600);
}

// ---------------------------------------------------------------------------
// Surface curation
// ---------------------------------------------------------------------------

#[test]
fn every_listed_tool_has_an_object_input_schema() {
    // Strict clients (the MCP Inspector's TS SDK) silently drop a
    // tool whose inputSchema is not an object schema; seahawk_status
    // once shipped a bare {} schema and vanished from such clients
    // while raw JSON-RPC listings still showed it.
    let (mut s, _stub) = Session::spawn(false);
    s.handshake();
    let response = s.rpc("tools/list", json!({"_meta": meta()}));
    let tools = response["result"]["tools"].as_array().expect("tools array");
    assert!(tools.len() >= 3);
    for tool in tools {
        assert_eq!(
            tool["inputSchema"]["type"], "object",
            "tool {} lacks an object inputSchema",
            tool["name"]
        );
    }
}

#[test]
fn tools_list_curates_the_surface() {
    let (mut s, _stub) = Session::spawn(false);
    s.handshake();
    let response = s.rpc("tools/list", json!({"_meta": meta()}));
    let tools = response["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in [
        "seahawk_status",
        "seahawk_surface",
        "seahawk_oplog",
        READ_TOOL,
        WRITE_TOOL,
        EXEC_TOOL,
    ] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }
    assert!(
        !names.contains(&UNCLASSIFIED_TOOL),
        "unclassified tool must be withheld: {names:?}"
    );
    let exec = tools
        .iter()
        .find(|t| t["name"] == EXEC_TOOL)
        .expect("execute tool listed");
    assert_eq!(exec["annotations"]["destructiveHint"], true);
    assert!(
        exec["description"]
            .as_str()
            .unwrap()
            .contains("default-deny"),
        "execute tool must be labeled: {exec}"
    );
    let read = tools.iter().find(|t| t["name"] == READ_TOOL).unwrap();
    assert_eq!(read["annotations"]["readOnlyHint"], true);
}

// ---------------------------------------------------------------------------
// Agent-token gate (guard)
// ---------------------------------------------------------------------------

#[test]
fn call_without_token_refused_32001_and_logged_and_never_dispatched() {
    let (mut s, stub) = Session::spawn(false);
    s.handshake();
    // Warm the surface (list is open by default policy).
    let _ = s.rpc("tools/list", json!({"_meta": meta()}));
    let before = stub.dispatch_count();
    let response = s.call_no_token(READ_TOOL, json!({}));
    assert_eq!(response["error"]["code"], -32001, "{response}");
    assert_eq!(response["error"]["data"]["code"], "seahawk_unauthorized");
    assert_eq!(response["error"]["data"]["reason"], "missing_token");
    assert_eq!(stub.dispatch_count(), before, "refused call dispatched!");
    let log = s.oplog_text();
    assert!(
        log.contains("refused:seahawk_unauthorized"),
        "op log must record the refusal: {log}"
    );
}

#[test]
fn call_with_wrong_token_refused_bad_token() {
    let (mut s, _stub) = Session::spawn(false);
    s.handshake();
    let response = s.rpc(
        "tools/call",
        json!({"name": READ_TOOL, "arguments": {},
               "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                         "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "0"},
                         "io.modelcontextprotocol/clientCapabilities": {},
                         "seahawk/agent_token": "not-the-token"}}),
    );
    assert_eq!(response["error"]["code"], -32001);
    assert_eq!(response["error"]["data"]["reason"], "bad_token");
}

#[test]
fn operator_token_alone_does_not_satisfy_the_agent_gate() {
    let (mut s, stub) = Session::spawn(true);
    s.handshake();
    let before = stub.dispatch_count();
    // Operator token present, agent token absent: the guard must
    // still refuse. The two tokens are independent gates.
    let response = s.rpc(
        "tools/call",
        json!({"name": EXEC_TOOL, "arguments": {"script": "pass"},
               "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                         "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "0"},
                         "io.modelcontextprotocol/clientCapabilities": {},
                         "seahawk/operator_token": OPERATOR_TOKEN}}),
    );
    assert_eq!(response["error"]["code"], -32001);
    assert_eq!(stub.dispatch_count(), before);
}

// ---------------------------------------------------------------------------
// Brokered round trips
// ---------------------------------------------------------------------------

#[test]
fn read_call_round_trips_strips_token_and_logs_digest() {
    let (mut s, stub) = Session::spawn(false);
    s.handshake();
    let response = s.call(READ_TOOL, json!({}), None);
    assert_eq!(
        result_text(&response),
        format!("called {}", "GetSelectedActors")
    );
    let dispatches = stub.dispatches();
    let call_tool_dispatches: Vec<&Value> = dispatches
        .iter()
        .filter(|d| d.get("tool_name").is_some())
        .collect();
    assert_eq!(call_tool_dispatches.len(), 1);
    assert_eq!(call_tool_dispatches[0]["tool_name"], "GetSelectedActors");
    assert_eq!(
        call_tool_dispatches[0]["toolset_name"],
        "EditorToolset.EditorAppToolset"
    );
    // The agent token must never reach the downstream.
    let raw = serde_json::to_string(&dispatches).unwrap();
    assert!(!raw.contains(AGENT_TOKEN), "token leaked downstream: {raw}");
    assert!(
        !raw.contains(OPERATOR_TOKEN),
        "token leaked downstream: {raw}"
    );
    // Op log: ok outcome, class read, 64-hex args digest, no raw args.
    let log = s.oplog_text();
    assert!(log.contains("\"outcome\":\"ok\""), "{log}");
    assert!(log.contains("\"class\":\"read\""), "{log}");
    assert!(log.contains("\"args_sha256\":\""), "{log}");
}

#[test]
fn write_call_round_trips() {
    let (mut s, _stub) = Session::spawn(false);
    s.handshake();
    let response = s.call(WRITE_TOOL, json!({"actors": ["Actor1"]}), None);
    assert_eq!(result_text(&response), "called SelectActors");
    let log = s.oplog_text();
    assert!(log.contains("\"class\":\"write\""), "{log}");
}

// ---------------------------------------------------------------------------
// Execute gate battery (S2)
// ---------------------------------------------------------------------------

#[test]
fn execute_is_default_deny_even_with_agent_token() {
    let (mut s, stub) = Session::spawn(false);
    s.handshake();
    let _ = s.rpc("tools/list", json!({"_meta": meta()}));
    let before = stub.dispatch_count();
    let response = s.call(EXEC_TOOL, json!({"script": "import unreal"}), None);
    assert_eq!(response["result"]["isError"], true, "{response}");
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_execute_disabled")
    );
    assert_eq!(stub.dispatch_count(), before, "denied execute dispatched!");
}

#[test]
fn execute_case_variant_name_is_still_execute_class() {
    let (mut s, stub) = Session::spawn(false);
    s.handshake();
    let _ = s.rpc("tools/list", json!({"_meta": meta()}));
    let before = stub.dispatch_count();
    // Downstream tool lookup is case-insensitive; a case variant
    // must not smuggle the tool past the class table.
    let shouted = EXEC_TOOL.to_uppercase();
    let response = s.call(&shouted, json!({"script": "pass"}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_execute_disabled"),
        "{response}"
    );
    assert_eq!(stub.dispatch_count(), before);
}

#[test]
fn unknown_and_renamed_tools_are_refused() {
    let (mut s, stub) = Session::spawn(false);
    s.handshake();
    let _ = s.rpc("tools/list", json!({"_meta": meta()}));
    let before = stub.dispatch_count();
    for name in [
        "EditorToolset.EditorAppToolset.GetSelectedActorsX",
        "editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script2",
        "Totally.MadeUp.Tool",
    ] {
        let response = s.call(name, json!({}), None);
        assert_eq!(
            structured_error_code(&response).as_deref(),
            Some("seahawk_unknown_tool"),
            "{name}: {response}"
        );
    }
    assert_eq!(stub.dispatch_count(), before);
}

#[test]
fn unclassified_tool_is_refused() {
    let (mut s, stub) = Session::spawn(false);
    s.handshake();
    let _ = s.rpc("tools/list", json!({"_meta": meta()}));
    let before = stub.dispatch_count();
    let response = s.call(UNCLASSIFIED_TOOL, json!({}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_unclassified"),
        "{response}"
    );
    assert_eq!(stub.dispatch_count(), before);
}

#[test]
fn operator_gate_full_cycle() {
    let (mut s, stub) = Session::spawn(true);
    s.handshake();
    let _ = s.rpc("tools/list", json!({"_meta": meta()}));

    // Enabled in policy, but no operator token on the call.
    let response = s.call(EXEC_TOOL, json!({"script": "pass"}), None);
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );

    // Wrong operator token.
    let response = s.call(EXEC_TOOL, json!({"script": "pass"}), Some("operator-wrong"));
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );

    // The agent token is not an operator token.
    let response = s.call(EXEC_TOOL, json!({"script": "pass"}), Some(AGENT_TOKEN));
    assert_eq!(
        structured_error_code(&response).as_deref(),
        Some("seahawk_operator_required"),
        "{response}"
    );

    // Correct operator token: the call goes through.
    let before = stub.dispatch_count();
    let response = s.call(EXEC_TOOL, json!({"script": "pass"}), Some(OPERATOR_TOKEN));
    assert_eq!(result_text(&response), "called execute_tool_script");
    assert_eq!(stub.dispatch_count(), before + 1);
    let log = s.oplog_text();
    assert!(log.contains("\"class\":\"execute\""), "{log}");
    assert!(log.contains("refused:seahawk_operator_required"), "{log}");
}

// ---------------------------------------------------------------------------
// Pipelining + native tools
// ---------------------------------------------------------------------------

#[test]
fn pipelined_burst_is_fully_answered_in_order() {
    let (mut s, stub) = Session::spawn(false);
    s.handshake();
    let _ = s.rpc("tools/list", json!({"_meta": meta()}));
    // Three frames in ONE write: an unauthorized call, an
    // authorized read, an unknown method.
    let burst = format!(
        "{}\n{}\n{}\n",
        json!({"jsonrpc": "2.0", "id": 41, "method": "tools/call",
               "params": {"name": READ_TOOL, "arguments": {}}}),
        json!({"jsonrpc": "2.0", "id": 42, "method": "tools/call",
               "params": {"name": READ_TOOL, "arguments": {},
                          "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                                    "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "0"},
                                    "io.modelcontextprotocol/clientCapabilities": {},
                                    "seahawk/agent_token": AGENT_TOKEN}}}),
        json!({"jsonrpc": "2.0", "id": 43, "method": "bogus/method", "params": {}}),
    );
    s.send_raw(&burst);
    let r41 = s.recv_for(41);
    let r42 = s.recv_for(42);
    let r43 = s.recv_for(43);
    assert_eq!(r41["error"]["code"], -32001, "{r41}");
    assert_eq!(result_text(&r42), "called GetSelectedActors", "{r42}");
    assert_eq!(r43["error"]["code"], -32601, "{r43}");
    let _ = stub;
}

#[test]
fn native_oplog_tool_returns_entries() {
    let (mut s, _stub) = Session::spawn(false);
    s.handshake();
    let _ = s.call_no_token(READ_TOOL, json!({}));
    let _ = s.call(READ_TOOL, json!({}), None);
    let response = s.call("seahawk_oplog", json!({"limit": 10}), None);
    let text = result_text(&response);
    assert!(text.contains("seahawk_unauthorized"), "{text}");
    assert!(text.contains("\"ok\""), "{text}");
}
