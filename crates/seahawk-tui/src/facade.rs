//! The narrow broker surface the TUI programs against.
//!
//! [`SeahawkFacade`] exposes exactly what the screens need:
//! `status`, `tools`, `call`, `oplog_entries`, `registered_apps`.
//! Three implementations:
//!
//! - [`LibFacade`] — over the `seahawk` library crate where it is
//!   reachable: config-derived status, the compiled-in class
//!   table, registered GUI apps from policy, and the op log read
//!   from disk. Brokered downstream calls are *not* reachable
//!   from the lib alone (they need the running broker's guard,
//!   tokens, and downstream session), so they answer
//!   [`FacadeError::Unavailable`] with that reason — never a
//!   fabricated success.
//! - [`StdioFacade`] — the MCP stdio client fallback: spawns the
//!   `seahawk` broker binary and speaks modern-era (2026-07-28)
//!   JSON-RPC over its stdio, the same transport the trigger
//!   layer (DESIGN §D4) uses. The agent token, when configured,
//!   comes from the `SEAHAWK_AGENT_TOKEN` environment variable
//!   and is never logged.
//! - [`FakeFacade`] — in-memory, scripted, records every call;
//!   used by every test, including the server-death case.
//!
//! The TUI never connects to a real Unreal editor session on its
//! own: the lib facade makes no downstream connection at all, and
//! the stdio facade only talks to a broker the operator started
//! it against.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use serde_json::{Value, json};

use seahawk::config::Config;
use seahawk::model::ToolClass;

use crate::oplog;

/// One tool as the Sessions screen lists it.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolInfo {
    /// Fully-qualified tool name.
    pub name: String,
    /// The tool's class, when classified. `None` = unclassified
    /// (Seahawk withholds unclassified tools by default).
    pub class: Option<ToolClass>,
    /// Human-facing description, may be empty.
    pub description: String,
}

impl ToolInfo {
    /// The class word (`read`/`write`/`actuate`/`execute`), or
    /// `unclassified`.
    pub fn class_str(&self) -> &str {
        match self.class {
            Some(class) => class.as_str(),
            None => "unclassified",
        }
    }

    /// Actuate- and execute-class are the gated classes: in
    /// Seahawk both share the two-key default-deny rule, and in
    /// this TUI both are plan-only in rung 1.
    pub fn is_gated_class(&self) -> bool {
        matches!(
            self.class,
            Some(ToolClass::Actuate) | Some(ToolClass::Execute)
        )
    }
}

/// Whether a class is gated (plan-only in rung 1).
pub fn is_gated_class(class: Option<ToolClass>) -> bool {
    matches!(class, Some(ToolClass::Actuate) | Some(ToolClass::Execute))
}

/// The class of a broker-native or GUI tool by construction, else
/// the compiled-in S0 class table (`seahawk::model::default_class`).
pub fn class_of_tool_name(name: &str) -> Option<ToolClass> {
    match name {
        "seahawk_status" | "seahawk_surface" | "seahawk_oplog" | "code.feedback"
        | "gui.observe" | "gui.ground" => Some(ToolClass::Read),
        "gui.act_verified" => Some(ToolClass::Actuate),
        // The acquisition verb is destructive by annotation in the
        // broker; the TUI classes it execute so rung-1 plan-only
        // gating covers it.
        "seahawk_acquire" => Some(ToolClass::Execute),
        _ => {
            if name.starts_with("gui.") && name.ends_with(".observe") {
                Some(ToolClass::Read)
            } else if name.starts_with("gui.") && name.ends_with(".actuate") {
                Some(ToolClass::Actuate)
            } else {
                seahawk::model::default_class(name)
            }
        }
    }
}

/// Typed facade failures. `ServerDied` is distinct because the
/// Sessions screen must say the broker went away mid-call, not
/// dress it up as an ordinary refusal.
#[derive(Clone, Debug, PartialEq)]
pub enum FacadeError {
    /// The operation is not reachable through this facade.
    Unavailable(String),
    /// The broker (or the facade's own gate) refused the call.
    Refused {
        /// Seahawk's typed refusal code, fleet mold.
        code: String,
        /// Human-facing refusal message.
        message: String,
    },
    /// The broker process exited or its stdio closed mid-call.
    ServerDied(String),
    /// The caller's input failed validation before any call.
    Invalid(String),
}

impl std::fmt::Display for FacadeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => write!(f, "unavailable: {message}"),
            Self::Refused { code, message } => write!(f, "refused:{code}: {message}"),
            Self::ServerDied(message) => write!(f, "server died: {message}"),
            Self::Invalid(message) => write!(f, "invalid: {message}"),
        }
    }
}

impl std::error::Error for FacadeError {}

/// Maximum serialized size of one `call` argument payload.
pub const CALL_ARGS_BYTES_MAX: usize = 65_536;
/// Maximum bytes of one stdio JSON-RPC line, either direction.
pub const STDIO_LINE_BYTES_MAX: usize = 1_048_576;
/// Default reply deadline for one stdio request, milliseconds.
pub const STDIO_REPLY_TIMEOUT_MS: u64 = 30_000;
/// Tools listed by the Sessions screen are capped at this count.
pub const TOOLS_MAX: usize = 2_048;

/// The broker operations the TUI screens need.
pub trait SeahawkFacade {
    /// Broker status (the `seahawk_status` shape).
    fn status(&mut self) -> Result<Value, FacadeError>;
    /// The tool list the Sessions screen stages from.
    fn tools(&mut self) -> Result<Vec<ToolInfo>, FacadeError>;
    /// One tool call. Implementations must refuse or fail typed,
    /// never panic, on broker errors or death.
    fn call(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError>;
    /// Recent op-log entries as raw JSON values, newest last.
    fn oplog_entries(&mut self, limit: usize) -> Result<Vec<Value>, FacadeError>;
    /// Registered GUI applications (policy data), as JSON objects
    /// with at least `name` and `display_name`.
    fn registered_apps(&mut self) -> Result<Vec<Value>, FacadeError>;
}

/// Validate one call's arguments against the byte bound before
/// any facade work happens.
pub fn validate_call(tool: &str, args: &Value) -> Result<(), FacadeError> {
    if tool.is_empty() || tool.chars().count() > 256 {
        return Err(FacadeError::Invalid(format!(
            "tool name must be 1..=256 chars, got {} chars",
            tool.chars().count()
        )));
    }
    let bytes = serde_json::to_string(args)
        .map(|text| text.len())
        .unwrap_or(0);
    if bytes > CALL_ARGS_BYTES_MAX {
        return Err(FacadeError::Invalid(format!(
            "arguments serialize to {bytes} bytes, over CALL_ARGS_BYTES_MAX {CALL_ARGS_BYTES_MAX}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FakeFacade
// ---------------------------------------------------------------------------

/// An in-memory [`SeahawkFacade`] for tests: scripted results,
/// recorded calls. `die_on_call` simulates the broker dying
/// mid-call: the named tool's call answers
/// [`FacadeError::ServerDied`] after being recorded.
#[derive(Debug, Default)]
pub struct FakeFacade {
    /// Result returned by `status`.
    pub status_result: Value,
    /// Tools returned by `tools`.
    pub tools_result: Vec<ToolInfo>,
    /// Results for successive `call`s; when empty, `call` returns
    /// `{"ok": true, "echo": <tool>}`.
    pub call_results: VecDeque<Result<Value, FacadeError>>,
    /// Every `(tool, args)` passed to `call`, in order. The
    /// plan-mode tests prove staging by asserting this stays
    /// empty until approval.
    pub calls: Vec<(String, Value)>,
    /// Entries returned by `oplog_entries`.
    pub oplog_result: Vec<Value>,
    /// Apps returned by `registered_apps`.
    pub apps_result: Vec<Value>,
    /// When set, a call to this tool answers `ServerDied`.
    pub die_on_call: Option<String>,
    /// When set, `status` answers this error.
    pub status_error: Option<FacadeError>,
}

impl FakeFacade {
    /// A fake with empty scripted results.
    pub fn new() -> Self {
        Self::default()
    }

    /// A fake preloaded with the canonical test surface: one tool
    /// per class plus the native status tool.
    pub fn with_default_surface() -> Self {
        let mut fake = Self::new();
        fake.status_result = json!({
            "server": "seahawk", "version": "1.0.0",
            "downstream_url": "http://127.0.0.1:8000/mcp",
            "downstream_surface_built": false,
            "operator_token_configured": false,
        });
        fake.tools_result = vec![
            ToolInfo {
                name: "seahawk_status".to_string(),
                class: Some(ToolClass::Read),
                description: "Broker status".to_string(),
            },
            ToolInfo {
                name: "EditorToolset.EditorAppToolset.GetSelectedActors".to_string(),
                class: Some(ToolClass::Read),
                description: "Read selection".to_string(),
            },
            ToolInfo {
                name: "EditorToolset.EditorAppToolset.SetActorTransform".to_string(),
                class: Some(ToolClass::Write),
                description: "Move an actor".to_string(),
            },
            ToolInfo {
                name: "gui.blender.actuate".to_string(),
                class: Some(ToolClass::Actuate),
                description: "Drive Blender".to_string(),
            },
            ToolInfo {
                name:
                    "editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script"
                        .to_string(),
                class: Some(ToolClass::Execute),
                description: "Run a tool script".to_string(),
            },
        ];
        fake.apps_result = vec![json!({"name": "blender", "display_name": "Blender"})];
        fake
    }
}

impl SeahawkFacade for FakeFacade {
    fn status(&mut self) -> Result<Value, FacadeError> {
        if let Some(error) = &self.status_error {
            return Err(error.clone());
        }
        Ok(self.status_result.clone())
    }

    fn tools(&mut self) -> Result<Vec<ToolInfo>, FacadeError> {
        Ok(self.tools_result.clone())
    }

    fn call(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError> {
        validate_call(tool, args)?;
        self.calls.push((tool.to_string(), args.clone()));
        if self.die_on_call.as_deref() == Some(tool) {
            return Err(FacadeError::ServerDied(format!(
                "fake broker exited during call to {tool}"
            )));
        }
        match self.call_results.pop_front() {
            Some(result) => result,
            None => Ok(json!({"ok": true, "echo": tool})),
        }
    }

    fn oplog_entries(&mut self, limit: usize) -> Result<Vec<Value>, FacadeError> {
        let start = self.oplog_result.len().saturating_sub(limit);
        Ok(self.oplog_result[start..].to_vec())
    }

    fn registered_apps(&mut self) -> Result<Vec<Value>, FacadeError> {
        Ok(self.apps_result.clone())
    }
}

// ---------------------------------------------------------------------------
// LibFacade
// ---------------------------------------------------------------------------

/// The library facade: Seahawk's own lib where it is reachable.
///
/// Reachable without a running broker: the validated config
/// (status, policy enablements, registered GUI apps, vision
/// route), the compiled-in class table (tool classes), and the
/// op log on disk. Not reachable: brokered downstream calls and
/// the downstream surface snapshot — those answer
/// [`FacadeError::Unavailable`] naming the stdio facade as the
/// transport that can serve them.
pub struct LibFacade {
    config: Option<Config>,
    config_error: Option<String>,
    oplog_path: PathBuf,
}

impl LibFacade {
    /// Build from an optional config path. A missing or invalid
    /// config degrades the facade (status says so) instead of
    /// failing construction: the op-log viewer must still work
    /// against a bare log file.
    pub fn new(config_path: Option<PathBuf>, oplog_override: Option<PathBuf>) -> Self {
        let (config, config_error) = match &config_path {
            Some(path) => match Config::load(path) {
                Ok(config) => (Some(config), None),
                Err(error) => (None, Some(format!("{error:#}"))),
            },
            None => (None, Some("no config path given".to_string())),
        };
        let oplog_path = oplog_override
            .or_else(|| config.as_ref().map(|config| config.oplog_path.clone()))
            .unwrap_or_else(|| PathBuf::from("seahawk-oplog.jsonl"));
        Self {
            config,
            config_error,
            oplog_path,
        }
    }

    /// Build directly from a parsed config (tests, embedding).
    pub fn from_config(config: Option<Config>, oplog_path: PathBuf) -> Self {
        Self {
            config,
            config_error: None,
            oplog_path,
        }
    }

    /// The op-log path this facade reads.
    pub fn oplog_path(&self) -> &std::path::Path {
        &self.oplog_path
    }

    fn gui_apps_json(&self) -> Vec<Value> {
        match &self.config {
            Some(config) => config
                .gui_apps
                .iter()
                .map(|app| {
                    json!({
                        "name": app.name,
                        "display_name": app.display_name,
                        "observe_tool": app.observe_tool(),
                        "actuate_tool": app.actuate_tool(),
                        "actuate_enabled": config.actuate_is_enabled(&app.actuate_tool()),
                        "window_match": app.window_match,
                    })
                })
                .collect(),
            None => Vec::new(),
        }
    }
}

impl SeahawkFacade for LibFacade {
    fn status(&mut self) -> Result<Value, FacadeError> {
        let (downstream_url, operator_configured, vision) = match &self.config {
            Some(config) => (
                Value::String(config.downstream_url.clone()),
                Value::Bool(config.operator_token_digest.is_some()),
                json!({
                    "grounder": match config.vision.route {
                        seahawk::config::VisionRoute::Ollama => "ollama",
                        seahawk::config::VisionRoute::Agent => "agent",
                        seahawk::config::VisionRoute::None => "none",
                    },
                    "min_confidence": config.vision.min_confidence,
                }),
            ),
            None => (Value::Null, Value::Bool(false), Value::Null),
        };
        Ok(json!({
            "server": "seahawk",
            "version": "1.0.0",
            "source": "lib",
            "config_loaded": self.config.is_some(),
            "config_error": self.config_error,
            "downstream_url": downstream_url,
            // The lib facade never opens a downstream session, so
            // reachability is honestly "unknown", never a guess.
            "downstream_reachability": "unknown (lib facade; use the stdio facade against a running broker for live state)",
            "downstream_surface_built": false,
            "operator_token_configured": operator_configured,
            "execute_enabled": self.config.as_ref().map(|c| c.execute_enabled.iter().collect::<Vec<_>>()).unwrap_or_default(),
            "actuate_enabled": self.config.as_ref().map(|c| c.actuate_enabled.iter().collect::<Vec<_>>()).unwrap_or_default(),
            "gui_apps": self.gui_apps_json(),
            "vision": vision,
            "oplog_path": self.oplog_path.display().to_string(),
        }))
    }

    fn tools(&mut self) -> Result<Vec<ToolInfo>, FacadeError> {
        let mut tools = vec![
            ToolInfo {
                name: "seahawk_status".to_string(),
                class: Some(ToolClass::Read),
                description: "Broker status (served locally by the lib facade)".to_string(),
            },
            ToolInfo {
                name: "seahawk_oplog".to_string(),
                class: Some(ToolClass::Read),
                description: "Recent op-log entries (served locally from the log file)".to_string(),
            },
            ToolInfo {
                name: "seahawk_surface".to_string(),
                class: Some(ToolClass::Read),
                description: "Brokered downstream surface (needs the live broker)".to_string(),
            },
            ToolInfo {
                name: "code.feedback".to_string(),
                class: Some(ToolClass::Read),
                description: "Structured code feedback (needs the live broker)".to_string(),
            },
            ToolInfo {
                name: "gui.observe".to_string(),
                class: Some(ToolClass::Read),
                description: "Observe a registered GUI app (needs the live broker)".to_string(),
            },
            ToolInfo {
                name: "gui.ground".to_string(),
                class: Some(ToolClass::Read),
                description: "Ground a target in a frame (needs the live broker)".to_string(),
            },
            ToolInfo {
                name: "gui.act_verified".to_string(),
                class: Some(ToolClass::Actuate),
                description: "Act and verify (actuate-class, default-deny)".to_string(),
            },
            ToolInfo {
                name: "seahawk_acquire".to_string(),
                class: Some(ToolClass::Execute),
                description: "Acquisition lane verb (execute-class for TUI gating)".to_string(),
            },
        ];
        if let Some(config) = &self.config {
            for app in &config.gui_apps {
                tools.push(ToolInfo {
                    name: app.observe_tool(),
                    class: Some(ToolClass::Read),
                    description: format!("Observe {} (read)", app.display_name),
                });
                tools.push(ToolInfo {
                    name: app.actuate_tool(),
                    class: Some(ToolClass::Actuate),
                    description: format!("Actuate {} (actuate, default-deny)", app.display_name),
                });
            }
        }
        tools.truncate(TOOLS_MAX);
        Ok(tools)
    }

    fn call(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError> {
        validate_call(tool, args)?;
        match tool {
            "seahawk_status" => self.status(),
            "seahawk_oplog" => {
                let limit = args
                    .get("limit")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(50)
                    .min(500);
                let entries = self.oplog_entries(limit)?;
                Ok(json!({"entries": entries}))
            }
            "seahawk_surface" => Err(FacadeError::Unavailable(
                "the downstream surface snapshot is built by the running broker; \
                 the lib facade cannot build it — run the TUI with --broker against \
                 a live broker (stdio facade)"
                    .to_string(),
            )),
            _ => Err(FacadeError::Unavailable(format!(
                "brokered call to {tool} requires the running broker (guard, tokens, \
                 downstream session); the lib facade serves seahawk_status and \
                 seahawk_oplog only — use --broker for live calls"
            ))),
        }
    }

    fn oplog_entries(&mut self, limit: usize) -> Result<Vec<Value>, FacadeError> {
        let report = oplog::load_oplog_file(&self.oplog_path)
            .map_err(|error| FacadeError::Unavailable(format!("reading op log: {error}")))?;
        let start = report.entries.len().saturating_sub(limit);
        Ok(report.entries[start..]
            .iter()
            .map(|entry| entry.raw.clone())
            .collect())
    }

    fn registered_apps(&mut self) -> Result<Vec<Value>, FacadeError> {
        Ok(self.gui_apps_json())
    }
}

// ---------------------------------------------------------------------------
// StdioFacade (MCP stdio client fallback)
// ---------------------------------------------------------------------------

/// The MCP stdio client facade: spawns the broker binary and
/// speaks modern-era JSON-RPC over its stdio.
///
/// Ownership: the child process and its stdin are owned here;
/// a reader thread owns stdout and forwards lines over a bounded
/// hand-off (an unbounded std `mpsc` channel, with the *line
/// count* bounded by the request/response discipline — one
/// outstanding request at a time, replies matched by id). Drop
/// kills the child. A closed channel or a reply timeout is
/// [`FacadeError::ServerDied`], never a hang.
pub struct StdioFacade {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
    agent_token: Option<String>,
    reply_timeout: Duration,
}

impl StdioFacade {
    /// Spawn `program` with `args` and run the modern-era
    /// initialize handshake. `agent_token` is presented per call
    /// in `_meta["seahawk/agent_token"]` when present.
    pub fn spawn(
        program: &str,
        args: &[String],
        agent_token: Option<String>,
    ) -> Result<Self, FacadeError> {
        Self::spawn_with_timeout(
            program,
            args,
            agent_token,
            Duration::from_millis(STDIO_REPLY_TIMEOUT_MS),
        )
    }

    /// [`Self::spawn`] with an explicit reply deadline (tests use
    /// a short one so a dead-on-spawn broker fails fast).
    pub fn spawn_with_timeout(
        program: &str,
        args: &[String],
        agent_token: Option<String>,
        reply_timeout: Duration,
    ) -> Result<Self, FacadeError> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| {
                FacadeError::Unavailable(format!("spawning broker {program}: {error}"))
            })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| FacadeError::Unavailable("broker stdin unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| FacadeError::Unavailable("broker stdout unavailable".to_string()))?;
        let (tx, rx) = channel::<String>();
        std::thread::Builder::new()
            .name("seahawk-tui-stdio-reader".to_string())
            .spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    match line {
                        Ok(line) => {
                            if tx.send(line).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|error| FacadeError::Unavailable(format!("reader thread: {error}")))?;
        let mut facade = Self {
            child,
            stdin,
            lines: rx,
            next_id: 0,
            agent_token,
            reply_timeout,
        };
        facade.request(
            "initialize",
            json!({
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "seahawk-tui", "version": env!("CARGO_PKG_VERSION")},
            }),
        )?;
        facade.notify("notifications/initialized", json!({}))?;
        Ok(facade)
    }

    fn write_frame(&mut self, frame: &Value) -> Result<(), FacadeError> {
        let text = serde_json::to_string(frame)
            .map_err(|error| FacadeError::Invalid(format!("serializing request: {error}")))?;
        if text.len() > STDIO_LINE_BYTES_MAX {
            return Err(FacadeError::Invalid(format!(
                "request line is {} bytes, over STDIO_LINE_BYTES_MAX {STDIO_LINE_BYTES_MAX}",
                text.len()
            )));
        }
        writeln!(self.stdin, "{text}")
            .and_then(|()| self.stdin.flush())
            .map_err(|error| FacadeError::ServerDied(format!("writing to broker stdin: {error}")))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), FacadeError> {
        self.write_frame(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, FacadeError> {
        self.next_id += 1;
        let id = self.next_id;
        self.write_frame(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params,
        }))?;
        loop {
            let line = self
                .lines
                .recv_timeout(self.reply_timeout)
                .map_err(|error| {
                    FacadeError::ServerDied(format!(
                        "broker did not answer {method} (id {id}): {error}"
                    ))
                })?;
            if line.len() > STDIO_LINE_BYTES_MAX {
                return Err(FacadeError::ServerDied(format!(
                    "broker sent a {}-byte line, over STDIO_LINE_BYTES_MAX {STDIO_LINE_BYTES_MAX}",
                    line.len()
                )));
            }
            let message: Value = serde_json::from_str(&line).map_err(|error| {
                FacadeError::ServerDied(format!("broker sent malformed JSON: {error}"))
            })?;
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue; // A notification or a stale reply; keep waiting.
            }
            if let Some(error) = message.get("error") {
                return Err(FacadeError::Refused {
                    code: error
                        .get("code")
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("broker error")
                        .to_string(),
                });
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    fn tool_call(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError> {
        let mut params = json!({"name": tool, "arguments": args});
        if let Some(token) = &self.agent_token
            && let Some(object) = params.as_object_mut()
        {
            object.insert("_meta".to_string(), json!({"seahawk/agent_token": token}));
        }
        let result = self.request("tools/call", params)?;
        // MCP tool results carry content blocks; surface the
        // structured content when present, else the text body.
        if let Some(structured) = result.get("structuredContent") {
            return Ok(structured.clone());
        }
        if result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let text = result
                .get("content")
                .and_then(Value::as_array)
                .and_then(|blocks| blocks.first())
                .and_then(|block| block.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("tool error")
                .to_string();
            return Err(FacadeError::Refused {
                code: "tool_error".to_string(),
                message: text,
            });
        }
        Ok(result)
    }
}

impl Drop for StdioFacade {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl SeahawkFacade for StdioFacade {
    fn status(&mut self) -> Result<Value, FacadeError> {
        self.tool_call("seahawk_status", &json!({}))
    }

    fn tools(&mut self) -> Result<Vec<ToolInfo>, FacadeError> {
        let result = self.request("tools/list", json!({}))?;
        let mut tools = Vec::new();
        if let Some(list) = result.get("tools").and_then(Value::as_array) {
            for item in list {
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                tools.push(ToolInfo {
                    class: class_of_tool_name(&name),
                    description: item
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    name,
                });
                if tools.len() >= TOOLS_MAX {
                    break;
                }
            }
        }
        Ok(tools)
    }

    fn call(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError> {
        validate_call(tool, args)?;
        self.tool_call(tool, args)
    }

    fn oplog_entries(&mut self, limit: usize) -> Result<Vec<Value>, FacadeError> {
        let result = self.tool_call("seahawk_oplog", &json!({"limit": limit.min(500)}))?;
        Ok(result
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    fn registered_apps(&mut self) -> Result<Vec<Value>, FacadeError> {
        let status = self.status()?;
        Ok(status
            .get("gui_apps")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }
}

impl FakeFacade {
    /// Queue one scripted `call` result (test convenience).
    pub fn queue_call(&mut self, value: Value) {
        self.call_results.push_back(Ok(value));
    }

    /// Queue one scripted `call` error (test convenience).
    pub fn queue_call_error(&mut self, error: FacadeError) {
        self.call_results.push_back(Err(error));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_of_tool_name_covers_native_gui_and_census() {
        assert_eq!(class_of_tool_name("seahawk_status"), Some(ToolClass::Read));
        assert_eq!(class_of_tool_name("gui.observe"), Some(ToolClass::Read));
        assert_eq!(
            class_of_tool_name("gui.act_verified"),
            Some(ToolClass::Actuate)
        );
        assert_eq!(
            class_of_tool_name("gui.blender.actuate"),
            Some(ToolClass::Actuate)
        );
        assert_eq!(
            class_of_tool_name("seahawk_acquire"),
            Some(ToolClass::Execute)
        );
        assert_eq!(
            class_of_tool_name(
                "editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script"
            ),
            Some(ToolClass::Execute)
        );
        assert_eq!(class_of_tool_name("NoSuch.Toolset.Nope"), None);
    }

    #[test]
    fn validate_call_bounds_args_bytes() {
        assert!(validate_call("seahawk_status", &json!({})).is_ok());
        let big = json!({"blob": "x".repeat(CALL_ARGS_BYTES_MAX + 1)});
        assert!(matches!(
            validate_call("seahawk_status", &big),
            Err(FacadeError::Invalid(_))
        ));
        assert!(matches!(
            validate_call("", &json!({})),
            Err(FacadeError::Invalid(_))
        ));
    }

    #[test]
    fn fake_facade_records_calls_and_scripts_results() {
        let mut fake = FakeFacade::with_default_surface();
        fake.queue_call(json!({"custom": 1}));
        // queue_call is a small test helper added via extension
        // below; the direct VecDeque path is exercised here.
        let value = fake.call("seahawk_status", &json!({})).expect("call");
        assert_eq!(value, json!({"custom": 1}));
        assert_eq!(fake.calls.len(), 1);
        assert_eq!(fake.calls[0].0, "seahawk_status");
        let status = fake.status().expect("status");
        assert_eq!(status["server"], "seahawk");
        assert_eq!(fake.tools().expect("tools").len(), 5);
        assert_eq!(fake.registered_apps().expect("apps").len(), 1);
    }

    #[test]
    fn fake_facade_death_is_typed_server_died() {
        let mut fake = FakeFacade::with_default_surface();
        fake.die_on_call = Some("seahawk_status".to_string());
        let error = fake.call("seahawk_status", &json!({})).unwrap_err();
        assert!(matches!(error, FacadeError::ServerDied(_)), "{error}");
        // The call was still recorded — the record shows the
        // attempt that killed the broker.
        assert_eq!(fake.calls.len(), 1);
    }

    #[test]
    fn lib_facade_serves_status_and_oplog_without_config() {
        let dir =
            std::env::temp_dir().join(format!("seahawk-tui-facade-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let log_path = dir.join("op.jsonl");
        std::fs::write(
            &log_path,
            "{\"ts\":1,\"seq\":0,\"tool\":\"seahawk_status\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
        )
        .expect("write log");
        let mut facade = LibFacade::from_config(None, log_path);
        let status = facade.status().expect("status");
        assert_eq!(status["config_loaded"], false);
        assert_eq!(status["downstream_surface_built"], false);
        let entries = facade.oplog_entries(10).expect("oplog");
        assert_eq!(entries.len(), 1);
        // Brokered calls are honestly unavailable, never faked.
        let error = facade
            .call(
                "EditorToolset.EditorAppToolset.GetSelectedActors",
                &json!({}),
            )
            .unwrap_err();
        assert!(matches!(error, FacadeError::Unavailable(_)), "{error}");
        let tools = facade.tools().expect("tools");
        assert!(
            tools.iter().any(
                |tool| tool.name == "seahawk_acquire" && tool.class == Some(ToolClass::Execute)
            )
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn stdio_facade_reports_dead_on_spawn_broker() {
        // `false` exits immediately: the initialize handshake must
        // answer ServerDied/Unavailable, never hang or panic.
        let result =
            StdioFacade::spawn_with_timeout("false", &[], None, Duration::from_millis(500));
        assert!(result.is_err(), "dead broker must fail the handshake");
    }
}
