//! The downstream client: Seahawk as a client of Epic's
//! ModelContextProtocol server (legacy era, Streamable HTTP,
//! loopback).
//!
//! Facts this module encodes (SURFACE.md §2, measured):
//! - `initialize` at 2025-11-25; the server issues a session id in
//!   the `Mcp-Session-Id` response header; later requests must
//!   carry it or they are refused with HTTP 400.
//! - Responses arrive as plain JSON or SSE-framed (`data:` lines).
//! - Tool discovery runs through the meta-tools: `list_toolsets`
//!   (prose), `describe_toolset` (strict JSON), `call_tool`
//!   (dispatch; wants the tool name without its toolset prefix).
//! - The surface can grow after the server starts answering, so it
//!   is a snapshot per session, rebuilt whenever a session is
//!   (re)established.
//!
//! Ownership shape: reqwest's blocking client creates and drops a
//! tokio runtime as part of its lifecycle, which panics inside an
//! async context — so the client lives on a dedicated worker
//! thread that owns the (single, stateful) editor session outright.
//! Callers send commands over a channel; every public method here
//! is blocking and is called from `spawn_blocking` tasks. One
//! worker also gives the ordering the sequencer discipline wants:
//! downstream calls apply strictly in arrival order.

use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::Config;
use crate::model::{Surface, ToolRecord, split_name};

/// The legacy protocol version Epic's 5.8 server prefers.
const DOWNSTREAM_PROTOCOL_VERSION: &str = "2025-11-25";

#[derive(Debug)]
pub struct DownstreamError(pub String);

impl std::fmt::Display for DownstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DownstreamError {}

type DownResult<T> = Result<T, DownstreamError>;

fn err<T>(message: impl Into<String>) -> DownResult<T> {
    Err(DownstreamError(message.into()))
}

enum RpcFail {
    /// HTTP 400 from Epic means (among other things) a missing or
    /// unknown session — the retryable signal.
    SessionInvalid(String),
    Other(String),
}

enum Command {
    Surface {
        config: Arc<Config>,
        reply: Sender<DownResult<Surface>>,
    },
    Refresh {
        config: Arc<Config>,
        reply: Sender<DownResult<Surface>>,
    },
    CallTool {
        toolset: String,
        short_name: String,
        arguments: Value,
        reply: Sender<DownResult<Value>>,
    },
}

/// Handle to the downstream worker thread. Cheap to share; all
/// methods block until the worker answers.
pub struct Downstream {
    url: String,
    commands: Sender<Command>,
    /// Mirror of the worker's snapshot, for `has_surface` and the
    /// handler's fast paths; the worker is the authority.
    snapshot: Arc<Mutex<Option<Surface>>>,
}

impl Downstream {
    pub fn new(url: &str, timeout_secs: u64) -> DownResult<Self> {
        let (tx, rx) = channel::<Command>();
        let snapshot: Arc<Mutex<Option<Surface>>> = Arc::new(Mutex::new(None));
        let worker_snapshot = snapshot.clone();
        let worker_url = url.to_string();
        std::thread::Builder::new()
            .name("seahawk-downstream".to_string())
            .spawn(move || {
                let client = match reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(timeout_secs))
                    .build()
                {
                    Ok(client) => client,
                    Err(error) => {
                        eprintln!("seahawk: downstream HTTP client failed to build: {error}");
                        return;
                    }
                };
                let mut session = Session {
                    url: worker_url,
                    client,
                    session_id: None,
                    surface: None,
                    next_id: 1,
                };
                while let Ok(command) = rx.recv() {
                    match command {
                        Command::Surface { config, reply } => {
                            let result = session.surface(&config);
                            if let Ok(surface) = &result {
                                *worker_snapshot.lock().unwrap_or_else(|p| p.into_inner()) =
                                    Some(surface.clone());
                            }
                            let _ = reply.send(result);
                        }
                        Command::Refresh { config, reply } => {
                            let result = session.refresh(&config);
                            if let Ok(surface) = &result {
                                *worker_snapshot.lock().unwrap_or_else(|p| p.into_inner()) =
                                    Some(surface.clone());
                            }
                            let _ = reply.send(result);
                        }
                        Command::CallTool {
                            toolset,
                            short_name,
                            arguments,
                            reply,
                        } => {
                            let _ =
                                reply.send(session.call_tool(&toolset, &short_name, &arguments));
                        }
                    }
                }
            })
            .map_err(|e| DownstreamError(format!("cannot spawn downstream worker: {e}")))?;
        Ok(Self {
            url: url.to_string(),
            commands: tx,
            snapshot,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether a surface snapshot exists. Does not touch the
    /// network.
    pub fn has_surface(&self) -> bool {
        self.snapshot
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some()
    }

    /// The current surface snapshot, establishing a session and
    /// building the snapshot first if needed.
    pub fn surface(&self, config: &Arc<Config>) -> DownResult<Surface> {
        if let Some(surface) = self
            .snapshot
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
        {
            return Ok(surface);
        }
        let (reply, rx) = channel();
        self.commands
            .send(Command::Surface {
                config: config.clone(),
                reply,
            })
            .map_err(|_| DownstreamError("downstream worker is gone".to_string()))?;
        rx.recv()
            .map_err(|_| DownstreamError("downstream worker stopped answering".to_string()))?
    }

    /// Drops the session and snapshot and rebuilds. Downstream
    /// toolsets can register late (SURFACE.md §3).
    pub fn refresh(&self, config: &Arc<Config>) -> DownResult<Surface> {
        let (reply, rx) = channel();
        self.commands
            .send(Command::Refresh {
                config: config.clone(),
                reply,
            })
            .map_err(|_| DownstreamError("downstream worker is gone".to_string()))?;
        rx.recv()
            .map_err(|_| DownstreamError("downstream worker stopped answering".to_string()))?
    }

    /// Dispatches one brokered call through Epic's `call_tool`
    /// meta-tool. On a session-invalid refusal the worker
    /// re-establishes the session once and retries once.
    pub fn call_tool(
        &self,
        toolset: &str,
        short_name: &str,
        arguments: &Value,
    ) -> DownResult<Value> {
        let (reply, rx) = channel();
        self.commands
            .send(Command::CallTool {
                toolset: toolset.to_string(),
                short_name: short_name.to_string(),
                arguments: arguments.clone(),
                reply,
            })
            .map_err(|_| DownstreamError("downstream worker is gone".to_string()))?;
        rx.recv()
            .map_err(|_| DownstreamError("downstream worker stopped answering".to_string()))?
    }
}

/// The worker-owned session state. All methods run on the worker
/// thread.
struct Session {
    url: String,
    client: reqwest::blocking::Client,
    session_id: Option<String>,
    surface: Option<Surface>,
    next_id: u64,
}

impl Session {
    fn surface(&mut self, config: &Config) -> DownResult<Surface> {
        if let Some(surface) = &self.surface {
            return Ok(surface.clone());
        }
        self.ensure_session()?;
        let surface = self.build_surface(config)?;
        self.surface = Some(surface.clone());
        Ok(surface)
    }

    fn refresh(&mut self, config: &Config) -> DownResult<Surface> {
        self.session_id = None;
        self.surface = None;
        self.ensure_session()?;
        let surface = self.build_surface(config)?;
        self.surface = Some(surface.clone());
        Ok(surface)
    }

    fn call_tool(
        &mut self,
        toolset: &str,
        short_name: &str,
        arguments: &Value,
    ) -> DownResult<Value> {
        self.ensure_session()?;
        let result = match self.call_tool_once(toolset, short_name, arguments) {
            Ok(result) => result,
            Err(RpcFail::SessionInvalid(detail)) => {
                eprintln!("seahawk: downstream session invalid ({detail}); re-initializing");
                self.session_id = None;
                self.surface = None;
                self.ensure_session()?;
                match self.call_tool_once(toolset, short_name, arguments) {
                    Ok(result) => result,
                    Err(RpcFail::SessionInvalid(detail)) => {
                        return err(format!(
                            "downstream session still invalid after re-initialize: {detail}"
                        ));
                    }
                    Err(RpcFail::Other(message)) => return err(message),
                }
            }
            Err(RpcFail::Other(message)) => return err(message),
        };
        // Epic's result is a CallToolResult-shaped object; anything
        // else is wrapped as a text block so the handler can convert.
        if result.is_object() {
            Ok(result)
        } else {
            Ok(json!({"content": [{"type": "text", "text": result.to_string()}]}))
        }
    }

    fn call_tool_once(
        &mut self,
        toolset: &str,
        short_name: &str,
        arguments: &Value,
    ) -> Result<Value, RpcFail> {
        let mut call_args = serde_json::Map::new();
        if !toolset.is_empty() {
            call_args.insert("toolset_name".to_string(), json!(toolset));
        }
        call_args.insert("tool_name".to_string(), json!(short_name));
        call_args.insert("arguments".to_string(), arguments.clone());
        let frame = self.rpc(
            "tools/call",
            Some(json!({"name": "call_tool", "arguments": Value::Object(call_args)})),
        )?;
        Ok(frame.get("result").cloned().unwrap_or(Value::Null))
    }

    fn ensure_session(&mut self) -> DownResult<()> {
        if self.session_id.is_some() {
            return Ok(());
        }
        // The initialize response's session id arrives in a header,
        // so this goes through the raw sender, not `rpc`.
        let id = self.alloc_id();
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": DOWNSTREAM_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "seahawk", "version": env!("CARGO_PKG_VERSION")}
            }
        });
        let (status, session, text) = self.send_raw(None, &body)?;
        if status == 400 || status >= 500 {
            return err(format!(
                "downstream initialize refused: HTTP {status}: {}",
                truncate(&text, 300)
            ));
        }
        let Some(session) = session.filter(|s| !s.is_empty()) else {
            return err("downstream initialize returned no Mcp-Session-Id header");
        };
        let frame = find_frame(&text, id).ok_or_else(|| {
            DownstreamError("downstream initialize response held no matching frame".to_string())
        })?;
        if let Some(error) = frame.get("error") {
            return err(format!("downstream initialize error: {error}"));
        }
        self.session_id = Some(session);
        // notifications/initialized completes the legacy handshake.
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let (status, _, _) = self.send_raw(self.session_id.as_deref(), &note)?;
        if status >= 400 {
            self.session_id = None;
            return err(format!(
                "downstream notifications/initialized refused: HTTP {status}"
            ));
        }
        Ok(())
    }

    fn build_surface(&mut self, config: &Config) -> DownResult<Surface> {
        let list_frame = self
            .rpc(
                "tools/call",
                Some(json!({"name": "list_toolsets", "arguments": {}})),
            )
            .map_err(fail_to_string)?;
        let text = result_text(&list_frame);
        let names = parse_toolset_names(&text);
        let mut surface = Surface::default();
        for name in names {
            let frame = self
                .rpc(
                    "tools/call",
                    Some(json!({"name": "describe_toolset", "arguments": {"toolset_name": name}})),
                )
                .map_err(fail_to_string)?;
            let describe_text = result_text(&frame);
            let Ok(described) = serde_json::from_str::<Value>(&describe_text) else {
                surface.skipped_toolsets.push(name);
                continue;
            };
            let Some(tools) = described.get("tools").and_then(Value::as_array) else {
                surface.skipped_toolsets.push(name);
                continue;
            };
            for tool in tools {
                let Some(qualified) = tool.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let Some(class) = config.class_of(qualified) else {
                    surface.unclassified_names.push(qualified.to_string());
                    continue;
                };
                let (toolset, short_name) = split_name(qualified);
                surface.tools.push(ToolRecord {
                    name: qualified.to_string(),
                    toolset,
                    short_name,
                    description: tool
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    input_schema: tool
                        .get("inputSchema")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object"})),
                    class,
                });
            }
        }
        Ok(surface)
    }

    /// One JSON-RPC request/response round trip (requests with an
    /// id). Handles the session header and JSON/SSE framing.
    fn rpc(&mut self, method: &str, params: Option<Value>) -> Result<Value, RpcFail> {
        let id = self.alloc_id();
        let mut body = json!({"jsonrpc": "2.0", "id": id, "method": method});
        if let Some(params) = params {
            body["params"] = params;
        }
        let (status, _, text) = self
            .send_raw(self.session_id.as_deref(), &body)
            .map_err(|e| RpcFail::Other(e.0))?;
        if status == 400 {
            return Err(RpcFail::SessionInvalid(format!(
                "HTTP 400: {}",
                truncate(&text, 200)
            )));
        }
        if status >= 400 {
            return Err(RpcFail::Other(format!(
                "downstream HTTP {status}: {}",
                truncate(&text, 300)
            )));
        }
        let frame = find_frame(&text, id).ok_or_else(|| {
            RpcFail::Other("downstream response held no matching frame".to_string())
        })?;
        if let Some(error) = frame.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("downstream error");
            // Epic reports an unknown session on the tools/call path
            // as an HTTP 400 in the measured build; keep a message
            // based fallback for other builds.
            if message.to_lowercase().contains("session") {
                return Err(RpcFail::SessionInvalid(message.to_string()));
            }
            return Err(RpcFail::Other(format!("downstream error: {message}")));
        }
        Ok(frame)
    }

    /// Sends one HTTP POST; returns (status, session header, body).
    fn send_raw(
        &self,
        session_id: Option<&str>,
        body: &Value,
    ) -> DownResult<(u16, Option<String>, String)> {
        let mut request = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .body(body.to_string());
        if let Some(session) = session_id {
            request = request.header("Mcp-Session-Id", session);
        }
        let response = request
            .send()
            .map_err(|e| DownstreamError(format!("downstream unreachable at {}: {e}", self.url)))?;
        let status = response.status().as_u16();
        let session = response
            .headers()
            .get("Mcp-Session-Id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let text = response
            .text()
            .map_err(|e| DownstreamError(format!("downstream response unreadable: {e}")))?;
        Ok((status, session, text))
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

fn fail_to_string(fail: RpcFail) -> DownstreamError {
    match fail {
        RpcFail::SessionInvalid(detail) | RpcFail::Other(detail) => DownstreamError(detail),
    }
}

/// Extracts the JSON-RPC response frame for `id` from a body that is
/// either a bare JSON object or SSE (`data:` lines).
fn find_frame(body: &str, id: u64) -> Option<Value> {
    let trimmed = body.trim();
    if trimmed.starts_with('{')
        && let Ok(value) = serde_json::from_str::<Value>(trimmed)
    {
        return (value.get("id").and_then(Value::as_u64) == Some(id)).then_some(value);
    }
    for line in body.lines() {
        let Some(data) = line.trim().strip_prefix("data:") else {
            continue;
        };
        if let Ok(value) = serde_json::from_str::<Value>(data.trim())
            && value.get("id").and_then(Value::as_u64) == Some(id)
        {
            return Some(value);
        }
    }
    None
}

/// The concatenated text content of a CallToolResult-shaped frame.
fn result_text(frame: &Value) -> String {
    let mut out = String::new();
    if let Some(content) = frame
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(Value::as_array)
    {
        for block in content {
            if let Some(text) = block.get("text").and_then(Value::as_str) {
                out.push_str(text);
            }
        }
    }
    out
}

/// Parses the toolset names out of Epic's prose `list_toolsets`
/// output: lines of the form `- <name>: <description>`.
pub fn parse_toolset_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix("- ") else {
            continue;
        };
        let Some((name, _)) = rest.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() && !name.contains(char::is_whitespace) {
            names.push(name.to_string());
        }
    }
    names
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        format!("{}…", &text[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toolset_names_from_epic_prose() {
        let text = "Available toolsets:\n  - EditorToolset.EditorAppToolset: App tools\n  - GetAssetDiscoveryInfo: mentioned in prose\nSome other line\n";
        assert_eq!(
            parse_toolset_names(text),
            vec![
                "EditorToolset.EditorAppToolset".to_string(),
                "GetAssetDiscoveryInfo".to_string()
            ]
        );
    }

    #[test]
    fn finds_frames_in_json_and_sse_bodies() {
        let bare = r#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
        assert!(find_frame(bare, 7).is_some());
        assert!(find_frame(bare, 8).is_none());
        let sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{}}\n\n";
        assert!(find_frame(sse, 3).is_some());
    }
}
