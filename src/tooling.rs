//! The D-230 wiring client: Seahawk as an MCP *client* of the
//! estate's language-tooling servers (theodolite, periscope),
//! feeding the read-class `code.feedback` tool.
//!
//! Shape, per the established broker pattern (downstream.rs,
//! the S5 grounder worker): each configured server lives behind
//! a dedicated worker thread that owns the child process and
//! its blocking stdio; handlers reach it over mpsc and never
//! perform blocking IO inside the async server context. The
//! client speaks the target's era — both estate tooling servers
//! are modern-only (2026-07-28, `server/discover`, per-request
//! `_meta`), verified against their own guard tests at build
//! time (seahawk-wiring SPEC §3.4). Seahawk presents
//! `clientInfo.name = "seahawk"`, which is also what keeps
//! theodolite's mutation allowlist able to exclude Seahawk by
//! construction: this client never asks for a mutation tool
//! (the dispatch table below is the whole reachable surface,
//! and a unit test asserts its contents — SPEC rule R6).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::{ToolingEntry, ToolingId};
use crate::gui::GuiError;
use crate::policy::codes;

/// The protocol version both estate tooling servers pin.
pub const TOOLING_PROTOCOL_VERSION: &str = "2026-07-28";

/// The checks `code.feedback` can run (SPEC §3.2).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CheckKind {
    Diagnostics,
    Lint,
    Format,
}

impl CheckKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Diagnostics => "diagnostics",
            Self::Lint => "lint",
            Self::Format => "format",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "diagnostics" => Some(Self::Diagnostics),
            "lint" => Some(Self::Lint),
            "format" => Some(Self::Format),
            _ => None,
        }
    }
}

/// A tooling route for one check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Theodolite,
    Periscope,
}

impl Route {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Theodolite => "theodolite",
            Self::Periscope => "periscope",
        }
    }

    pub fn id(&self) -> ToolingId {
        match self {
            Self::Theodolite => ToolingId::Theodolite,
            Self::Periscope => ToolingId::Periscope,
        }
    }
}

/// The routing table (SPEC §2, rules R1–R5) as a pure function
/// over (check, forced route, file extension, availability).
/// Returns the route or the reason no route can serve the
/// check — the caller turns a reason into the typed
/// `seahawk_tooling_unavailable` refusal, never a silent
/// fallback to a different server (R5).
pub fn route_for(
    check: CheckKind,
    forced: Option<Route>,
    extension: &str,
    have_theodolite: bool,
    have_periscope: bool,
) -> Result<Route, String> {
    if let Some(route) = forced {
        let available = match route {
            Route::Theodolite => have_theodolite,
            Route::Periscope => have_periscope,
        };
        if !available {
            return Err(format!(
                "route {:?} was forced but no {} server is configured in [[tooling]]",
                check.as_str(),
                route.as_str()
            ));
        }
        // A forced route that cannot serve the check refuses
        // (SPEC §3.2): theodolite has no lint/format by design.
        if route == Route::Theodolite && check != CheckKind::Diagnostics {
            return Err(format!(
                "theodolite cannot serve the {:?} check (it has no lint/format \
                 tools by design); the periscope route serves it",
                check.as_str()
            ));
        }
        return Ok(route);
    }
    match check {
        CheckKind::Diagnostics => {
            // R4: GDScript's language server lives inside the
            // Godot editor; theodolite cannot pin it, so
            // diagnostics route through periscope while an
            // editor surface exists.
            if extension == "gd" {
                if have_periscope {
                    return Ok(Route::Periscope);
                }
                return Err("GDScript diagnostics need the periscope route (the Godot \
                     language server is editor-hosted; theodolite cannot pin \
                     it) and no periscope server is configured"
                    .to_string());
            }
            // R1: headless diagnostics default to theodolite.
            if have_theodolite {
                Ok(Route::Theodolite)
            } else if have_periscope {
                Ok(Route::Periscope)
            } else {
                Err("no tooling server is configured for diagnostics".to_string())
            }
        }
        // R2: format/lint are periscope's pipelines, always.
        CheckKind::Lint | CheckKind::Format => {
            if have_periscope {
                Ok(Route::Periscope)
            } else {
                Err(format!(
                    "the {:?} check routes through periscope (diver's own \
                     pipelines) and no periscope server is configured",
                    check.as_str()
                ))
            }
        }
    }
}

/// The complete dispatch table of the tooling client (R6):
/// the only tools Seahawk will ever call on each server.
/// Feedback is read-class only — theodolite's apply tools and
/// every other write-shaped name are absent by construction,
/// and periscope's two pipeline tools are themselves
/// non-writing (`run_format` never writes disk; `run_lint`
/// only reads).
pub fn allowed_call(server: ToolingId, tool: &str) -> bool {
    match server {
        ToolingId::Theodolite => matches!(tool, "diagnostics" | "session_status"),
        ToolingId::Periscope => matches!(
            tool,
            "broker_status"
                | "get_diagnostics"
                | "list_formatters"
                | "list_linters"
                | "list_servers"
                | "run_format"
                | "run_lint"
        ),
    }
}

// ---------------------------------------------------------------------------
// The stdio client (worker-thread owned)
// ---------------------------------------------------------------------------

enum ClientCommand {
    Call {
        tool: String,
        arguments: Value,
        reply: mpsc::Sender<Result<Value, GuiError>>,
    },
}

/// Handle to one tooling server's worker thread. Cheap to
/// clone (a channel sender); the worker owns the child.
#[derive(Clone)]
pub struct ToolingClient {
    id: ToolingId,
    commands: mpsc::Sender<ClientCommand>,
    timeout: Duration,
}

impl ToolingClient {
    pub fn id(&self) -> ToolingId {
        self.id
    }

    /// Calls one tool on the server and returns its structured
    /// payload (or the JSON-parsed text content when the server
    /// returns no structured content). Refuses names outside
    /// the dispatch table before any IO (R6).
    pub fn call(&self, tool: &str, arguments: Value) -> Result<Value, GuiError> {
        if !allowed_call(self.id, tool) {
            return Err(GuiError::new(
                codes::TOOLING_UNAVAILABLE,
                format!(
                    "tool {tool:?} is outside Seahawk's tooling dispatch table \
                     for {} (feedback is read-class only)",
                    self.id.as_str()
                ),
            ));
        }
        let (reply_tx, reply_rx) = mpsc::channel();
        self.commands
            .send(ClientCommand::Call {
                tool: tool.to_string(),
                arguments,
                reply: reply_tx,
            })
            .map_err(|_| {
                GuiError::new(
                    codes::TOOLING_UNAVAILABLE,
                    format!(
                        "the {} tooling worker is not running (spawn failed or \
                         the worker exited)",
                        self.id.as_str()
                    ),
                )
            })?;
        reply_rx.recv_timeout(self.timeout).map_err(|_| {
            GuiError::new(
                codes::TOOLING_UNAVAILABLE,
                format!(
                    "the {} tooling server did not answer within {:?}",
                    self.id.as_str(),
                    self.timeout
                ),
            )
        })?
    }
}

/// The configured tooling clients, keyed by server id.
pub struct ToolingPool {
    clients: HashMap<ToolingId, ToolingClient>,
}

impl ToolingPool {
    /// Spawns one worker per configured entry (the child itself
    /// spawns lazily inside the worker on first use, so a
    /// missing binary degrades calls to typed unavailability
    /// instead of failing broker startup).
    pub fn from_config(entries: &[ToolingEntry]) -> Self {
        let mut clients = HashMap::new();
        for entry in entries {
            let (tx, rx) = mpsc::channel::<ClientCommand>();
            let worker_entry = entry.clone();
            let spawned = std::thread::Builder::new()
                .name(format!("seahawk-tooling-{}", entry.id.as_str()))
                .spawn(move || run_worker(&worker_entry, rx));
            match spawned {
                Ok(_) => {
                    clients.insert(
                        entry.id,
                        ToolingClient {
                            id: entry.id,
                            commands: tx,
                            timeout: Duration::from_secs(entry.timeout_secs),
                        },
                    );
                }
                Err(error) => {
                    eprintln!(
                        "seahawk: cannot spawn the {} tooling worker: {error}",
                        entry.id.as_str()
                    );
                }
            }
        }
        Self { clients }
    }

    pub fn get(&self, id: ToolingId) -> Option<&ToolingClient> {
        self.clients.get(&id)
    }

    pub fn has(&self, id: ToolingId) -> bool {
        self.clients.contains_key(&id)
    }
}

/// One live child session: the process, its stdin, and the
/// line channel its stdout reader thread feeds.
struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    next_id: i64,
}

impl Session {
    fn spawn(entry: &ToolingEntry) -> Result<Self, GuiError> {
        let unavailable = |reason: String| {
            GuiError::new(
                codes::TOOLING_UNAVAILABLE,
                format!("{} tooling server unavailable: {reason}", entry.id.as_str()),
            )
        };
        let mut child = Command::new(&entry.command)
            .args(&entry.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| unavailable(format!("cannot spawn {:?}: {e}", entry.command)))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| unavailable("child has no stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| unavailable("child has no stdout".to_string()))?;
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
        let mut session = Self {
            child,
            stdin,
            lines: rx,
            next_id: 0,
        };
        // Modern-era open: server/discover with the fleet _meta.
        session.request(
            "server/discover",
            json!({
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": TOOLING_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "seahawk",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            }),
            entry.timeout_secs,
        )?;
        Ok(session)
    }

    /// Sends one request and waits for its correlated response,
    /// skipping notifications and unrelated frames.
    fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout_secs: u64,
    ) -> Result<Value, GuiError> {
        self.next_id += 1;
        let id = self.next_id;
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        writeln!(self.stdin, "{frame}").map_err(|e| {
            GuiError::new(
                codes::TOOLING_UNAVAILABLE,
                format!("tooling write failed: {e}"),
            )
        })?;
        self.stdin.flush().map_err(|e| {
            GuiError::new(
                codes::TOOLING_UNAVAILABLE,
                format!("tooling flush failed: {e}"),
            )
        })?;
        let deadline = Duration::from_secs(timeout_secs);
        loop {
            let line = self.lines.recv_timeout(deadline).map_err(|_| {
                GuiError::new(
                    codes::TOOLING_UNAVAILABLE,
                    format!("tooling server did not answer {method} within {timeout_secs}s"),
                )
            })?;
            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if value.get("id").and_then(Value::as_i64) != Some(id) {
                continue;
            }
            if let Some(error) = value.get("error") {
                return Err(GuiError::new(
                    codes::TOOLING_UNAVAILABLE,
                    format!("tooling server refused {method}: {error}"),
                ));
            }
            return Ok(value.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// One tools/call against the session; returns the result's
    /// structured payload.
    fn call_tool(
        &mut self,
        entry: &ToolingEntry,
        tool: &str,
        arguments: Value,
    ) -> Result<Value, GuiError> {
        let result = self.request(
            "tools/call",
            json!({
                "name": tool,
                "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": TOOLING_PROTOCOL_VERSION,
                    "io.modelcontextprotocol/clientInfo": {
                        "name": "seahawk",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            }),
            entry.timeout_secs,
        )?;
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            let message = result
                .get("content")
                .and_then(|c| c.as_array())
                .and_then(|blocks| blocks.first())
                .and_then(|b| b.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("tooling tool returned an error")
                .to_string();
            return Err(GuiError::new(codes::TOOLING_UNAVAILABLE, message));
        }
        if let Some(structured) = result.get("structuredContent") {
            return Ok(structured.clone());
        }
        // Fall back to the first text block parsed as JSON.
        if let Some(text) = result
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|blocks| blocks.first())
            .and_then(|b| b.get("text"))
            .and_then(Value::as_str)
            && let Ok(parsed) = serde_json::from_str::<Value>(text)
        {
            return Ok(parsed);
        }
        Ok(result)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The worker loop: own at most one session; a failed call
/// drops it (a dead session is never silently respawned
/// mid-call — the NEXT call pays the respawn, per theodolite's
/// own rule, inherited by the client).
fn run_worker(entry: &ToolingEntry, commands: mpsc::Receiver<ClientCommand>) {
    let mut session: Option<Session> = None;
    while let Ok(ClientCommand::Call {
        tool,
        arguments,
        reply,
    }) = commands.recv()
    {
        if session.is_none() {
            match Session::spawn(entry) {
                Ok(spawned) => session = Some(spawned),
                Err(error) => {
                    let _ = reply.send(Err(error));
                    continue;
                }
            }
        }
        let result = session
            .as_mut()
            .map(|active| active.call_tool(entry, &tool, arguments));
        match result {
            Some(Ok(value)) => {
                let _ = reply.send(Ok(value));
            }
            Some(Err(error)) => {
                session = None;
                let _ = reply.send(Err(error));
            }
            None => {
                let _ = reply.send(Err(GuiError::new(
                    codes::TOOLING_UNAVAILABLE,
                    "tooling session is not available".to_string(),
                )));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_table_matches_spec_rules() {
        // R1: headless diagnostics default to theodolite.
        assert_eq!(
            route_for(CheckKind::Diagnostics, None, "rs", true, true),
            Ok(Route::Theodolite)
        );
        // R2: lint/format always periscope.
        assert_eq!(
            route_for(CheckKind::Lint, None, "rs", true, true),
            Ok(Route::Periscope)
        );
        assert_eq!(
            route_for(CheckKind::Format, None, "py", true, true),
            Ok(Route::Periscope)
        );
        // R4: GDScript diagnostics via periscope.
        assert_eq!(
            route_for(CheckKind::Diagnostics, None, "gd", true, true),
            Ok(Route::Periscope)
        );
        // R5: no route → a reason, never a silent substitution.
        assert!(route_for(CheckKind::Diagnostics, None, "rs", false, false).is_err());
        assert!(route_for(CheckKind::Diagnostics, None, "gd", true, false).is_err());
        assert!(route_for(CheckKind::Lint, None, "rs", true, false).is_err());
        // Diagnostics fall back to periscope only when theodolite
        // is absent (R3's surface is the editor's own truth).
        assert_eq!(
            route_for(CheckKind::Diagnostics, None, "rs", false, true),
            Ok(Route::Periscope)
        );
        // Forced routes: served or refused, never rerouted.
        assert_eq!(
            route_for(
                CheckKind::Diagnostics,
                Some(Route::Periscope),
                "rs",
                true,
                true
            ),
            Ok(Route::Periscope)
        );
        assert!(route_for(CheckKind::Lint, Some(Route::Theodolite), "rs", true, true).is_err());
        assert!(
            route_for(
                CheckKind::Diagnostics,
                Some(Route::Theodolite),
                "rs",
                false,
                true
            )
            .is_err()
        );
    }

    #[test]
    fn dispatch_table_contains_no_write_path() {
        // R6: the table is the whole reachable surface; assert
        // its exact contents so a future edit that widens it
        // fails here first.
        let theodolite = ["diagnostics", "session_status"];
        let periscope = [
            "broker_status",
            "get_diagnostics",
            "list_formatters",
            "list_linters",
            "list_servers",
            "run_format",
            "run_lint",
        ];
        for tool in theodolite {
            assert!(allowed_call(ToolingId::Theodolite, tool), "{tool}");
        }
        for tool in periscope {
            assert!(allowed_call(ToolingId::Periscope, tool), "{tool}");
        }
        for forbidden in [
            "code_action_apply",
            "rename_apply",
            "edit_file",
            "write_file",
            "execute_tool_script",
            "run_command",
        ] {
            assert!(
                !allowed_call(ToolingId::Theodolite, forbidden),
                "{forbidden}"
            );
            assert!(
                !allowed_call(ToolingId::Periscope, forbidden),
                "{forbidden}"
            );
        }
        // Cross-server names are not interchangeable.
        assert!(!allowed_call(ToolingId::Theodolite, "run_lint"));
        assert!(!allowed_call(ToolingId::Periscope, "diagnostics"));
    }
}
