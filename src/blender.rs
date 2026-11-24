//! The Blender downstream client: Seahawk as a client of the
//! stroke-data provider addon inside a pinned Blender 5.3.0
//! session (DESIGN §1, §5).
//!
//! The transport mirrors the UE downstream's discipline —
//! JSON-RPC 2.0 over HTTP on loopback, a session id issued at
//! `initialize`, calls serialized through one worker thread
//! that owns the (single, stateful) provider session outright
//! (D5) — with the differences the Blender side dictates: the
//! provider secret rides in a header on every request (the
//! addon has no native auth, exactly Epic's situation), and the
//! worker records the provider's reported Blender version at
//! session establishment so write/execute calls can be held to
//! the pinned-build gate (DESIGN §4).
//!
//! Ownership shape matches `downstream.rs`: reqwest's blocking
//! client lives on a dedicated worker thread; every public
//! method blocks and is called from `spawn_blocking` tasks.

use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::BlenderConfig;
use crate::model::ToolClass;
use crate::policy::codes;

/// One failed provider call. `code` is the seahawk refusal code
/// the server answers with; `message` is the human detail;
/// `session_invalid` marks the provider's retryable session
/// refusal (the worker re-initializes once and retries once).
#[derive(Debug)]
pub struct BlenderError {
    pub code: &'static str,
    pub message: String,
    pub session_invalid: bool,
}

impl BlenderError {
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            code: codes::BLENDER_UNAVAILABLE,
            message: message.into(),
            session_invalid: false,
        }
    }

    fn provider(message: impl Into<String>, session_invalid: bool) -> Self {
        Self {
            code: codes::BLENDER_PROVIDER_ERROR,
            message: message.into(),
            session_invalid,
        }
    }
}

impl std::fmt::Display for BlenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for BlenderError {}

type BlenderResult<T> = Result<T, BlenderError>;

/// The provider's session-invalid signal (JSON-RPC error code):
/// the retryable refusal, mirroring Epic's HTTP 400 session
/// shape.
const SESSION_INVALID_CODE: i64 = -32001;

enum Command {
    Call {
        method: String,
        params: Value,
        class: ToolClass,
        reply: Sender<BlenderResult<Value>>,
    },
}

/// Handle to the Blender provider worker thread. Cheap to
/// share; all methods block until the worker answers.
pub struct BlenderClient {
    url: String,
    commands: Sender<Command>,
    /// The provider session's reported Blender version, once a
    /// session has been established (mirror for status reads;
    /// the worker is the authority for the gate).
    version: Arc<Mutex<Option<String>>>,
}

impl BlenderClient {
    pub fn new(config: &BlenderConfig) -> BlenderResult<Self> {
        let (tx, rx) = channel::<Command>();
        let version: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let worker_version = version.clone();
        let worker_config = config.clone();
        std::thread::Builder::new()
            .name("seahawk-blender".to_string())
            .spawn(move || {
                let client = match reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(worker_config.timeout_secs))
                    .build()
                {
                    Ok(client) => client,
                    Err(error) => {
                        eprintln!("seahawk: blender HTTP client failed to build: {error}");
                        return;
                    }
                };
                let mut session = Session {
                    config: worker_config,
                    client,
                    session_id: None,
                    version: None,
                    next_id: 1,
                };
                while let Ok(command) = rx.recv() {
                    match command {
                        Command::Call {
                            method,
                            params,
                            class,
                            reply,
                        } => {
                            let result = session.call(&method, &params, class);
                            if let Some(version) = &session.version {
                                *worker_version.lock().unwrap_or_else(|p| p.into_inner()) =
                                    Some(version.clone());
                            }
                            let _ = reply.send(result);
                        }
                    }
                }
            })
            .map_err(|e| BlenderError {
                code: codes::BLENDER_UNAVAILABLE,
                message: format!("cannot spawn blender worker: {e}"),
                session_invalid: false,
            })?;
        Ok(Self {
            url: config.url.clone(),
            commands: tx,
            version,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The Blender version the live provider session reported,
    /// if a session has been established.
    pub fn reported_version(&self) -> Option<String> {
        self.version
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Dispatches one provider call. `class` is the tool's
    /// decided class: write/execute calls are held to the
    /// pinned-build gate inside the worker (the session's
    /// reported version must equal the configured expectation,
    /// DESIGN §4); read calls always pass so a mismatch stays
    /// diagnosable through `session_status`.
    pub fn call(&self, method: &str, params: &Value, class: ToolClass) -> BlenderResult<Value> {
        let (reply, rx) = channel();
        self.commands
            .send(Command::Call {
                method: method.to_string(),
                params: params.clone(),
                class,
                reply,
            })
            .map_err(|_| BlenderError {
                code: codes::BLENDER_UNAVAILABLE,
                message: "blender worker is gone".to_string(),
                session_invalid: false,
            })?;
        rx.recv().map_err(|_| BlenderError {
            code: codes::BLENDER_UNAVAILABLE,
            message: "blender worker stopped answering".to_string(),
            session_invalid: false,
        })?
    }
}

/// The worker-owned provider session. All methods run on the
/// worker thread.
struct Session {
    config: BlenderConfig,
    client: reqwest::blocking::Client,
    session_id: Option<String>,
    version: Option<String>,
    next_id: u64,
}

impl Session {
    fn call(&mut self, method: &str, params: &Value, class: ToolClass) -> BlenderResult<Value> {
        self.ensure_session()?;
        if matches!(class, ToolClass::Write | ToolClass::Execute)
            && self.version.as_deref() != Some(self.config.expected_blender.as_str())
        {
            return Err(BlenderError {
                code: codes::BLENDER_BUILD_MISMATCH,
                message: format!(
                    "provider reports Blender {:?}; policy pins {:?} — write/execute \
                     calls are refused until the provider runs the pinned build \
                     (read calls still serve, DESIGN §4)",
                    self.version.as_deref().unwrap_or("<none>"),
                    self.config.expected_blender
                ),
                session_invalid: false,
            });
        }
        match self.call_once(method, params) {
            Ok(result) => Ok(result),
            Err(error) if error.session_invalid => {
                eprintln!("seahawk: blender provider session invalid; re-initializing");
                self.session_id = None;
                self.version = None;
                self.ensure_session()?;
                self.call_once(method, params)
            }
            Err(error) => Err(error),
        }
    }

    fn call_once(&mut self, method: &str, params: &Value) -> BlenderResult<Value> {
        let id = self.alloc_id();
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let (status, text) = self.send_raw(&body)?;
        if status >= 400 {
            return Err(BlenderError::provider(
                format!("provider HTTP {status}: {}", truncate(&text, 300)),
                false,
            ));
        }
        let frame: Value = serde_json::from_str(&text).map_err(|e| {
            BlenderError::provider(format!("provider response is not JSON: {e}"), false)
        })?;
        if frame.get("id").and_then(Value::as_u64) != Some(id) {
            return Err(BlenderError::provider(
                "provider response held no matching frame",
                false,
            ));
        }
        if let Some(error) = frame.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("provider error")
                .to_string();
            return Err(BlenderError::provider(
                format!("provider error: {message}"),
                code == SESSION_INVALID_CODE,
            ));
        }
        Ok(frame.get("result").cloned().unwrap_or(Value::Null))
    }

    fn ensure_session(&mut self) -> BlenderResult<()> {
        if self.session_id.is_some() {
            return Ok(());
        }
        let id = self.alloc_id();
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {"client": {"name": "seahawk", "version": env!("CARGO_PKG_VERSION")}}
        });
        let (status, text) = self.send_raw(&body)?;
        if status >= 400 {
            return Err(BlenderError::unavailable(format!(
                "provider initialize refused: HTTP {status}: {}",
                truncate(&text, 300)
            )));
        }
        let frame: Value = serde_json::from_str(&text).map_err(|e| {
            BlenderError::unavailable(format!("provider initialize response is not JSON: {e}"))
        })?;
        if let Some(error) = frame.get("error") {
            return Err(BlenderError::unavailable(format!(
                "provider initialize error: {error}"
            )));
        }
        let result = frame.get("result").cloned().unwrap_or(Value::Null);
        let Some(session_id) = result
            .get("session_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            return Err(BlenderError::unavailable(
                "provider initialize returned no session_id",
            ));
        };
        self.session_id = Some(session_id.to_string());
        self.version = result
            .get("blender_version")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(())
    }

    /// Sends one HTTP POST with the provider secret header (and
    /// the session header once established); returns (status,
    /// body).
    fn send_raw(&self, body: &Value) -> BlenderResult<(u16, String)> {
        let mut request = self
            .client
            .post(&self.config.url)
            .header("Content-Type", "application/json")
            .header("X-Seahawk-Provider-Secret", &self.config.provider_secret)
            .body(body.to_string());
        if let Some(session) = &self.session_id {
            request = request.header("X-Seahawk-Session-Id", session);
        }
        let response = request.send().map_err(|e| {
            BlenderError::unavailable(format!(
                "blender provider unreachable at {}: {e}",
                self.config.url
            ))
        })?;
        let status = response.status().as_u16();
        let text = response
            .text()
            .map_err(|e| BlenderError::unavailable(format!("provider response unreadable: {e}")))?;
        Ok((status, text))
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        format!("{}…", &text[..max])
    }
}
