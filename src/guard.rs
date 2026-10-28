//! The era guard + sequencer, per the fleet template (D-113),
//! with Seahawk's agent authentication enforced at the frame level.
//!
//! The guard owns the client's stdin/stdout:
//! - A legacy `initialize` (any shape) is refused with the fleet's
//!   typed `-32022`; the connection stays up.
//! - Malformed JSON draws `-32700`; non-object frames `-32600`;
//!   unknown methods `-32601`. Notifications are dropped silently.
//! - Only `server/discover`, `ping`, `tools/list`, and `tools/call`
//!   frames reach the SDK, and only after authentication:
//!   `tools/call` frames must carry the agent token in
//!   `params._meta["seahawk/agent_token"]`. A missing or wrong token
//!   draws a typed `-32001` refusal and an op-log entry; the frame
//!   never enters the SDK and never reaches the editor. A valid
//!   token is stripped from the frame before forwarding, so it
//!   exists nowhere downstream — not in handler state, not in the
//!   op log, not at Epic's server.
//! - Forwarded requests run through the sequencer `Ordering`:
//!   downstream is a single stateful editor session, so requests
//!   are forwarded one settle at a time, in arrival order, and
//!   guard-answered frames wait for outstanding responses to drain
//!   (bounded) so the wire stays strictly ordered.

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::oplog::OpLog;
use crate::policy::{codes, token_matches};

const SUPPORTED_YEARS: [&str; 1] = ["2026-07-28"];
const META_AGENT_TOKEN: &str = "seahawk/agent_token";

/// Guard-answered frames wait at most this long for outstanding SDK
/// responses to drain, so a wedged request cannot hold the wire.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// A single request may stay outstanding at most this long before
/// the sequencer stops waiting for it and moves on.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(3600);
/// Refuse absurd input lines instead of buffering without bound.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// What the guard needs to authenticate frames.
pub struct GuardAuth {
    pub agent_token_digest: [u8; 32],
    pub require_token_for_list: bool,
    pub oplog: Arc<OpLog>,
}

/// Tracks which forwarded request ids are still outstanding so
/// guard frames are not written ahead of their responses.
pub struct Ordering {
    state: Mutex<OrderState>,
    drain_eps: Mutex<Vec<(Value, Instant)>>,
}

#[derive(Default)]
struct OrderState {
    outstanding: Vec<Value>,
}

impl Default for Ordering {
    fn default() -> Self {
        Self {
            state: Mutex::new(OrderState::default()),
            drain_eps: Mutex::new(Vec::new()),
        }
    }
}

impl Ordering {
    pub fn new() -> Self {
        Self::default()
    }

    fn on_forwarded(&self, id: &Value) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .outstanding
            .push(id.clone());
        let until = Instant::now() + SETTLE_TIMEOUT;
        self.drain_eps
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((id.clone(), until));
    }

    /// Marks a forwarded id complete. Called by the pump for every
    /// SDK response it forwards to the client.
    pub fn on_completed(&self, id: &Value) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.outstanding.retain(|o| o != id);
    }

    /// Settles every outstanding id — the pump calls this when the
    /// SDK side dies, so the guard never waits on a dead service.
    /// Id-less frames settle under `Null`.
    pub fn abandon(&self) {
        let ids: Vec<Value> = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            state.outstanding.clone()
        };
        for id in &ids {
            self.on_completed(id);
        }
        self.on_completed(&Value::Null);
    }

    fn is_drained(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .outstanding
            .is_empty()
    }

    /// Waits until the oldest outstanding request has settled (or
    /// its settle deadline elapses): the sequencer heartbeat that
    /// keeps forwarded requests strictly ordered. Async on purpose:
    /// these waits run on runtime workers, and a synchronous wait
    /// here starves the very service tasks that settle requests
    /// (measured: a burst response delayed by exactly the drain
    /// timeout on a 2-worker runtime).
    pub async fn wait_settled(&self) {
        let deadline = {
            let eps = self.drain_eps.lock().unwrap_or_else(|p| p.into_inner());
            eps.first().map(|(_, until)| *until)
        };
        let Some(deadline) = deadline else {
            return;
        };
        while !self.is_drained() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// Waits (bounded by DRAIN_TIMEOUT) until nothing is
    /// outstanding.
    pub async fn wait_for_drain(&self) {
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        while !self.is_drained() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

/// Writes one JSON-RPC frame to the real stdout under the shared
/// lock, so the guard and the response pump never interleave bytes.
fn write_frame(stdout: &Arc<Mutex<std::io::Stdout>>, frame: &Value) {
    let mut out = stdout.lock().unwrap_or_else(|p| p.into_inner());
    let _ = writeln!(out, "{frame}");
    let _ = out.flush();
}

fn error_frame(id: &Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({"code": code, "message": message});
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": error})
}

/// Sends a guard-answered error frame, waiting (bounded) for
/// outstanding responses first so wires stay ordered.
async fn guard_error(
    ordering: &Ordering,
    stdout: &Arc<Mutex<std::io::Stdout>>,
    id: &Value,
    code: i64,
    message: &str,
    data: Option<Value>,
) {
    ordering.wait_for_drain().await;
    write_frame(stdout, &error_frame(id, code, message, data));
}

/// The outcome of an authentication attempt on one frame.
enum Auth {
    /// Token valid (and stripped from the frame).
    Ok,
    /// No `_meta` token present.
    Missing,
    /// A token was present but did not match.
    Bad,
}

fn authenticate(frame: &mut Value, auth: &GuardAuth) -> Auth {
    let token = frame
        .get("params")
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(META_AGENT_TOKEN))
        .and_then(Value::as_str)
        .map(str::to_string);
    let Some(token) = token else {
        return Auth::Missing;
    };
    if !token_matches(&token, &auth.agent_token_digest) {
        return Auth::Bad;
    }
    // Strip the spent token: it must not travel further.
    if let Some(meta) = frame
        .get_mut("params")
        .and_then(|p| p.get_mut("_meta"))
        .and_then(Value::as_object_mut)
    {
        meta.remove(META_AGENT_TOKEN);
    }
    Auth::Ok
}

async fn refuse_unauthorized(
    ordering: &Ordering,
    stdout: &Arc<Mutex<std::io::Stdout>>,
    auth: &GuardAuth,
    frame: &Value,
    id: &Value,
    outcome: Auth,
) {
    let reason = match outcome {
        Auth::Missing => "missing_token",
        Auth::Bad => "bad_token",
        Auth::Ok => unreachable!(),
    };
    let tool = frame
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    auth.oplog.record(
        tool,
        None,
        None,
        &format!("refused:{}", codes::UNAUTHORIZED),
        None,
        Some(reason),
    );
    guard_error(
        ordering,
        stdout,
        id,
        -32001,
        "unauthorized: tools/call requires the agent token in _meta[\"seahawk/agent_token\"]",
        Some(json!({"code": codes::UNAUTHORIZED, "reason": reason})),
    )
    .await;
}

/// Line source for the guard: tokio stdin, read in chunks and
/// split locally. The guard must work under any spawner (cargo
/// tests, the MCP Inspector, IDE hosts), so it reads the async
/// stdin handle directly — an earlier build opened /dev/stdin,
/// which some spawners' stdio plumbing refuses (ENXIO).
struct LineReader {
    reader: tokio::io::BufReader<tokio::io::Stdin>,
    buf: Vec<u8>,
}

impl LineReader {
    /// The next line (without its terminator), or None at EOF or
    /// on an over-limit line (which ends the session, as a wedged
    /// peer has nothing valid left to say).
    async fn next_line(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                if pos > MAX_LINE_BYTES {
                    return None;
                }
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                let line = line.strip_suffix(b"\n").unwrap_or(&line);
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                return Some(line.to_vec());
            }
            if self.buf.len() > MAX_LINE_BYTES {
                return None;
            }
            let mut chunk = [0u8; 8192];
            match self.reader.read(&mut chunk).await {
                Ok(0) => {
                    if self.buf.is_empty() {
                        return None;
                    }
                    return Some(std::mem::take(&mut self.buf));
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(_) => return None,
            }
        }
    }
}

/// Reads client lines from stdin, applies the guard, and forwards
/// accepted frames into the SDK duplex.
pub async fn guard_incoming<W>(
    input: tokio::io::Stdin,
    mut to_sdk: W,
    ordering: Arc<Ordering>,
    stdout: Arc<Mutex<std::io::Stdout>>,
    auth: Arc<GuardAuth>,
) where
    W: AsyncWrite + Unpin,
{
    let mut lines = LineReader {
        reader: tokio::io::BufReader::new(input),
        buf: Vec::new(),
    };
    while let Some(line) = lines.next_line().await {
        let line: &[u8] = &line;
        if line.is_empty() {
            continue;
        }
        let frame: Value = match serde_json::from_slice(line) {
            Ok(frame) => frame,
            Err(_) => {
                write_frame(
                    &stdout,
                    &error_frame(
                        &Value::Null,
                        -32700,
                        "Parse error: frame is not valid JSON.",
                        None,
                    ),
                );
                continue;
            }
        };
        if !frame.is_object() {
            write_frame(
                &stdout,
                &error_frame(
                    &Value::Null,
                    -32600,
                    "Invalid Request: frame must be a JSON object.",
                    None,
                ),
            );
            continue;
        }
        let id = frame.get("id").cloned().unwrap_or(Value::Null);
        let method = frame.get("method").and_then(Value::as_str);
        // Notifications (no id) are dropped silently — the fleet
        // template behavior: there is no legacy surface to notify.
        if frame.get("id").is_none() {
            continue;
        }
        match method {
            // A legacy initialize at any requested version: typed
            // refusal, connection stays up.
            Some("initialize") => {
                let requested = frame
                    .get("params")
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                guard_error(
                    &ordering,
                    &stdout,
                    &id,
                    -32022,
                    "Unsupported protocol version.",
                    Some(json!({
                        "requested": requested,
                        "supported": SUPPORTED_YEARS,
                    })),
                )
                .await;
            }
            Some("server/discover") | Some("ping") => {
                forward(&mut to_sdk, &ordering, &frame).await;
            }
            Some("tools/list") => {
                let mut frame = frame;
                if auth.require_token_for_list {
                    match authenticate(&mut frame, &auth) {
                        Auth::Ok => forward(&mut to_sdk, &ordering, &frame).await,
                        outcome => {
                            refuse_unauthorized(&ordering, &stdout, &auth, &frame, &id, outcome)
                                .await
                        }
                    }
                } else {
                    forward(&mut to_sdk, &ordering, &frame).await;
                }
            }
            Some("tools/call") => {
                let mut frame = frame;
                // Frames too shapeless to carry `_meta` also cannot
                // name a tool; the SDK's shape validation answers
                // them (-32602) before any decide() or dispatch.
                if frame.get("params").is_some_and(Value::is_object) {
                    match authenticate(&mut frame, &auth) {
                        Auth::Ok => forward(&mut to_sdk, &ordering, &frame).await,
                        outcome => {
                            refuse_unauthorized(&ordering, &stdout, &auth, &frame, &id, outcome)
                                .await
                        }
                    }
                } else {
                    forward(&mut to_sdk, &ordering, &frame).await;
                }
            }
            _ => {
                guard_error(&ordering, &stdout, &id, -32601, "Method not found.", None).await;
            }
        }
    }
    // Input closed: let outstanding work drain, then end.
    ordering.wait_for_drain().await;
}

/// Forwards one frame into the SDK duplex, running the sequencer:
/// the previous outstanding request must settle first.
async fn forward<W: AsyncWrite + Unpin>(to_sdk: &mut W, ordering: &Ordering, frame: &Value) {
    ordering.wait_settled().await;
    let id = frame.get("id").cloned().unwrap_or(Value::Null);
    let mut bytes = serde_json::to_vec(frame).unwrap_or_default();
    bytes.push(b'\n');
    if to_sdk.write_all(&bytes).await.is_ok() {
        ordering.on_forwarded(&id);
    }
}

/// Copies SDK responses from the duplex to the real stdout (through
/// the shared lock) and marks their ids complete in the ordering.
pub async fn pump_responses<R: AsyncRead + Unpin>(
    mut from_sdk: R,
    ordering: Arc<Ordering>,
    stdout: Arc<Mutex<std::io::Stdout>>,
) {
    use tokio::io::AsyncReadExt;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match from_sdk.read(&mut chunk).await {
            Ok(0) | Err(_) => {
                ordering.abandon();
                return;
            }
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = buf.drain(..=pos).collect();
                    let trimmed = line.strip_suffix(b"\n").unwrap_or(&line);
                    if let Ok(frame) = serde_json::from_slice::<Value>(trimmed) {
                        if let Some(id) = frame.get("id") {
                            ordering.on_completed(id);
                        } else {
                            ordering.on_completed(&Value::Null);
                        }
                    }
                    let mut out = stdout.lock().unwrap_or_else(|p| p.into_inner());
                    let _ = out.write_all(&line);
                    let _ = out.flush();
                }
            }
        }
    }
}
