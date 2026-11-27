//! seahawk stdio session: server/discover, tools/list, and one seahawk_status call (agent token carried in _meta, per the broker contract). Expected output: server name/version, the core tool list, and a status payload (truncated). No Unreal editor is required for the native status tool.
//!
//! Run after a debug build: `cargo run --example stdio_session`
//! (or set SEAHAWK_BIN to the server binary path).
const BIN_NAME: &str = "seahawk";
const BIN_ENV: &str = "SEAHAWK_BIN";
const REPO_TAG: &str = "seahawk";
const TOOL_NAME: &str = "seahawk_status";

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const PROTOCOL_VERSION: &str = "2026-07-28";
const DEADLINE: Duration = Duration::from_secs(30);

fn temp_root(tag: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!(
        "bench-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .map_err(|e| format!("system time: {e}"))?
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    Ok(dir)
}

fn binary_path() -> PathBuf {
    if let Ok(p) = std::env::var(BIN_ENV)
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join(BIN_NAME)
}

fn meta() -> Value {
    let mut m = json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "bench-example", "version": "0.1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    if let Some((k, v)) = extra_meta() {
        m[k] = v;
    }
    m
}

fn frame(id: u64, method: &str, mut params: Value) -> Value {
    if !params.is_object() {
        params = json!({});
    }
    params["_meta"] = meta();
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    next_id: u64,
}

impl Session {
    fn spawn(command: &mut Command) -> Result<Self, String> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn server: {e}"))?;
        let stdin = child.stdin.take().ok_or("server stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("server stdout unavailable")?;
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
        Ok(Self {
            child,
            stdin,
            lines: rx,
            next_id: 0,
        })
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        let req = frame(id, method, params);
        let text = serde_json::to_string(&req).map_err(|e| format!("encode request: {e}"))?;
        writeln!(self.stdin, "{text}").map_err(|e| format!("write request: {e}"))?;
        self.stdin.flush().map_err(|e| format!("flush: {e}"))?;
        loop {
            let line = self
                .lines
                .recv_timeout(DEADLINE)
                .map_err(|e| format!("no response for id {id} within {DEADLINE:?}: {e}"))?;
            let value: Value =
                serde_json::from_str(&line).map_err(|e| format!("parse response: {e}"))?;
            if value.get("id").and_then(Value::as_u64) == Some(id) {
                return Ok(value);
            }
        }
    }

    fn discover(&mut self) -> Result<Value, String> {
        self.request("server/discover", json!({}))
    }

    fn tools_list(&mut self) -> Result<Value, String> {
        self.request("tools/list", json!({}))
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, String> {
        self.request("tools/call", json!({"name": name, "arguments": arguments}))
    }

    fn finish(mut self) -> Result<(), String> {
        // Seahawk does not exit promptly on stdin EOF (its own wire
        // tests kill the broker): close stdin, allow a short grace
        // period, then kill and reap.
        drop(self.stdin);
        let started = Instant::now();
        loop {
            match self
                .child
                .try_wait()
                .map_err(|e| format!("poll server: {e}"))?
            {
                Some(_) => return Ok(()),
                None => {
                    if started.elapsed() > Duration::from_secs(3) {
                        self.child.kill().map_err(|e| format!("kill server: {e}"))?;
                        self.child.wait().map_err(|e| format!("reap server: {e}"))?;
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }
}

fn tool_names(list: &Value) -> Vec<String> {
    list["result"]["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|t| t["name"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn result_text(response: &Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        format!("{}...", &text[..max])
    }
}

const AGENT_TOKEN: &str = "bench-agent-token";

fn extra_meta() -> Option<(&'static str, Value)> {
    Some(("seahawk/agent_token", json!(AGENT_TOKEN)))
}

/// Build the server command: seahawk takes a config path. The config
/// uses a loopback downstream URL on an unused port (the native
/// status tool does not need a live editor) and a temp op log.
fn server_command(root: &Path) -> Result<Command, String> {
    let body = format!(
        "[server]\nagent_token = \"{AGENT_TOKEN}\"\n[downstream]\nurl = \"http://127.0.0.1:9/mcp\"\ntimeout_secs = 2\n[policy]\n[oplog]\npath = \"{}\"\n",
        root.join("oplog.jsonl").display()
    );
    let config = root.join("seahawk.toml");
    std::fs::write(&config, body).map_err(|e| format!("write config: {e}"))?;
    let mut cmd = Command::new(binary_path());
    cmd.arg(&config);
    Ok(cmd)
}

fn representative_args(_root: &Path) -> Value {
    json!({})
}

fn run() -> Result<(), String> {
    let root = temp_root(REPO_TAG)?;
    let mut cmd = server_command(&root)?;
    let mut session = Session::spawn(&mut cmd)?;
    let discover = session.discover()?;
    println!("discover: {}", truncate(&discover.to_string(), 400));
    let list = session.tools_list()?;
    let names = tool_names(&list);
    println!("tools/list: {} tools: {}", names.len(), names.join(", "));
    let response = session.call_tool(TOOL_NAME, representative_args(&root))?;
    println!(
        "tools/call {TOOL_NAME}: {}",
        truncate(&result_text(&response), 600)
    );
    if response["result"]["isError"].as_bool() == Some(true) {
        return Err(format!(
            "{TOOL_NAME} returned isError: {}",
            result_text(&response)
        ));
    }
    session.finish()?;
    println!("stdio_session: ok");
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("stdio_session: error: {e}");
        std::process::exit(1);
    }
}
