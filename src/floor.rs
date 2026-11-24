//! The generic-GUI floor: the target adapter for applications
//! with no scripting API, over primo's live Wayland session.
//!
//! Verbs, all through the session's own tools (never a shell):
//! window discovery via `hyprctl clients -j`, screenshots via
//! `grim`, input injection via `ydotool` (the estate's proven
//! route on this host: `YDOTOOL_SOCKET` at the session socket).
//!
//! The floor's limits are declared, not implied (see
//! `target.rs`): it offers no script execution, and no state
//! guarantee beyond what a window list or a screenshot shows.
//! Focus is by clicking the target window's centre — the floor
//! has no other focus primitive on a Wayland session, and
//! `hyprctl dispatch` on this host's build wraps its arguments
//! as raw Lua, which the estate has measured broken for the
//! classic syntax (TOOLS.md) — so dispatch is not used.
//!
//! Session environment is resolved at call time: the runtime
//! dir from config, else `$XDG_RUNTIME_DIR`, else
//! `/run/user/<uid>`; the Hyprland instance signature is
//! discovered from the runtime dir's `hypr/` entries.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::FloorConfig;
use crate::policy::codes;
use crate::runner::{default_runtime_dir, run_bounded};
use crate::target::{
    TargetAdapter, TargetCaps, TargetDepth, TargetError, TargetInfo, TargetResult,
};

/// hyprctl / grim / ydotool all answer in well under this.
const FLOOR_TIMEOUT: Duration = Duration::from_secs(30);

/// The floor's input vocabulary. Deliberately smaller than the
/// X11 provider's: every verb here is one the Wayland route
/// performs honestly (no scroll — ydotool's wheel path is not
/// estate-proven; no drag — a held-button move is two verbs
/// the caller can sequence only with state the floor does not
/// keep).
pub const FLOOR_ACTIONS: [&str; 5] = ["focus", "click", "double_click", "key", "type"];

static SHOT_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct GuiFloorAdapter {
    config: FloorConfig,
}

impl GuiFloorAdapter {
    pub fn new(config: FloorConfig) -> Self {
        Self { config }
    }

    /// The runtime dir this adapter addresses.
    fn runtime_dir(&self) -> TargetResult<PathBuf> {
        if let Some(dir) = &self.config.runtime_dir {
            return Ok(dir.clone());
        }
        default_runtime_dir().ok_or_else(|| {
            TargetError::unavailable(
                "cannot resolve the session runtime dir (no [floor] runtime_dir, \
                 no XDG_RUNTIME_DIR, no /proc uid)",
            )
        })
    }

    /// The Hyprland instance signature: the `hypr/` entry under
    /// the runtime dir that carries the socket.
    fn hyprland_instance(&self, runtime_dir: &Path) -> Option<String> {
        let hypr_dir = runtime_dir.join("hypr");
        let entries = std::fs::read_dir(hypr_dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.join(".socket.sock").exists() {
                return Some(entry.file_name().to_string_lossy().into_owned());
            }
        }
        None
    }

    /// The environment every floor child runs with.
    fn session_env(&self) -> TargetResult<Vec<(String, String)>> {
        let runtime_dir = self.runtime_dir()?;
        let mut env = vec![
            (
                "XDG_RUNTIME_DIR".to_string(),
                runtime_dir.display().to_string(),
            ),
            (
                "WAYLAND_DISPLAY".to_string(),
                std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "wayland-1".to_string()),
            ),
            (
                "YDOTOOL_SOCKET".to_string(),
                self.config.ydotool_socket.display().to_string(),
            ),
        ];
        if let Some(instance) = self.hyprland_instance(&runtime_dir) {
            env.push(("HYPRLAND_INSTANCE_SIGNATURE".to_string(), instance));
        }
        Ok(env)
    }

    fn run_tool(&self, program: &str, args: &[&str]) -> TargetResult<crate::runner::RunOutcome> {
        let env = self.session_env()?;
        let env_refs: Vec<(&str, &str)> = env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let outcome = run_bounded(program, args, &env_refs, FLOOR_TIMEOUT).map_err(|error| {
            TargetError::unavailable(format!("{program} cannot be started: {error}"))
        })?;
        if outcome.timed_out {
            return Err(TargetError::unavailable(format!(
                "{program} timed out after {} s",
                FLOOR_TIMEOUT.as_secs()
            )));
        }
        if outcome.exit_code != Some(0) {
            return Err(TargetError::failed(format!(
                "{program} {} exited {:?}: {}",
                args.join(" "),
                outcome.exit_code,
                crate::runner::tail_lines(&outcome.stderr, 5)
            )));
        }
        Ok(outcome)
    }

    /// The session's window list, normalized from
    /// `hyprctl clients -j` + `activewindow -j`.
    pub fn windows(&self) -> TargetResult<Value> {
        let clients = self.run_tool("hyprctl", &["clients", "-j"])?;
        let parsed: Value = serde_json::from_str(&clients.stdout).map_err(|error| {
            TargetError::failed(format!("hyprctl clients output is not JSON: {error}"))
        })?;
        let active = self
            .run_tool("hyprctl", &["activewindow", "-j"])
            .ok()
            .and_then(|outcome| serde_json::from_str::<Value>(&outcome.stdout).ok());
        let active_address = active
            .as_ref()
            .and_then(|value| value.get("address"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let windows: Vec<Value> = parsed
            .as_array()
            .map(|array| {
                array
                    .iter()
                    .map(|window| {
                        let address = window
                            .get("address")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        json!({
                            "address": address,
                            "class": window.get("class").cloned().unwrap_or(Value::Null),
                            "title": window.get("title").cloned().unwrap_or(Value::Null),
                            "workspace": window.get("workspace").cloned().unwrap_or(Value::Null),
                            "at": window.get("at").cloned().unwrap_or(Value::Null),
                            "size": window.get("size").cloned().unwrap_or(Value::Null),
                            "focused": active_address.as_deref() == Some(address.as_str()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(json!({
            "windows": windows,
            "count": windows.len(),
        }))
    }

    /// One window by address, from a fresh window list.
    fn window_by_address(&self, address: &str) -> TargetResult<Value> {
        let windows = self.windows()?;
        windows
            .get("windows")
            .and_then(Value::as_array)
            .and_then(|array| {
                array
                    .iter()
                    .find(|window| window.get("address").and_then(Value::as_str) == Some(address))
                    .cloned()
            })
            .ok_or_else(|| {
                TargetError::new(
                    codes::GUI_NO_WINDOW,
                    format!("no window with address {address:?} in the session's window list"),
                )
            })
    }

    /// `gui.floor_screenshot`: a grim capture of the whole
    /// session, or of one window's rectangle when `address` is
    /// given. Returns the PNG as base64 with its digest — the
    /// handler renders it as an image content block.
    pub fn screenshot(&self, address: Option<&str>) -> TargetResult<Value> {
        let region = match address {
            Some(address) => {
                let window = self.window_by_address(address)?;
                let at = window.get("at").and_then(Value::as_array);
                let size = window.get("size").and_then(Value::as_array);
                let (Some(at), Some(size)) = (at, size) else {
                    return Err(TargetError::failed(format!(
                        "window {address:?} reports no geometry to capture"
                    )));
                };
                let coord = |value: Option<&Value>| value.and_then(Value::as_i64).unwrap_or(0);
                Some(format!(
                    "{},{} {}x{}",
                    coord(at.first()),
                    coord(at.get(1)),
                    coord(size.first()),
                    coord(size.get(1))
                ))
            }
            None => None,
        };
        let counter = SHOT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "seahawk-floor-{}-{counter}.png",
            std::process::id()
        ));
        let path_text = path.display().to_string();
        let mut args: Vec<&str> = Vec::new();
        if let Some(region) = &region {
            args.push("-g");
            args.push(region);
        }
        args.push(&path_text);
        let outcome = self.run_tool("grim", &args);
        let bytes = std::fs::read(&path);
        let _ = std::fs::remove_file(&path);
        outcome?;
        let bytes = bytes.map_err(|error| {
            TargetError::failed(format!("grim wrote no readable frame: {error}"))
        })?;
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        Ok(json!({
            "sha256": sha256,
            "bytes": bytes.len(),
            "region": region,
            "image_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
        }))
    }

    /// `gui.floor_act`: one input action from the floor
    /// vocabulary, injected with ydotool.
    pub fn act(&self, args: &Value) -> TargetResult<Value> {
        let Some(action) = args.get("action").and_then(Value::as_str) else {
            return Err(TargetError::new(
                codes::BAD_ARGUMENTS,
                "argument \"action\" is required (focus, click, double_click, key, type)",
            ));
        };
        if !FLOOR_ACTIONS.contains(&action) {
            return Err(TargetError::new(
                codes::GUI_UNKNOWN_ACTION,
                format!(
                    "unknown floor action {action:?}; the floor vocabulary is \
                     {FLOOR_ACTIONS:?} — no scroll and no drag at the floor, by \
                     declaration"
                ),
            ));
        }
        match action {
            "focus" => {
                let address = required_str(args, "address")?;
                let window = self.window_by_address(&address)?;
                let (cx, cy) = window_centre(&window).ok_or_else(|| {
                    TargetError::failed(format!("window {address:?} reports no geometry to focus"))
                })?;
                self.ydotool(&[
                    "mousemove",
                    "--absolute",
                    "-x",
                    &cx.to_string(),
                    "-y",
                    &cy.to_string(),
                ])?;
                self.ydotool(&["click", "0xC0"])?;
                Ok(json!({
                    "action": "focus",
                    "address": address,
                    "clicked_centre": [cx, cy],
                    "note": "focus at the floor is a click into the window's centre; \
                             the floor has no other focus primitive",
                }))
            }
            "click" | "double_click" => {
                let (x, y) = required_xy(args)?;
                self.ydotool(&[
                    "mousemove",
                    "--absolute",
                    "-x",
                    &x.to_string(),
                    "-y",
                    &y.to_string(),
                ])?;
                self.ydotool(&["click", "0xC0"])?;
                if action == "double_click" {
                    self.ydotool(&["click", "0xC0"])?;
                }
                Ok(json!({"action": action, "at": [x, y]}))
            }
            "key" => {
                let keys = required_str(args, "keys")?;
                let tokens: Vec<&str> = keys.split_whitespace().collect();
                if tokens.is_empty() || !tokens.iter().all(|token| valid_key_token(token)) {
                    return Err(TargetError::new(
                        codes::BAD_ARGUMENTS,
                        format!(
                            "keys {keys:?} must be ydotool keycodes in \
                             <keycode>:<pressed> form, whitespace-separated \
                             (e.g. \"28:1 28:0\" is Enter) — this ydotool build \
                             speaks raw keycodes only and silently ignores \
                             symbolic names, so the broker refuses them instead \
                             of reporting a no-op as success"
                        ),
                    ));
                }
                let mut argv: Vec<&str> = vec!["key"];
                argv.extend(tokens);
                self.ydotool(&argv)?;
                Ok(json!({"action": "key", "keys": keys}))
            }
            "type" => {
                let text = required_str(args, "text")?;
                if text.starts_with('-') {
                    return Err(TargetError::new(
                        codes::BAD_ARGUMENTS,
                        "text must not start with '-' (it rides as a bare argv value)",
                    ));
                }
                self.ydotool(&["type", &text])?;
                Ok(json!({"action": "type", "chars": text.chars().count()}))
            }
            _ => unreachable!("vocabulary checked above"),
        }
    }

    fn ydotool(&self, args: &[&str]) -> TargetResult<()> {
        if !self.config.ydotool_socket.exists() {
            return Err(TargetError::unavailable(format!(
                "ydotool socket {} does not exist — ydotoold is not running in the \
                 session, so no input can be injected",
                self.config.ydotool_socket.display()
            )));
        }
        self.run_tool("ydotool", args)?;
        Ok(())
    }
}

/// One ydotool key token in `<keycode>:<pressed>` form: a
/// 1–3 digit Linux keycode, a colon, and state 0 or 1. The
/// estate's ydotool build interprets nothing else (its own
/// help: "Non-interpretable values … will only cause a
/// delay"), so anything else refuses broker-side.
fn valid_key_token(token: &str) -> bool {
    let Some((code, state)) = token.split_once(':') else {
        return false;
    };
    !code.is_empty()
        && code.len() <= 3
        && code.bytes().all(|byte| byte.is_ascii_digit())
        && matches!(state, "0" | "1")
}

/// A required string argument.
fn required_str(args: &Value, field: &str) -> TargetResult<String> {
    args.get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            TargetError::new(
                codes::BAD_ARGUMENTS,
                format!("argument \"{field}\" is required (a non-empty string)"),
            )
        })
}

/// The required raw x/y arguments (absolute session pixels).
fn required_xy(args: &Value) -> TargetResult<(i64, i64)> {
    let x = args.get("x").and_then(Value::as_i64);
    let y = args.get("y").and_then(Value::as_i64);
    match (x, y) {
        (Some(x), Some(y)) => Ok((x, y)),
        _ => Err(TargetError::new(
            codes::BAD_ARGUMENTS,
            "arguments \"x\" and \"y\" are required (absolute session pixels)",
        )),
    }
}

/// A window's centre from its hyprctl geometry.
fn window_centre(window: &Value) -> Option<(i64, i64)> {
    let at = window.get("at")?.as_array()?;
    let size = window.get("size")?.as_array()?;
    let x = at.first()?.as_i64()?;
    let y = at.get(1)?.as_i64()?;
    let w = size.first()?.as_i64()?;
    let h = size.get(1)?.as_i64()?;
    Some((x + w / 2, y + h / 2))
}

impl TargetAdapter for GuiFloorAdapter {
    fn info(&self) -> TargetInfo {
        TargetInfo {
            id: "gui-floor",
            display_name: "Generic GUI floor — Wayland session (hyprctl, grim, ydotool)",
            depth: TargetDepth::GenericFloor,
            caps: TargetCaps::floor(),
        }
    }

    fn attach(&self) -> TargetResult<Value> {
        let runtime_dir = self.runtime_dir()?;
        let windows = self.windows()?;
        Ok(json!({
            "runtime_dir": runtime_dir.display().to_string(),
            "hyprland_instance_found": self
                .hyprland_instance(&runtime_dir)
                .is_some(),
            "ydotool_socket": self.config.ydotool_socket.display().to_string(),
            "ydotool_socket_present": self.config.ydotool_socket.exists(),
            "windows": windows["count"],
            "limits": "the floor declares no execute; state is only what the \
                       window list and screenshots show",
        }))
    }

    fn execute(&self, _op: &str, _args: &Value) -> TargetResult<Value> {
        // The registry refuses first (caps.execute is false);
        // this is the fail-closed backstop for direct callers.
        Err(TargetError::capability(
            &self.info(),
            crate::target::TargetOp::Execute,
        ))
    }

    fn inspect(&self, _args: &Value) -> TargetResult<Value> {
        self.windows()
    }

    fn observe(&self, args: &Value) -> TargetResult<Value> {
        let address = args.get("address").and_then(Value::as_str);
        self.screenshot(address)
    }

    fn actuate(&self, args: &Value) -> TargetResult<Value> {
        self.act(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> GuiFloorAdapter {
        GuiFloorAdapter::new(FloorConfig {
            ydotool_socket: PathBuf::from("/nonexistent/ydotool.sock"),
            runtime_dir: Some(PathBuf::from("/nonexistent")),
        })
    }

    #[test]
    fn floor_declares_generic_depth_and_no_execute() {
        let info = adapter().info();
        assert_eq!(info.depth.as_str(), "generic-floor");
        assert!(!info.caps.execute);
        assert!(info.caps.actuate && info.caps.observe && info.caps.inspect);
    }

    // -- adversarial -------------------------------------------

    #[test]
    fn floor_execute_refuses_by_declaration() {
        let error = adapter()
            .execute("run_script", &json!({}))
            .expect_err("the floor has no execute");
        assert_eq!(error.code, codes::TARGET_CAPABILITY);
    }

    #[test]
    fn unknown_floor_action_refuses() {
        let error = adapter()
            .act(&json!({"action": "scroll"}))
            .expect_err("scroll is not in the floor vocabulary");
        assert_eq!(error.code, codes::GUI_UNKNOWN_ACTION);
        let error = adapter()
            .act(&json!({"action": "run"}))
            .expect_err("run is not an input action");
        assert_eq!(error.code, codes::GUI_UNKNOWN_ACTION);
    }

    #[test]
    fn key_tokens_are_shape_checked() {
        // A token carrying shell punctuation must refuse before
        // ydotool is consulted (the socket is absent here, so a
        // pass would surface as unavailable, not bad-arguments).
        let error = adapter()
            .act(&json!({"action": "key", "keys": "a; rm -rf /"}))
            .expect_err("shell-shaped keys must refuse");
        assert_eq!(error.code, codes::BAD_ARGUMENTS);
        // Symbolic names are non-interpretable to this ydotool
        // (they would silently only cause a delay): refuse.
        let error = adapter()
            .act(&json!({"action": "key", "keys": "KEY_ENTER"}))
            .expect_err("symbolic key names must refuse");
        assert_eq!(error.code, codes::BAD_ARGUMENTS);
        // Raw keycode:state tokens pass the shape check and
        // reach the socket check (unavailable in this fixture).
        let error = adapter()
            .act(&json!({"action": "key", "keys": "28:1 28:0"}))
            .expect_err("no socket in the fixture");
        assert_eq!(error.code, codes::TARGET_UNAVAILABLE);
        assert!(valid_key_token("28:1"));
        assert!(valid_key_token("42:0"));
        assert!(!valid_key_token("28:2"));
        assert!(!valid_key_token("1234:1"));
        assert!(!valid_key_token(":1"));
    }

    #[test]
    fn type_text_must_not_look_like_a_flag() {
        let error = adapter()
            .act(&json!({"action": "type", "text": "--file=/etc/passwd"}))
            .expect_err("flag-shaped text must refuse");
        assert_eq!(error.code, codes::BAD_ARGUMENTS);
    }

    #[test]
    fn window_centre_math() {
        let window = json!({"at": [100, 50], "size": [400, 200]});
        assert_eq!(window_centre(&window), Some((300, 150)));
        assert_eq!(window_centre(&json!({})), None);
    }
}
