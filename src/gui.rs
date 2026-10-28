//! The S4 host-GUI provider: Seahawk's built-in downstream for
//! the operator's desktop.
//!
//! Registration is policy data only (`[[gui.apps]]` in the config,
//! parsed once at startup). For each registered application this
//! module builds two tools — `gui.<app>.observe` (read class) and
//! `gui.<app>.actuate` (actuate class) — and serves them against
//! the X11 display Seahawk runs on. There is no agent-callable
//! registration, no runtime re-registration, and no shell anywhere
//! in the path: window enumeration, focus, input injection, and
//! screenshots are X11 protocol operations (x11rb), because a
//! subprocess helper would be an execute-shaped side channel
//! around decide().
//!
//! Confinement: actuation resolves the registered application's
//! window by WM_CLASS/title match and validates every coordinate
//! against that window's rectangle before injecting anything.
//! Input cannot be aimed outside the registered window through
//! this surface. Every actuation is bracketed by screenshots
//! whose digests land in the op log (see oplog::LogExtra).

use std::fmt;
use std::sync::Arc;

use rmcp::model::{Tool, ToolAnnotations};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::model::GuiApp;
use crate::oplog::bytes_digest;
use crate::policy::codes;

// ---------------------------------------------------------------------------
// Bounds (named, per Tiger Style: every external input is bounded
// before it is used)
// ---------------------------------------------------------------------------

/// Longest `type` payload, in characters.
pub const MAX_TYPE_TEXT_CHARS: usize = 512;
/// Longest `key` spec (e.g. `ctrl+shift+s`), in characters.
pub const MAX_KEY_SPEC_CHARS: usize = 64;
/// Largest accepted window-relative coordinate.
pub const MAX_COORDINATE: i64 = 100_000;
/// Cap on enumerated client windows per observe/actuate call.
pub const MAX_WINDOWS: usize = 512;
/// Cap on a screenshot's pixel count (8192 x 8192 worst case is
/// refused well before allocation: 16.7 Mpx here).
pub const MAX_FRAME_PIXELS: u64 = 16_777_216;
/// Settle time after an actuation before the post-action
/// screenshot, in milliseconds: long enough for the application
/// to redraw, short enough to keep the broker responsive.
pub const ACTUATION_SETTLE_MS: u64 = 150;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A typed GUI failure. `code` is one of policy::codes' GUI codes
/// (or BAD_ARGUMENTS for shape failures); the handler renders it
/// as a structured refusal exactly like downstream failures.
#[derive(Debug)]
pub struct GuiError {
    pub code: &'static str,
    pub message: String,
}

impl GuiError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn bad_arguments(message: impl Into<String>) -> Self {
        Self::new(codes::BAD_ARGUMENTS, message)
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self::new(codes::GUI_UNAVAILABLE, message)
    }

    fn failed(message: impl Into<String>) -> Self {
        Self::new(codes::GUI_ACTION_FAILED, message)
    }
}

impl fmt::Display for GuiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for GuiError {}

type GuiResult<T> = Result<T, GuiError>;

// ---------------------------------------------------------------------------
// Actions (parsed, validated argument vocabulary)
// ---------------------------------------------------------------------------

/// Observe vocabulary: the whole read surface of one GUI app.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveKind {
    /// PNG screenshot of the app's window region on the root
    /// window (what an operator looking at the screen would see).
    Screenshot,
    /// The app's windows: ids, classes, titles, geometry, focus.
    Windows,
    /// Focus state: which window holds input focus, and whether
    /// it belongs to this app.
    State,
}

/// Actuate vocabulary: the whole input surface of one GUI app.
/// Anything outside this vocabulary — in particular anything
/// shaped like running a command — is refused as an unknown
/// action before any backend is touched: the actuate surface
/// cannot be talked into an execute.
#[derive(Clone, Debug, PartialEq)]
pub enum ActuateAction {
    Focus,
    Click {
        x: i32,
        y: i32,
        button: u8,
    },
    DoubleClick {
        x: i32,
        y: i32,
    },
    Key {
        spec: String,
    },
    Type {
        text: String,
    },
    Scroll {
        x: i32,
        y: i32,
        dx: i32,
        dy: i32,
    },
    Drag {
        from_x: i32,
        from_y: i32,
        to_x: i32,
        to_y: i32,
    },
}

impl ActuateAction {
    /// Short human description for the op log's target field.
    pub fn describe(&self) -> String {
        match self {
            Self::Focus => "focus".to_string(),
            Self::Click { x, y, button } => format!("click {x},{y} button {button}"),
            Self::DoubleClick { x, y } => format!("double_click {x},{y}"),
            Self::Key { spec } => format!("key {spec}"),
            Self::Type { text } => format!("type {} chars", text.chars().count()),
            Self::Scroll { x, y, dx, dy } => format!("scroll {x},{y} dx {dx} dy {dy}"),
            Self::Drag {
                from_x,
                from_y,
                to_x,
                to_y,
            } => format!("drag {from_x},{from_y} -> {to_x},{to_y}"),
        }
    }

    /// Window-relative points this action aims at; the backend
    /// validates each against the target window's rectangle.
    pub fn points(&self) -> Vec<(i32, i32)> {
        match self {
            Self::Focus | Self::Key { .. } | Self::Type { .. } => Vec::new(),
            Self::Click { x, y, .. } | Self::DoubleClick { x, y } | Self::Scroll { x, y, .. } => {
                vec![(*x, *y)]
            }
            Self::Drag {
                from_x,
                from_y,
                to_x,
                to_y,
            } => vec![(*from_x, *from_y), (*to_x, *to_y)],
        }
    }
}

fn arg_i32(args: &Value, field: &str) -> GuiResult<i32> {
    let value = args
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| GuiError::bad_arguments(format!("argument {field:?} must be an integer")))?;
    if !(-MAX_COORDINATE..=MAX_COORDINATE).contains(&value) {
        return Err(GuiError::bad_arguments(format!(
            "argument {field:?} is out of bounds (|v| <= {MAX_COORDINATE})"
        )));
    }
    i32::try_from(value)
        .map_err(|_| GuiError::bad_arguments(format!("argument {field:?} is out of range")))
}

fn arg_i32_default(args: &Value, field: &str, default: i32) -> GuiResult<i32> {
    if args.get(field).is_none() {
        return Ok(default);
    }
    arg_i32(args, field)
}

/// A window-relative point coordinate: non-negative (negative
/// points are meaningless inside a window and are refused at
/// parse time; the backend additionally validates against the
/// resolved window's actual rectangle).
fn arg_point(args: &Value, field: &str) -> GuiResult<i32> {
    let value = arg_i32(args, field)?;
    if value < 0 {
        return Err(GuiError::bad_arguments(format!(
            "argument {field:?} must be a non-negative window-relative coordinate"
        )));
    }
    Ok(value)
}

/// Parses and validates the observe arguments. Unknown actions
/// are refused with the GUI unknown-action code, never mapped
/// onto a default.
pub fn parse_observe(args: &Value) -> GuiResult<ObserveKind> {
    match args.get("action").and_then(Value::as_str) {
        None | Some("screenshot") => Ok(ObserveKind::Screenshot),
        Some("windows") => Ok(ObserveKind::Windows),
        Some("state") => Ok(ObserveKind::State),
        Some(other) => Err(GuiError::new(
            codes::GUI_UNKNOWN_ACTION,
            format!(
                "unknown observe action {other:?}: the vocabulary is \
                 screenshot | windows | state"
            ),
        )),
    }
}

/// Parses and validates the actuate arguments. The action
/// vocabulary is closed (see ActuateAction): a spec like
/// `run_command` or `execute` is refused as an unknown action —
/// this is the seam where an execute attempt through an actuate
/// registration dies.
pub fn parse_actuate(args: &Value) -> GuiResult<ActuateAction> {
    let action = args
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| GuiError::bad_arguments("argument \"action\" is required"))?;
    match action {
        "focus" => Ok(ActuateAction::Focus),
        "click" => {
            let button = arg_i32_default(args, "button", 1)?;
            if !(1..=3).contains(&button) {
                return Err(GuiError::bad_arguments(
                    "argument \"button\" must be 1 (left), 2 (middle), or 3 (right)",
                ));
            }
            Ok(ActuateAction::Click {
                x: arg_point(args, "x")?,
                y: arg_point(args, "y")?,
                button: u8::try_from(button).unwrap_or(1),
            })
        }
        "double_click" => Ok(ActuateAction::DoubleClick {
            x: arg_point(args, "x")?,
            y: arg_point(args, "y")?,
        }),
        "key" => {
            let spec = args.get("keys").and_then(Value::as_str).ok_or_else(|| {
                GuiError::bad_arguments("action \"key\" requires a string \"keys\" argument")
            })?;
            if spec.is_empty() || spec.chars().count() > MAX_KEY_SPEC_CHARS {
                return Err(GuiError::bad_arguments(format!(
                    "\"keys\" must be 1..={MAX_KEY_SPEC_CHARS} characters"
                )));
            }
            Ok(ActuateAction::Key {
                spec: spec.to_string(),
            })
        }
        "type" => {
            let text = args.get("text").and_then(Value::as_str).ok_or_else(|| {
                GuiError::bad_arguments("action \"type\" requires a string \"text\" argument")
            })?;
            if text.chars().count() > MAX_TYPE_TEXT_CHARS {
                return Err(GuiError::bad_arguments(format!(
                    "\"text\" is bounded at {MAX_TYPE_TEXT_CHARS} characters"
                )));
            }
            Ok(ActuateAction::Type {
                text: text.to_string(),
            })
        }
        "scroll" => Ok(ActuateAction::Scroll {
            x: arg_point(args, "x")?,
            y: arg_point(args, "y")?,
            dx: arg_i32_default(args, "dx", 0)?,
            dy: arg_i32_default(args, "dy", 0)?,
        }),
        "drag" => Ok(ActuateAction::Drag {
            from_x: arg_point(args, "from_x")?,
            from_y: arg_point(args, "from_y")?,
            to_x: arg_point(args, "to_x")?,
            to_y: arg_point(args, "to_y")?,
        }),
        other => Err(GuiError::new(
            codes::GUI_UNKNOWN_ACTION,
            format!(
                "unknown actuate action {other:?}: the vocabulary is \
                 focus | click | double_click | key | type | scroll | drag — \
                 the actuate surface has no code-execution action"
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// One screenshot: PNG bytes + dimensions. The op log records
/// only the digest and dimensions; the bytes go to the caller.
#[derive(Clone, Debug)]
pub struct Frame {
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

impl Frame {
    pub fn digest(&self) -> String {
        bytes_digest(&self.png)
    }
}

/// One window on the display, as observed.
#[derive(Clone, Debug, Serialize)]
pub struct WindowInfo {
    /// X11 window id, decimal.
    pub id: u32,
    pub wm_class: String,
    pub instance: String,
    pub title: String,
    /// Root-relative geometry.
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub focused: bool,
    /// True when this window matched the app's registration.
    pub matched: bool,
}

/// What an observe call produced.
#[derive(Debug)]
pub struct ObserveOutcome {
    /// Set for screenshots (and included in the op log by digest).
    pub frame: Option<Frame>,
    /// Structured payload returned to the caller.
    pub payload: Value,
    /// Op-log target description (window identity for screenshots).
    pub target: Option<String>,
}

/// What an actuate call produced: the bracketing frames plus a
/// detail payload. `post` is None only when the post-action
/// screenshot itself failed; the action still happened and the
/// detail payload says so.
#[derive(Debug)]
pub struct ActuateOutcome {
    pub pre: Frame,
    pub post: Option<Frame>,
    pub target: String,
    pub detail: Value,
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// The GUI driver. One implementation ships (X11); tests use a
/// fake. All methods block and are called from `spawn_blocking`.
pub trait GuiBackend: Send + Sync {
    fn observe(&self, app: &GuiApp, kind: ObserveKind) -> GuiResult<ObserveOutcome>;
    fn actuate(&self, app: &GuiApp, action: &ActuateAction) -> GuiResult<ActuateOutcome>;
}

/// The S4 provider facade: parses arguments, then drives the
/// backend. The server wraps it with decide() and the op log.
pub struct Gui {
    backend: Box<dyn GuiBackend>,
}

impl Gui {
    /// The production provider: X11, display from `$DISPLAY`.
    pub fn x11() -> Self {
        Self {
            backend: Box::new(X11Backend { display: None }),
        }
    }

    pub fn with_backend(backend: Box<dyn GuiBackend>) -> Self {
        Self { backend }
    }

    pub fn observe(&self, app: &GuiApp, args: &Value) -> GuiResult<ObserveOutcome> {
        let kind = parse_observe(args)?;
        self.backend.observe(app, kind)
    }

    pub fn actuate(&self, app: &GuiApp, args: &Value) -> GuiResult<ActuateOutcome> {
        let action = parse_actuate(args)?;
        self.backend.actuate(app, &action)
    }
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

fn observe_schema() -> Map<String, Value> {
    let mut props = Map::new();
    props.insert(
        "action".to_string(),
        json!({
            "type": "string",
            "enum": ["screenshot", "windows", "state"],
            "description": "screenshot (default): PNG of the app's window region. windows: the app's window list. state: focus state."
        }),
    );
    let mut schema = Map::new();
    schema.insert("type".to_string(), json!("object"));
    schema.insert("properties".to_string(), Value::Object(props));
    schema
}

fn actuate_schema() -> Map<String, Value> {
    let mut props = Map::new();
    props.insert(
        "action".to_string(),
        json!({
            "type": "string",
            "enum": ["focus", "click", "double_click", "key", "type", "scroll", "drag"],
            "description": "The input action. The vocabulary is closed: there is no run/execute action."
        }),
    );
    props.insert(
        "x".to_string(),
        json!({"type": "integer", "description": "Window-relative x for click / double_click / scroll."}),
    );
    props.insert(
        "y".to_string(),
        json!({"type": "integer", "description": "Window-relative y for click / double_click / scroll."}),
    );
    props.insert(
        "button".to_string(),
        json!({"type": "integer", "enum": [1, 2, 3], "description": "Mouse button for click (default 1)."}),
    );
    props.insert(
        "keys".to_string(),
        json!({"type": "string", "description": "For key: a key spec like \"Return\", \"Escape\", \"ctrl+s\", \"alt+F4\"."}),
    );
    props.insert(
        "text".to_string(),
        json!({"type": "string", "description": "For type: text to enter (bounded, see server limits)."}),
    );
    props.insert(
        "dx".to_string(),
        json!({"type": "integer", "description": "For scroll: horizontal steps (default 0)."}),
    );
    props.insert(
        "dy".to_string(),
        json!({"type": "integer", "description": "For scroll: vertical steps (default 0; positive scrolls down)."}),
    );
    for field in ["from_x", "from_y", "to_x", "to_y"] {
        props.insert(
            field.to_string(),
            json!({"type": "integer", "description": "For drag: window-relative endpoints."}),
        );
    }
    let mut schema = Map::new();
    schema.insert("type".to_string(), json!("object"));
    schema.insert("properties".to_string(), Value::Object(props));
    schema
}

/// The two tools one registration contributes.
pub fn gui_tools(app: &GuiApp) -> Vec<Tool> {
    let observe = Tool::new(
        app.observe_tool(),
        format!(
            "Observe {}'s GUI (read-class): screenshot of its window, its window \
             list, or focus state. The application is registered in Seahawk \
             policy; observation passes under the agent token.",
            app.display_name
        ),
        Arc::new(observe_schema()),
    )
    .with_annotations(
        ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false),
    );
    let actuate = Tool::new(
        app.actuate_tool(),
        format!(
            "[actuate-class: default-deny — requires policy enablement \
             (policy.actuate_enabled) and a per-call operator token] Drive {}'s \
             GUI: focus, click, key, type, scroll, drag, confined to the \
             registered window's rectangle. Every action is op-logged with \
             pre/post screenshot digests. Caution: input into an application \
             that hosts scripting can compose into code execution through the \
             UI — treat enablement with execute-class gravity.",
            app.display_name
        ),
        Arc::new(actuate_schema()),
    )
    .with_annotations(
        ToolAnnotations::new()
            .read_only(false)
            .destructive(true)
            .idempotent(false)
            .open_world(false),
    );
    vec![observe, actuate]
}

// ---------------------------------------------------------------------------
// Window matching (pure; unit-tested)
// ---------------------------------------------------------------------------

/// Whether a window belongs to a registered app: any match string
/// equal (case-insensitive) to the window's WM_CLASS or instance,
/// or a case-insensitive substring of its title.
pub fn window_matches(app: &GuiApp, window: &WindowInfo) -> bool {
    app.window_match.iter().any(|matcher| {
        let matcher = matcher.to_lowercase();
        window.wm_class.to_lowercase() == matcher
            || window.instance.to_lowercase() == matcher
            || window.title.to_lowercase().contains(&matcher)
    })
}

/// Picks the actuation target from the matched windows: the
/// focused one if any, else the first in enumeration order.
pub fn pick_target<'a>(matched: &[&'a WindowInfo]) -> Option<&'a WindowInfo> {
    matched
        .iter()
        .find(|w| w.focused)
        .copied()
        .or_else(|| matched.first().copied())
}

// ---------------------------------------------------------------------------
// X11 backend
// ---------------------------------------------------------------------------

mod x11 {
    use super::*;
    use std::time::Duration;

    use x11rb::connection::Connection;
    use x11rb::protocol::Event;
    use x11rb::protocol::xproto::{
        AtomEnum, BUTTON_PRESS_EVENT, BUTTON_RELEASE_EVENT, ButtonPressEvent, ButtonReleaseEvent,
        CLIENT_MESSAGE_EVENT, ClientMessageData, ClientMessageEvent, ConnectionExt as _, EventMask,
        GetGeometryReply, ImageFormat, InputFocus, KEY_PRESS_EVENT, KEY_RELEASE_EVENT,
        KeyPressEvent, KeyReleaseEvent, MotionNotifyEvent, PropMode, Time,
    };
    use x11rb::protocol::xtest::ConnectionExt as _;
    use x11rb::rust_connection::RustConnection;

    type Conn = RustConnection;

    /// Keysym values (X11 protocol constants) for the named keys
    /// the `key`/`type` actions accept. ASCII printable keysyms
    /// are the codepoints themselves; the table covers the named
    /// specials. Keysym → keycode resolution runs through the
    /// server's live keyboard mapping, so layout stays the
    /// server's business, not Seahawk's.
    fn named_keysym(name: &str) -> Option<u32> {
        let keysym = match name {
            "space" => 0x0020,
            "tab" => 0xff09,
            "return" | "enter" => 0xff0d,
            "escape" | "esc" => 0xff1b,
            "backspace" => 0xff08,
            "delete" | "del" => 0xffff,
            "insert" => 0xff63,
            "home" => 0xff50,
            "end" => 0xff57,
            "pageup" | "page_up" => 0xff55,
            "pagedown" | "page_down" => 0xff56,
            "left" => 0xff51,
            "up" => 0xff52,
            "right" => 0xff53,
            "down" => 0xff54,
            "capslock" => 0xffe5,
            "f1" => 0xffbe,
            "f2" => 0xffbf,
            "f3" => 0xffc0,
            "f4" => 0xffc1,
            "f5" => 0xffc2,
            "f6" => 0xffc3,
            "f7" => 0xffc4,
            "f8" => 0xffc5,
            "f9" => 0xffc6,
            "f10" => 0xffc7,
            "f11" => 0xffc8,
            "f12" => 0xffc9,
            _ => {
                let mut chars = name.chars();
                match (chars.next(), chars.next()) {
                    (Some(c), None) if c.is_ascii_graphic() => c as u32,
                    _ => return None,
                }
            }
        };
        Some(keysym)
    }

    const KEYSYM_SHIFT_L: u32 = 0xffe1;
    const KEYSYM_CONTROL_L: u32 = 0xffe3;
    const KEYSYM_ALT_L: u32 = 0xffe9;
    const KEYSYM_SUPER_L: u32 = 0xffeb;

    pub struct X11Backend {
        /// Display name override; None = `$DISPLAY`.
        pub display: Option<String>,
    }

    struct Session {
        conn: Conn,
        root: u32,
    }

    impl X11Backend {
        fn connect(&self) -> GuiResult<Session> {
            let display = self
                .display
                .clone()
                .or_else(|| std::env::var("DISPLAY").ok())
                .filter(|d| !d.is_empty());
            let Some(display) = display else {
                return Err(GuiError::unavailable(
                    "no X11 display is configured (DISPLAY is unset): the GUI \
                     provider can only run where Seahawk itself has a display",
                ));
            };
            let (conn, screen_num) = RustConnection::connect(Some(&display)).map_err(|e| {
                GuiError::unavailable(format!("cannot connect to X11 display {display}: {e}"))
            })?;
            let root = conn.setup().roots[screen_num].root;
            Ok(Session { conn, root })
        }
    }

    impl Session {
        fn atom(&self, name: &str) -> GuiResult<u32> {
            self.conn
                .intern_atom(false, name.as_bytes())
                .map_err(|e| GuiError::failed(format!("intern_atom {name}: {e}")))?
                .reply()
                .map(|r| r.atom)
                .map_err(|e| GuiError::failed(format!("intern_atom {name} reply: {e}")))
        }

        fn property_string(&self, window: u32, property: u32, type_: u32) -> GuiResult<String> {
            let reply = self
                .conn
                .get_property(false, window, property, type_, 0, 1024)
                .map_err(|e| GuiError::failed(format!("get_property: {e}")))?
                .reply()
                .map_err(|e| GuiError::failed(format!("get_property reply: {e}")))?;
            Ok(String::from_utf8_lossy(&reply.value).into_owned())
        }

        /// All client windows (EWMH list), with class/title/
        /// geometry/focus filled in. Windows that vanish mid-walk
        /// are skipped, never fatal.
        fn windows(&self) -> GuiResult<Vec<WindowInfo>> {
            let client_list = self.atom("_NET_CLIENT_LIST")?;
            let reply = self
                .conn
                .get_property(
                    false,
                    self.root,
                    client_list,
                    u32::from(AtomEnum::WINDOW),
                    0,
                    u32::MAX,
                )
                .map_err(|e| GuiError::failed(format!("get _NET_CLIENT_LIST: {e}")))?
                .reply()
                .map_err(|e| GuiError::failed(format!("get _NET_CLIENT_LIST reply: {e}")))?;
            let ids: Vec<u32> = reply
                .value32()
                .map(|iter| iter.take(MAX_WINDOWS).collect())
                .unwrap_or_default();
            let focus = self
                .conn
                .get_input_focus()
                .ok()
                .and_then(|c| c.reply().ok())
                .map(|r| r.focus)
                .unwrap_or(0);
            let wm_name = self.atom("_NET_WM_NAME")?;
            let utf8 = self.atom("UTF8_STRING")?;
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                let Ok(geometry) = self
                    .conn
                    .get_geometry(id)
                    .map_err(|_| ())
                    .and_then(|c| c.reply().map_err(|_| ()))
                else {
                    continue;
                };
                let (origin_x, origin_y) = self
                    .conn
                    .translate_coordinates(id, self.root, 0, 0)
                    .ok()
                    .and_then(|c| c.reply().ok())
                    .map(|r| (i32::from(r.dst_x), i32::from(r.dst_y)))
                    .unwrap_or((i32::from(geometry.x), i32::from(geometry.y)));
                let class_raw = self
                    .property_string(
                        id,
                        u32::from(AtomEnum::WM_CLASS),
                        u32::from(AtomEnum::STRING),
                    )
                    .unwrap_or_default();
                let mut parts = class_raw.split('\0');
                let instance = parts.next().unwrap_or("").to_string();
                let wm_class = parts.next().unwrap_or("").to_string();
                let mut title = self.property_string(id, wm_name, utf8).unwrap_or_default();
                if title.is_empty() {
                    title = self
                        .property_string(
                            id,
                            u32::from(AtomEnum::WM_NAME),
                            u32::from(AtomEnum::STRING),
                        )
                        .unwrap_or_default();
                }
                out.push(WindowInfo {
                    id,
                    wm_class,
                    instance,
                    title: title.trim_matches('\0').to_string(),
                    x: origin_x,
                    y: origin_y,
                    width: u32::from(geometry.width),
                    height: u32::from(geometry.height),
                    focused: id == focus,
                    matched: false,
                });
            }
            Ok(out)
        }

        fn resolve(&self, app: &GuiApp) -> GuiResult<(Vec<WindowInfo>, WindowInfo)> {
            let all = self.windows()?;
            let mut windows: Vec<WindowInfo> = all
                .into_iter()
                .map(|mut w| {
                    w.matched = window_matches(app, &w);
                    w
                })
                .collect();
            let matched: Vec<&WindowInfo> = windows.iter().filter(|w| w.matched).collect();
            let Some(target) = pick_target(&matched) else {
                return Err(GuiError::new(
                    codes::GUI_NO_WINDOW,
                    format!(
                        "no window of {} ({}) is present on the display: match {:?}",
                        app.display_name, app.name, app.window_match
                    ),
                ));
            };
            let target = target.clone();
            windows.retain(|w| w.matched);
            Ok((windows, target))
        }

        /// Root-window crop over the target window's rectangle:
        /// what an operator sees of that window, occlusions and
        /// all. Bounds are checked against the frame budget before
        /// the (potentially large) GetImage reply is requested.
        fn screenshot(&self, window: &WindowInfo) -> GuiResult<Frame> {
            if u64::from(window.width) * u64::from(window.height) > MAX_FRAME_PIXELS {
                return Err(GuiError::failed(format!(
                    "window {}x{} exceeds the {MAX_FRAME_PIXELS}-pixel frame budget",
                    window.width, window.height
                )));
            }
            let reply = self
                .conn
                .get_image(
                    ImageFormat::Z_PIXMAP,
                    self.root,
                    window.x as i16,
                    window.y as i16,
                    u16::try_from(window.width).unwrap_or(u16::MAX),
                    u16::try_from(window.height).unwrap_or(u16::MAX),
                    u32::MAX,
                )
                .map_err(|e| GuiError::failed(format!("get_image: {e}")))?
                .reply()
                .map_err(|e| GuiError::failed(format!("get_image reply: {e}")))?;
            frame_from_zpixmap(&reply, window.width, window.height)
        }

        fn focus_window(&self, window: &WindowInfo) -> GuiResult<()> {
            let active = self.atom("_NET_ACTIVE_WINDOW")?;
            let message = ClientMessageEvent {
                response_type: CLIENT_MESSAGE_EVENT,
                format: 32,
                sequence: 0,
                window: window.id,
                type_: active,
                data: ClientMessageData::from([1u32, 0, 0, 0, 0]),
            };
            self.conn
                .send_event(
                    false,
                    self.root,
                    EventMask::SUBSTRUCTURE_REDIRECT | EventMask::SUBSTRUCTURE_NOTIFY,
                    message,
                )
                .map_err(|e| GuiError::failed(format!("send _NET_ACTIVE_WINDOW: {e}")))?;
            self.conn
                .set_input_focus(InputFocus::PARENT, window.id, Time::CURRENT_TIME)
                .map_err(|e| GuiError::failed(format!("set_input_focus: {e}")))?;
            self.conn
                .flush()
                .map_err(|e| GuiError::failed(format!("flush after focus: {e}")))?;
            Ok(())
        }

        fn warp(&self, root_x: i32, root_y: i32) -> GuiResult<()> {
            self.conn
                .warp_pointer(
                    x11rb::NONE,
                    self.root,
                    0,
                    0,
                    0,
                    0,
                    i16::try_from(root_x).unwrap_or(i16::MAX),
                    i16::try_from(root_y).unwrap_or(i16::MAX),
                )
                .map_err(|e| GuiError::failed(format!("warp_pointer: {e}")))?;
            Ok(())
        }

        fn fake_button(&self, press: bool, button: u8, root_x: i32, root_y: i32) -> GuiResult<()> {
            self.conn
                .xtest_fake_input(
                    if press {
                        BUTTON_PRESS_EVENT
                    } else {
                        BUTTON_RELEASE_EVENT
                    },
                    button,
                    0, // CURRENT_TIME
                    self.root,
                    i16::try_from(root_x).unwrap_or(i16::MAX),
                    i16::try_from(root_y).unwrap_or(i16::MAX),
                    0,
                )
                .map_err(|e| GuiError::failed(format!("fake_input button: {e}")))?;
            Ok(())
        }

        fn fake_key(&self, press: bool, keycode: u8) -> GuiResult<()> {
            self.conn
                .xtest_fake_input(
                    if press {
                        KEY_PRESS_EVENT
                    } else {
                        KEY_RELEASE_EVENT
                    },
                    keycode,
                    0, // CURRENT_TIME
                    self.root,
                    0,
                    0,
                    0,
                )
                .map_err(|e| GuiError::failed(format!("fake_input key: {e}")))?;
            Ok(())
        }

        /// The server's live keysym → (keycode, needs_shift) map,
        /// from its keyboard mapping (level 0 = plain, level 1 =
        /// shifted). First mapping wins, matching how the server
        /// itself resolves unshifted keys first.
        fn keymap(&self) -> GuiResult<std::collections::HashMap<u32, (u8, bool)>> {
            let setup = self.conn.setup();
            let first = setup.min_keycode;
            let count = setup.max_keycode - first + 1;
            let reply = self
                .conn
                .get_keyboard_mapping(first, count)
                .map_err(|e| GuiError::failed(format!("get_keyboard_mapping: {e}")))?
                .reply()
                .map_err(|e| GuiError::failed(format!("get_keyboard_mapping reply: {e}")))?;
            let per = usize::from(reply.keysyms_per_keycode.max(1));
            let mut map = std::collections::HashMap::new();
            for (index, chunk) in reply.keysyms.chunks(per).enumerate() {
                let keycode = first + u8::try_from(index).unwrap_or(u8::MAX);
                for (level, keysym) in chunk.iter().take(2).enumerate() {
                    if *keysym != 0 && !map.contains_key(keysym) {
                        map.insert(*keysym, (keycode, level == 1));
                    }
                }
            }
            Ok(map)
        }

        fn press_keysym(
            &self,
            keymap: &std::collections::HashMap<u32, (u8, bool)>,
            keysym: u32,
        ) -> GuiResult<bool> {
            let Some(&(keycode, shifted)) = keymap.get(&keysym) else {
                return Ok(false);
            };
            let shift_code = if shifted {
                keymap.get(&KEYSYM_SHIFT_L).map(|(code, _)| *code)
            } else {
                None
            };
            if let Some(shift) = shift_code {
                self.fake_key(true, shift)?;
            }
            self.fake_key(true, keycode)?;
            self.fake_key(false, keycode)?;
            if let Some(shift) = shift_code {
                self.fake_key(false, shift)?;
            }
            self.conn
                .flush()
                .map_err(|e| GuiError::failed(format!("flush after key: {e}")))?;
            Ok(true)
        }

        /// `ctrl+shift+s` style specs: modifiers first, one main
        /// key last. Unresolvable keys are an argument failure,
        /// reported before anything is pressed.
        fn send_key_spec(
            &self,
            keymap: &std::collections::HashMap<u32, (u8, bool)>,
            spec: &str,
        ) -> GuiResult<()> {
            let parts: Vec<&str> = spec.split('+').map(str::trim).collect();
            let (main, modifiers) = parts
                .split_last()
                .ok_or_else(|| GuiError::bad_arguments("empty key spec"))?;
            let main_keysym = named_keysym(&main.to_lowercase()).ok_or_else(|| {
                GuiError::bad_arguments(format!("unknown key name {main:?} in spec {spec:?}"))
            })?;
            let mut modifier_codes: Vec<u8> = Vec::new();
            for modifier in modifiers {
                let keysym = match modifier.to_lowercase().as_str() {
                    "ctrl" | "control" => KEYSYM_CONTROL_L,
                    "shift" => KEYSYM_SHIFT_L,
                    "alt" | "mod1" => KEYSYM_ALT_L,
                    "super" | "win" | "cmd" | "meta" => KEYSYM_SUPER_L,
                    other => {
                        return Err(GuiError::bad_arguments(format!(
                            "unknown modifier {other:?} in key spec {spec:?}"
                        )));
                    }
                };
                let code = keymap.get(&keysym).map(|(code, _)| *code).ok_or_else(|| {
                    GuiError::failed(format!("modifier {modifier} is unmapped on this server"))
                })?;
                modifier_codes.push(code);
            }
            if !keymap.contains_key(&main_keysym) {
                return Err(GuiError::failed(format!(
                    "key {main:?} is unmapped on this server's keyboard layout"
                )));
            }
            for code in &modifier_codes {
                self.fake_key(true, *code)?;
            }
            let pressed = self.press_keysym(keymap, main_keysym)?;
            for code in modifier_codes.iter().rev() {
                self.fake_key(false, *code)?;
            }
            self.conn
                .flush()
                .map_err(|e| GuiError::failed(format!("flush after key spec: {e}")))?;
            if !pressed {
                return Err(GuiError::failed(format!(
                    "key {main:?} could not be pressed on this server"
                )));
            }
            Ok(())
        }

        fn check_points(&self, window: &WindowInfo, action: &ActuateAction) -> GuiResult<()> {
            for (x, y) in action.points() {
                if x < 0 || y < 0 || x >= window.width as i32 || y >= window.height as i32 {
                    return Err(GuiError::bad_arguments(format!(
                        "point {x},{y} is outside {}'s window ({}x{}): actuation is \
                         confined to the registered window",
                        window.title, window.width, window.height
                    )));
                }
            }
            Ok(())
        }

        fn perform(&self, window: &WindowInfo, action: &ActuateAction) -> GuiResult<Value> {
            let root_point = |x: i32, y: i32| (window.x + x, window.y + y);
            match action {
                ActuateAction::Focus => Ok(json!({"focused_window": window.id})),
                ActuateAction::Click { x, y, button } => {
                    let (rx, ry) = root_point(*x, *y);
                    self.warp(rx, ry)?;
                    self.fake_button(true, *button, rx, ry)?;
                    self.fake_button(false, *button, rx, ry)?;
                    self.conn
                        .flush()
                        .map_err(|e| GuiError::failed(format!("flush after click: {e}")))?;
                    Ok(json!({"clicked": [x, y], "button": button}))
                }
                ActuateAction::DoubleClick { x, y } => {
                    let (rx, ry) = root_point(*x, *y);
                    self.warp(rx, ry)?;
                    for _ in 0..2 {
                        self.fake_button(true, 1, rx, ry)?;
                        self.fake_button(false, 1, rx, ry)?;
                    }
                    self.conn
                        .flush()
                        .map_err(|e| GuiError::failed(format!("flush after double_click: {e}")))?;
                    Ok(json!({"double_clicked": [x, y]}))
                }
                ActuateAction::Key { spec } => {
                    let keymap = self.keymap()?;
                    self.send_key_spec(&keymap, spec)?;
                    Ok(json!({"key": spec}))
                }
                ActuateAction::Type { text } => {
                    let keymap = self.keymap()?;
                    let mut typed = 0usize;
                    let mut skipped = 0usize;
                    for ch in text.chars() {
                        let keysym = match ch {
                            '\n' => 0xff0d,
                            '\t' => 0xff09,
                            c if c.is_ascii_graphic() || c == ' ' => c as u32,
                            _ => {
                                skipped += 1;
                                continue;
                            }
                        };
                        if self.press_keysym(&keymap, keysym)? {
                            typed += 1;
                        } else {
                            skipped += 1;
                        }
                    }
                    Ok(json!({"typed_chars": typed, "skipped_chars": skipped}))
                }
                ActuateAction::Scroll { x, y, dx, dy } => {
                    let (rx, ry) = root_point(*x, *y);
                    self.warp(rx, ry)?;
                    let mut steps = 0i32;
                    let mut roll = |button: u8, count: i32| -> GuiResult<()> {
                        for _ in 0..count {
                            self.fake_button(true, button, rx, ry)?;
                            self.fake_button(false, button, rx, ry)?;
                            steps += 1;
                        }
                        Ok(())
                    };
                    // X11 convention: 4/5 = vertical down/up,
                    // 6/7 = horizontal right/left. Steps bounded by
                    // the coordinate bound on dx/dy; clamp hard.
                    let dy = (*dy).clamp(-100, 100);
                    let dx = (*dx).clamp(-100, 100);
                    if dy > 0 {
                        roll(5, dy)?;
                    } else if dy < 0 {
                        roll(4, -dy)?;
                    }
                    if dx > 0 {
                        roll(7, dx)?;
                    } else if dx < 0 {
                        roll(6, -dx)?;
                    }
                    self.conn
                        .flush()
                        .map_err(|e| GuiError::failed(format!("flush after scroll: {e}")))?;
                    Ok(json!({"scrolled": [x, y], "steps": steps}))
                }
                ActuateAction::Drag {
                    from_x,
                    from_y,
                    to_x,
                    to_y,
                } => {
                    let (fx, fy) = root_point(*from_x, *from_y);
                    let (tx, ty) = root_point(*to_x, *to_y);
                    self.warp(fx, fy)?;
                    self.fake_button(true, 1, fx, fy)?;
                    // A few interpolated steps so applications
                    // that track motion see a drag, not a teleport.
                    for step in 1..=4 {
                        let mx = fx + (tx - fx) * step / 4;
                        let my = fy + (ty - fy) * step / 4;
                        self.warp(mx, my)?;
                    }
                    self.fake_button(false, 1, tx, ty)?;
                    self.conn
                        .flush()
                        .map_err(|e| GuiError::failed(format!("flush after drag: {e}")))?;
                    Ok(json!({"dragged": [[from_x, from_y], [to_x, to_y]]}))
                }
            }
        }
    }

    impl GuiBackend for X11Backend {
        fn observe(&self, app: &GuiApp, kind: ObserveKind) -> GuiResult<ObserveOutcome> {
            let session = self.connect()?;
            match kind {
                ObserveKind::Windows => {
                    let (windows, _) = session.resolve(app)?;
                    Ok(ObserveOutcome {
                        frame: None,
                        target: None,
                        payload: json!({
                            "app": app.name,
                            "windows": windows,
                        }),
                    })
                }
                ObserveKind::State => {
                    let all = session.windows()?;
                    let focused = all.iter().find(|w| w.focused);
                    let focused_id = focused.map(|w| w.id);
                    let focused_is_app = focused.map(|w| window_matches(app, w)).unwrap_or(false);
                    Ok(ObserveOutcome {
                        frame: None,
                        target: None,
                        payload: json!({
                            "app": app.name,
                            "focused_window": focused_id,
                            "focused_title": focused.map(|w| w.title.clone()),
                            "focused_is_app": focused_is_app,
                            "app_windows": all.iter().filter(|w| window_matches(app, w)).count(),
                        }),
                    })
                }
                ObserveKind::Screenshot => {
                    let (_, target) = session.resolve(app)?;
                    let frame = session.screenshot(&target)?;
                    let payload = json!({
                        "app": app.name,
                        "window": target.id,
                        "title": target.title,
                        "width": frame.width,
                        "height": frame.height,
                        "sha256": frame.digest(),
                    });
                    Ok(ObserveOutcome {
                        target: Some(format!("window {} {:?}", target.id, target.title)),
                        payload,
                        frame: Some(frame),
                    })
                }
            }
        }

        fn actuate(&self, app: &GuiApp, action: &ActuateAction) -> GuiResult<ActuateOutcome> {
            let session = self.connect()?;
            let (_, target) = session.resolve(app)?;
            session.check_points(&target, action)?;
            // Bracket first: an actuation that cannot be bracketed
            // does not happen — the op log is the non-idempotency
            // record and it must hold both sides of the action.
            let pre = session.screenshot(&target)?;
            session.focus_window(&target)?;
            let detail = session.perform(&target, action)?;
            std::thread::sleep(Duration::from_millis(ACTUATION_SETTLE_MS));
            let post = session.screenshot(&target).ok();
            Ok(ActuateOutcome {
                pre,
                post,
                target: format!(
                    "{} window {} {:?}",
                    action.describe(),
                    target.id,
                    truncate_title(&target.title)
                ),
                detail,
            })
        }
    }

    fn truncate_title(title: &str) -> String {
        const MAX_TITLE_CHARS: usize = 80;
        if title.chars().count() <= MAX_TITLE_CHARS {
            title.to_string()
        } else {
            format!(
                "{}…",
                title.chars().take(MAX_TITLE_CHARS).collect::<String>()
            )
        }
    }

    /// Converts a ZPixmap GetImage reply (depth 24 or 32, BGRA
    /// byte order on little-endian servers) into an RGB8 PNG.
    fn frame_from_zpixmap(
        reply: &x11rb::protocol::xproto::GetImageReply,
        width: u32,
        height: u32,
    ) -> GuiResult<Frame> {
        if reply.depth != 24 && reply.depth != 32 {
            return Err(GuiError::failed(format!(
                "unsupported root window depth {} (need 24 or 32)",
                reply.depth
            )));
        }
        let (w, h) = (width as usize, height as usize);
        let expected = w
            .checked_mul(h)
            .and_then(|px| px.checked_mul(4))
            .ok_or_else(|| GuiError::failed("frame size overflow".to_string()))?;
        if reply.data.len() < expected {
            return Err(GuiError::failed(format!(
                "get_image returned {} bytes, expected at least {expected}",
                reply.data.len()
            )));
        }
        let mut rgb = Vec::with_capacity(w * h * 3);
        for pixel in reply.data[..expected].as_chunks::<4>().0 {
            // ZPixmap depth-24/32 pixels are B, G, R, (pad) in
            // memory order on the (little-endian) servers Seahawk
            // runs against.
            rgb.push(pixel[2]);
            rgb.push(pixel[1]);
            rgb.push(pixel[0]);
        }
        let mut png = Vec::new();
        {
            let mut encoder = png::Encoder::new(&mut png, width, height);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer = encoder
                .write_header()
                .map_err(|e| GuiError::failed(format!("png header: {e}")))?;
            writer
                .write_image_data(&rgb)
                .map_err(|e| GuiError::failed(format!("png data: {e}")))?;
        }
        Ok(Frame { png, width, height })
    }

    // Keep protocol event types referenced: fake_input is the
    // XTest path, but the event structs document the shapes the
    // server synthesizes; silence unused-import drift across
    // x11rb feature sets.
    #[allow(dead_code)]
    type _EventDoc = (
        Event,
        ButtonPressEvent,
        ButtonReleaseEvent,
        KeyPressEvent,
        KeyReleaseEvent,
        MotionNotifyEvent,
        GetGeometryReply,
        PropMode,
    );
}

use x11::X11Backend;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn observe_vocabulary_is_closed() {
        assert_eq!(parse_observe(&json!({})).unwrap(), ObserveKind::Screenshot);
        assert_eq!(
            parse_observe(&json!({"action": "windows"})).unwrap(),
            ObserveKind::Windows
        );
        match parse_observe(&json!({"action": "run_command"})) {
            Err(e) => assert_eq!(e.code, codes::GUI_UNKNOWN_ACTION),
            Ok(kind) => panic!("unknown observe action accepted: {kind:?}"),
        }
    }

    #[test]
    fn actuate_vocabulary_refuses_execute_shaped_actions() {
        // The S4.3 seam: an execute attempt through an actuate
        // registration dies in the parser, before any backend.
        for action in ["run_command", "execute", "shell", "type_text", "screenshot"] {
            match parse_actuate(&json!({"action": action, "text": "id", "x": 1, "y": 1})) {
                Err(e) => assert_eq!(e.code, codes::GUI_UNKNOWN_ACTION, "{action}"),
                Ok(parsed) => panic!("action {action} accepted as {parsed:?}"),
            }
        }
    }

    #[test]
    fn actuate_arguments_are_validated_and_bounded() {
        match parse_actuate(&json!({"action": "click", "x": -5, "y": 10})) {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(a) => panic!("negative coordinate accepted: {a:?}"),
        }
        match parse_actuate(&json!({"action": "click", "x": 10})) {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(a) => panic!("missing y accepted: {a:?}"),
        }
        let long = "x".repeat(MAX_TYPE_TEXT_CHARS + 1);
        match parse_actuate(&json!({"action": "type", "text": long})) {
            Err(e) => assert_eq!(e.code, codes::BAD_ARGUMENTS),
            Ok(a) => panic!("over-long type text accepted: {a:?}"),
        }
        let ok = parse_actuate(&json!({"action": "key", "keys": "ctrl+s"})).unwrap();
        assert_eq!(
            ok,
            ActuateAction::Key {
                spec: "ctrl+s".to_string()
            }
        );
        let click = parse_actuate(&json!({"action": "click", "x": 3, "y": 4})).unwrap();
        assert_eq!(
            click,
            ActuateAction::Click {
                x: 3,
                y: 4,
                button: 1
            }
        );
    }

    #[test]
    fn window_matching_uses_class_instance_and_title() {
        let app = GuiApp {
            name: "comfyui".to_string(),
            display_name: "ComfyUI".to_string(),
            window_match: vec!["ComfyUI".to_string()],
        };
        let browser = WindowInfo {
            id: 7,
            wm_class: "Chromium".to_string(),
            instance: "chromium".to_string(),
            title: "*Unsaved Workflow - ComfyUI".to_string(),
            x: 0,
            y: 0,
            width: 800,
            height: 600,
            focused: true,
            matched: false,
        };
        assert!(window_matches(&app, &browser), "title substring must match");
        let other = WindowInfo {
            title: "Terminal".to_string(),
            ..browser.clone()
        };
        assert!(!window_matches(&app, &other));
        let blender_app = GuiApp {
            name: "blender".to_string(),
            display_name: "Blender".to_string(),
            window_match: vec!["Blender".to_string()],
        };
        let blender = WindowInfo {
            wm_class: "Blender".to_string(),
            title: String::new(),
            ..browser
        };
        assert!(
            window_matches(&blender_app, &blender),
            "class equality must match"
        );
    }

    struct FakeBackend {
        actuated: Mutex<Vec<ActuateAction>>,
    }

    impl GuiBackend for FakeBackend {
        fn observe(&self, app: &GuiApp, kind: ObserveKind) -> GuiResult<ObserveOutcome> {
            Ok(ObserveOutcome {
                frame: None,
                target: None,
                payload: json!({"app": app.name, "kind": format!("{kind:?}")}),
            })
        }

        fn actuate(&self, app: &GuiApp, action: &ActuateAction) -> GuiResult<ActuateOutcome> {
            self.actuated
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(action.clone());
            let frame = Frame {
                png: vec![1, 2, 3],
                width: 2,
                height: 2,
            };
            Ok(ActuateOutcome {
                target: format!("{} window 1", action.describe()),
                detail: json!({"app": app.name}),
                pre: frame.clone(),
                post: Some(frame),
            })
        }
    }

    #[test]
    fn gui_facade_parses_then_drives_backend() {
        let app = GuiApp {
            name: "blender".to_string(),
            display_name: "Blender".to_string(),
            window_match: vec!["Blender".to_string()],
        };
        let gui = Gui::with_backend(Box::new(FakeBackend {
            actuated: Mutex::new(Vec::new()),
        }));
        let outcome = gui
            .actuate(&app, &json!({"action": "click", "x": 10, "y": 20}))
            .expect("actuate");
        assert_eq!(outcome.pre.digest().len(), 64);
        assert!(outcome.target.contains("click 10,20"));
        // Unknown actions never reach the backend.
        match gui.actuate(&app, &json!({"action": "run_command", "x": 1, "y": 1})) {
            Err(e) => assert_eq!(e.code, codes::GUI_UNKNOWN_ACTION),
            Ok(_) => panic!("unknown action reached the backend"),
        }
    }

    #[test]
    fn x11_backend_without_a_display_fails_closed() {
        let backend = X11Backend {
            display: Some("seahawk-no-such-display:99".to_string()),
        };
        let app = GuiApp {
            name: "blender".to_string(),
            display_name: "Blender".to_string(),
            window_match: vec!["Blender".to_string()],
        };
        match backend.observe(&app, ObserveKind::Windows) {
            Err(e) => assert_eq!(e.code, codes::GUI_UNAVAILABLE),
            Ok(_) => panic!("observe against a dead display must fail closed"),
        }
    }
}
