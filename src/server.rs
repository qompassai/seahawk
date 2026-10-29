//! The rmcp agent-facing surface (protocol 2026-07-28 era only).
//!
//! Tools = three broker-native tools (`seahawk_status`,
//! `seahawk_surface`, `seahawk_oplog`) plus the brokered Unreal
//! tools from the downstream surface snapshot: classified read and
//! write tools, and execute-class tools listed with destructive
//! annotations but refused by default (policy::decide). Domain
//! refusals are typed `is_error` results with a structured
//! `{"error": {"code", "message"}}` body, fleet mold; argument shape
//! failures answer -32602. Synchronous downstream work runs on
//! `spawn_blocking`.

use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    InitializeResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    Tool, ToolAnnotations,
};
use rmcp::{ErrorData as McpError, RoleServer};
use serde_json::{Map, Value, json};

use crate::config::{Config, ToolingId, VisionRoute};
use crate::downstream::Downstream;
use crate::gui::WindowInfo;
use crate::gui::{ActuateOutcome, Capture, Frame, Gui, GuiError, ObserveOutcome};
use crate::model::{GuiApp, Surface, ToolClass, ToolRecord};
use crate::oplog::{LogExtra, OpLog};
use crate::policy::{self, Decision, ToolKnowledge, codes, token_matches};
use crate::tooling::{self, CheckKind, Route, ToolingPool};
use crate::vision::{
    self, CheckOutcome, Expectation, FrameStore, GroundHit, Grounder, OllamaGrounder, RawGrounding,
    StoredFrame,
};

pub const META_OPERATOR_TOKEN: &str = "seahawk/operator_token";

const NATIVE_STATUS: &str = "seahawk_status";
const NATIVE_SURFACE: &str = "seahawk_surface";
const NATIVE_OPLOG: &str = "seahawk_oplog";

/// S5 broker-level vision tools (the `gui.` namespace, but not
/// per-app: the app is an argument, validated against the same
/// policy registrations).
const VISION_OBSERVE: &str = "gui.observe";
const VISION_GROUND: &str = "gui.ground";
const VISION_ACT_VERIFIED: &str = "gui.act_verified";

/// D-230 wiring: the one new broker tool. Read-class; the
/// tooling client behind it is in the `tooling` module.
const CODE_FEEDBACK: &str = "code.feedback";

/// One `code.feedback` episode (SPEC §3.2): calls sharing a
/// (workspace, file-set) key inside the configured window.
/// The bound exists so a fix-and-recheck loop cannot grind
/// through the broker; the 4th call is refused with the last
/// result's counts and the episode closes.
struct FeedbackEpisode {
    window_start: Instant,
    count: usize,
    last_dirty: bool,
    last_counts: String,
}

/// Mutable wiring state: feedback episodes + the periscope
/// catalog snapshot (SPEC §3.2 / §1.4 — the snapshot is taken
/// once per broker run, refreshed only at restart, and its
/// provenance id rides in feedback results and the op log).
#[derive(Default)]
struct FeedbackState {
    episodes: std::collections::HashMap<String, FeedbackEpisode>,
    catalog: Option<(String, Value)>,
}

/// S5 vision state: the bounded frame store frames are referenced
/// by, and the configured local grounder (None unless policy
/// selects the ollama route).
struct VisionState {
    frames: Mutex<FrameStore>,
    grounder: Option<Arc<GrounderClient>>,
}

impl VisionState {
    fn lock_frames(&self) -> std::sync::MutexGuard<'_, FrameStore> {
        self.frames.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn has_local_grounder(&self) -> bool {
        self.grounder.is_some()
    }

    fn grounder_ready(&self) -> bool {
        self.grounder
            .as_ref()
            .is_some_and(|client| client.ready.load(std::sync::atomic::Ordering::Relaxed))
    }
}

/// One request to the grounder worker thread.
enum GrounderCommand {
    Ground {
        frame: Frame,
        target: String,
        reply: std::sync::mpsc::Sender<Result<RawGrounding, GuiError>>,
    },
    Present {
        frame: Frame,
        text: String,
        reply: std::sync::mpsc::Sender<Result<bool, GuiError>>,
    },
}

/// The handle handlers use to reach the local grounder. The
/// blocking HTTP client lives on a dedicated worker thread —
/// the downstream client's pattern (downstream.rs): a
/// reqwest::blocking client must never be built, used, or
/// dropped inside the tokio runtime (its internal runtime
/// panics on drop in an async context), so the broker sends
/// grounding requests over a channel and the worker answers.
/// Calls block the calling (blocking-pool) thread until the
/// worker replies; the HTTP timeout bounds the wait.
struct GrounderClient {
    commands: std::sync::mpsc::Sender<GrounderCommand>,
    ready: Arc<std::sync::atomic::AtomicBool>,
}

impl GrounderClient {
    fn call<T>(
        &self,
        command: impl FnOnce(std::sync::mpsc::Sender<Result<T, GuiError>>) -> GrounderCommand,
    ) -> Result<T, GuiError> {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        self.commands.send(command(reply_tx)).map_err(|_| {
            GuiError::new(
                codes::GUI_GROUNDER_UNAVAILABLE,
                "the local vision grounder worker is not running (its client \
                 failed to build or the worker exited)",
            )
        })?;
        reply_rx.recv().map_err(|_| {
            GuiError::new(
                codes::GUI_GROUNDER_UNAVAILABLE,
                "the local vision grounder worker exited without answering",
            )
        })?
    }
}

impl Grounder for GrounderClient {
    fn route_name(&self) -> &'static str {
        "ollama"
    }

    fn ground(&self, frame: &Frame, target: &str) -> Result<RawGrounding, GuiError> {
        let frame = frame.clone();
        let target = target.to_string();
        self.call(|reply| GrounderCommand::Ground {
            frame,
            target,
            reply,
        })
    }

    fn text_present(&self, frame: &Frame, text: &str) -> Result<bool, GuiError> {
        let frame = frame.clone();
        let text = text.to_string();
        self.call(|reply| GrounderCommand::Present { frame, text, reply })
    }
}

/// Spawns the grounder worker thread for the ollama route. The
/// thread owns the OllamaGrounder for its whole life; a client
/// build failure is reported on stderr, leaves `ready` false,
/// and makes every call answer grounder-unavailable.
fn spawn_grounder_worker(url: &str, model: &str, timeout_secs: u64) -> GrounderClient {
    let (tx, rx) = std::sync::mpsc::channel::<GrounderCommand>();
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_ready = ready.clone();
    let (url, model) = (url.to_string(), model.to_string());
    let spawned = std::thread::Builder::new()
        .name("seahawk-grounder".to_string())
        .spawn(move || {
            let grounder = match OllamaGrounder::new(&url, &model, timeout_secs) {
                Ok(grounder) => grounder,
                Err(error) => {
                    eprintln!("seahawk: local vision grounder unavailable: {error}");
                    return;
                }
            };
            worker_ready.store(true, std::sync::atomic::Ordering::Relaxed);
            while let Ok(command) = rx.recv() {
                match command {
                    GrounderCommand::Ground {
                        frame,
                        target,
                        reply,
                    } => {
                        let _ = reply.send(grounder.ground(&frame, &target));
                    }
                    GrounderCommand::Present { frame, text, reply } => {
                        let _ = reply.send(grounder.text_present(&frame, &text));
                    }
                }
            }
        });
    if let Err(error) = spawned {
        eprintln!("seahawk: cannot spawn the grounder worker thread: {error}");
    }
    GrounderClient {
        commands: tx,
        ready,
    }
}

#[derive(Clone)]
pub struct SeahawkServer {
    config: Arc<Config>,
    downstream: Arc<Downstream>,
    oplog: Arc<OpLog>,
    gui: Arc<Gui>,
    vision: Arc<VisionState>,
    /// Lowercased GUI tool name → (registered app, is_actuate).
    /// Built once from policy at startup; registrations cannot
    /// change under a running server.
    gui_targets: Arc<std::collections::HashMap<String, (GuiApp, bool)>>,
    /// D-230 wiring: the tooling clients (worker-thread owned).
    tooling: Arc<ToolingPool>,
    /// D-230 wiring: feedback episodes + catalog snapshot.
    feedback_state: Arc<Mutex<FeedbackState>>,
}

impl SeahawkServer {
    pub fn new(config: Arc<Config>, downstream: Arc<Downstream>, oplog: Arc<OpLog>) -> Self {
        let mut gui_targets = std::collections::HashMap::new();
        for app in &config.gui_apps {
            gui_targets.insert(app.observe_tool(), (app.clone(), false));
            gui_targets.insert(app.actuate_tool(), (app.clone(), true));
        }
        let grounder = match config.vision.route {
            VisionRoute::Ollama => Some(Arc::new(spawn_grounder_worker(
                &config.vision.ollama_url,
                &config.vision.ollama_model,
                config.vision.timeout_secs,
            ))),
            VisionRoute::Agent | VisionRoute::None => None,
        };
        let tooling = Arc::new(ToolingPool::from_config(&config.tooling));
        Self {
            config,
            downstream,
            oplog,
            gui: Arc::new(Gui::x11()),
            vision: Arc::new(VisionState {
                frames: Mutex::new(FrameStore::new()),
                grounder,
            }),
            gui_targets: Arc::new(gui_targets),
            tooling,
            feedback_state: Arc::new(Mutex::new(FeedbackState::default())),
        }
    }

    fn native_tools() -> Vec<Tool> {
        let mut surface_props = Map::new();
        surface_props.insert(
            "refresh".to_string(),
            json!({"type": "boolean", "description": "Drop the cached downstream session and rebuild the surface snapshot (toolsets can register late)."}),
        );
        let mut surface_schema = Map::new();
        surface_schema.insert("type".to_string(), json!("object"));
        surface_schema.insert("properties".to_string(), Value::Object(surface_props));
        let mut oplog_props = Map::new();
        oplog_props.insert(
            "limit".to_string(),
            json!({"type": "integer", "description": "How many recent op-log entries to return (default 50, max 500)."}),
        );
        let mut oplog_schema = Map::new();
        oplog_schema.insert("type".to_string(), json!("object"));
        oplog_schema.insert("properties".to_string(), Value::Object(oplog_props));
        let annotations = ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false);
        let mut status_schema = Map::new();
        status_schema.insert("type".to_string(), json!("object"));
        status_schema.insert("properties".to_string(), Value::Object(Map::new()));
        vec![
            Tool::new(
                NATIVE_STATUS,
                "Seahawk broker status: downstream reachability, surface counts, execute policy, op-log health. Does not connect downstream.",
                Arc::new(status_schema),
            )
            .with_annotations(annotations.clone()),
            Tool::new(
                NATIVE_SURFACE,
                "The brokered tool surface: every downstream tool Seahawk exposes, with its class, plus withheld unclassified tools and skipped toolsets. Connects downstream if needed.",
                Arc::new(surface_schema),
            )
            .with_annotations(annotations.clone()),
            Tool::new(
                NATIVE_OPLOG,
                "Recent op-log entries (tool, class, args digest, outcome, latency). Digests only — raw argument values are never logged.",
                Arc::new(oplog_schema),
            )
            .with_annotations(annotations),
        ]
    }

    /// The three S5 vision tools. Contracts are written for a
    /// caller that never reads this source (the D-207 loop is the
    /// first consumer): each description states its inputs, its
    /// outputs, and its refusal behaviour.
    fn vision_tools() -> Vec<Tool> {
        let read_annotations = ToolAnnotations::new()
            .read_only(true)
            .destructive(false)
            .idempotent(true)
            .open_world(false);
        let mut observe_props = Map::new();
        observe_props.insert(
            "app".to_string(),
            json!({"type": "string", "description": "Registered GUI application name (see seahawk_status gui_apps, e.g. \"blender\"). Unregistered names are refused with seahawk_unknown_tool."}),
        );
        let mut observe_schema = Map::new();
        observe_schema.insert("type".to_string(), json!("object"));
        observe_schema.insert("properties".to_string(), Value::Object(observe_props));
        observe_schema.insert("required".to_string(), json!(["app"]));

        let mut ground_props = Map::new();
        ground_props.insert(
            "frame_sha256".to_string(),
            json!({"type": "string", "description": "Digest of a frame returned by gui.observe (or gui.act_verified). The broker grounds against exactly those pixels; unknown or evicted digests are refused with seahawk_gui_no_frame."}),
        );
        ground_props.insert(
            "target".to_string(),
            json!({"type": "string", "description": "Natural-language description of the UI element to locate, e.g. \"the Queue button\" or \"the render engine selector\"."}),
        );
        ground_props.insert(
            "route".to_string(),
            json!({"type": "string", "enum": ["local", "agent"], "description": "Grounding route. local: the broker's configured local vision model answers. agent: you answer — the first call returns status awaiting_agent_answer with the frame as an image; call again with the same frame_sha256 and target plus agent_answer. Default: the broker's configured route."}),
        );
        ground_props.insert(
            "agent_answer".to_string(),
            json!({"type": "object", "description": "Your grounding answer for the agent route: the element's center in WINDOW-RELATIVE pixels of the referenced frame, plus your confidence. Optional bbox {x_min, y_min, x_max, y_max} (window-relative pixels): when given, the broker acts on the bbox centre.", "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}, "confidence": {"type": "number"}, "bbox": {"type": "object", "properties": {"x_min": {"type": "integer"}, "y_min": {"type": "integer"}, "x_max": {"type": "integer"}, "y_max": {"type": "integer"}}, "required": ["x_min", "y_min", "x_max", "y_max"]}}, "required": ["x", "y", "confidence"]}),
        );
        let mut ground_schema = Map::new();
        ground_schema.insert("type".to_string(), json!("object"));
        ground_schema.insert("properties".to_string(), Value::Object(ground_props));
        ground_schema.insert("required".to_string(), json!(["frame_sha256", "target"]));

        let mut act_props = Map::new();
        act_props.insert(
            "app".to_string(),
            json!({"type": "string", "description": "Registered GUI application name (see seahawk_status gui_apps). Unregistered names are refused with seahawk_unknown_tool."}),
        );
        act_props.insert(
            "action".to_string(),
            json!({"type": "string", "enum": ["focus", "click", "double_click", "key", "type", "scroll", "drag"], "description": "The input action — the same closed vocabulary as gui.<app>.actuate. There is no run/execute action."}),
        );
        act_props.insert(
            "target".to_string(),
            json!({"type": "string", "description": "Natural-language description of the element to act on. The broker grounds it on a fresh capture before each attempt. Mutually exclusive with raw x/y targeting (drag requires raw coordinates)."}),
        );
        act_props.insert(
            "x".to_string(),
            json!({"type": "integer", "description": "Raw targeting: window-relative x for click / double_click / scroll."}),
        );
        act_props.insert(
            "y".to_string(),
            json!({"type": "integer", "description": "Raw targeting: window-relative y for click / double_click / scroll."}),
        );
        act_props.insert(
            "button".to_string(),
            json!({"type": "integer", "enum": [1, 2, 3], "description": "Mouse button for click (default 1)."}),
        );
        act_props.insert(
            "keys".to_string(),
            json!({"type": "string", "description": "For key: a key spec like \"Return\", \"Escape\", \"ctrl+s\"."}),
        );
        act_props.insert(
            "text".to_string(),
            json!({"type": "string", "description": "For type: the text to enter (max 512 chars). Verify it with expect.text_visible or a title check where the UI allows readback."}),
        );
        act_props.insert(
            "dx".to_string(),
            json!({"type": "integer", "description": "For scroll: horizontal steps (default 0)."}),
        );
        act_props.insert(
            "dy".to_string(),
            json!({"type": "integer", "description": "For scroll: vertical steps (default 0; positive scrolls down)."}),
        );
        for field in ["from_x", "from_y", "to_x", "to_y"] {
            act_props.insert(
                field.to_string(),
                json!({"type": "integer", "description": "For drag: window-relative endpoints (raw targeting only)."}),
            );
        }
        act_props.insert(
            "route".to_string(),
            json!({"type": "string", "enum": ["local", "agent"], "description": "Grounding route when target is used. With route agent and no agent_answer, the call returns a grounding ticket (status awaiting_agent_answer, no action taken); re-call with agent_answer added."}),
        );
        act_props.insert(
            "agent_answer".to_string(),
            json!({"type": "object", "description": "Your grounding answer for the agent route: the element's center in window-relative pixels, plus confidence. Optional bbox {x_min, y_min, x_max, y_max} (window-relative pixels): when given, the broker acts on the bbox centre.", "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}, "confidence": {"type": "number"}, "bbox": {"type": "object", "properties": {"x_min": {"type": "integer"}, "y_min": {"type": "integer"}, "x_max": {"type": "integer"}, "y_max": {"type": "integer"}}, "required": ["x_min", "y_min", "x_max", "y_max"]}}, "required": ["x", "y", "confidence"]}),
        );
        act_props.insert(
            "window_id".to_string(),
            json!({"type": "integer", "description": "Optional window-identity pin (C4): an X window id from a prior gui.observe result. When given, the broker refuses with seahawk_gui_window_mismatch if the window that resolves at act time is a different one — never a silent re-match by title."}),
        );
        act_props.insert(
            "expect".to_string(),
            json!({"type": "object", "description": "The expected effect, verified against a FRESH capture after acting. At least one machine check is required: changed (frame region around the point changed), title_contains (window title contains text), focused (app window holds focus), text_visible (text visibly present, needs the local grounder). description is free text for humans and the op log.", "properties": {"changed": {"type": "boolean"}, "changed_around": {"type": "object", "description": "Anchor the changed diff on this window-relative point (for effects that appear away from the action point, e.g. menus).", "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}}, "required": ["x", "y"]}, "full_frame": {"type": "boolean", "description": "Diff the whole frame for the changed check instead of a region around the point."}, "title_contains": {"type": "string"}, "focused": {"type": "boolean"}, "text_visible": {"type": "string"}, "description": {"type": "string"}}}),
        );
        let mut act_schema = Map::new();
        act_schema.insert("type".to_string(), json!("object"));
        act_schema.insert("properties".to_string(), Value::Object(act_props));
        act_schema.insert("required".to_string(), json!(["app", "action", "expect"]));

        vec![
            Tool::new(
                VISION_OBSERVE,
                "Observe a registered GUI application WITH display geometry (read-class): \
                 screenshot of the app's window, its rectangle, and the display geometry \
                 (root resolution, scale factor, virtual-vs-live flag). The frame is \
                 stored by the broker and referenced by frame_sha256 in the result — \
                 pass that digest to gui.ground so coordinates stay tied to the exact \
                 pixels they were read from.",
                Arc::new(observe_schema),
            )
            .with_annotations(read_annotations.clone()),
            Tool::new(
                VISION_GROUND,
                "Ground a natural-language target to coordinates in a frame from \
                 gui.observe (read-class). Returns window-relative x/y, \
                 display-absolute coordinates, the grounder's confidence, and an \
                 evidence crop image around the point. Routes: local (the broker's \
                 configured vision model) or agent (you answer the broker's ticket \
                 with agent_answer). Grounding is perception only — it grants no \
                 permission to act; a point below the confidence floor is refused \
                 with seahawk_gui_ground_failed rather than returned.",
                Arc::new(ground_schema),
            )
            .with_annotations(read_annotations),
            Tool::new(
                VISION_ACT_VERIFIED,
                "[actuate-class: default-deny — requires policy enablement of \
                 gui.<app>.actuate and a per-call operator token] Act on a GUI target \
                 and VERIFY the effect. Target by description (grounded on a fresh \
                 capture per attempt) or by raw window-relative coordinates; the \
                 action runs through the same decide() gate and window confinement \
                 as gui.<app>.actuate. After acting, the broker captures a fresh \
                 frame and evaluates the expect checks; on mismatch it re-grounds \
                 and retries at most 2 times, then refuses with \
                 seahawk_gui_verify_mismatch — note the action HAS been performed \
                 in that case; both sides' screenshot hashes are in the op log and \
                 the refusal's evidence.",
                Arc::new(act_schema),
            )
            .with_annotations(
                ToolAnnotations::new()
                    .read_only(false)
                    .destructive(true)
                    .idempotent(false)
                    .open_world(false),
            ),
        ]
    }

    /// The `code.feedback` tool definition (D-230 wiring,
    /// SPEC §3.2). Read-class: diagnostics/lint/format only,
    /// never a write — the dispatch table in `tooling.rs` is
    /// the enforcement, this description is the contract.
    fn feedback_tool() -> Tool {
        let mut props = Map::new();
        props.insert(
            "workspace".to_string(),
            json!({"type": "string", "description": "Absolute path of the engine project workspace. Must be inside a [feedback] project_roots entry in the broker's policy; anything else is refused."}),
        );
        props.insert(
            "files".to_string(),
            json!({"type": "array", "items": {"type": "string"}, "description": "Workspace-relative file paths to check (1..=16, per policy [feedback] max_files). Parent-escaping or absolute entries are refused."}),
        );
        props.insert(
            "checks".to_string(),
            json!({"type": "array", "items": {"type": "string", "enum": ["diagnostics", "lint", "format"]}, "description": "Which checks to run (default: all three). Diagnostics route to theodolite headless (GDScript: periscope); lint and format route to periscope's diver pipelines."}),
        );
        props.insert(
            "route".to_string(),
            json!({"type": "string", "enum": ["auto", "theodolite", "periscope"], "description": "Force a tooling route (default auto). A forced route that cannot serve a check is refused with seahawk_tooling_unavailable rather than silently rerouted."}),
        );
        props.insert(
            "include_text".to_string(),
            json!({"type": "boolean", "description": "Also return the formatter's text for files whose format check reports changed (bounded). Default false: format answers are changed booleans plus the steps that ran."}),
        );
        let mut schema = Map::new();
        schema.insert("type".to_string(), json!("object"));
        schema.insert("properties".to_string(), Value::Object(props));
        schema.insert("required".to_string(), json!(["workspace", "files"]));
        Tool::new(
            CODE_FEEDBACK,
            "Structured code feedback for brokered engine work (read-class, D-230):              per file, LSP diagnostics (theodolite headless route; GDScript via              periscope), lint verdicts and format changed flags (periscope running              diver's own pipelines), plus the file's sha256 and the catalog              provenance the answers came from. Bounded episodes: at most 3 calls              per (workspace, file set) per policy window — the 4th is refused              with seahawk_code_feedback_unresolved and the last counts, so change              strategy instead of grinding. A route that cannot serve a check              answers seahawk_tooling_unavailable; feedback is never assumed clean              and never writes anything.",
            Arc::new(schema),
        )
        .with_annotations(
            ToolAnnotations::new()
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        )
    }

    fn brokered_tool(record: &ToolRecord) -> Tool {
        let schema_map = match &record.input_schema {
            Value::Object(map) => map.clone(),
            _ => {
                let mut map = Map::new();
                map.insert("type".to_string(), json!("object"));
                map
            }
        };
        let (read_only, destructive, idempotent) = match record.class {
            ToolClass::Read => (true, false, true),
            ToolClass::Write => (false, true, false),
            ToolClass::Actuate => (false, true, false),
            ToolClass::Execute => (false, true, false),
        };
        let annotations = ToolAnnotations::new()
            .read_only(read_only)
            .destructive(destructive)
            .idempotent(idempotent)
            .open_world(false);
        let description = if record.class == ToolClass::Execute {
            format!(
                "[execute-class: default-deny — requires policy enablement and a per-call operator token] {}",
                record.description
            )
        } else if record.class == ToolClass::Actuate {
            format!(
                "[actuate-class: default-deny — requires policy enablement and a per-call operator token] {}",
                record.description
            )
        } else if record.description.is_empty() {
            format!(
                "Brokered Unreal editor tool ({}-class).",
                record.class.as_str()
            )
        } else {
            record.description.clone()
        };
        Tool::new(record.name.clone(), description, Arc::new(schema_map))
            .with_annotations(annotations)
    }

    async fn surface_snapshot(&self) -> Option<Surface> {
        let downstream = self.downstream.clone();
        let config = self.config.clone();
        tokio::task::spawn_blocking(move || downstream.surface(&config).ok())
            .await
            .ok()
            .flatten()
    }

    fn status_result(&self) -> CallToolResult {
        let gui_apps: Vec<Value> = self
            .config
            .gui_apps
            .iter()
            .map(|app| {
                json!({
                    "name": app.name,
                    "display_name": app.display_name,
                    "observe_tool": app.observe_tool(),
                    "actuate_tool": app.actuate_tool(),
                    "actuate_enabled": self.config.actuate_is_enabled(&app.actuate_tool()),
                })
            })
            .collect();
        let payload = json!({
            "server": "seahawk",
            "version": env!("CARGO_PKG_VERSION"),
            "downstream_url": self.downstream.url(),
            "downstream_surface_built": self.downstream.has_surface(),
            "operator_token_configured": self.config.operator_token_digest.is_some(),
            "execute_enabled": self.config.execute_enabled.iter().collect::<Vec<_>>(),
            "actuate_enabled": self.config.actuate_enabled.iter().collect::<Vec<_>>(),
            "gui_apps": gui_apps,
            "vision": {
                "grounder": match self.config.vision.route {
                    VisionRoute::Ollama => "ollama",
                    VisionRoute::Agent => "agent",
                    VisionRoute::None => "none",
                },
                "ollama_url": (self.config.vision.route == VisionRoute::Ollama)
                    .then(|| self.config.vision.ollama_url.clone()),
                "ollama_model": (self.config.vision.route == VisionRoute::Ollama)
                    .then(|| self.config.vision.ollama_model.clone()),
                "grounder_ready": self.vision.grounder_ready(),
                "min_confidence": self.config.vision.min_confidence,
                "frames_stored": self.vision.lock_frames().len(),
            },
            "tooling": self.config.tooling.iter().map(|entry| json!({
                "id": entry.id.as_str(),
                "command": entry.command,
            })).collect::<Vec<_>>(),
            "feedback": {
                "max_files": self.config.feedback.max_files,
                "max_iterations_per_episode": self.config.feedback.max_iterations_per_episode,
                "episode_window_secs": self.config.feedback.episode_window_secs,
                "project_roots": self.config.feedback.project_roots.iter()
                    .map(|root| root.display().to_string()).collect::<Vec<_>>(),
            },
            "class_overrides": self.config.class_overrides.len(),
            "oplog_path": self.oplog.path().display().to_string(),
            "oplog_write_failures": self.oplog.write_failures(),
        });
        json_result(&payload)
    }

    async fn surface_result(&self, refresh: bool) -> CallToolResult {
        let downstream = self.downstream.clone();
        let config = self.config.clone();
        let built = tokio::task::spawn_blocking(move || {
            if refresh {
                downstream.refresh(&config)
            } else {
                downstream.surface(&config)
            }
        })
        .await;
        match built {
            Ok(Ok(surface)) => {
                let tools: Vec<Value> = surface
                    .tools
                    .iter()
                    .map(|t| json!({"name": t.name, "class": t.class.as_str()}))
                    .collect();
                json_result(&json!({
                    "tools": tools,
                    "counts": {
                        "read": surface.count(ToolClass::Read),
                        "write": surface.count(ToolClass::Write),
                        "actuate": surface.count(ToolClass::Actuate),
                        "execute": surface.count(ToolClass::Execute),
                    },
                    "skipped_toolsets": surface.skipped_toolsets,
                    "unclassified_withheld": surface.unclassified_names,
                }))
            }
            Ok(Err(error)) => typed_refusal(
                codes::DOWNSTREAM_UNAVAILABLE,
                &format!(
                    "downstream editor server at {} is unavailable: {error}",
                    self.downstream.url()
                ),
            ),
            Err(join) => typed_refusal(
                codes::DOWNSTREAM_UNAVAILABLE,
                &format!("surface build task failed: {join}"),
            ),
        }
    }

    fn brokered_call(
        &self,
        name: &str,
        arguments: Value,
        operator_token: Option<String>,
    ) -> CallToolResult {
        let surface = match self.downstream.surface(&self.config) {
            Ok(surface) => surface,
            Err(error) => {
                self.oplog.record(
                    name,
                    None,
                    Some(&arguments),
                    &format!("refused:{}", codes::DOWNSTREAM_UNAVAILABLE),
                    None,
                    Some(&error.to_string()),
                );
                return typed_refusal(
                    codes::DOWNSTREAM_UNAVAILABLE,
                    &format!(
                        "downstream editor server at {} is unavailable: {error}",
                        self.downstream.url()
                    ),
                );
            }
        };
        let knowledge;
        let record = surface.find(name);
        match record {
            Some(record) => knowledge = ToolKnowledge::Classified(record),
            None => {
                if surface
                    .unclassified_names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(name))
                {
                    knowledge = ToolKnowledge::Unclassified;
                } else {
                    let Decision::Refuse { code, message } = policy::unknown_tool(name) else {
                        unreachable!()
                    };
                    self.oplog.record(
                        name,
                        None,
                        Some(&arguments),
                        &format!("refused:{code}"),
                        None,
                        None,
                    );
                    return typed_refusal(code, &message);
                }
            }
        }
        let operator_ok = match (&operator_token, &self.config.operator_token_digest) {
            (Some(token), Some(digest)) => token_matches(token, digest),
            _ => false,
        };
        match policy::decide(&knowledge, &self.config, operator_ok) {
            Decision::Refuse { code, message } => {
                let class = match &knowledge {
                    ToolKnowledge::Classified(record) => Some(record.class.as_str()),
                    ToolKnowledge::Unclassified => None,
                };
                self.oplog.record(
                    name,
                    class,
                    Some(&arguments),
                    &format!("refused:{code}"),
                    None,
                    None,
                );
                typed_refusal(code, &message)
            }
            Decision::Allow => {
                let ToolKnowledge::Classified(record) = knowledge else {
                    unreachable!("decide allows only classified tools")
                };
                let (toolset, short_name, class) = (
                    record.toolset.clone(),
                    record.short_name.clone(),
                    record.class.as_str(),
                );
                let started = Instant::now();
                match self.downstream.call_tool(&toolset, &short_name, &arguments) {
                    Ok(value) => {
                        let downstream_ms =
                            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                        let is_error = value
                            .get("isError")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        self.oplog.record(
                            name,
                            Some(class),
                            Some(&arguments),
                            if is_error { "error" } else { "ok" },
                            Some(downstream_ms),
                            None,
                        );
                        convert_downstream_result(value)
                    }
                    Err(error) => {
                        let downstream_ms =
                            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                        self.oplog.record(
                            name,
                            Some(class),
                            Some(&arguments),
                            "error",
                            Some(downstream_ms),
                            Some(&error.to_string()),
                        );
                        typed_refusal(
                            codes::DOWNSTREAM_UNAVAILABLE,
                            &format!("downstream call failed: {error}"),
                        )
                    }
                }
            }
        }
    }

    /// One call to a registered GUI application (S4). The class
    /// gate is decide(), exactly as for brokered tools: observe is
    /// read (agent token suffices — the guard already checked it),
    /// actuate runs the actuate two-key rule. Backend work is
    /// blocking X11 I/O and runs on `spawn_blocking`.
    async fn gui_call(
        &self,
        app: &GuiApp,
        actuate: bool,
        arguments: Value,
        operator_token: Option<String>,
    ) -> CallToolResult {
        let tool_name = if actuate {
            app.actuate_tool()
        } else {
            app.observe_tool()
        };
        let (toolset, short_name) = crate::model::split_name(&tool_name);
        let class = if actuate {
            ToolClass::Actuate
        } else {
            ToolClass::Read
        };
        let record = ToolRecord {
            name: tool_name.clone(),
            toolset,
            short_name,
            description: String::new(),
            input_schema: json!({"type": "object"}),
            class,
        };
        let operator_ok = match (&operator_token, &self.config.operator_token_digest) {
            (Some(token), Some(digest)) => token_matches(token, digest),
            _ => false,
        };
        if let Decision::Refuse { code, message } = policy::decide(
            &ToolKnowledge::Classified(&record),
            &self.config,
            operator_ok,
        ) {
            self.oplog.record(
                &tool_name,
                Some(class.as_str()),
                Some(&arguments),
                &format!("refused:{code}"),
                None,
                None,
            );
            return typed_refusal(code, &message);
        }
        let gui = self.gui.clone();
        let app_name_owned = app.name.clone();
        let app = app.clone();
        let backend_args = arguments.clone();
        let started = Instant::now();
        let joined = tokio::task::spawn_blocking(move || {
            if actuate {
                gui.actuate(&app, &backend_args).map(GuiOutcome::Actuated)
            } else {
                gui.observe(&app, &backend_args).map(GuiOutcome::Observed)
            }
        })
        .await;
        let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match joined {
            Ok(Ok(GuiOutcome::Observed(outcome))) => {
                let ObserveOutcome {
                    frame,
                    payload,
                    target,
                } = outcome;
                let (log_extra, result) = match frame {
                    Some(frame) => {
                        use base64::Engine as _;
                        let extra = LogExtra {
                            frame_sha256: Some(frame.digest()),
                            frame_width: Some(frame.width),
                            frame_height: Some(frame.height),
                            target,
                            ..Default::default()
                        };
                        let summary = format!(
                            "screenshot of {} ({}x{}, sha256 {}): see image content",
                            payload
                                .get("title")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                            frame.width,
                            frame.height,
                            frame.digest(),
                        );
                        let mut result = CallToolResult::success(vec![
                            ContentBlock::image(
                                base64::engine::general_purpose::STANDARD.encode(&frame.png),
                                "image/png",
                            ),
                            ContentBlock::text(summary),
                        ]);
                        result.structured_content = Some(payload);
                        (extra, result)
                    }
                    None => (
                        LogExtra {
                            target,
                            ..Default::default()
                        },
                        json_result(&payload),
                    ),
                };
                self.oplog.record_with(
                    &tool_name,
                    Some(class.as_str()),
                    Some(&arguments),
                    "ok",
                    Some(elapsed_ms),
                    None,
                    log_extra,
                );
                result
            }
            Ok(Ok(GuiOutcome::Actuated(outcome))) => {
                let ActuateOutcome {
                    pre,
                    post,
                    target,
                    detail,
                } = outcome;
                let mut payload = detail;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("app".to_string(), json!(app_name_owned));
                    object.insert("pre_sha256".to_string(), json!(pre.digest()));
                    object.insert(
                        "post_sha256".to_string(),
                        json!(post.as_ref().map(Frame::digest)),
                    );
                    if post.is_none() {
                        object.insert("post_screenshot_failed".to_string(), json!(true));
                    }
                }
                self.oplog.record_with(
                    &tool_name,
                    Some(class.as_str()),
                    Some(&arguments),
                    "ok",
                    Some(elapsed_ms),
                    None,
                    LogExtra {
                        pre_sha256: Some(pre.digest()),
                        post_sha256: post.as_ref().map(Frame::digest),
                        target: Some(target),
                        ..Default::default()
                    },
                );
                json_result(&payload)
            }
            Ok(Err(error)) => {
                self.oplog.record(
                    &tool_name,
                    Some(class.as_str()),
                    Some(&arguments),
                    "error",
                    Some(elapsed_ms),
                    Some(&error.message),
                );
                typed_refusal(error.code, &error.message)
            }
            Err(join) => {
                self.oplog.record(
                    &tool_name,
                    Some(class.as_str()),
                    Some(&arguments),
                    "error",
                    Some(elapsed_ms),
                    Some(&format!("gui task failed: {join}")),
                );
                typed_refusal(
                    codes::GUI_ACTION_FAILED,
                    &format!("gui task failed: {join}"),
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// S5 vision handlers
// ---------------------------------------------------------------------------

/// Which grounding route a call uses: the broker's local vision
/// model, or the calling agent answering through the ticket
/// protocol.
#[derive(Clone, Copy, Eq, PartialEq)]
enum GroundRoute {
    Local,
    Agent,
}

impl GroundRoute {
    fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Agent => "agent",
        }
    }
}

/// One completed act-verified attempt (actuation + verification),
/// for the result payload and the mismatch evidence.
struct AttemptRecord {
    attempt: u32,
    point: (i32, i32),
    confidence: Option<f64>,
    route: Option<&'static str>,
    /// C1: the grounded element bounds for this attempt, when
    /// the grounder supplied them.
    bbox: Option<vision::PixelBBox>,
    /// C4: the window this attempt resolved, recorded BEFORE
    /// the action's effects are judged — a retarget (a spawned
    /// render window, a focus change) is visible in the record.
    window_id: u32,
    window_title: String,
    pre_sha256: String,
    post_sha256: String,
    checks: Vec<CheckOutcome>,
}

impl AttemptRecord {
    fn to_json(&self) -> Value {
        json!({
            "attempt": self.attempt,
            "point": {"x": self.point.0, "y": self.point.1},
            "confidence": self.confidence,
            "route": self.route,
            "bbox": self.bbox.map(|bbox| bbox.to_json()),
            "window_id": self.window_id,
            "window_title": self.window_title,
            "pre_sha256": self.pre_sha256,
            "post_sha256": self.post_sha256,
            "checks": self.checks,
        })
    }
}

/// How an act-verified run ended.
enum ActVerifiedEnd {
    Verified {
        attempts: Vec<AttemptRecord>,
        post_frame: Frame,
        window: WindowInfo,
    },
    Mismatch {
        attempts: Vec<AttemptRecord>,
    },
    Failed(GuiError),
}

fn window_json(window: &WindowInfo) -> Value {
    json!({
        "id": window.id,
        "title": window.title,
        "x": window.x,
        "y": window.y,
        "width": window.width,
        "height": window.height,
        "focused": window.focused,
    })
}

/// A success result carrying a frame: image block + text summary,
/// structured payload attached (the gui_call screenshot shape).
fn image_result(payload: &Value, frame: &Frame, summary: String) -> CallToolResult {
    use base64::Engine as _;
    let mut result = CallToolResult::success(vec![
        ContentBlock::image(
            base64::engine::general_purpose::STANDARD.encode(&frame.png),
            "image/png",
        ),
        ContentBlock::text(summary),
    ]);
    result.structured_content = Some(payload.clone());
    result
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl SeahawkServer {
    /// Logs a pre-action refusal (`refused:<code>`) and renders it.
    fn refuse_logged(
        &self,
        tool: &str,
        class: Option<&str>,
        args: &Value,
        error: &GuiError,
    ) -> CallToolResult {
        self.oplog.record(
            tool,
            class,
            Some(args),
            &format!("refused:{}", error.code),
            None,
            None,
        );
        typed_refusal(error.code, &error.message)
    }

    /// Logs a failure (`error`) and renders it as a typed refusal.
    fn error_logged(
        &self,
        tool: &str,
        class: Option<&str>,
        args: &Value,
        ms: Option<u64>,
        error: &GuiError,
    ) -> CallToolResult {
        self.oplog
            .record(tool, class, Some(args), "error", ms, Some(&error.message));
        typed_refusal(error.code, &error.message)
    }

    /// Resolves the `app` argument of an S5 call against the
    /// policy registrations. An unregistered app is refused with
    /// the unknown-tool code — grounding grants no new surface.
    fn gui_app_for(&self, tool: &str, args: &Value) -> Result<GuiApp, CallToolResult> {
        let Some(name) = args.get("app").and_then(Value::as_str) else {
            return Err(self.refuse_logged(
                tool,
                None,
                args,
                &GuiError::bad_arguments(
                    "argument \"app\" is required (a registered GUI application name)",
                ),
            ));
        };
        match self
            .config
            .gui_apps
            .iter()
            .find(|app| app.name.eq_ignore_ascii_case(name))
        {
            Some(app) => Ok(app.clone()),
            None => Err(self.refuse_logged(
                tool,
                None,
                args,
                &GuiError::new(
                    codes::UNKNOWN_TOOL,
                    format!(
                        "app {name:?} is not a registered GUI application: registrations \
                         are policy data ([[gui.apps]] in the config); the registered \
                         names are listed by seahawk_status"
                    ),
                ),
            )),
        }
    }

    /// decide() for one S5 call, against a synthetic record named
    /// exactly like the equivalent per-app tool — `gui.observe`
    /// gates as `gui.<app>.observe` (read), `gui.act_verified` as
    /// `gui.<app>.actuate` (actuate) — so S4's enablement policy
    /// covers S5 verbatim and grounding grants no permission.
    fn gate(
        &self,
        log_tool: &str,
        app: &GuiApp,
        actuate: bool,
        args: &Value,
        operator_token: &Option<String>,
    ) -> Result<(), CallToolResult> {
        let tool_name = if actuate {
            app.actuate_tool()
        } else {
            app.observe_tool()
        };
        let (toolset, short_name) = crate::model::split_name(&tool_name);
        let class = if actuate {
            ToolClass::Actuate
        } else {
            ToolClass::Read
        };
        let record = ToolRecord {
            name: tool_name,
            toolset,
            short_name,
            description: String::new(),
            input_schema: json!({"type": "object"}),
            class,
        };
        let operator_ok = match (operator_token, &self.config.operator_token_digest) {
            (Some(token), Some(digest)) => token_matches(token, digest),
            _ => false,
        };
        match policy::decide(
            &ToolKnowledge::Classified(&record),
            &self.config,
            operator_ok,
        ) {
            Decision::Allow => Ok(()),
            Decision::Refuse { code, message } => {
                self.oplog.record(
                    log_tool,
                    Some(class.as_str()),
                    Some(args),
                    &format!("refused:{code}"),
                    None,
                    None,
                );
                Err(typed_refusal(code, &message))
            }
        }
    }

    fn ground_route(&self, args: &Value) -> Result<GroundRoute, GuiError> {
        match args.get("route").and_then(Value::as_str) {
            None => match self.config.vision.route {
                VisionRoute::Ollama => Ok(GroundRoute::Local),
                VisionRoute::Agent => Ok(GroundRoute::Agent),
                VisionRoute::None => Err(GuiError::new(
                    codes::GUI_GROUNDER_UNAVAILABLE,
                    "grounding is disabled by policy (vision.grounder = \"none\")",
                )),
            },
            Some("local") => Ok(GroundRoute::Local),
            Some("agent") => Ok(GroundRoute::Agent),
            Some(other) => Err(GuiError::bad_arguments(format!(
                "argument \"route\" must be \"local\" or \"agent\" (got {other:?})"
            ))),
        }
    }

    fn store_capture(&self, app: &GuiApp, capture: &Capture) -> String {
        self.vision.lock_frames().put(
            capture.frame.clone(),
            app,
            capture.window.clone(),
            capture.geometry.clone(),
        )
    }

    /// The local grounder's raw answer for a frame. Runs on a
    /// blocking thread (HTTP to the loopback model server).
    fn ground_locally_raw(&self, frame: &Frame, target: &str) -> Result<RawGrounding, GuiError> {
        let Some(grounder) = &self.vision.grounder else {
            return Err(GuiError::new(
                codes::GUI_GROUNDER_UNAVAILABLE,
                "no local vision grounder is available: policy must set \
                 [vision] grounder = \"ollama\" with a served model, or the \
                 caller uses route \"agent\"",
            ));
        };
        grounder.ground(frame, target)
    }

    /// The agent-route ticket: a successful result carrying the
    /// frame and the protocol for answering it. Nothing is
    /// grounded and nothing is actuated by a ticket.
    fn ground_ticket(&self, stored: &StoredFrame, target: &str, for_tool: &str) -> CallToolResult {
        let payload = json!({
            "status": "awaiting_agent_answer",
            "frame_sha256": stored.frame.digest(),
            "app": stored.app,
            "target": target,
            "width": stored.frame.width,
            "height": stored.frame.height,
            "window": window_json(&stored.window),
            "display": stored.geometry.to_json(),
            "how_to_answer": format!(
                "Look at the attached frame and call {for_tool} again with the same \
                 arguments plus agent_answer {{\"x\": <window-relative pixel x>, \
                 \"y\": <window-relative pixel y>, \"confidence\": <0..1>, \
                 \"bbox\": {{\"x_min\": <int>, \"y_min\": <int>, \"x_max\": <int>, \
                 \"y_max\": <int>}} (optional)}} — the center of the target element \
                 in the frame's pixel coordinates; when bbox is given, the broker \
                 acts on its centre instead."
            ),
        });
        image_result(
            &payload,
            &stored.frame,
            format!(
                "grounding ticket for {target:?} in {} (frame {}): see image content",
                stored.app,
                stored.frame.digest()
            ),
        )
    }

    /// A completed grounding: evidence crop + structured hit,
    /// op-logged with the ground evidence fields.
    fn ground_hit_result(
        &self,
        args: &Value,
        stored: &StoredFrame,
        target: &str,
        hit: GroundHit,
        route_name: &str,
        started: Instant,
    ) -> CallToolResult {
        let crop = match vision::evidence_crop(&stored.frame, hit.x, hit.y) {
            Ok(crop) => crop,
            Err(error) => {
                return self.error_logged(VISION_GROUND, Some("read"), args, None, &error);
            }
        };
        let crop_sha = crop.digest();
        // The crop is itself a frame reference: stored under the
        // same app/window/geometry so a caller can ground inside
        // it or hand it to a reviewer as a first-class frame.
        if let Some(app) = self
            .config
            .gui_apps
            .iter()
            .find(|app| app.name == stored.app)
        {
            self.vision.lock_frames().put(
                crop.clone(),
                app,
                stored.window.clone(),
                stored.geometry.clone(),
            );
        }
        let payload = json!({
            "status": "grounded",
            "app": stored.app,
            "frame_sha256": stored.frame.digest(),
            "target": target,
            "route": route_name,
            "x": hit.x,
            "y": hit.y,
            "display_x": stored.window.x + hit.x,
            "display_y": stored.window.y + hit.y,
            "confidence": hit.confidence,
            "bbox": hit.bbox.map(|bbox| bbox.to_json()),
            "bbox_source": if hit.bbox.is_some() { "grounder" } else { "point_only" },
            "window": window_json(&stored.window),
            "display": stored.geometry.to_json(),
            "evidence_crop_sha256": crop_sha,
            "evidence_crop": {"width": crop.width, "height": crop.height},
        });
        self.oplog.record_with(
            VISION_GROUND,
            Some("read"),
            Some(args),
            "ok",
            Some(elapsed_ms(started)),
            None,
            LogExtra {
                frame_sha256: Some(stored.frame.digest()),
                frame_width: Some(stored.frame.width),
                frame_height: Some(stored.frame.height),
                ground_x: Some(i64::from(hit.x)),
                ground_y: Some(i64::from(hit.y)),
                ground_confidence: Some(hit.confidence),
                target: Some(target.to_string()),
                ..Default::default()
            },
        );
        image_result(
            &payload,
            &crop,
            format!(
                "grounded {target:?} in {} at window-relative {},{} (confidence {:.2}); \
                 image content is the evidence crop around the point",
                stored.app, hit.x, hit.y, hit.confidence
            ),
        )
    }

    /// `gui.observe`: capture + geometry, frame stored by digest.
    async fn vision_observe(&self, args: Value) -> CallToolResult {
        let started = Instant::now();
        let app = match self.gui_app_for(VISION_OBSERVE, &args) {
            Ok(app) => app,
            Err(result) => return result,
        };
        if let Err(result) = self.gate(VISION_OBSERVE, &app, false, &args, &None) {
            return result;
        }
        let gui = self.gui.clone();
        let capture_app = app.clone();
        let joined = tokio::task::spawn_blocking(move || gui.capture(&capture_app)).await;
        match joined {
            Ok(Ok(capture)) => {
                let sha = self.store_capture(&app, &capture);
                let content = match vision::frame_content(&capture.frame) {
                    Ok(vision::FrameContent::SuspectBlank) => "suspect_blank",
                    Ok(vision::FrameContent::Content) => "content",
                    Err(_) => "content",
                };
                let payload = json!({
                    "app": app.name,
                    "frame_sha256": sha,
                    "width": capture.frame.width,
                    "height": capture.frame.height,
                    "window_id": capture.window.id,
                    "content": content,
                    "window": window_json(&capture.window),
                    "display": capture.geometry.to_json(),
                    "next": "pass frame_sha256 and a target description to gui.ground",
                });
                self.oplog.record_with(
                    VISION_OBSERVE,
                    Some("read"),
                    Some(&args),
                    "ok",
                    Some(elapsed_ms(started)),
                    None,
                    LogExtra {
                        frame_sha256: Some(sha.clone()),
                        frame_width: Some(capture.frame.width),
                        frame_height: Some(capture.frame.height),
                        target: Some(format!(
                            "window {} {:?}",
                            capture.window.id, capture.window.title
                        )),
                        ..Default::default()
                    },
                );
                image_result(
                    &payload,
                    &capture.frame,
                    format!(
                        "screenshot of {} window {:?} ({}x{}, sha256 {}): see image content",
                        app.name,
                        capture.window.title,
                        capture.frame.width,
                        capture.frame.height,
                        sha
                    ),
                )
            }
            Ok(Err(error)) => self.error_logged(
                VISION_OBSERVE,
                Some("read"),
                &args,
                Some(elapsed_ms(started)),
                &error,
            ),
            Err(join) => self.error_logged(
                VISION_OBSERVE,
                Some("read"),
                &args,
                Some(elapsed_ms(started)),
                &GuiError::failed(format!("capture task failed: {join}")),
            ),
        }
    }

    /// `gui.ground`: description → coordinates in a stored frame.
    async fn vision_ground(&self, args: Value) -> CallToolResult {
        let started = Instant::now();
        let Some(frame_sha) = args
            .get("frame_sha256")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
        else {
            return self.refuse_logged(
                VISION_GROUND,
                Some("read"),
                &args,
                &GuiError::bad_arguments(
                    "argument \"frame_sha256\" is required (a digest returned by gui.observe)",
                ),
            );
        };
        let target = match parse_target_arg(&args, true) {
            Ok(Some(target)) => target,
            Ok(None) => unreachable!("required target parse yields a value or an error"),
            Err(error) => return self.refuse_logged(VISION_GROUND, Some("read"), &args, &error),
        };
        let route = match self.ground_route(&args) {
            Ok(route) => route,
            Err(error) => return self.refuse_logged(VISION_GROUND, Some("read"), &args, &error),
        };
        let Some(stored) = self.vision.lock_frames().get(&frame_sha).cloned() else {
            return self.refuse_logged(
                VISION_GROUND,
                Some("read"),
                &args,
                &GuiError::new(
                    codes::GUI_NO_FRAME,
                    format!(
                        "frame {frame_sha} is not in the broker's frame store (unknown \
                         digest, or evicted after {} stored captures): call gui.observe \
                         to take a fresh frame",
                        vision::MAX_STORED_FRAMES
                    ),
                ),
            );
        };
        match route {
            GroundRoute::Agent => match parse_agent_answer(&args) {
                None => {
                    self.oplog.record_with(
                        VISION_GROUND,
                        Some("read"),
                        Some(&args),
                        "ticket",
                        Some(elapsed_ms(started)),
                        None,
                        LogExtra {
                            frame_sha256: Some(stored.frame.digest()),
                            frame_width: Some(stored.frame.width),
                            frame_height: Some(stored.frame.height),
                            target: Some(target.clone()),
                            ..Default::default()
                        },
                    );
                    self.ground_ticket(&stored, &target, VISION_GROUND)
                }
                Some(Err(error)) => self.refuse_logged(VISION_GROUND, Some("read"), &args, &error),
                Some(Ok((x, y, confidence, bbox))) => {
                    match vision::hit_from_agent_answer(&stored.frame, x, y, confidence, bbox) {
                        Ok(hit) => {
                            self.ground_hit_result(&args, &stored, &target, hit, "agent", started)
                        }
                        Err(error) => {
                            self.refuse_logged(VISION_GROUND, Some("read"), &args, &error)
                        }
                    }
                }
            },
            GroundRoute::Local => {
                let Some(grounder) = self.vision.grounder.clone() else {
                    return self.refuse_logged(
                        VISION_GROUND,
                        Some("read"),
                        &args,
                        &GuiError::new(
                            codes::GUI_GROUNDER_UNAVAILABLE,
                            "no local vision grounder is available: policy must set \
                             [vision] grounder = \"ollama\" with a served model, or \
                             the caller uses route \"agent\"",
                        ),
                    );
                };
                let frame = stored.frame.clone();
                let ground_target = target.clone();
                let joined =
                    tokio::task::spawn_blocking(move || grounder.ground(&frame, &ground_target))
                        .await;
                match joined {
                    Ok(Ok(raw)) => {
                        let hit = vision::hit_from_raw(raw, &stored.frame);
                        if hit.confidence < self.config.vision.min_confidence {
                            let error = GuiError::new(
                                codes::GUI_GROUND_FAILED,
                                format!(
                                    "grounder confidence {:.2} for {target:?} is below \
                                     the configured floor {:.2}: refusing to return a \
                                     point the grounder itself does not stand behind",
                                    hit.confidence, self.config.vision.min_confidence
                                ),
                            );
                            self.oplog.record_with(
                                VISION_GROUND,
                                Some("read"),
                                Some(&args),
                                "error",
                                Some(elapsed_ms(started)),
                                Some(&error.message),
                                LogExtra {
                                    frame_sha256: Some(stored.frame.digest()),
                                    frame_width: Some(stored.frame.width),
                                    frame_height: Some(stored.frame.height),
                                    ground_x: Some(i64::from(hit.x)),
                                    ground_y: Some(i64::from(hit.y)),
                                    ground_confidence: Some(hit.confidence),
                                    target: Some(target.clone()),
                                    ..Default::default()
                                },
                            );
                            return typed_refusal(error.code, &error.message);
                        }
                        self.ground_hit_result(&args, &stored, &target, hit, "ollama", started)
                    }
                    Ok(Err(error)) => self.error_logged(
                        VISION_GROUND,
                        Some("read"),
                        &args,
                        Some(elapsed_ms(started)),
                        &error,
                    ),
                    Err(join) => self.error_logged(
                        VISION_GROUND,
                        Some("read"),
                        &args,
                        Some(elapsed_ms(started)),
                        &GuiError::failed(format!("grounder task failed: {join}")),
                    ),
                }
            }
        }
    }

    /// `gui.act_verified`: decide() first, then the bounded
    /// ground → act → verify loop (the loop itself is blocking
    /// and runs in `act_verified_run` on a blocking thread).
    async fn vision_act_verified(
        &self,
        args: Value,
        operator_token: Option<String>,
    ) -> CallToolResult {
        let started = Instant::now();
        let app = match self.gui_app_for(VISION_ACT_VERIFIED, &args) {
            Ok(app) => app,
            Err(result) => return result,
        };
        // The gate runs before any argument interpretation beyond
        // the app name: an unenabled actuation is refused exactly
        // as S4 refuses it, whatever else the call carries.
        if let Err(result) = self.gate(VISION_ACT_VERIFIED, &app, true, &args, &operator_token) {
            return result;
        }
        let expect = match Expectation::parse(&args) {
            Ok(expect) => expect,
            Err(error) => {
                return self.refuse_logged(VISION_ACT_VERIFIED, Some("actuate"), &args, &error);
            }
        };
        // A check the configured route cannot evaluate refuses
        // the call BEFORE acting — never act unverified.
        if expect.text_visible.is_some() && !self.vision.has_local_grounder() {
            return self.refuse_logged(
                VISION_ACT_VERIFIED,
                Some("actuate"),
                &args,
                &GuiError::new(
                    codes::GUI_VERIFY_UNAVAILABLE,
                    "expect.text_visible needs the local vision grounder to evaluate, \
                     and none is configured (vision.grounder): refusing before \
                     acting rather than acting unverified",
                ),
            );
        }
        let target = match parse_target_arg(&args, false) {
            Ok(target) => target,
            Err(error) => {
                return self.refuse_logged(VISION_ACT_VERIFIED, Some("actuate"), &args, &error);
            }
        };
        let route = match self.ground_route(&args) {
            Ok(route) => route,
            Err(error) => {
                return self.refuse_logged(VISION_ACT_VERIFIED, Some("actuate"), &args, &error);
            }
        };
        let agent_answer = match parse_agent_answer(&args) {
            Some(Ok(answer)) => Some(answer),
            Some(Err(error)) => {
                return self.refuse_logged(VISION_ACT_VERIFIED, Some("actuate"), &args, &error);
            }
            None => None,
        };
        if let Some(target_text) = &target {
            let action_name = args.get("action").and_then(Value::as_str).unwrap_or("");
            if action_name == "drag" {
                return self.refuse_logged(
                    VISION_ACT_VERIFIED,
                    Some("actuate"),
                    &args,
                    &GuiError::bad_arguments(
                        "drag takes raw from_x/from_y/to_x/to_y coordinates; a single \
                         grounded point cannot describe it",
                    ),
                );
            }
            // Agent-route grounding is a conversation, not a
            // mid-call blocking wait: hand back a ticket and let
            // the caller re-call with its answer. No action taken.
            if route == GroundRoute::Agent && agent_answer.is_none() {
                let gui = self.gui.clone();
                let capture_app = app.clone();
                let joined = tokio::task::spawn_blocking(move || gui.capture(&capture_app)).await;
                return match joined {
                    Ok(Ok(capture)) => {
                        self.store_capture(&app, &capture);
                        let stored = StoredFrame {
                            frame: capture.frame,
                            app: app.name.clone(),
                            window: capture.window,
                            geometry: capture.geometry,
                        };
                        self.oplog.record_with(
                            VISION_ACT_VERIFIED,
                            Some("actuate"),
                            Some(&args),
                            "ticket",
                            Some(elapsed_ms(started)),
                            None,
                            LogExtra {
                                frame_sha256: Some(stored.frame.digest()),
                                frame_width: Some(stored.frame.width),
                                frame_height: Some(stored.frame.height),
                                target: Some(target_text.clone()),
                                ..Default::default()
                            },
                        );
                        self.ground_ticket(&stored, target_text, VISION_ACT_VERIFIED)
                    }
                    Ok(Err(error)) => self.error_logged(
                        VISION_ACT_VERIFIED,
                        Some("actuate"),
                        &args,
                        Some(elapsed_ms(started)),
                        &error,
                    ),
                    Err(join) => self.error_logged(
                        VISION_ACT_VERIFIED,
                        Some("actuate"),
                        &args,
                        Some(elapsed_ms(started)),
                        &GuiError::failed(format!("capture task failed: {join}")),
                    ),
                };
            }
        }
        let window_pin = match args.get("window_id") {
            None => None,
            Some(value) => match value.as_u64().and_then(|n| u32::try_from(n).ok()) {
                Some(id) => Some(id),
                None => {
                    return self.refuse_logged(
                        VISION_ACT_VERIFIED,
                        Some("actuate"),
                        &args,
                        &GuiError::bad_arguments(
                            "argument \"window_id\" must be a non-negative integer \
                             (an X window id from a gui.observe result)",
                        ),
                    );
                }
            },
        };
        let expect_description = expect.description.clone();
        let this = self.clone();
        let run_app = app.clone();
        let run_args = args.clone();
        let joined = tokio::task::spawn_blocking(move || {
            this.act_verified_run(
                &run_app,
                &run_args,
                &expect,
                target.as_deref(),
                route,
                agent_answer,
                window_pin,
            )
        })
        .await;
        match joined {
            Ok(ActVerifiedEnd::Verified {
                attempts,
                post_frame,
                window,
            }) => {
                let last = attempts.last();
                let payload = json!({
                    "status": "verified",
                    "app": app.name,
                    "action": args.get("action").and_then(Value::as_str),
                    "attempts": attempts.len(),
                    "point": last.map(|a| json!({"x": a.point.0, "y": a.point.1})),
                    "bbox": last.and_then(|a| a.bbox).map(|bbox| bbox.to_json()),
                    "confidence": last.and_then(|a| a.confidence),
                    "route": last.and_then(|a| a.route),
                    "checks": last.map(|a| a.checks.clone()).unwrap_or_default(),
                    "history": attempts.iter().map(AttemptRecord::to_json).collect::<Vec<_>>(),
                    "pre_sha256": attempts.first().map(|a| a.pre_sha256.clone()),
                    "post_sha256": last.map(|a| a.post_sha256.clone()),
                    "window": window_json(&window),
                    "expect_description": expect_description,
                });
                image_result(
                    &payload,
                    &post_frame,
                    format!(
                        "verified: {} on {} produced the expected effect after {} \
                         attempt(s); image content is the post-action frame",
                        args.get("action")
                            .and_then(Value::as_str)
                            .unwrap_or("action"),
                        app.name,
                        attempts.len()
                    ),
                )
            }
            Ok(ActVerifiedEnd::Mismatch { attempts }) => {
                let last_failed = attempts
                    .last()
                    .and_then(|a| a.checks.iter().find(|c| !c.passed))
                    .map(|c| c.check)
                    .unwrap_or("unknown");
                let message = format!(
                    "the action was performed {} time(s) on {} but the expected effect \
                     was not observed (last failed check: {last_failed}); bounded \
                     correction is exhausted after {} re-ground+retry cycle(s) and \
                     the broker stops here rather than acting blind — both sides' \
                     screenshot hashes are in the evidence and the op log",
                    attempts.len(),
                    app.name,
                    vision::MAX_VERIFY_RETRIES
                );
                let evidence = json!({
                    "attempts": attempts.iter().map(AttemptRecord::to_json).collect::<Vec<_>>(),
                    "pre_sha256": attempts.first().map(|a| a.pre_sha256.clone()),
                    "post_sha256": attempts.last().map(|a| a.post_sha256.clone()),
                    "action_performed": !attempts.is_empty(),
                });
                let mut result = CallToolResult::error(vec![ContentBlock::text(format!(
                    "{}: {message}",
                    codes::GUI_VERIFY_MISMATCH
                ))]);
                result.structured_content = Some(json!({
                    "error": {"code": codes::GUI_VERIFY_MISMATCH, "message": message},
                    "evidence": evidence,
                }));
                result
            }
            Ok(ActVerifiedEnd::Failed(error)) => self.error_logged(
                VISION_ACT_VERIFIED,
                Some("actuate"),
                &args,
                Some(elapsed_ms(started)),
                &error,
            ),
            Err(join) => self.error_logged(
                VISION_ACT_VERIFIED,
                Some("actuate"),
                &args,
                Some(elapsed_ms(started)),
                &GuiError::failed(format!("act-verified task failed: {join}")),
            ),
        }
    }

    /// Captures a frame that passes the C4 blank-frame screen:
    /// a suspect-blank capture polls (up to 5 further captures
    /// over ~10 s — an app still painting its first frame is the
    /// ComfyUI-on-Xvfb shape) and only then refuses with
    /// `seahawk_gui_suspect_blank`. A blank frame never verifies
    /// anything and never grounds an act.
    fn capture_contentful(&self, app: &GuiApp) -> Result<crate::gui::Capture, GuiError> {
        let mut last_sha = String::new();
        for poll in 0..=5 {
            let capture = self.gui.capture(app)?;
            last_sha = capture.frame.digest();
            match vision::frame_content(&capture.frame) {
                Ok(vision::FrameContent::Content) => return Ok(capture),
                Ok(vision::FrameContent::SuspectBlank) => {
                    if poll < 5 {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(GuiError::new(
            codes::GUI_SUSPECT_BLANK,
            format!(
                "frames of {} stayed suspect-blank (>99% one colour) through the                  content poll (last frame sha256 {last_sha}): the window is not                  presenting content, so nothing on it can be verified",
                app.name
            ),
        ))
    }

    /// C2 crop escalation: ground `target` inside the evidence
    /// crop around the previous attempt's point (a zoomed second
    /// look), then map the hit back into frame coordinates.
    fn ground_in_crop(
        &self,
        frame: &Frame,
        target: &str,
        prev: (i32, i32),
    ) -> Result<GroundHit, GuiError> {
        let crop = vision::evidence_crop(frame, prev.0, prev.1)?;
        let x0 = (prev.0 - vision::EVIDENCE_CROP_HALF).clamp(0, frame.width as i32);
        let y0 = (prev.1 - vision::EVIDENCE_CROP_HALF).clamp(0, frame.height as i32);
        let raw = self.ground_locally_raw(&crop, target)?;
        let inner = vision::hit_from_raw(raw, &crop);
        Ok(GroundHit {
            x: inner.x + x0,
            y: inner.y + y0,
            confidence: inner.confidence,
            bbox: inner.bbox.map(|bbox| vision::PixelBBox {
                x_min: bbox.x_min + x0,
                y_min: bbox.y_min + y0,
                x_max: bbox.x_max + x0,
                y_max: bbox.y_max + y0,
            }),
        })
    }

    /// The act-verified loop, blocking. Every completed attempt
    /// appends its own op-log entries (a `gui.ground` entry when
    /// the attempt grounded, then the `gui.act_verified` entry
    /// with bracket hashes, ground fields, and the verify
    /// outcome). decide() has already run in the handler — this
    /// loop is one authorized call, retries included.
    ///
    /// Curative round (C2/C3/C4): retries CHANGE STRATEGY —
    /// attempt 2 re-grounds with the prior attempt's outcome in
    /// the description, attempt 3 escalates (local: crop-zoom
    /// grounding; agent: the local grounder where configured) —
    /// and an identical re-ground is a strategy failure that
    /// stops early instead of repeating an act that already
    /// failed to verify. Every frame the loop judges passes the
    /// blank-frame screen first, a caller `window_id` pin is
    /// checked against the resolved window before acting, and a
    /// point-less action's `changed` check diffs the full frame
    /// (G-1: there is no region "around the point" when there is
    /// no point; the S5 window-centre fallback verified nothing).
    #[allow(clippy::too_many_arguments)]
    fn act_verified_run(
        &self,
        app: &GuiApp,
        args: &Value,
        expect: &Expectation,
        target: Option<&str>,
        route: GroundRoute,
        agent_answer: Option<AgentAnswer>,
        window_pin: Option<u32>,
    ) -> ActVerifiedEnd {
        let grounder_ref: Option<&dyn Grounder> = self
            .vision
            .grounder
            .as_deref()
            .map(|grounder| grounder as &dyn Grounder);
        let mut attempts: Vec<AttemptRecord> = Vec::new();
        // The previous attempt's (point, first failed check) —
        // the strategy loop's memory.
        let mut prev: Option<((i32, i32), String)> = None;
        for attempt in 0..=vision::MAX_VERIFY_RETRIES {
            let attempt_started = Instant::now();
            // A raw-coordinate action is vocabulary-checked
            // BEFORE any backend contact (the S4 ordering: an
            // execute-shaped action dies in the vocabulary, not
            // at the display). Grounded actions parse after
            // grounding inserts the point, below.
            if target.is_none()
                && let Err(error) = crate::gui::parse_actuate(args)
            {
                return ActVerifiedEnd::Failed(error);
            }
            // --- C4: a contentful capture before anything is
            // acted on; the window pin is checked against it.
            let capture = match self.capture_contentful(app) {
                Ok(capture) => capture,
                Err(error) => return ActVerifiedEnd::Failed(error),
            };
            if let Some(pin) = window_pin
                && capture.window.id != pin
            {
                return ActVerifiedEnd::Failed(GuiError::new(
                    codes::GUI_WINDOW_MISMATCH,
                    format!(
                        "window_id pin {pin} does not match the window that                          resolves for {} now (id {} {:?}): refusing rather than                          silently re-matching by title",
                        app.name, capture.window.id, capture.window.title
                    ),
                ));
            }
            // --- Targeting: ground on the fresh capture, or take
            // the caller's raw point from the action's own fields.
            let mut act_args = args.clone();
            let (ground_point, confidence, route_label, ground_bbox) = match target {
                Some(target_text) => {
                    let frame_sha = self.store_capture(app, &capture);
                    // C2: the description this attempt grounds
                    // with — refined by the prior outcome from
                    // attempt 2 on.
                    let refined = prev.as_ref().map(|((px, py), check)| {
                        format!(
                            "{target_text} — a previous attempt grounded at {px},{py}                              but the expected effect was not observed (failed check:                              {check}); locate the element precisely by its visible                              label and its full widget bounds"
                        )
                    });
                    let ground_desc: &str = refined.as_deref().unwrap_or(target_text);
                    let (hit, route_label) = if attempt == vision::MAX_VERIFY_RETRIES
                        && route == GroundRoute::Local
                        && prev.is_some()
                    {
                        // Final attempt, local route: escalate to
                        // a crop-zoom ground around the prior point.
                        match self.ground_in_crop(
                            &capture.frame,
                            ground_desc,
                            prev.as_ref().map(|(point, _)| *point).unwrap_or((0, 0)),
                        ) {
                            Ok(hit) => (hit, "local-crop"),
                            Err(error) => return ActVerifiedEnd::Failed(error),
                        }
                    } else if attempt == vision::MAX_VERIFY_RETRIES
                        && route == GroundRoute::Agent
                        && self.vision.grounder.is_some()
                    {
                        // Final attempt, agent route with a local
                        // grounder configured: escalate routes.
                        let raw = match self.ground_locally_raw(&capture.frame, ground_desc) {
                            Ok(raw) => raw,
                            Err(error) => return ActVerifiedEnd::Failed(error),
                        };
                        (
                            vision::hit_from_raw(raw, &capture.frame),
                            "ollama-escalated",
                        )
                    } else {
                        match route {
                            GroundRoute::Agent => {
                                // The handler only reaches the loop
                                // with an answer in hand for this route.
                                let Some((ax, ay, ac, abbox)) = agent_answer else {
                                    return ActVerifiedEnd::Failed(GuiError::new(
                                        codes::GUI_GROUNDER_UNAVAILABLE,
                                        "agent-route grounding inside gui.act_verified \
                                         requires agent_answer in the call",
                                    ));
                                };
                                match vision::hit_from_agent_answer(
                                    &capture.frame,
                                    ax,
                                    ay,
                                    ac,
                                    abbox,
                                ) {
                                    Ok(hit) => (hit, route.label()),
                                    Err(error) => return ActVerifiedEnd::Failed(error),
                                }
                            }
                            GroundRoute::Local => {
                                let raw = match self.ground_locally_raw(&capture.frame, ground_desc)
                                {
                                    Ok(raw) => raw,
                                    Err(error) => return ActVerifiedEnd::Failed(error),
                                };
                                (vision::hit_from_raw(raw, &capture.frame), route.label())
                            }
                        }
                    };
                    if hit.confidence < self.config.vision.min_confidence {
                        self.oplog.record_with(
                            VISION_GROUND,
                            Some("read"),
                            Some(args),
                            "error",
                            None,
                            Some("grounder confidence below the configured floor"),
                            LogExtra {
                                frame_sha256: Some(frame_sha),
                                frame_width: Some(capture.frame.width),
                                frame_height: Some(capture.frame.height),
                                ground_x: Some(i64::from(hit.x)),
                                ground_y: Some(i64::from(hit.y)),
                                ground_confidence: Some(hit.confidence),
                                target: Some(target_text.to_string()),
                                ..Default::default()
                            },
                        );
                        return ActVerifiedEnd::Failed(GuiError::new(
                            codes::GUI_GROUND_FAILED,
                            format!(
                                "grounder confidence {:.2} for {target_text:?} \
                                 is below the configured floor {:.2} (bbox {:?})",
                                hit.confidence,
                                self.config.vision.min_confidence,
                                hit.bbox.map(|bbox| bbox.to_json())
                            ),
                        ));
                    }
                    // C2: an identical re-ground after a failed
                    // attempt is a strategy failure — stop early
                    // rather than repeat the same act.
                    if let Some(((px, py), _)) = prev
                        && (hit.x - px).abs() <= 2
                        && (hit.y - py).abs() <= 2
                    {
                        self.oplog.record_with(
                            VISION_ACT_VERIFIED,
                            Some("actuate"),
                            Some(args),
                            "error",
                            Some(elapsed_ms(attempt_started)),
                            Some("correction re-grounded the identical point; strategy failure"),
                            LogExtra {
                                ground_x: Some(i64::from(hit.x)),
                                ground_y: Some(i64::from(hit.y)),
                                ground_confidence: Some(hit.confidence),
                                target: Some(target_text.to_string()),
                                verify: Some("mismatch:strategy".to_string()),
                                ..Default::default()
                            },
                        );
                        return ActVerifiedEnd::Mismatch { attempts };
                    }
                    self.oplog.record_with(
                        VISION_GROUND,
                        Some("read"),
                        Some(args),
                        "ok",
                        None,
                        None,
                        LogExtra {
                            frame_sha256: Some(frame_sha),
                            frame_width: Some(capture.frame.width),
                            frame_height: Some(capture.frame.height),
                            ground_x: Some(i64::from(hit.x)),
                            ground_y: Some(i64::from(hit.y)),
                            ground_confidence: Some(hit.confidence),
                            target: Some(target_text.to_string()),
                            ..Default::default()
                        },
                    );
                    if let Some(object) = act_args.as_object_mut() {
                        object.insert("x".to_string(), json!(hit.x));
                        object.insert("y".to_string(), json!(hit.y));
                    }
                    (
                        Some((hit.x, hit.y)),
                        Some(hit.confidence),
                        Some(route_label),
                        hit.bbox,
                    )
                }
                None => (None, None, None, None),
            };
            // --- Act (through the S4 surface: parse, confine,
            // bracket — unchanged).
            let action = match crate::gui::parse_actuate(&act_args) {
                Ok(action) => action,
                Err(error) => return ActVerifiedEnd::Failed(error),
            };
            let outcome = match self.gui.actuate(app, &act_args) {
                Ok(outcome) => outcome,
                Err(error) => return ActVerifiedEnd::Failed(error),
            };
            // --- Verify against a fresh, content-screened capture.
            let post_capture = match self.capture_contentful(app) {
                Ok(capture) => capture,
                Err(error) => {
                    if error.code == codes::GUI_SUSPECT_BLANK {
                        return ActVerifiedEnd::Failed(GuiError::new(
                            codes::GUI_SUSPECT_BLANK,
                            format!(
                                "the action was performed on {} but the post-action \
                                 frame stayed suspect-blank, so the effect cannot be \
                                 verified: {}",
                                app.name, error.message
                            ),
                        ));
                    }
                    return ActVerifiedEnd::Failed(GuiError::new(
                        codes::GUI_ACTION_FAILED,
                        format!(
                            "the action was performed on {} but the post-action \
                             capture failed, so the effect cannot be verified: {}",
                            app.name, error.message
                        ),
                    ));
                }
            };
            let post_sha = self.store_capture(app, &post_capture);
            let diff_frame = outcome
                .post
                .clone()
                .unwrap_or_else(|| post_capture.frame.clone());
            let verify_point = ground_point
                .or_else(|| action.points().first().copied())
                .unwrap_or((
                    i32::try_from(outcome.pre.width / 2).unwrap_or(0),
                    i32::try_from(outcome.pre.height / 2).unwrap_or(0),
                ));
            // C3/G-1: a point-less action (a key press) has no
            // region to centre on; its `changed` check diffs the
            // full frame unless the caller anchored it.
            let mut effective_expect = expect.clone();
            if effective_expect.changed.is_some()
                && effective_expect.changed_around.is_none()
                && !effective_expect.full_frame
                && ground_point.is_none()
                && action.points().is_empty()
            {
                effective_expect.full_frame = true;
            }
            let checks = vision::evaluate_checks(
                &effective_expect,
                &outcome.pre,
                &diff_frame,
                &post_capture.window,
                verify_point,
                grounder_ref,
            );
            let passed = checks.iter().all(|check| check.passed);
            let first_failed = checks
                .iter()
                .find(|check| !check.passed)
                .map(|check| check.check);
            self.oplog.record_with(
                VISION_ACT_VERIFIED,
                Some("actuate"),
                Some(args),
                if passed { "ok" } else { "error" },
                Some(elapsed_ms(attempt_started)),
                if passed {
                    None
                } else {
                    Some("expected effect not observed")
                },
                LogExtra {
                    pre_sha256: Some(outcome.pre.digest()),
                    post_sha256: Some(post_sha.clone()),
                    ground_x: ground_point.map(|(x, _)| i64::from(x)),
                    ground_y: ground_point.map(|(_, y)| i64::from(y)),
                    ground_confidence: confidence,
                    target: Some(outcome.target.clone()),
                    verify: Some(if passed {
                        "verified".to_string()
                    } else {
                        format!("mismatch:{}", first_failed.unwrap_or("unknown"))
                    }),
                    ..Default::default()
                },
            );
            attempts.push(AttemptRecord {
                attempt: attempt + 1,
                point: verify_point,
                confidence,
                route: route_label,
                bbox: ground_bbox,
                window_id: post_capture.window.id,
                window_title: post_capture.window.title.clone(),
                pre_sha256: outcome.pre.digest(),
                post_sha256: post_sha,
                checks,
            });
            if passed {
                return ActVerifiedEnd::Verified {
                    attempts,
                    post_frame: post_capture.frame,
                    window: post_capture.window,
                };
            }
            prev = Some((verify_point, first_failed.unwrap_or("unknown").to_string()));
        }
        ActVerifiedEnd::Mismatch { attempts }
    }

    /// `code.feedback` (D-230 wiring): async shell — the work
    /// blocks on tooling stdio, so it runs on a blocking thread.
    async fn code_feedback(&self, args: Value) -> CallToolResult {
        let this = self.clone();
        let run_args = args.clone();
        let joined = tokio::task::spawn_blocking(move || this.code_feedback_run(&run_args)).await;
        match joined {
            Ok(result) => result,
            Err(join) => self.error_logged(
                CODE_FEEDBACK,
                Some("read"),
                &args,
                None,
                &GuiError::failed(format!("feedback task failed: {join}")),
            ),
        }
    }

    /// The blocking feedback run: parse + workspace gate,
    /// episode bound, catalog snapshot, per-file checks over
    /// the tooling routes, staleness re-check, op-log summary.
    /// Every refusal is typed; an unserved check is reported
    /// per file, and a call where NOTHING could be served is a
    /// `seahawk_tooling_unavailable` refusal — feedback never
    /// reports an assumed-clean result (SPEC §5).
    fn code_feedback_run(&self, args: &Value) -> CallToolResult {
        let started = Instant::now();
        // ---- Parse -------------------------------------------------
        let Some(workspace_raw) = args.get("workspace").and_then(Value::as_str) else {
            return self.refuse_logged(
                CODE_FEEDBACK,
                Some("read"),
                args,
                &GuiError::bad_arguments("argument \"workspace\" is required (absolute path)"),
            );
        };
        let workspace_path = std::path::PathBuf::from(workspace_raw);
        let Ok(workspace) = workspace_path.canonicalize() else {
            return self.refuse_logged(
                CODE_FEEDBACK,
                Some("read"),
                args,
                &GuiError::bad_arguments(format!(
                    "workspace {workspace_raw:?} does not exist or cannot be resolved"
                )),
            );
        };
        let roots: Vec<std::path::PathBuf> = self
            .config
            .feedback
            .project_roots
            .iter()
            .filter_map(|root| root.canonicalize().ok())
            .collect();
        if !roots.iter().any(|root| workspace.starts_with(root)) {
            return self.refuse_logged(
                CODE_FEEDBACK,
                Some("read"),
                args,
                &GuiError::bad_arguments(format!(
                    "workspace {} is not inside a registered engine project root \
                     ([feedback] project_roots in policy): feedback serves \
                     registered workspaces only",
                    workspace.display()
                )),
            );
        }
        let Some(files_value) = args.get("files").and_then(Value::as_array) else {
            return self.refuse_logged(
                CODE_FEEDBACK,
                Some("read"),
                args,
                &GuiError::bad_arguments(
                    "argument \"files\" is required (an array of workspace-relative paths)",
                ),
            );
        };
        if files_value.is_empty() || files_value.len() > self.config.feedback.max_files {
            return self.refuse_logged(
                CODE_FEEDBACK,
                Some("read"),
                args,
                &GuiError::bad_arguments(format!(
                    "argument \"files\" must name 1..={} files",
                    self.config.feedback.max_files
                )),
            );
        }
        let mut files: Vec<String> = Vec::with_capacity(files_value.len());
        for entry in files_value {
            let Some(rel) = entry.as_str() else {
                return self.refuse_logged(
                    CODE_FEEDBACK,
                    Some("read"),
                    args,
                    &GuiError::bad_arguments("\"files\" entries must be strings"),
                );
            };
            let rel_path = std::path::Path::new(rel);
            let escapes = rel_path.is_absolute()
                || rel_path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir));
            if escapes {
                return self.refuse_logged(
                    CODE_FEEDBACK,
                    Some("read"),
                    args,
                    &GuiError::bad_arguments(format!(
                        "file {rel:?} is absolute or escapes the workspace: \
                         files are workspace-relative paths"
                    )),
                );
            }
            if !workspace.join(rel_path).is_file() {
                return self.refuse_logged(
                    CODE_FEEDBACK,
                    Some("read"),
                    args,
                    &GuiError::bad_arguments(format!(
                        "file {rel:?} does not exist inside the workspace"
                    )),
                );
            }
            files.push(rel.to_string());
        }
        let mut checks: Vec<CheckKind> = Vec::new();
        match args.get("checks") {
            None => checks.extend([CheckKind::Diagnostics, CheckKind::Lint, CheckKind::Format]),
            Some(Value::Array(items)) => {
                for item in items {
                    let Some(name) = item.as_str() else {
                        return self.refuse_logged(
                            CODE_FEEDBACK,
                            Some("read"),
                            args,
                            &GuiError::bad_arguments("\"checks\" entries must be strings"),
                        );
                    };
                    let Some(kind) = CheckKind::parse(name) else {
                        return self.refuse_logged(
                            CODE_FEEDBACK,
                            Some("read"),
                            args,
                            &GuiError::bad_arguments(format!(
                                "unknown check {name:?}: diagnostics | lint | format"
                            )),
                        );
                    };
                    if !checks.contains(&kind) {
                        checks.push(kind);
                    }
                }
                if checks.is_empty() {
                    return self.refuse_logged(
                        CODE_FEEDBACK,
                        Some("read"),
                        args,
                        &GuiError::bad_arguments("\"checks\" must name at least one check"),
                    );
                }
            }
            Some(_) => {
                return self.refuse_logged(
                    CODE_FEEDBACK,
                    Some("read"),
                    args,
                    &GuiError::bad_arguments("\"checks\" must be an array"),
                );
            }
        }
        let forced: Option<Route> = match args.get("route").and_then(Value::as_str) {
            None | Some("auto") => None,
            Some("theodolite") => Some(Route::Theodolite),
            Some("periscope") => Some(Route::Periscope),
            Some(other) => {
                return self.refuse_logged(
                    CODE_FEEDBACK,
                    Some("read"),
                    args,
                    &GuiError::bad_arguments(format!(
                        "argument \"route\" must be auto | theodolite | periscope (got {other:?})"
                    )),
                );
            }
        };
        let include_text = args
            .get("include_text")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        // ---- Episode bound (SPEC §3.2) ------------------------------
        let episode_key = crate::oplog::args_digest(&json!({
            "workspace": workspace.display().to_string(),
            "files": files,
        }));
        let max_iterations = self.config.feedback.max_iterations_per_episode;
        let window = std::time::Duration::from_secs(self.config.feedback.episode_window_secs);
        let iteration = {
            let mut state = self
                .feedback_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let episode = state
                .episodes
                .entry(episode_key.clone())
                .or_insert_with(|| FeedbackEpisode {
                    window_start: Instant::now(),
                    count: 0,
                    last_dirty: false,
                    last_counts: String::new(),
                });
            if episode.window_start.elapsed() > window {
                episode.window_start = Instant::now();
                episode.count = 0;
            }
            episode.count += 1;
            if episode.count > max_iterations {
                let message = format!(
                    "feedback episode bound reached: {max_iterations} calls for this \
                     workspace + file set inside the window and the last result was \
                     still dirty ({}); the episode is closed — change strategy \
                     (a different fix, a human, or the Owner) rather than grinding",
                    episode.last_counts
                );
                drop(state);
                return self.refuse_logged(
                    CODE_FEEDBACK,
                    Some("read"),
                    args,
                    &GuiError::new(codes::FEEDBACK_UNRESOLVED, message),
                );
            }
            episode.count
        };

        // ---- Catalog snapshot (once per broker run) -----------------
        let catalog = self.catalog_snapshot();

        // ---- Check passes with a staleness re-check -----------------
        let hashes_before = hash_files(&workspace, &files);
        let mut outcome = self.feedback_pass(&workspace, &files, &checks, forced, include_text);
        let hashes_after = hash_files(&workspace, &files);
        if hashes_after != hashes_before {
            // A file changed while it was being checked: re-run
            // once against the new bytes; still moving → stale.
            outcome = self.feedback_pass(&workspace, &files, &checks, forced, include_text);
            let hashes_final = hash_files(&workspace, &files);
            if hashes_final != hashes_after {
                return self.refuse_logged(
                    CODE_FEEDBACK,
                    Some("read"),
                    args,
                    &GuiError::new(
                        codes::FEEDBACK_STALE,
                        "files changed on disk again while feedback was re-checked: \
                         the result would describe bytes that no longer exist in \
                         that form (seahawk_feedback_stale)",
                    ),
                );
            }
            outcome.stale_suspect = true;
        }

        if !outcome.any_served {
            let reason = outcome
                .first_unavailable_reason
                .clone()
                .unwrap_or_else(|| "no tooling route served any check".to_string());
            return self.refuse_logged(
                CODE_FEEDBACK,
                Some("read"),
                args,
                &GuiError::new(
                    codes::TOOLING_UNAVAILABLE,
                    format!(
                        "code.feedback could not serve any check: {reason}. \
                         Feedback reports unavailable, never an assumed-clean result"
                    ),
                ),
            );
        }

        let counts = json!({
            "errors": outcome.errors,
            "warnings": outcome.warnings,
            "lint_diagnostics": outcome.lint_diagnostics,
            "format_changed": outcome.format_changed,
        });
        let dirty = outcome.errors + outcome.warnings + outcome.lint_diagnostics > 0
            || outcome.format_changed > 0;
        {
            let mut state = self
                .feedback_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(episode) = state.episodes.get_mut(&episode_key) {
                episode.last_dirty = dirty;
                episode.last_counts = counts.to_string();
            }
        }
        let summary = json!({
            "checks": checks.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            "counts": counts,
            "iteration": iteration,
            "routes": outcome.routes_used,
            "stale_suspect": outcome.stale_suspect,
        });
        self.oplog.record_with(
            CODE_FEEDBACK,
            Some("read"),
            Some(args),
            "ok",
            Some(elapsed_ms(started)),
            None,
            LogExtra {
                feedback: Some(summary.to_string()),
                ..Default::default()
            },
        );
        let payload = json!({
            "workspace": workspace.display().to_string(),
            "iteration": iteration,
            "max_iterations": max_iterations,
            "dirty": dirty,
            "counts": counts,
            "stale_suspect": outcome.stale_suspect,
            "catalog": catalog,
            "files": outcome.files,
        });
        json_result(&payload)
    }

    /// The periscope catalog snapshot (SPEC §1.4): taken once,
    /// on the first feedback call that can reach periscope;
    /// provenance is the sha256 of the canonical snapshot. A
    /// failed snapshot is reported in the result, never faked.
    fn catalog_snapshot(&self) -> Value {
        {
            let state = self
                .feedback_state
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some((provenance, counts)) = &state.catalog {
                return json!({"provenance": provenance, "counts": counts});
            }
        }
        let Some(client) = self.tooling.get(ToolingId::Periscope) else {
            return json!(null);
        };
        let mut snapshot = serde_json::Map::new();
        for tool in [
            "list_servers",
            "list_formatters",
            "list_linters",
            "broker_status",
        ] {
            match client.call(tool, json!({})) {
                Ok(value) => {
                    snapshot.insert(tool.to_string(), value);
                }
                Err(error) => {
                    return json!({"unavailable": error.message});
                }
            }
        }
        let snapshot = Value::Object(snapshot);
        let provenance = crate::oplog::args_digest(&snapshot);
        let counts = json!({
            "servers": array_len_any(&snapshot, &["servers", "tools"]),
            "formatters": array_len_any(&snapshot, &["formatters"]),
            "linters": array_len_any(&snapshot, &["linters"]),
        });
        let mut state = self
            .feedback_state
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        state.catalog = Some((provenance.clone(), counts.clone()));
        json!({"provenance": provenance, "counts": counts})
    }

    /// One full pass of checks over the file set.
    fn feedback_pass(
        &self,
        workspace: &std::path::Path,
        files: &[String],
        checks: &[CheckKind],
        forced: Option<Route>,
        include_text: bool,
    ) -> FeedbackPass {
        let have_theodolite = self.tooling.has(ToolingId::Theodolite);
        let have_periscope = self.tooling.has(ToolingId::Periscope);
        let mut pass = FeedbackPass::default();
        for rel in files {
            let abs = workspace.join(rel);
            let abs_str = abs.display().to_string();
            let ext = abs
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            let sha = std::fs::read(&abs)
                .map(|bytes| crate::oplog::bytes_digest(&bytes))
                .unwrap_or_default();
            let mut file_json = json!({"path": rel, "file_sha256": sha});
            for check in checks {
                let route =
                    match tooling::route_for(*check, forced, &ext, have_theodolite, have_periscope)
                    {
                        Ok(route) => route,
                        Err(reason) => {
                            pass.note_unavailable(&reason);
                            file_json[check.as_str()] =
                                json!({"status": "unavailable", "reason": reason});
                            continue;
                        }
                    };
                pass.routes_used
                    .insert(format!("{}:{}", check.as_str(), route.as_str()));
                let Some(client) = self.tooling.get(route.id()) else {
                    let reason = format!("{} is not configured", route.as_str());
                    pass.note_unavailable(&reason);
                    file_json[check.as_str()] = json!({"status": "unavailable", "reason": reason});
                    continue;
                };
                match (check, route) {
                    (CheckKind::Diagnostics, Route::Theodolite) => {
                        let server = self
                            .config
                            .tooling_entry(ToolingId::Theodolite)
                            .and_then(|entry| entry.diagnostics_servers.get(&ext))
                            .cloned();
                        let Some(server) = server else {
                            let reason = format!(
                                "no theodolite server is pinned for extension {ext:?} \
                                 ([[tooling]] diagnostics_servers): the pin mirrors \
                                 diver's lsp choice for the language (SPEC REQ-8)"
                            );
                            pass.note_unavailable(&reason);
                            file_json["diagnostics"] =
                                json!({"status": "unavailable", "reason": reason});
                            continue;
                        };
                        match client.call(
                            "diagnostics",
                            json!({"workspace": workspace.display().to_string(), "server": server, "path": rel}),
                        ) {
                            Ok(result) => {
                                let mapped = map_diagnostics(&result, Some(&server));
                                pass.errors += mapped.1;
                                pass.warnings += mapped.2;
                                pass.any_served = true;
                                file_json["diagnostics"] = mapped.0;
                            }
                            Err(error) => {
                                pass.note_unavailable(&error.message);
                                file_json["diagnostics"] = json!({
                                    "status": "unavailable", "code": error.code,
                                    "reason": error.message,
                                });
                            }
                        }
                    }
                    (CheckKind::Diagnostics, Route::Periscope) => {
                        match client.call("get_diagnostics", json!({"path": abs_str})) {
                            Ok(result) => {
                                let mapped = map_diagnostics(&result, None);
                                pass.errors += mapped.1;
                                pass.warnings += mapped.2;
                                pass.any_served = true;
                                file_json["diagnostics"] = mapped.0;
                            }
                            Err(error) => {
                                pass.note_unavailable(&error.message);
                                file_json["diagnostics"] = json!({
                                    "status": "unavailable", "code": error.code,
                                    "reason": error.message,
                                });
                            }
                        }
                    }
                    (CheckKind::Lint, _) => match client.call("run_lint", json!({"path": abs_str}))
                    {
                        Ok(result) => {
                            let (lint_json, diagnostics) = map_lint(&result);
                            pass.lint_diagnostics += diagnostics;
                            pass.any_served = true;
                            file_json["lint"] = lint_json;
                        }
                        Err(error) => {
                            pass.note_unavailable(&error.message);
                            file_json["lint"] = json!({
                                "status": "unavailable", "code": error.code,
                                "reason": error.message,
                            });
                        }
                    },
                    (CheckKind::Format, _) => {
                        match client.call("run_format", json!({"path": abs_str})) {
                            Ok(result) => {
                                let changed = result
                                    .get("changed")
                                    .and_then(Value::as_bool)
                                    .unwrap_or(false);
                                if changed {
                                    pass.format_changed += 1;
                                }
                                pass.any_served = true;
                                let mut format_json = json!({
                                    "changed": changed,
                                    "steps": result.get("steps").cloned().unwrap_or(json!([])),
                                    "written": false,
                                });
                                if include_text
                                    && changed
                                    && let Some(text) = result.get("text").and_then(Value::as_str)
                                {
                                    format_json["text"] = json!(truncate_chars(text, 4000));
                                }
                                file_json["format"] = format_json;
                            }
                            Err(error) => {
                                pass.note_unavailable(&error.message);
                                file_json["format"] = json!({
                                    "status": "unavailable", "code": error.code,
                                    "reason": error.message,
                                });
                            }
                        }
                    }
                }
            }
            pass.files.push(file_json);
        }
        pass
    }
}

/// The accumulated result of one `code.feedback` pass.
#[derive(Default)]
struct FeedbackPass {
    files: Vec<Value>,
    errors: usize,
    warnings: usize,
    lint_diagnostics: usize,
    format_changed: usize,
    any_served: bool,
    stale_suspect: bool,
    routes_used: std::collections::BTreeSet<String>,
    first_unavailable_reason: Option<String>,
}

impl FeedbackPass {
    fn note_unavailable(&mut self, reason: &str) {
        if self.first_unavailable_reason.is_none() {
            self.first_unavailable_reason = Some(reason.to_string());
        }
    }
}

/// sha256 of each file's current bytes, keyed by relative path.
fn hash_files(
    workspace: &std::path::Path,
    files: &[String],
) -> std::collections::HashMap<String, String> {
    files
        .iter()
        .map(|rel| {
            let digest = std::fs::read(workspace.join(rel))
                .map(|bytes| crate::oplog::bytes_digest(&bytes))
                .unwrap_or_default();
            (rel.clone(), digest)
        })
        .collect()
}

/// Truncates to at most `max` characters (char-boundary safe).
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push_str("…[truncated]");
    out
}

/// Normalizes a diagnostic severity (LSP number 1..=4, or a
/// string label from either tooling server) to a label.
fn severity_label(value: Option<&Value>) -> String {
    match value {
        Some(Value::Number(number)) => match number.as_i64() {
            Some(1) => "error".to_string(),
            Some(2) => "warning".to_string(),
            Some(3) => "information".to_string(),
            Some(4) => "hint".to_string(),
            _ => "unknown".to_string(),
        },
        Some(Value::String(text)) => text.to_lowercase(),
        _ => "unknown".to_string(),
    }
}

/// Maps a tooling diagnostics result (theodolite's shape, or
/// periscope's buffer-diagnostics shape) into the feedback
/// per-file form: bounded item list (first 20) + honest total +
/// error/warning counts. Returns (json, errors, warnings).
fn map_diagnostics(result: &Value, pinned_server: Option<&str>) -> (Value, usize, usize) {
    let items = result
        .get("diagnostics")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let total = result
        .get("count")
        .and_then(Value::as_u64)
        .map(|count| count as usize)
        .unwrap_or(items.len());
    let mut errors = 0usize;
    let mut warnings = 0usize;
    let mut mapped: Vec<Value> = Vec::new();
    for item in &items {
        let severity = severity_label(item.get("severity"));
        match severity.as_str() {
            "error" => errors += 1,
            "warning" => warnings += 1,
            _ => {}
        }
        if mapped.len() < 20 {
            mapped.push(json!({
                "severity": severity,
                "source": item.get("source").and_then(Value::as_str).unwrap_or(""),
                "message": truncate_chars(
                    item.get("message").and_then(Value::as_str).unwrap_or(""), 300),
                "range": item.get("range").cloned().unwrap_or(Value::Null),
                "path": item.get("uri").and_then(Value::as_str)
                    .or_else(|| item.get("path").and_then(Value::as_str)).unwrap_or(""),
            }));
        }
    }
    let server = result
        .get("server")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| pinned_server.map(str::to_string));
    (
        json!({
            "status": "ok",
            "server": server,
            "count": total,
            "overflow": total.saturating_sub(mapped.len()),
            "diagnostics": mapped,
        }),
        errors,
        warnings,
    )
}

/// Maps a periscope `run_lint` result into the feedback form:
/// per-linter status + diagnostic counts.
fn map_lint(result: &Value) -> (Value, usize) {
    if let Some(linters) = result.get("linters").and_then(Value::as_array) {
        let mut total = 0usize;
        let mapped: Vec<Value> = linters
            .iter()
            .map(|linter| {
                let diagnostics = linter
                    .get("diagnostics")
                    .and_then(Value::as_array)
                    .map(|items| items.len())
                    .unwrap_or(0);
                total += diagnostics;
                json!({
                    "name": linter.get("name").and_then(Value::as_str)
                        .or_else(|| linter.get("linter").and_then(Value::as_str)).unwrap_or(""),
                    "status": linter.get("status").and_then(Value::as_str).unwrap_or(""),
                    "diagnostics": diagnostics,
                })
            })
            .collect();
        return (json!({"status": "ok", "linters": mapped}), total);
    }
    let diagnostics = result
        .get("diagnostics")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    (
        json!({
            "status": result.get("status").and_then(Value::as_str).unwrap_or("ok"),
            "linters": [],
            "diagnostics": diagnostics,
        }),
        diagnostics,
    )
}

/// The length of the first array found under any of `keys` in
/// any of the snapshot's tool results (catalog counts are
/// defensive: server payload shapes vary by tool).
fn array_len_any(snapshot: &Value, keys: &[&str]) -> Value {
    if let Some(object) = snapshot.as_object() {
        for result in object.values() {
            for key in keys {
                if let Some(array) = result.get(key).and_then(Value::as_array) {
                    return json!(array.len());
                }
            }
            if let Some(array) = result.as_array() {
                return json!(array.len());
            }
        }
    }
    Value::Null
}

/// Parses the optional `target` argument (bounded like all
/// external input).
fn parse_target_arg(args: &Value, required: bool) -> Result<Option<String>, GuiError> {
    match args.get("target") {
        None if !required => Ok(None),
        None => Err(GuiError::bad_arguments(
            "argument \"target\" is required (a natural-language description of the \
             UI element to locate)",
        )),
        Some(value) => {
            let Some(text) = value.as_str() else {
                return Err(GuiError::bad_arguments(
                    "argument \"target\" must be a string",
                ));
            };
            if text.is_empty() || text.chars().count() > vision::MAX_TARGET_CHARS {
                return Err(GuiError::bad_arguments(format!(
                    "argument \"target\" must be 1..={} characters",
                    vision::MAX_TARGET_CHARS
                )));
            }
            Ok(Some(text.to_string()))
        }
    }
}

/// An agent-route grounding answer: window-relative point,
/// confidence, and the optional C1 bbox.
type AgentAnswer = (i64, i64, f64, Option<vision::PixelBBox>);

/// Parses the optional `agent_answer` argument: absent → None;
/// present but malformed → an argument error (never silently
/// ignored — a caller who thinks it answered must learn it did
/// not). The C1 curative shape adds an optional pixel `bbox`
/// ({x_min, y_min, x_max, y_max}); when present, the act point
/// is derived as its centre by `hit_from_agent_answer`.
fn parse_agent_answer(args: &Value) -> Option<Result<AgentAnswer, GuiError>> {
    let answer = args.get("agent_answer")?;
    let parsed = (|| {
        let x = answer
            .get("x")
            .and_then(Value::as_i64)
            .ok_or_else(|| GuiError::bad_arguments("agent_answer.x must be an integer"))?;
        let y = answer
            .get("y")
            .and_then(Value::as_i64)
            .ok_or_else(|| GuiError::bad_arguments("agent_answer.y must be an integer"))?;
        let confidence = answer
            .get("confidence")
            .and_then(Value::as_f64)
            .ok_or_else(|| GuiError::bad_arguments("agent_answer.confidence must be a number"))?;
        let bbox = match answer.get("bbox") {
            None => None,
            Some(bbox) => {
                let field = |key: &str| {
                    bbox.get(key)
                        .and_then(Value::as_i64)
                        .ok_or_else(|| {
                            GuiError::bad_arguments(format!(
                                "agent_answer.bbox.{key} must be an integer"
                            ))
                        })
                        .and_then(|v| {
                            i32::try_from(v).map_err(|_| {
                                GuiError::bad_arguments(format!(
                                    "agent_answer.bbox.{key} is out of range"
                                ))
                            })
                        })
                };
                Some(vision::PixelBBox {
                    x_min: field("x_min")?,
                    y_min: field("y_min")?,
                    x_max: field("x_max")?,
                    y_max: field("y_max")?,
                })
            }
        };
        Ok((x, y, confidence, bbox))
    })();
    Some(parsed)
}

enum GuiOutcome {
    Observed(ObserveOutcome),
    Actuated(ActuateOutcome),
}

/// Converts Epic's CallToolResult-shaped JSON into an rmcp result,
/// preserving content blocks and structured content. Unparseable
/// content degrades to a single text block rather than failing.
fn convert_downstream_result(value: Value) -> CallToolResult {
    let blocks: Vec<ContentBlock> = value
        .get("content")
        .and_then(|c| serde_json::from_value(c.clone()).ok())
        .unwrap_or_else(|| {
            vec![ContentBlock::text(
                value
                    .get("content")
                    .map(Value::to_string)
                    .unwrap_or_default(),
            )]
        });
    let is_error = value
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut result = if is_error {
        CallToolResult::error(blocks)
    } else {
        CallToolResult::success(blocks)
    };
    if let Some(structured) = value.get("structuredContent") {
        result.structured_content = Some(structured.clone());
    }
    result
}

fn typed_refusal(code: &str, message: &str) -> CallToolResult {
    let mut result = CallToolResult::error(vec![ContentBlock::text(format!("{code}: {message}"))]);
    result.structured_content = Some(json!({"error": {"code": code, "message": message}}));
    result
}

fn json_result(payload: &Value) -> CallToolResult {
    let mut result = CallToolResult::success(vec![ContentBlock::text(
        serde_json::to_string_pretty(payload).unwrap_or_default(),
    )]);
    result.structured_content = Some(payload.clone());
    result
}

impl ServerHandler for SeahawkServer {
    fn get_info(&self) -> InitializeResult {
        let mut server_info = Implementation::default();
        server_info.name = "seahawk".to_string();
        server_info.version = env!("CARGO_PKG_VERSION").to_string();
        let mut info = InitializeResult::default();
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = server_info;
        info.instructions = Some(
            "Seahawk brokers Unreal Engine's editor MCP server. Every tools/call must \
             carry the agent token in _meta[\"seahawk/agent_token\"] (enforced by the \
             wire guard). Execute-class tools are default-deny: they additionally \
             require policy enablement and a per-call operator token in \
             _meta[\"seahawk/operator_token\"]. Registered GUI applications appear \
             as gui.<app>.observe (read) and gui.<app>.actuate (actuate-class: the \
             same default-deny two-key rule, enabled via policy.actuate_enabled). \
             Vision grounding (S5): gui.observe captures a registered app's window \
             WITH display geometry and stores the frame under its sha256; \
             gui.ground turns a target description into coordinates in that frame \
             (the broker's local vision model, or answer the broker's ticket \
             yourself with agent_answer); gui.act_verified actuates through the \
             same actuate gate and verifies the expected effect against a fresh \
             capture, re-grounding and retrying at most twice before refusing."
                .to_string(),
        );
        info
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
    }

    async fn list_tools(
        &self,
        _params: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = Self::native_tools();
        // GUI tools come from policy registrations, not from the
        // downstream: they are listed whether or not an editor is
        // running.
        tools.extend(self.config.gui_apps.iter().flat_map(crate::gui::gui_tools));
        // S5 vision tools are broker-level (the app is an
        // argument), likewise independent of the downstream.
        tools.extend(Self::vision_tools());
        // D-230 wiring: the read-class feedback tool, likewise
        // independent of the downstream and of tooling config
        // (an unconfigured deployment refuses its calls typed).
        tools.push(Self::feedback_tool());
        if let Some(surface) = self.surface_snapshot().await {
            tools.extend(surface.tools.iter().map(Self::brokered_tool));
        }
        Ok(ListToolsResult {
            tools,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: rmcp::service::RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.as_ref();
        if name.is_empty() {
            return Err(McpError::invalid_params(
                "tool name must be non-empty",
                None,
            ));
        }
        let arguments = request
            .arguments
            .as_ref()
            .map(|m| Value::Object(m.clone()))
            .unwrap_or_else(|| json!({}));
        // GUI tools dispatch before the brokered surface: their
        // names are Seahawk's own (policy-built), matched
        // case-insensitively so a case variant hits the same
        // decide() gate as the canonical name.
        if let Some((app, actuate)) = self
            .gui_targets
            .get(&name.to_lowercase())
            .map(|(app, actuate)| (app.clone(), *actuate))
        {
            let operator_token = context
                .meta
                .get(META_OPERATOR_TOKEN)
                .and_then(Value::as_str)
                .map(str::to_string);
            let result = self
                .gui_call(&app, actuate, arguments, operator_token)
                .await;
            return Ok(result.into());
        }
        // S5 vision tools: broker-level names in the same `gui.`
        // namespace, matched before the unknown-name refusal
        // below. The app is an argument, validated against the
        // same registrations inside the handlers.
        if name.eq_ignore_ascii_case(VISION_OBSERVE) {
            return Ok(self.vision_observe(arguments).await.into());
        }
        if name.eq_ignore_ascii_case(VISION_GROUND) {
            return Ok(self.vision_ground(arguments).await.into());
        }
        if name.eq_ignore_ascii_case(CODE_FEEDBACK) {
            return Ok(self.code_feedback(arguments).await.into());
        }
        if name.eq_ignore_ascii_case(VISION_ACT_VERIFIED) {
            let operator_token = context
                .meta
                .get(META_OPERATOR_TOKEN)
                .and_then(Value::as_str)
                .map(str::to_string);
            return Ok(self
                .vision_act_verified(arguments, operator_token)
                .await
                .into());
        }
        // The `gui.` prefix is Seahawk's own namespace: a name in
        // it that policy did not register is unknown, full stop —
        // it is never forwarded downstream (where it would blur
        // provenance) and its refusal does not depend on whether
        // an editor happens to be running.
        if name.to_lowercase().starts_with("gui.") {
            let Decision::Refuse { code, message } = policy::unknown_tool(name) else {
                unreachable!()
            };
            self.oplog.record(
                name,
                None,
                Some(&arguments),
                &format!("refused:{code}"),
                None,
                None,
            );
            return Ok(typed_refusal(code, &message).into());
        }
        let result = match name {
            NATIVE_STATUS => self.status_result(),
            NATIVE_SURFACE => {
                let refresh = arguments
                    .get("refresh")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                self.surface_result(refresh).await
            }
            NATIVE_OPLOG => {
                let limit = arguments
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(50)
                    .clamp(1, 500);
                let entries = self.oplog.read_recent(usize::try_from(limit).unwrap_or(50));
                json_result(&json!({"entries": entries}))
            }
            _ => {
                let operator_token = context
                    .meta
                    .get(META_OPERATOR_TOKEN)
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let this = self.clone();
                let name = name.to_string();
                tokio::task::spawn_blocking(move || {
                    this.brokered_call(&name, arguments, operator_token)
                })
                .await
                .map_err(|e| McpError::internal_error(format!("broker task failed: {e}"), None))?
            }
        };
        Ok(result.into())
    }
}
