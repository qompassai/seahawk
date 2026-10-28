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
use std::sync::Arc;
use std::time::Instant;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    InitializeResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    Tool, ToolAnnotations,
};
use rmcp::{ErrorData as McpError, RoleServer};
use serde_json::{Map, Value, json};

use crate::config::Config;
use crate::downstream::Downstream;
use crate::gui::{ActuateOutcome, Frame, Gui, ObserveOutcome};
use crate::model::{GuiApp, Surface, ToolClass, ToolRecord};
use crate::oplog::{LogExtra, OpLog};
use crate::policy::{self, Decision, ToolKnowledge, codes, token_matches};

pub const META_OPERATOR_TOKEN: &str = "seahawk/operator_token";

const NATIVE_STATUS: &str = "seahawk_status";
const NATIVE_SURFACE: &str = "seahawk_surface";
const NATIVE_OPLOG: &str = "seahawk_oplog";

#[derive(Clone)]
pub struct SeahawkServer {
    config: Arc<Config>,
    downstream: Arc<Downstream>,
    oplog: Arc<OpLog>,
    gui: Arc<Gui>,
    /// Lowercased GUI tool name → (registered app, is_actuate).
    /// Built once from policy at startup; registrations cannot
    /// change under a running server.
    gui_targets: Arc<std::collections::HashMap<String, (GuiApp, bool)>>,
}

impl SeahawkServer {
    pub fn new(config: Arc<Config>, downstream: Arc<Downstream>, oplog: Arc<OpLog>) -> Self {
        let mut gui_targets = std::collections::HashMap::new();
        for app in &config.gui_apps {
            gui_targets.insert(app.observe_tool(), (app.clone(), false));
            gui_targets.insert(app.actuate_tool(), (app.clone(), true));
        }
        Self {
            config,
            downstream,
            oplog,
            gui: Arc::new(Gui::x11()),
            gui_targets: Arc::new(gui_targets),
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
             same default-deny two-key rule, enabled via policy.actuate_enabled)."
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
