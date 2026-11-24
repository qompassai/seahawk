//! The target-adapter core (the generalization, 2026-11-24):
//! one trait every automation target implements — the brokered
//! Unreal downstream, the Blender provider, Unity, Godot, and
//! the generic-GUI floor — behind a capability declaration the
//! tool surface reports verbatim (`target.list`,
//! `seahawk_status`).
//!
//! The declaration is the honesty contract. An adapter declares
//! the operations it can actually perform (attach, execute,
//! inspect, actuate, observe) and its depth: `scripted-deep`
//! (the target's own scripting / API surface) or
//! `generic-floor` (window discovery, screenshots, injected
//! input — nothing deeper is promised, and no state guarantee
//! is made beyond what is observable). The registry refuses any
//! operation outside the declared capabilities with
//! `seahawk_target_capability` *before* the adapter is touched,
//! so a caller can never be silently served a shallower
//! operation than it asked for, and an adapter that claims a
//! capability it does not have fails its own declaration tests.
//!
//! Refit note: the Unreal and Blender adapters below wrap the
//! existing downstream clients. Their agent-facing tool paths
//! (`brokered_call`, `blender_call` in `server.rs`) are
//! unchanged — the adapters give those targets the shared
//! declaration, attach, and inspection shape, and are the
//! construction the newer targets (Unity, Godot, the floor)
//! are built against directly.

use std::sync::Arc;

use serde::Serialize;
use serde_json::{Value, json};

use crate::blender::{BlenderClient, BlenderError};
use crate::config::Config;
use crate::downstream::Downstream;
use crate::model::ToolClass;
use crate::policy::codes;

/// How deep an adapter's reach into its target goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetDepth {
    /// The target's own scripting / API surface: named methods,
    /// scene state, structured results.
    ScriptedDeep,
    /// No scripting API: windows, screenshots, injected input.
    /// State is only ever what can be observed.
    GenericFloor,
}

impl TargetDepth {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ScriptedDeep => "scripted-deep",
            Self::GenericFloor => "generic-floor",
        }
    }
}

/// One operation class an adapter may declare.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetOp {
    Attach,
    Execute,
    Inspect,
    Actuate,
    Observe,
}

impl TargetOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Execute => "execute",
            Self::Inspect => "inspect",
            Self::Actuate => "actuate",
            Self::Observe => "observe",
        }
    }
}

/// The operations one adapter declares it can perform.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TargetCaps {
    pub attach: bool,
    pub execute: bool,
    pub inspect: bool,
    pub actuate: bool,
    pub observe: bool,
}

impl TargetCaps {
    /// The scripted-deep shape: attach, execute, inspect. Input
    /// injection and window observation are the floor's verbs,
    /// not a scripted target's.
    pub const fn scripted() -> Self {
        Self {
            attach: true,
            execute: true,
            inspect: true,
            actuate: false,
            observe: false,
        }
    }

    /// The generic-floor shape: attach, inspect (window state),
    /// actuate (injected input), observe (screenshots). No
    /// script execution exists at the floor.
    pub const fn floor() -> Self {
        Self {
            attach: true,
            execute: false,
            inspect: true,
            actuate: true,
            observe: true,
        }
    }

    pub fn allows(&self, op: TargetOp) -> bool {
        match op {
            TargetOp::Attach => self.attach,
            TargetOp::Execute => self.execute,
            TargetOp::Inspect => self.inspect,
            TargetOp::Actuate => self.actuate,
            TargetOp::Observe => self.observe,
        }
    }

    /// The declared operation names, in declaration order.
    pub fn ops(&self) -> Vec<&'static str> {
        let mut ops = Vec::new();
        for op in [
            TargetOp::Attach,
            TargetOp::Execute,
            TargetOp::Inspect,
            TargetOp::Actuate,
            TargetOp::Observe,
        ] {
            if self.allows(op) {
                ops.push(op.as_str());
            }
        }
        ops
    }
}

/// One adapter's identity and declared reach.
#[derive(Clone, Debug)]
pub struct TargetInfo {
    pub id: &'static str,
    pub display_name: &'static str,
    pub depth: TargetDepth,
    pub caps: TargetCaps,
}

impl TargetInfo {
    /// The declaration document the tool surface reports:
    /// identity, depth, the capability map, the operation list,
    /// and the last-known attach state (`null` when the adapter
    /// has not been probed — declarations never probe).
    pub fn declaration(&self, attached: Option<bool>) -> Value {
        json!({
            "id": self.id,
            "display_name": self.display_name,
            "depth": self.depth.as_str(),
            "capabilities": {
                "attach": self.caps.attach,
                "execute": self.caps.execute,
                "inspect": self.caps.inspect,
                "actuate": self.caps.actuate,
                "observe": self.caps.observe,
            },
            "ops": self.caps.ops(),
            "attached": attached,
        })
    }
}

/// One failed adapter operation. `code` is a seahawk refusal
/// code (the target codes in `policy::codes`, or the wrapped
/// downstream's own code, e.g. the Blender provider's).
#[derive(Debug)]
pub struct TargetError {
    pub code: &'static str,
    pub message: String,
}

impl TargetError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The target is not configured, or its transport cannot be
    /// reached.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(codes::TARGET_UNAVAILABLE, message)
    }

    /// The adapter ran and the operation failed; the message
    /// carries the target's own report.
    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(codes::TARGET_FAILED, message)
    }

    /// The operation is outside the adapter's declaration.
    pub fn capability(info: &TargetInfo, op: TargetOp) -> Self {
        Self::new(
            codes::TARGET_CAPABILITY,
            format!(
                "target {:?} ({}) does not declare the {} operation; its declared \
                 ops are {:?} — the refusal is by declaration, before the target \
                 was touched",
                info.id,
                info.display_name,
                op.as_str(),
                info.caps.ops()
            ),
        )
    }
}

impl std::fmt::Display for TargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for TargetError {}

impl From<BlenderError> for TargetError {
    fn from(error: BlenderError) -> Self {
        Self {
            code: error.code,
            message: error.message,
        }
    }
}

pub type TargetResult<T> = Result<T, TargetError>;

/// One automation target behind the shared shape. All methods
/// block; handlers call them from `spawn_blocking` tasks.
///
/// `execute` takes the adapter's own operation name (a Blender
/// provider method, a Unity verb, a Godot verb) plus JSON
/// arguments, and returns the target's structured result.
/// `observe` and `actuate` default to the capability refusal:
/// only the generic floor implements them.
pub trait TargetAdapter: Send + Sync {
    fn info(&self) -> TargetInfo;
    /// Cheap, cached reachability: `None` when the adapter has
    /// not been probed. Never probes — declarations must stay
    /// free of side effects (an Unreal surface build can take
    /// minutes against a cold editor).
    fn attached(&self) -> Option<bool> {
        None
    }
    /// Establishes or probes the session; returns the target's
    /// own status document.
    fn attach(&self) -> TargetResult<Value>;
    /// Runs one named operation against the target.
    fn execute(&self, op: &str, args: &Value) -> TargetResult<Value>;
    /// Reads target state without mutating it.
    fn inspect(&self, args: &Value) -> TargetResult<Value>;
    /// Captures an observation (the floor's screenshot).
    fn observe(&self, args: &Value) -> TargetResult<Value> {
        let _ = args;
        Err(TargetError::capability(&self.info(), TargetOp::Observe))
    }
    /// Injects one input action (the floor's verb).
    fn actuate(&self, args: &Value) -> TargetResult<Value> {
        let _ = args;
        Err(TargetError::capability(&self.info(), TargetOp::Actuate))
    }
}

/// The broker's declared targets, in construction order.
/// Every operation routes through the capability check first.
pub struct TargetRegistry {
    adapters: Vec<Arc<dyn TargetAdapter>>,
}

impl TargetRegistry {
    pub fn new(adapters: Vec<Arc<dyn TargetAdapter>>) -> Self {
        Self { adapters }
    }

    /// One adapter by id (case-insensitive, matching the
    /// server's dispatch discipline for its own names).
    pub fn find(&self, id: &str) -> Option<Arc<dyn TargetAdapter>> {
        self.adapters
            .iter()
            .find(|adapter| adapter.info().id.eq_ignore_ascii_case(id))
            .cloned()
    }

    /// Every adapter's declaration document, with last-known
    /// attach states.
    pub fn declarations(&self) -> Value {
        Value::Array(
            self.adapters
                .iter()
                .map(|adapter| adapter.info().declaration(adapter.attached()))
                .collect(),
        )
    }

    pub fn attach(&self, id: &str) -> TargetResult<Value> {
        let adapter = self.adapter(id)?;
        self.require(&adapter, TargetOp::Attach)?;
        adapter.attach()
    }

    pub fn execute(&self, id: &str, op: &str, args: &Value) -> TargetResult<Value> {
        let adapter = self.adapter(id)?;
        self.require(&adapter, TargetOp::Execute)?;
        adapter.execute(op, args)
    }

    pub fn inspect(&self, id: &str, args: &Value) -> TargetResult<Value> {
        let adapter = self.adapter(id)?;
        self.require(&adapter, TargetOp::Inspect)?;
        adapter.inspect(args)
    }

    pub fn observe(&self, id: &str, args: &Value) -> TargetResult<Value> {
        let adapter = self.adapter(id)?;
        self.require(&adapter, TargetOp::Observe)?;
        adapter.observe(args)
    }

    pub fn actuate(&self, id: &str, args: &Value) -> TargetResult<Value> {
        let adapter = self.adapter(id)?;
        self.require(&adapter, TargetOp::Actuate)?;
        adapter.actuate(args)
    }

    fn adapter(&self, id: &str) -> TargetResult<Arc<dyn TargetAdapter>> {
        self.find(id).ok_or_else(|| {
            TargetError::new(
                codes::TARGET_UNKNOWN,
                format!("unknown target {id:?}; the declared targets are listed by target.list"),
            )
        })
    }

    fn require(&self, adapter: &Arc<dyn TargetAdapter>, op: TargetOp) -> TargetResult<()> {
        let info = adapter.info();
        if info.caps.allows(op) {
            Ok(())
        } else {
            Err(TargetError::capability(&info, op))
        }
    }
}

// ---------------------------------------------------------------------------
// Unreal — the brokered Epic downstream, refit onto the core
// ---------------------------------------------------------------------------

/// The Unreal adapter wraps the existing downstream client.
/// The agent-facing brokered dispatch is unchanged
/// (`server.rs::brokered_call`); this adapter gives the target
/// its declaration, attach, and inspection shape.
pub struct UnrealAdapter {
    downstream: Arc<Downstream>,
    config: Arc<Config>,
}

impl UnrealAdapter {
    pub fn new(downstream: Arc<Downstream>, config: Arc<Config>) -> Self {
        Self { downstream, config }
    }
}

impl TargetAdapter for UnrealAdapter {
    fn info(&self) -> TargetInfo {
        TargetInfo {
            id: "unreal",
            display_name: "Unreal Engine — Epic's in-editor MCP server, brokered",
            depth: TargetDepth::ScriptedDeep,
            caps: TargetCaps::scripted(),
        }
    }

    fn attached(&self) -> Option<bool> {
        Some(self.downstream.has_surface())
    }

    fn attach(&self) -> TargetResult<Value> {
        let surface = self.downstream.surface(&self.config).map_err(|error| {
            TargetError::unavailable(format!(
                "downstream editor server at {} is unavailable: {error}",
                self.downstream.url()
            ))
        })?;
        Ok(json!({
            "url": self.downstream.url(),
            "surface_tools": surface.tools.len(),
            "unclassified_withheld": surface.unclassified_names.len(),
            "skipped_toolsets": surface.skipped_toolsets.len(),
        }))
    }

    fn execute(&self, op: &str, args: &Value) -> TargetResult<Value> {
        // The adapter-level path (the server handler's brokered
        // dispatch remains the agent path, with its decide()
        // gate): resolve the name against the classified
        // surface, refuse unclassified names, and dispatch
        // through Epic's call_tool meta-tool.
        let surface = self.downstream.surface(&self.config).map_err(|error| {
            TargetError::unavailable(format!(
                "downstream editor server at {} is unavailable: {error}",
                self.downstream.url()
            ))
        })?;
        if surface
            .unclassified_names
            .iter()
            .any(|name| name.eq_ignore_ascii_case(op))
        {
            return Err(TargetError::new(
                codes::UNCLASSIFIED,
                format!(
                    "downstream tool {op:?} is present but unclassified; it is \
                     withheld until an operator classifies it"
                ),
            ));
        }
        let Some(record) = surface.find(op) else {
            return Err(TargetError::new(
                codes::UNKNOWN_TOOL,
                format!("downstream tool {op:?} is not in the brokered surface"),
            ));
        };
        self.downstream
            .call_tool(&record.toolset, &record.short_name, args)
            .map_err(|error| {
                TargetError::unavailable(format!("downstream call to {op:?} failed: {error}"))
            })
    }

    fn inspect(&self, _args: &Value) -> TargetResult<Value> {
        let surface = self.downstream.surface(&self.config).map_err(|error| {
            TargetError::unavailable(format!(
                "downstream editor server at {} is unavailable: {error}",
                self.downstream.url()
            ))
        })?;
        let tools: Vec<Value> = surface
            .tools
            .iter()
            .map(|tool| json!({"name": tool.name, "class": tool.class.as_str()}))
            .collect();
        Ok(json!({
            "url": self.downstream.url(),
            "tools": tools,
            "counts": {
                "read": surface.count(ToolClass::Read),
                "write": surface.count(ToolClass::Write),
                "actuate": surface.count(ToolClass::Actuate),
                "execute": surface.count(ToolClass::Execute),
            },
            "unclassified_withheld": surface.unclassified_names,
            "skipped_toolsets": surface.skipped_toolsets,
        }))
    }
}

// ---------------------------------------------------------------------------
// Blender — the provider addon downstream, refit onto the core
// ---------------------------------------------------------------------------

/// The Blender adapter wraps the existing provider client.
/// The agent-facing `blender.*` dispatch is unchanged
/// (`server.rs::blender_call`, with its artifact and path
/// pre-checks); this adapter gives the target its declaration,
/// attach, and inspection shape.
pub struct BlenderAdapter {
    client: Arc<BlenderClient>,
}

impl BlenderAdapter {
    pub fn new(client: Arc<BlenderClient>) -> Self {
        Self { client }
    }
}

impl TargetAdapter for BlenderAdapter {
    fn info(&self) -> TargetInfo {
        TargetInfo {
            id: "blender",
            display_name: "Blender — stroke/animation provider addon (pinned build)",
            depth: TargetDepth::ScriptedDeep,
            caps: TargetCaps::scripted(),
        }
    }

    fn attached(&self) -> Option<bool> {
        // A reported version means a session was established.
        self.client.reported_version().map(|_| true)
    }

    fn attach(&self) -> TargetResult<Value> {
        Ok(self
            .client
            .call("session_status", &json!({}), ToolClass::Read)?)
    }

    fn execute(&self, op: &str, args: &Value) -> TargetResult<Value> {
        let full = format!("blender.{op}");
        let Some(class) = crate::model::blender_class(&full) else {
            return Err(TargetError::new(
                codes::UNKNOWN_TOOL,
                format!("unknown blender provider operation {op:?}"),
            ));
        };
        Ok(self.client.call(op, args, class)?)
    }

    fn inspect(&self, _args: &Value) -> TargetResult<Value> {
        Ok(self
            .client
            .call("scene_census", &json!({}), ToolClass::Read)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A floor-shaped fake that counts every touch, so the
    /// adversarial tests can prove a refusal happened *before*
    /// the adapter was reached.
    struct FakeFloor {
        touches: std::sync::Mutex<usize>,
    }

    impl FakeFloor {
        fn new() -> Self {
            Self {
                touches: std::sync::Mutex::new(0),
            }
        }
        fn touch(&self) {
            *self.touches.lock().unwrap() += 1;
        }
        fn touches(&self) -> usize {
            *self.touches.lock().unwrap()
        }
    }

    impl TargetAdapter for FakeFloor {
        fn info(&self) -> TargetInfo {
            TargetInfo {
                id: "fake-floor",
                display_name: "Fake floor",
                depth: TargetDepth::GenericFloor,
                caps: TargetCaps::floor(),
            }
        }
        fn attach(&self) -> TargetResult<Value> {
            self.touch();
            Ok(json!({"attached": true}))
        }
        fn execute(&self, _op: &str, _args: &Value) -> TargetResult<Value> {
            self.touch();
            Ok(json!({"executed": true}))
        }
        fn inspect(&self, _args: &Value) -> TargetResult<Value> {
            self.touch();
            Ok(json!({"windows": []}))
        }
    }

    fn registry_with_floor() -> (TargetRegistry, Arc<FakeFloor>) {
        let fake = Arc::new(FakeFloor::new());
        let registry = TargetRegistry::new(vec![fake.clone() as Arc<dyn TargetAdapter>]);
        (registry, fake)
    }

    #[test]
    fn declarations_report_depth_caps_and_ops() {
        let (registry, _fake) = registry_with_floor();
        let declarations = registry.declarations();
        let floor = &declarations[0];
        assert_eq!(floor["id"], "fake-floor");
        assert_eq!(floor["depth"], "generic-floor");
        assert_eq!(floor["capabilities"]["execute"], false);
        assert_eq!(floor["capabilities"]["actuate"], true);
        assert_eq!(
            floor["ops"],
            json!(["attach", "inspect", "actuate", "observe"])
        );
        // Unprobed: attach state is null, never a guessed bool.
        assert_eq!(floor["attached"], Value::Null);
    }

    #[test]
    fn scripted_caps_declare_no_floor_verbs() {
        let caps = TargetCaps::scripted();
        assert!(caps.allows(TargetOp::Execute));
        assert!(!caps.allows(TargetOp::Actuate));
        assert!(!caps.allows(TargetOp::Observe));
        assert_eq!(caps.ops(), vec!["attach", "execute", "inspect"]);
    }

    // -- adversarial -------------------------------------------

    #[test]
    fn unknown_target_refuses_before_any_adapter() {
        let (registry, fake) = registry_with_floor();
        let error = registry
            .execute("no-such-target", "anything", &json!({}))
            .expect_err("unknown target must refuse");
        assert_eq!(error.code, codes::TARGET_UNKNOWN);
        assert_eq!(fake.touches(), 0);
    }

    #[test]
    fn floor_execute_refuses_by_declaration_and_never_touches() {
        // The floor declares no execute: the registry must
        // refuse from the declaration alone.
        let (registry, fake) = registry_with_floor();
        let error = registry
            .execute("fake-floor", "run_script", &json!({}))
            .expect_err("floor execute must refuse");
        assert_eq!(error.code, codes::TARGET_CAPABILITY);
        assert!(error.message.contains("does not declare the execute"));
        assert_eq!(fake.touches(), 0);
    }

    #[test]
    fn trait_default_observe_and_actuate_refuse_fail_closed() {
        // The fixture does not override observe/actuate: the
        // trait defaults must refuse with the capability code,
        // so an adapter that forgets a verb fails closed rather
        // than serving something undeclared.
        let (_registry, fake) = registry_with_floor();
        let error = fake
            .observe(&json!({}))
            .expect_err("default observe must refuse");
        assert_eq!(error.code, codes::TARGET_CAPABILITY);
        let error = fake
            .actuate(&json!({}))
            .expect_err("default actuate must refuse");
        assert_eq!(error.code, codes::TARGET_CAPABILITY);
        assert_eq!(fake.touches(), 0);
    }

    #[test]
    fn declared_ops_reach_the_adapter() {
        let (registry, fake) = registry_with_floor();
        let attached = registry.attach("FAKE-FLOOR").expect("attach is declared");
        assert_eq!(attached["attached"], true);
        let inspected = registry
            .inspect("fake-floor", &json!({}))
            .expect("inspect is declared");
        assert_eq!(inspected["windows"], json!([]));
        assert_eq!(fake.touches(), 2);
    }
}
