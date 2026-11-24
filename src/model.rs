//! Shared types: tool classes, the compiled-in class table, and the
//! downstream surface snapshot.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Serialize;
use serde_json::Value;

/// What a brokered tool is allowed to do. Classification comes from
/// the S0 census table (SURFACE.md §4–5) refined by operator policy,
/// or — for Seahawk's built-in GUI tools (S4) — by construction.
///
/// The class lattice is `Read < Write < Actuate < Execute`
/// (GATE-REPORT S4 design): classification follows *reach*, not
/// mechanism — a tool whose effects can reach code execution is
/// execute even when its mechanism is GUI input (Epic's Slate
/// inspector tools are the measured example and stay execute).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolClass {
    /// No state change. GUI observation (screenshots, window lists,
    /// focus state) is read.
    Read,
    /// Mutates editor/project state inside the editor's domain model.
    Write,
    /// Injects input events or window operations into a GUI
    /// application (click, key, text entry, drag, scroll, focus,
    /// resize). Changes GUI state but invokes no code-execution
    /// primitive directly. Default-deny, gated exactly like
    /// execute (policy enablement + per-call operator token) —
    /// see policy.rs. Operators should weigh that actuation into
    /// an application that itself hosts scripting can compose
    /// into code execution through the UI; the class records the
    /// mechanism, the two-key gate prices the risk.
    Actuate,
    /// Runs code, loads code, writes arbitrary files, mutates the
    /// environment, injects UI input, persists agent instructions, or
    /// starts a session that runs project logic.
    Execute,
}

impl ToolClass {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "actuate" => Some(Self::Actuate),
            "execute" => Some(Self::Execute),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Actuate => "actuate",
            Self::Execute => "execute",
        }
    }

    /// Position in the class lattice: read 0 < write 1 < actuate 2
    /// < execute 3. A provider tool that can reach a higher class
    /// is classified at the higher class.
    pub fn rank(&self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Actuate => 2,
            Self::Execute => 3,
        }
    }
}

/// One GUI application registered by the operator in policy (S4).
/// Registrations exist only as policy data: Seahawk exposes
/// `gui.<name>.observe` and `gui.<name>.actuate` for each, and
/// there is deliberately no runtime registration path.
#[derive(Clone, Debug)]
pub struct GuiApp {
    /// Registration name, validated in config: lowercase ASCII
    /// letters/digits/`-`/`_`, starting with a letter. Tool names
    /// are built from it, so it is kept identifier-safe.
    pub name: String,
    /// Human-facing name for tool descriptions.
    pub display_name: String,
    /// Window match strings: a window belongs to this app when any
    /// string equals its WM_CLASS class or instance
    /// (case-insensitive) or appears in its window title
    /// (case-insensitive substring). Title matching is what reaches
    /// browser-hosted GUIs such as ComfyUI.
    pub window_match: Vec<String>,
}

impl GuiApp {
    /// The observe (read-class) tool name for this app.
    pub fn observe_tool(&self) -> String {
        format!("gui.{}.observe", self.name)
    }

    /// The actuate (actuate-class) tool name for this app.
    pub fn actuate_tool(&self) -> String {
        format!("gui.{}.actuate", self.name)
    }
}

/// The S0 class table: qualified tool name → class, compiled in from
/// `assets/default_classes.json` (830 tools at build time; the census
/// and reasoning live in SURFACE.md and `s0-evidence/classes.json`).
static DEFAULT_CLASSES_JSON: &str = include_str!("../assets/default_classes.json");

/// Case-insensitive lookup: downstream tool lookup is case-insensitive
/// (SURFACE.md §2), so the table must be too — keys are stored
/// lowercased and lookups lowercase the query.
static DEFAULT_CLASSES: LazyLock<HashMap<String, ToolClass>> = LazyLock::new(|| {
    let raw: HashMap<String, String> = serde_json::from_str(DEFAULT_CLASSES_JSON)
        .expect("compiled-in default class table must parse");
    raw.into_iter()
        .map(|(name, class)| {
            let class = ToolClass::parse(&class)
                .expect("compiled-in default class table holds valid classes");
            (name.to_lowercase(), class)
        })
        .collect()
});

/// The compiled-in class of a tool, if the S0 census classified it.
pub fn default_class(tool_name: &str) -> Option<ToolClass> {
    DEFAULT_CLASSES.get(&tool_name.to_lowercase()).copied()
}

/// The Blender stroke provider's class table (DESIGN §1 +
/// DESIGN-ANIM §2): the twenty-five `blender.*` tools and their
/// classes — the twelve v1 stroke ops plus the thirteen v2
/// animation ops (pose/curve/take capture+apply, GP frame
/// ranges, take render/contact sheet/bake/export). Unlike the UE
/// surface there is no census — the downstream is authored by
/// the estate, so this table *is* the surface definition, and
/// `server.rs` builds the served tools from exactly these names.
/// Classification follows reach (DESIGN §1): reads observe or
/// compute purely, writes mutate editor-domain state in memory,
/// executes touch the filesystem. No blender tool is
/// actuate-class: the data provider never injects input.
pub const BLENDER_CLASSES: [(&str, ToolClass); 25] = [
    ("blender.session_status", ToolClass::Read),
    ("blender.scene_census", ToolClass::Read),
    ("blender.gp_capture", ToolClass::Read),
    ("blender.artifact_validate", ToolClass::Read),
    ("blender.gp_replay", ToolClass::Write),
    ("blender.paint_apply", ToolClass::Write),
    ("blender.stroke_to_shell", ToolClass::Write),
    ("blender.shells_along_flow", ToolClass::Write),
    ("blender.image_export_png", ToolClass::Execute),
    ("blender.proof_render", ToolClass::Execute),
    ("blender.blend_save", ToolClass::Execute),
    ("blender.scene_open", ToolClass::Execute),
    // DESIGN-ANIM §2, ops 13–25: classification follows reach,
    // as in v1 — captures and validation observe or compute
    // purely, applies mutate editor-domain state in memory,
    // renders/sheets/bakes/exports touch the filesystem or run
    // the whole dependency graph. None is actuate-class.
    ("blender.pose_capture", ToolClass::Read),
    ("blender.pose_apply", ToolClass::Write),
    ("blender.curve_capture", ToolClass::Read),
    ("blender.curve_apply", ToolClass::Write),
    ("blender.take_capture", ToolClass::Read),
    ("blender.take_apply", ToolClass::Write),
    ("blender.take_validate", ToolClass::Read),
    ("blender.gp_capture_range", ToolClass::Read),
    ("blender.gp_replay_range", ToolClass::Write),
    ("blender.take_render", ToolClass::Execute),
    ("blender.contact_sheet", ToolClass::Execute),
    ("blender.sim_bake", ToolClass::Execute),
    ("blender.take_export", ToolClass::Execute),
];

/// The compiled-in class of a `blender.*` tool, if the name is
/// one of the twenty-five provider tools (case-insensitive, matching
/// the server's dispatch discipline for Seahawk-owned names).
pub fn blender_class(tool_name: &str) -> Option<ToolClass> {
    BLENDER_CLASSES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(tool_name))
        .map(|(_, class)| *class)
}

/// The canonical names of the twenty-five provider tools, in
/// table order.
pub fn blender_tool_names() -> Vec<&'static str> {
    BLENDER_CLASSES.iter().map(|(name, _)| *name).collect()
}

/// The Unity adapter's class table (generalization, 2026-11-24):
/// the four `unity.*` tools. Like the Blender table there is no
/// census — the adapter is authored by the estate, so this
/// table *is* the surface definition. Classification follows
/// reach: status/projects/inspect observe, and `run_method`
/// executes project code inside an Editor, so it is
/// execute-class and carries the two-key rule.
pub const UNITY_CLASSES: [(&str, ToolClass); 4] = [
    ("unity.status", ToolClass::Read),
    ("unity.projects", ToolClass::Read),
    ("unity.inspect", ToolClass::Read),
    ("unity.run_method", ToolClass::Execute),
];

/// The compiled-in class of a `unity.*` tool (case-insensitive).
pub fn unity_class(tool_name: &str) -> Option<ToolClass> {
    UNITY_CLASSES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(tool_name))
        .map(|(_, class)| *class)
}

/// The canonical names of the four Unity tools, in table order.
pub fn unity_tool_names() -> Vec<&'static str> {
    UNITY_CLASSES.iter().map(|(name, _)| *name).collect()
}

/// The Godot adapter's class table (generalization,
/// 2026-11-24): the three `godot.*` tools, estate-authored
/// like the Unity table. `run_script` executes project code in
/// the engine, so it is execute-class.
pub const GODOT_CLASSES: [(&str, ToolClass); 3] = [
    ("godot.status", ToolClass::Read),
    ("godot.inspect", ToolClass::Read),
    ("godot.run_script", ToolClass::Execute),
];

/// The compiled-in class of a `godot.*` tool (case-insensitive).
pub fn godot_class(tool_name: &str) -> Option<ToolClass> {
    GODOT_CLASSES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(tool_name))
        .map(|(_, class)| *class)
}

/// The canonical names of the three Godot tools, in table
/// order.
pub fn godot_tool_names() -> Vec<&'static str> {
    GODOT_CLASSES.iter().map(|(name, _)| *name).collect()
}

/// The generic-GUI floor's class table (generalization,
/// 2026-11-24): the three `gui.floor_*` tools. Window lists and
/// screenshots observe (read); injected input is actuate-class
/// and carries the two-key rule, exactly like the per-app
/// `gui.<app>.actuate` tools.
pub const FLOOR_CLASSES: [(&str, ToolClass); 3] = [
    ("gui.floor_windows", ToolClass::Read),
    ("gui.floor_screenshot", ToolClass::Read),
    ("gui.floor_act", ToolClass::Actuate),
];

/// The compiled-in class of a floor tool (case-insensitive).
pub fn floor_class(tool_name: &str) -> Option<ToolClass> {
    FLOOR_CLASSES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(tool_name))
        .map(|(_, class)| *class)
}

/// The canonical names of the three floor tools, in table
/// order.
pub fn floor_tool_names() -> Vec<&'static str> {
    FLOOR_CLASSES.iter().map(|(name, _)| *name).collect()
}

/// One brokered tool as discovered downstream, with its class
/// already decided (policy overrides applied at surface build).
#[derive(Clone, Debug)]
pub struct ToolRecord {
    /// Fully-qualified downstream name, canonical casing, e.g.
    /// `EditorToolset.EditorAppToolset.GetSelectedActors`.
    pub name: String,
    /// The toolset part of `name` (everything before the last dot).
    pub toolset: String,
    /// The tool part of `name` (after the last dot); `call_tool`
    /// wants the name without the toolset prefix.
    pub short_name: String,
    pub description: String,
    pub input_schema: Value,
    pub class: ToolClass,
}

/// A snapshot of the downstream surface, built when a downstream
/// session is established: every toolset that described cleanly,
/// classified. Tools present downstream but absent from the class
/// table never appear here — `unclassified_names` records them so
/// the operator can see what was withheld.
#[derive(Clone, Debug, Default)]
pub struct Surface {
    pub tools: Vec<ToolRecord>,
    /// Toolsets whose describe did not parse as a toolset document
    /// (Epic's list output mentions some tool names in prose; they
    /// are not toolsets).
    pub skipped_toolsets: Vec<String>,
    /// Qualified names of tools that appear downstream but have no
    /// class (not in the S0 table, no policy override). Withheld
    /// from agents; calls to them are refused as unclassified.
    pub unclassified_names: Vec<String>,
}

impl Surface {
    /// Case-insensitive tool lookup (mirrors downstream semantics).
    pub fn find(&self, name: &str) -> Option<&ToolRecord> {
        let needle = name.to_lowercase();
        self.tools.iter().find(|t| t.name.to_lowercase() == needle)
    }

    pub fn count(&self, class: ToolClass) -> usize {
        self.tools.iter().filter(|t| t.class == class).count()
    }
}

/// Splits a fully-qualified tool name into (toolset, short name).
pub fn split_name(qualified: &str) -> (String, String) {
    match qualified.rfind('.') {
        Some(idx) => (
            qualified[..idx].to_string(),
            qualified[idx + 1..].to_string(),
        ),
        None => (String::new(), qualified.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_table_loads_and_covers_the_census_centerpiece() {
        // The S0 centerpiece must be execute, and lookup must be
        // case-insensitive like the downstream's.
        let centerpiece =
            "editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script";
        assert_eq!(default_class(centerpiece), Some(ToolClass::Execute));
        assert_eq!(
            default_class(&centerpiece.to_uppercase()),
            Some(ToolClass::Execute)
        );
        assert_eq!(
            default_class("EditorToolset.EditorAppToolset.GetSelectedActors"),
            Some(ToolClass::Read)
        );
        assert_eq!(default_class("NoSuch.Toolset.Nope"), None);
    }

    #[test]
    fn class_lattice_orders_read_write_actuate_execute() {
        assert!(ToolClass::Read < ToolClass::Write);
        assert!(ToolClass::Write < ToolClass::Actuate);
        assert!(ToolClass::Actuate < ToolClass::Execute);
        assert_eq!(ToolClass::parse("actuate"), Some(ToolClass::Actuate));
        assert_eq!(ToolClass::Actuate.as_str(), "actuate");
        assert_eq!(ToolClass::Actuate.rank(), 2);
    }

    #[test]
    fn gui_app_tool_names_are_prefixed_and_stable() {
        let app = GuiApp {
            name: "blender".to_string(),
            display_name: "Blender".to_string(),
            window_match: vec!["Blender".to_string()],
        };
        assert_eq!(app.observe_tool(), "gui.blender.observe");
        assert_eq!(app.actuate_tool(), "gui.blender.actuate");
    }

    #[test]
    fn blender_class_table_matches_the_design_surface() {
        // DESIGN §1 + DESIGN-ANIM §2: twenty-five ops, nine
        // read / eight write / eight execute, none actuate.
        assert_eq!(BLENDER_CLASSES.len(), 25);
        let count = |class: ToolClass| BLENDER_CLASSES.iter().filter(|(_, c)| *c == class).count();
        assert_eq!(count(ToolClass::Read), 9);
        assert_eq!(count(ToolClass::Write), 8);
        assert_eq!(count(ToolClass::Execute), 8);
        assert_eq!(count(ToolClass::Actuate), 0);
        assert_eq!(
            blender_class("blender.blend_save"),
            Some(ToolClass::Execute)
        );
        assert_eq!(blender_class("BLENDER.PAINT_APPLY"), Some(ToolClass::Write));
        assert_eq!(blender_class("blender.nope"), None);
        assert_eq!(blender_class("gui.blender.actuate"), None);
    }

    #[test]
    fn target_adapter_class_tables_match_their_surfaces() {
        // Generalization (2026-11-24): the estate-authored
        // adapter tables. Execution verbs are execute-class;
        // the floor's input verb is actuate; nothing else in
        // these tables mutates.
        assert_eq!(UNITY_CLASSES.len(), 4);
        assert_eq!(unity_class("unity.run_method"), Some(ToolClass::Execute));
        assert_eq!(unity_class("UNITY.STATUS"), Some(ToolClass::Read));
        assert_eq!(unity_class("unity.eval"), None);
        assert_eq!(unity_tool_names().len(), 4);
        assert_eq!(GODOT_CLASSES.len(), 3);
        assert_eq!(godot_class("godot.run_script"), Some(ToolClass::Execute));
        assert_eq!(godot_class("godot.inspect"), Some(ToolClass::Read));
        assert_eq!(godot_class("godot.nope"), None);
        assert_eq!(FLOOR_CLASSES.len(), 3);
        assert_eq!(floor_class("gui.floor_act"), Some(ToolClass::Actuate));
        assert_eq!(floor_class("gui.floor_windows"), Some(ToolClass::Read));
        assert_eq!(floor_class("gui.floor_screenshot"), Some(ToolClass::Read));
        // The floor table must not swallow per-app GUI tools.
        assert_eq!(floor_class("gui.blender.actuate"), None);
        assert_eq!(floor_tool_names().len(), 3);
    }

    #[test]
    fn split_name_handles_qualified_and_bare() {
        assert_eq!(split_name("A.B.C"), ("A.B".to_string(), "C".to_string()));
        assert_eq!(split_name("Bare"), (String::new(), "Bare".to_string()));
    }
}
