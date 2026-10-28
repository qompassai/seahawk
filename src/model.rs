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
    fn split_name_handles_qualified_and_bare() {
        assert_eq!(split_name("A.B.C"), ("A.B".to_string(), "C".to_string()));
        assert_eq!(split_name("Bare"), (String::new(), "Bare".to_string()));
    }
}
