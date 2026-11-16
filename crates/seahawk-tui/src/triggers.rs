//! The D4 trigger-rule surface for Seahawk.
//!
//! **Rung-1 ruling (task brief): no outbound trigger rules
//! tonight.** Broker events feeding other MCPs is a design
//! question for the Owner, so this module ships the *surface*
//! — the typed rule shape from DESIGN §D4, the loader, the
//! bounded audit log, and the Fleet-panel data — with an empty
//! rule set by design. A `triggers.toml` the operator writes is
//! loaded and *displayed*; rung 1 evaluates nothing and fires
//! nothing, and the panel says exactly that. A rule that is not
//! listed does not exist (DESIGN §D4, no hidden behaviour).

use std::collections::VecDeque;
use std::path::Path;

use serde::Deserialize;

/// Maximum rules loaded from one `triggers.toml`.
pub const TRIGGER_RULES_MAX: usize = 64;
/// Maximum audit lines retained in memory.
pub const AUDIT_LINES_MAX: usize = 256;
/// Maximum bytes of one `triggers.toml`.
pub const TRIGGER_FILE_BYTES_MAX: usize = 65_536;

/// One declared rule, in the DESIGN §D4 shape.
#[derive(Clone, Debug, PartialEq)]
pub struct TriggerRule {
    /// Rule id, unique in the file.
    pub id: String,
    /// BLOCH lane stamp, from birth (D-1030).
    pub origin_lane: String,
    /// `sfw` / `nsfw` content label, from birth.
    pub content_label: String,
    /// Event name that would trigger evaluation.
    pub on_event: String,
    /// Bounded predicate text, displayed verbatim.
    pub on_where: String,
    /// Target MCP server name.
    pub target_mcp: String,
    /// Target tool name.
    pub target_tool: String,
    /// `auto` or `plan` as declared.
    pub mode: String,
    /// Declared maximum trigger depth (hard ceiling 2 in D4).
    pub max_depth: u32,
}

#[derive(Debug, Deserialize)]
struct TriggerFile {
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    id: String,
    #[serde(default = "default_origin_lane")]
    origin_lane: String,
    #[serde(default = "default_content_label")]
    content_label: String,
    on: RawOn,
    then: RawThen,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default = "default_max_depth")]
    max_depth: u32,
}

fn default_origin_lane() -> String {
    "qompass".to_string()
}

fn default_content_label() -> String {
    "sfw".to_string()
}

fn default_mode() -> String {
    "plan".to_string()
}

fn default_max_depth() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
struct RawOn {
    event: String,
    #[serde(default, rename = "where")]
    where_clause: String,
}

#[derive(Debug, Deserialize)]
struct RawThen {
    mcp: String,
    tool: String,
}

/// The loaded rule set plus its provenance.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TriggerLoad {
    /// Rules in file order, bounded to [`TRIGGER_RULES_MAX`].
    pub rules: Vec<TriggerRule>,
    /// Where the rules came from (a path, or the empty-by-design
    /// explanation).
    pub source: String,
    /// A load error, when the file existed but did not parse.
    pub error: Option<String>,
    /// Whether evaluation is enabled. Always `false` in rung 1.
    pub evaluation_enabled: bool,
}

/// Load trigger rules from `path`.
///
/// - No path, or a path that does not exist: the empty-by-design
///   set — this is the rung-1 normal case, not an error.
/// - A file that exists but is oversized or unparseable: empty
///   rules plus a recorded error, so the Fleet panel shows the
///   failure instead of silently pretending there are no rules.
pub fn load_trigger_rules(path: Option<&Path>) -> TriggerLoad {
    let empty = TriggerLoad {
        rules: Vec::new(),
        source: "none — no triggers.toml (empty by design: rung 1 ships no outbound \
                 rules; broker events feeding other MCPs is an Owner design question)"
            .to_string(),
        error: None,
        evaluation_enabled: false,
    };
    let Some(path) = path else {
        return empty;
    };
    if !path.exists() {
        return empty;
    }
    let failed = |message: String| TriggerLoad {
        rules: Vec::new(),
        source: format!("{} (failed to load)", path.display()),
        error: Some(message),
        evaluation_enabled: false,
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => return failed(format!("reading {}: {error}", path.display())),
    };
    if text.len() > TRIGGER_FILE_BYTES_MAX {
        return failed(format!(
            "triggers file is {} bytes, over TRIGGER_FILE_BYTES_MAX {TRIGGER_FILE_BYTES_MAX}",
            text.len()
        ));
    }
    let parsed: TriggerFile = match toml::from_str(&text) {
        Ok(parsed) => parsed,
        Err(error) => return failed(format!("parsing {}: {error}", path.display())),
    };
    let mut rules: Vec<TriggerRule> = parsed
        .rule
        .into_iter()
        .map(|raw| TriggerRule {
            id: raw.id,
            origin_lane: raw.origin_lane,
            content_label: raw.content_label,
            on_event: raw.on.event,
            on_where: raw.on.where_clause,
            target_mcp: raw.then.mcp,
            target_tool: raw.then.tool,
            mode: raw.mode,
            max_depth: raw.max_depth.min(2),
        })
        .collect();
    rules.truncate(TRIGGER_RULES_MAX);
    TriggerLoad {
        rules,
        source: path.display().to_string(),
        error: None,
        evaluation_enabled: false,
    }
}

/// The bounded trigger audit log. Rung 1 records evaluations of
/// the TUI's own staging gate (notably execute-class auto
/// refusals) so the Fleet panel's audit tail is real, local, and
/// honest about its scope: these are TUI-local audit lines, not
/// broker op-log entries.
#[derive(Clone, Debug, Default)]
pub struct TriggerAudit {
    lines: VecDeque<String>,
}

impl TriggerAudit {
    /// An empty audit log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one line, evicting the oldest beyond the bound.
    pub fn push(&mut self, line: String) {
        if self.lines.len() >= AUDIT_LINES_MAX {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    /// The retained lines, oldest first.
    pub fn lines(&self) -> impl Iterator<Item = &String> {
        self.lines.iter()
    }

    /// Number of retained lines.
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_file_is_empty_by_design_not_an_error() {
        let load = load_trigger_rules(None);
        assert!(load.rules.is_empty());
        assert!(load.error.is_none());
        assert!(!load.evaluation_enabled);
        assert!(load.source.contains("empty by design"));
        let missing = load_trigger_rules(Some(Path::new("/nonexistent/triggers.toml")));
        assert!(missing.rules.is_empty());
        assert!(missing.error.is_none());
    }

    #[test]
    fn declared_rules_load_with_birth_stamps_and_depth_clamped() {
        let dir =
            std::env::temp_dir().join(format!("seahawk-tui-triggers-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("triggers.toml");
        std::fs::write(
            &path,
            concat!(
                "[[rule]]\n",
                "id = \"hypothetical\"\n",
                "origin_lane = \"qompass\"\n",
                "content_label = \"sfw\"\n",
                "on = { event = \"workflow.completed\", where = \"error_count > 0\" }\n",
                "then = { mcp = \"bloch\", tool = \"lesson_candidate\" }\n",
                "mode = \"plan\"\n",
                "max_depth = 9\n",
            ),
        )
        .expect("write");
        let load = load_trigger_rules(Some(&path));
        assert_eq!(load.rules.len(), 1);
        assert_eq!(load.rules[0].origin_lane, "qompass");
        assert_eq!(load.rules[0].content_label, "sfw");
        assert_eq!(load.rules[0].max_depth, 2, "hard ceiling 2 (D4)");
        // Even with a declared rule, rung 1 evaluates nothing.
        assert!(!load.evaluation_enabled);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn malformed_file_records_error_instead_of_silence() {
        let dir =
            std::env::temp_dir().join(format!("seahawk-tui-triggers-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("triggers.toml");
        std::fs::write(&path, "this is not [ valid toml").expect("write");
        let load = load_trigger_rules(Some(&path));
        assert!(load.rules.is_empty());
        assert!(load.error.is_some());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn audit_log_is_bounded() {
        let mut audit = TriggerAudit::new();
        for index in 0..(AUDIT_LINES_MAX + 10) {
            audit.push(format!("line {index}"));
        }
        assert_eq!(audit.len(), AUDIT_LINES_MAX);
        assert_eq!(audit.lines().next().map(String::as_str), Some("line 10"));
    }
}
