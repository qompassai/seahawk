//! The server-side decision point, in the fleet mold: a pure
//! `decide()` over (tool class, policy, operator-token state) that
//! the handler calls for every brokered tool. Guard-level agent
//! authentication happens earlier (guard.rs); this module owns the
//! class gate and the execute gate.

use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::model::{ToolClass, ToolRecord};

/// Seahawk's typed refusal codes (carried in the `error.code` field
/// of the structured refusal result, fleet mold).
pub mod codes {
    pub const EXECUTE_DISABLED: &str = "seahawk_execute_disabled";
    pub const EXECUTE_NO_OPERATOR_TOKEN_CONFIGURED: &str = "seahawk_execute_no_operator_token";
    pub const ACTUATE_DISABLED: &str = "seahawk_actuate_disabled";
    pub const ACTUATE_NO_OPERATOR_TOKEN_CONFIGURED: &str = "seahawk_actuate_no_operator_token";
    pub const OPERATOR_REQUIRED: &str = "seahawk_operator_required";
    pub const UNCLASSIFIED: &str = "seahawk_unclassified";
    pub const UNKNOWN_TOOL: &str = "seahawk_unknown_tool";
    pub const GUI_UNAVAILABLE: &str = "seahawk_gui_unavailable";
    pub const GUI_NO_WINDOW: &str = "seahawk_gui_no_window";
    pub const GUI_UNKNOWN_ACTION: &str = "seahawk_gui_unknown_action";
    pub const GUI_ACTION_FAILED: &str = "seahawk_gui_action_failed";
    /// S5: the referenced screenshot is not in the broker's frame
    /// store (unknown digest, or evicted).
    pub const GUI_NO_FRAME: &str = "seahawk_gui_no_frame";
    /// S5: the grounder ran and reported no confident location
    /// (not found, or below the configured confidence floor).
    pub const GUI_GROUND_FAILED: &str = "seahawk_gui_ground_failed";
    /// S5: the requested grounding route is not available (no
    /// local vision grounder configured, or it cannot be reached).
    pub const GUI_GROUNDER_UNAVAILABLE: &str = "seahawk_gui_grounder_unavailable";
    /// S5: an actuation happened but the post-action verification
    /// did not observe the expected effect (bounded correction
    /// exhausted). The action is NOT silently retried further.
    pub const GUI_VERIFY_MISMATCH: &str = "seahawk_gui_verify_mismatch";
    /// S5: the requested verification check cannot be evaluated
    /// by the configured grounder route; the call is refused
    /// before acting rather than acting unverified.
    pub const GUI_VERIFY_UNAVAILABLE: &str = "seahawk_gui_verify_unavailable";
    /// S5 curative (C4): a frame captured for verification is
    /// (near-)uniform — an unpainted or crashed window — and so
    /// cannot verify anything; the act is refused rather than
    /// judged against a blank.
    pub const GUI_SUSPECT_BLANK: &str = "seahawk_gui_suspect_blank";
    /// S5 curative (C4): the caller pinned a `window_id` and the
    /// window that resolves now is a different one (or the pin
    /// no longer resolves) — never a silent re-match by title.
    pub const GUI_WINDOW_MISMATCH: &str = "seahawk_gui_window_mismatch";
    /// Wiring (D-230): no configured tooling route can serve a
    /// `code.feedback` check (server unconfigured, unspawned, or
    /// the language unpinned) — feedback reports unavailable,
    /// never an assumed-clean result.
    pub const TOOLING_UNAVAILABLE: &str = "seahawk_tooling_unavailable";
    /// Wiring (D-230): the feedback episode bound (3 calls per
    /// workspace+files window) is exhausted and the last result
    /// was still dirty — the caller must change strategy.
    pub const FEEDBACK_UNRESOLVED: &str = "seahawk_code_feedback_unresolved";
    /// Wiring (D-230): a file changed on disk while its feedback
    /// was being computed, and the re-check still diverges — the
    /// result would describe a file that no longer exists in
    /// that form.
    pub const FEEDBACK_STALE: &str = "seahawk_feedback_stale";
    pub const UNAUTHORIZED: &str = "seahawk_unauthorized";
    pub const DOWNSTREAM_UNAVAILABLE: &str = "seahawk_downstream_unavailable";
    pub const BAD_ARGUMENTS: &str = "seahawk_bad_arguments";
}

#[derive(Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Refuse { code: &'static str, message: String },
}

impl Decision {
    fn refuse(code: &'static str, message: String) -> Self {
        Self::Refuse { code, message }
    }
}

/// What the handler knows about the requested tool.
pub enum ToolKnowledge<'a> {
    /// Present downstream and classified.
    Classified(&'a ToolRecord),
    /// Present downstream but with no class: withheld by default.
    Unclassified,
}

/// Decides one brokered call.
///
/// - read/write: allowed (agent authentication already happened in
///   the guard).
/// - actuate/execute: allowed only when the operator enabled this
///   tool in policy AND a valid per-call operator token was
///   presented AND an operator token is configured at all. The
///   two classes share the two-key rule; only the enablement list
///   and the refusal codes differ.
/// - unclassified: always refused.
pub fn decide(knowledge: &ToolKnowledge<'_>, config: &Config, operator_token_ok: bool) -> Decision {
    let ToolKnowledge::Classified(record) = knowledge else {
        return Decision::refuse(
            codes::UNCLASSIFIED,
            "tool is not in Seahawk's class table; unclassified tools are \
             withheld by default — an operator can classify it via \
             policy.class_overrides"
                .to_string(),
        );
    };
    match record.class {
        ToolClass::Read | ToolClass::Write => Decision::Allow,
        ToolClass::Actuate => two_key_gate(
            config.actuate_is_enabled(&record.name),
            record,
            "actuate",
            "policy.actuate_enabled",
            codes::ACTUATE_DISABLED,
            codes::ACTUATE_NO_OPERATOR_TOKEN_CONFIGURED,
            config,
            operator_token_ok,
        ),
        ToolClass::Execute => two_key_gate(
            config.execute_is_enabled(&record.name),
            record,
            "execute",
            "policy.execute_enabled",
            codes::EXECUTE_DISABLED,
            codes::EXECUTE_NO_OPERATOR_TOKEN_CONFIGURED,
            config,
            operator_token_ok,
        ),
    }
}

/// The default-deny two-key gate shared by the actuate and execute
/// classes: per-tool policy enablement is the first key, a distinct
/// per-call operator token is the second. Neither key alone opens
/// the gate, and with no operator token configured the class is
/// impossible, not merely closed.
#[allow(clippy::too_many_arguments)]
fn two_key_gate(
    enabled: bool,
    record: &ToolRecord,
    class_word: &str,
    enablement_key: &str,
    disabled_code: &'static str,
    no_token_code: &'static str,
    config: &Config,
    operator_token_ok: bool,
) -> Decision {
    if !enabled {
        return Decision::refuse(
            disabled_code,
            format!(
                "{} is {class_word}-class and is not enabled in policy \
                 ({enablement_key}); {class_word}-class calls are default-deny",
                record.name
            ),
        );
    }
    if config.operator_token_digest.is_none() {
        return Decision::refuse(
            no_token_code,
            format!(
                "{} is enabled in policy but no operator token is \
                 configured (server.operator_token); {class_word} is \
                 impossible without one",
                record.name
            ),
        );
    }
    if !operator_token_ok {
        return Decision::refuse(
            codes::OPERATOR_REQUIRED,
            format!(
                "{} is {class_word}-class; the call must carry a valid \
                 operator token in _meta[\"seahawk/operator_token\"], \
                 distinct from the agent token",
                record.name
            ),
        );
    }
    Decision::Allow
}

/// Unknown-tool refusal (the name is not in the downstream surface
/// snapshot at all — including renamed tools, which are simply
/// unknown names).
pub fn unknown_tool(name: &str) -> Decision {
    Decision::refuse(
        codes::UNKNOWN_TOOL,
        format!("unknown tool {name:?}: not in Seahawk's downstream surface snapshot"),
    )
}

/// Constant-time token check: hashes the presented token and
/// compares digests byte-by-byte without early exit.
pub fn token_matches(presented: &str, expected_digest: &[u8; 32]) -> bool {
    let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= digest[i] ^ expected_digest[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ToolClass;
    use serde_json::json;

    fn record(name: &str, class: ToolClass) -> ToolRecord {
        let (toolset, short_name) = crate::model::split_name(name);
        ToolRecord {
            name: name.to_string(),
            toolset,
            short_name,
            description: String::new(),
            input_schema: json!({"type": "object"}),
            class,
        }
    }

    fn config(extra: &str) -> Config {
        Config::parse(&format!(
            "[server]\nagent_token = \"agent\"\noperator_token = \"operator\"\n{extra}"
        ))
        .expect("config")
    }

    const EXEC_TOOL: &str =
        "editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script";

    #[test]
    fn read_and_write_allow() {
        let cfg = config("");
        let read = record("A.B.Get", ToolClass::Read);
        let write = record("A.B.Set", ToolClass::Write);
        assert_eq!(
            decide(&ToolKnowledge::Classified(&read), &cfg, false),
            Decision::Allow
        );
        assert_eq!(
            decide(&ToolKnowledge::Classified(&write), &cfg, false),
            Decision::Allow
        );
    }

    #[test]
    fn unclassified_refuses() {
        let cfg = config("");
        match decide(&ToolKnowledge::Unclassified, &cfg, true) {
            Decision::Refuse { code, .. } => assert_eq!(code, codes::UNCLASSIFIED),
            Decision::Allow => panic!("unclassified must refuse"),
        }
    }

    #[test]
    fn execute_default_deny_even_with_operator_token() {
        let cfg = config("");
        let tool = record(EXEC_TOOL, ToolClass::Execute);
        match decide(&ToolKnowledge::Classified(&tool), &cfg, true) {
            Decision::Refuse { code, .. } => assert_eq!(code, codes::EXECUTE_DISABLED),
            Decision::Allow => panic!("execute must be default-deny"),
        }
    }

    #[test]
    fn execute_enabled_still_needs_operator_token() {
        let cfg = config(&format!("[policy]\nexecute_enabled = [\"{EXEC_TOOL}\"]\n"));
        let tool = record(EXEC_TOOL, ToolClass::Execute);
        match decide(&ToolKnowledge::Classified(&tool), &cfg, false) {
            Decision::Refuse { code, .. } => assert_eq!(code, codes::OPERATOR_REQUIRED),
            Decision::Allow => panic!("enabled execute without operator token must refuse"),
        }
        assert_eq!(
            decide(&ToolKnowledge::Classified(&tool), &cfg, true),
            Decision::Allow
        );
    }

    #[test]
    fn execute_enabled_but_no_operator_token_configured_is_impossible() {
        let cfg = Config::parse(&format!(
            "[server]\nagent_token = \"agent\"\n[policy]\nexecute_enabled = [\"{EXEC_TOOL}\"]\n"
        ))
        .expect("config");
        let tool = record(EXEC_TOOL, ToolClass::Execute);
        match decide(&ToolKnowledge::Classified(&tool), &cfg, false) {
            Decision::Refuse { code, .. } => {
                assert_eq!(code, codes::EXECUTE_NO_OPERATOR_TOKEN_CONFIGURED)
            }
            Decision::Allow => panic!("execute without any operator token configured must refuse"),
        }
    }

    const ACTUATE_TOOL: &str = "gui.blender.actuate";

    #[test]
    fn actuate_default_deny_even_with_operator_token() {
        let cfg = config("");
        let tool = record(ACTUATE_TOOL, ToolClass::Actuate);
        match decide(&ToolKnowledge::Classified(&tool), &cfg, true) {
            Decision::Refuse { code, .. } => assert_eq!(code, codes::ACTUATE_DISABLED),
            Decision::Allow => panic!("actuate must be default-deny"),
        }
    }

    #[test]
    fn actuate_enabled_still_needs_operator_token() {
        let cfg = config(&format!(
            "[policy]\nactuate_enabled = [\"{ACTUATE_TOOL}\"]\n"
        ));
        let tool = record(ACTUATE_TOOL, ToolClass::Actuate);
        match decide(&ToolKnowledge::Classified(&tool), &cfg, false) {
            Decision::Refuse { code, .. } => assert_eq!(code, codes::OPERATOR_REQUIRED),
            Decision::Allow => panic!("enabled actuate without operator token must refuse"),
        }
        assert_eq!(
            decide(&ToolKnowledge::Classified(&tool), &cfg, true),
            Decision::Allow
        );
    }

    #[test]
    fn actuate_enablement_does_not_cross_classes() {
        // Enabling an actuate tool must not enable an execute tool
        // of a similar name, and vice versa: the enablement lists
        // are per-class keys.
        let cfg = config(&format!(
            "[policy]\nactuate_enabled = [\"{ACTUATE_TOOL}\"]\n"
        ));
        let exec_tool = record(ACTUATE_TOOL, ToolClass::Execute);
        match decide(&ToolKnowledge::Classified(&exec_tool), &cfg, true) {
            Decision::Refuse { code, .. } => assert_eq!(code, codes::EXECUTE_DISABLED),
            Decision::Allow => panic!("actuate enablement leaked into execute"),
        }
        let cfg = config(&format!(
            "[policy]\nexecute_enabled = [\"{ACTUATE_TOOL}\"]\n"
        ));
        let actuate_tool = record(ACTUATE_TOOL, ToolClass::Actuate);
        match decide(&ToolKnowledge::Classified(&actuate_tool), &cfg, true) {
            Decision::Refuse { code, .. } => assert_eq!(code, codes::ACTUATE_DISABLED),
            Decision::Allow => panic!("execute enablement leaked into actuate"),
        }
    }

    #[test]
    fn actuate_enabled_but_no_operator_token_configured_is_impossible() {
        let cfg = Config::parse(&format!(
            "[server]\nagent_token = \"agent\"\n[policy]\nactuate_enabled = [\"{ACTUATE_TOOL}\"]\n"
        ))
        .expect("config");
        let tool = record(ACTUATE_TOOL, ToolClass::Actuate);
        match decide(&ToolKnowledge::Classified(&tool), &cfg, false) {
            Decision::Refuse { code, .. } => {
                assert_eq!(code, codes::ACTUATE_NO_OPERATOR_TOKEN_CONFIGURED)
            }
            Decision::Allow => panic!("actuate without any operator token configured must refuse"),
        }
    }

    #[test]
    fn token_matches_is_exact() {
        let cfg = config("");
        assert!(token_matches("agent", &cfg.agent_token_digest));
        assert!(!token_matches("Agent", &cfg.agent_token_digest));
        assert!(!token_matches("agent ", &cfg.agent_token_digest));
        assert!(!token_matches("", &cfg.agent_token_digest));
    }
}
