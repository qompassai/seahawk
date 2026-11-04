//! Tool-surface profiles (D-934): deterministic, launch-time
//! scoping of the tool surface a Seahawk process serves.
//!
//! The conformance loop's handshake budget (2,500 tokens of
//! tools/list payload, cl100k_base over the served array) is
//! broken by the full native surface alone (8 tools, 3,962
//! tokens at 1.0.0), because two native tools carry ~1.2k-token
//! contracts each (`seahawk_acquire`, `gui.act_verified`). A
//! profile selects which tool families a launch serves; the
//! default `core` profile serves only the standing operator
//! surface (broker status / surface / op-log) and measures
//! ~330 tokens.
//!
//! Resolution precedence (highest first): the `--profile`
//! command-line argument, then the `SEAHAWK_TOOL_PROFILE`
//! environment variable, then `tool_profile` in the `[server]`
//! section of the config file, then the default `core`.
//! Unknown pack names, empty segments, and `full` combined with
//! anything else are a typed startup error (fail-closed, listing
//! the valid packs) — never a silent fallback to `full`.
//!
//! Profiles decide what a launch *serves* — both tools/list and
//! tools/call scope to the profile, so a tool outside the
//! profile is unknown to the process, not merely unlisted.
//! `policy::decide` still decides what a served tool may *run*:
//! token authentication (guard), class gates, execute/actuate
//! default-deny, the acquisition allowlist, and the op log are
//! all untouched and compose exactly as before. The `full`
//! profile applies no filter: its served surface is the
//! unfiltered surface, byte-identical by construction.

use std::collections::BTreeSet;
use std::fmt;

/// The valid profile words, in the order error messages list
/// them: the two whole-surface words, then the packs in
/// alphabetical order.
pub const VALID_WORDS: &str = "core, full, acquire, broker, feedback, gui, vision";

/// Broker-core tool names: the standing operator surface. These
/// belong to no pack and are served under every profile,
/// including `core` itself. The names mirror the `NATIVE_*`
/// constants in `server.rs`; the coverage test there pins the
/// two together over the real tool constructors.
pub const CORE_TOOLS: [&str; 3] = ["seahawk_oplog", "seahawk_status", "seahawk_surface"];

/// The acquisition lane's one native verb (pack `acquire`).
pub const ACQUIRE_TOOL: &str = "seahawk_acquire";

/// The D-230 code-feedback tool (pack `feedback`).
pub const FEEDBACK_TOOL: &str = "code.feedback";

/// The three S5 broker-level vision tools (pack `vision`).
/// Per-app tools (`gui.<app>.observe` / `gui.<app>.actuate`)
/// belong to pack `gui` instead: they exist only for
/// operator-registered applications, a different family from
/// the broker-level verbs below.
pub const VISION_TOOLS: [&str; 3] = ["gui.act_verified", "gui.ground", "gui.observe"];

/// One combinable tool family. Every tool Seahawk can serve
/// belongs to exactly one pack or to the always-served core
/// (the coverage law, pinned by tests over the real surface
/// constructors in `server.rs`).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Pack {
    /// The acquisition lane's verb (`seahawk_acquire`).
    Acquire,
    /// Tools brokered from the downstream Epic editor surface.
    Broker,
    /// The D-230 `code.feedback` tool.
    Feedback,
    /// Per-app GUI tools from operator policy registrations
    /// (`gui.<app>.observe`, `gui.<app>.actuate`).
    Gui,
    /// The S5 broker-level vision tools (`gui.observe`,
    /// `gui.ground`, `gui.act_verified`).
    Vision,
}

impl Pack {
    /// Every pack, alphabetical by name — the canonical order
    /// for listings and for `ToolProfile::spec_string`.
    pub const ALL: [Pack; 5] = [
        Pack::Acquire,
        Pack::Broker,
        Pack::Feedback,
        Pack::Gui,
        Pack::Vision,
    ];

    /// The pack's profile word.
    pub fn name(self) -> &'static str {
        match self {
            Pack::Acquire => "acquire",
            Pack::Broker => "broker",
            Pack::Feedback => "feedback",
            Pack::Gui => "gui",
            Pack::Vision => "vision",
        }
    }

    /// Parses one profile word into a pack. `core` and `full`
    /// are whole-surface words, not packs, and parse to `None`
    /// here; `ToolProfile::parse` handles them.
    pub fn parse(word: &str) -> Option<Pack> {
        Pack::ALL.iter().find(|pack| pack.name() == word).copied()
    }
}

/// A malformed profile spec. Startup refuses with this message
/// (fail-closed): a typo must never silently widen or narrow
/// the served surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileError {
    message: String,
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProfileError {}

/// A resolved tool-surface profile: either the unfiltered
/// surface (`full`), or the always-served core plus a set of
/// packs. Construct via `parse`, `core`, or `full`; the
/// default is `core`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolProfile {
    full: bool,
    packs: BTreeSet<Pack>,
}

impl Default for ToolProfile {
    fn default() -> Self {
        Self::core()
    }
}

impl ToolProfile {
    /// The default profile: core only, no packs.
    pub fn core() -> Self {
        Self {
            full: false,
            packs: BTreeSet::new(),
        }
    }

    /// The unfiltered surface: every tool, exactly as a
    /// pre-profile build serves it.
    pub fn full() -> Self {
        Self {
            full: true,
            packs: BTreeSet::new(),
        }
    }

    /// Parses a profile spec: `core`, `full`, or a
    /// comma-separated list of pack names (`core` may appear in
    /// a list as an explicit no-op). Matching is exact — case,
    /// whitespace, and spelling all matter. Fail-closed: any
    /// deviation is a `ProfileError` naming the valid words.
    pub fn parse(spec: &str) -> Result<Self, ProfileError> {
        let invalid = |message: String| ProfileError { message };
        if spec.is_empty() {
            return Err(invalid(format!(
                "tool profile is empty (valid: {VALID_WORDS})"
            )));
        }
        let words: Vec<&str> = spec.split(',').collect();
        if words.iter().any(|word| word.is_empty()) {
            return Err(invalid(format!(
                "tool profile {spec:?} contains an empty pack name (valid: {VALID_WORDS})"
            )));
        }
        if words.contains(&"full") {
            if words.len() == 1 {
                return Ok(Self::full());
            }
            return Err(invalid(format!(
                "tool profile {spec:?} combines 'full' with other words; \
                 'full' stands alone (valid: {VALID_WORDS})"
            )));
        }
        let mut packs = BTreeSet::new();
        for word in words {
            if word == "core" {
                continue;
            }
            let Some(pack) = Pack::parse(word) else {
                return Err(invalid(format!(
                    "tool profile names unknown pack {word:?} (valid: {VALID_WORDS})"
                )));
            };
            packs.insert(pack);
        }
        Ok(Self { full: false, packs })
    }

    /// Whether this is the unfiltered profile.
    pub fn is_full(&self) -> bool {
        self.full
    }

    /// Whether the profile serves a whole pack.
    pub fn serves_pack(&self, pack: Pack) -> bool {
        self.full || self.packs.contains(&pack)
    }

    /// The pack a tool name belongs to, or `None` when the tool
    /// is broker core (always served). Classification is by the
    /// name families the surface is built from in `server.rs`:
    /// the native verbs, the `gui.` namespace (broker-level
    /// vision verbs first, then per-app tools), `code.feedback`,
    /// and — for every other name — the downstream brokered
    /// surface, which is the only remaining source of tools.
    /// Matching follows the server's own dispatch discipline:
    /// Seahawk-owned names compare case-insensitively, because
    /// `call_tool` dispatches them case-insensitively.
    pub fn pack_of(tool_name: &str) -> Option<Pack> {
        if CORE_TOOLS
            .iter()
            .any(|name| name.eq_ignore_ascii_case(tool_name))
        {
            return None;
        }
        if ACQUIRE_TOOL.eq_ignore_ascii_case(tool_name) {
            return Some(Pack::Acquire);
        }
        if FEEDBACK_TOOL.eq_ignore_ascii_case(tool_name) {
            return Some(Pack::Feedback);
        }
        if VISION_TOOLS
            .iter()
            .any(|name| name.eq_ignore_ascii_case(tool_name))
        {
            return Some(Pack::Vision);
        }
        if tool_name.len() >= 4 && tool_name[..4].eq_ignore_ascii_case("gui.") {
            return Some(Pack::Gui);
        }
        Some(Pack::Broker)
    }

    /// Whether this profile serves the named tool.
    pub fn serves_tool(&self, tool_name: &str) -> bool {
        match Self::pack_of(tool_name) {
            None => true,
            Some(pack) => self.serves_pack(pack),
        }
    }

    /// The canonical spec string for this profile (`core`,
    /// `full`, or the pack names comma-joined alphabetically) —
    /// what status surfaces report so the scoping is visible
    /// in-band.
    pub fn spec_string(&self) -> String {
        if self.full {
            return "full".to_string();
        }
        if self.packs.is_empty() {
            return "core".to_string();
        }
        self.packs
            .iter()
            .map(|pack| pack.name())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_full_and_packs() {
        assert_eq!(ToolProfile::parse("core"), Ok(ToolProfile::core()));
        assert_eq!(ToolProfile::parse("full"), Ok(ToolProfile::full()));
        let broker = ToolProfile::parse("broker").expect("broker");
        assert!(broker.serves_pack(Pack::Broker));
        assert!(!broker.serves_pack(Pack::Gui));
        let combo = ToolProfile::parse("gui,broker").expect("combo");
        assert!(combo.serves_pack(Pack::Gui));
        assert!(combo.serves_pack(Pack::Broker));
        // `core` inside a list is an explicit no-op.
        assert_eq!(ToolProfile::parse("core,broker"), Ok(broker));
        // Duplicate pack words collapse (set semantics).
        assert_eq!(
            ToolProfile::parse("broker,broker"),
            Ok(ToolProfile::parse("broker").expect("broker"))
        );
    }

    #[test]
    fn spec_string_is_canonical() {
        assert_eq!(ToolProfile::core().spec_string(), "core");
        assert_eq!(ToolProfile::full().spec_string(), "full");
        let combo = ToolProfile::parse("vision,acquire").expect("combo");
        assert_eq!(combo.spec_string(), "acquire,vision");
        // Round-trip: parse(spec_string(p)) == p for every shape.
        for spec in ["core", "full", "broker", "acquire,gui,vision"] {
            let profile = ToolProfile::parse(spec).expect(spec);
            assert_eq!(
                ToolProfile::parse(&profile.spec_string()),
                Ok(profile),
                "{spec}"
            );
        }
    }

    #[test]
    fn pack_table_is_alphabetical_and_complete() {
        let names: Vec<&str> = Pack::ALL.iter().map(|pack| pack.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        for pack in Pack::ALL {
            assert_eq!(Pack::parse(pack.name()), Some(pack));
        }
        // The whole-surface words are not packs.
        assert_eq!(Pack::parse("core"), None);
        assert_eq!(Pack::parse("full"), None);
    }

    #[test]
    fn core_serves_only_core_tools() {
        let core = ToolProfile::core();
        for name in CORE_TOOLS {
            assert!(core.serves_tool(name), "{name}");
        }
        for name in [
            ACQUIRE_TOOL,
            FEEDBACK_TOOL,
            "gui.observe",
            "gui.ground",
            "gui.act_verified",
            "gui.blender.observe",
            "gui.blender.actuate",
            "EditorToolset.EditorAppToolset.GetSelectedActors",
        ] {
            assert!(!core.serves_tool(name), "{name}");
        }
    }

    #[test]
    fn full_serves_everything() {
        let full = ToolProfile::full();
        for name in [
            "seahawk_status",
            ACQUIRE_TOOL,
            FEEDBACK_TOOL,
            "gui.act_verified",
            "gui.blender.actuate",
            "EditorToolset.EditorAppToolset.GetSelectedActors",
            "anything.at.all",
        ] {
            assert!(full.serves_tool(name), "{name}");
        }
    }

    #[test]
    fn each_pack_serves_exactly_its_family_plus_core() {
        let cases: [(&str, &str, &str); 5] = [
            ("acquire", ACQUIRE_TOOL, FEEDBACK_TOOL),
            ("broker", "EditorToolset.X.Y", ACQUIRE_TOOL),
            ("feedback", FEEDBACK_TOOL, "gui.observe"),
            ("gui", "gui.blender.actuate", "gui.observe"),
            ("vision", "gui.act_verified", "gui.blender.actuate"),
        ];
        for (spec, served, withheld) in cases {
            let profile = ToolProfile::parse(spec).expect(spec);
            assert!(profile.serves_tool(served), "{spec} serves {served}");
            assert!(
                !profile.serves_tool(withheld),
                "{spec} withholds {withheld}"
            );
            assert!(profile.serves_tool("seahawk_status"), "{spec} keeps core");
        }
    }

    #[test]
    fn classification_matches_dispatch_case_discipline() {
        // Seahawk-owned names dispatch case-insensitively, so a
        // case variant classifies with its canonical name — a
        // variant can never slip into a different family.
        assert_eq!(ToolProfile::pack_of("GUI.OBSERVE"), Some(Pack::Vision));
        assert_eq!(ToolProfile::pack_of("SeaHawk_Status"), None);
        assert_eq!(ToolProfile::pack_of("GUI.Blender.Actuate"), Some(Pack::Gui));
    }

    // -- adversarial: malformed specs fail closed ----------------

    #[test]
    fn unknown_pack_fails_closed_and_lists_valid() {
        let error = ToolProfile::parse("brokerr").expect_err("unknown pack");
        assert!(
            error.to_string().contains("unknown pack \"brokerr\""),
            "{error}"
        );
        assert!(error.to_string().contains(VALID_WORDS), "{error}");
        assert!(ToolProfile::parse("broker,visionn").is_err());
    }

    #[test]
    fn empty_and_blank_segments_fail_closed() {
        for spec in ["", ",", "broker,", ",broker", "broker,,gui"] {
            assert!(ToolProfile::parse(spec).is_err(), "{spec:?}");
        }
    }

    #[test]
    fn full_combined_fails_closed() {
        for spec in ["full,broker", "broker,full", "full,core", "full,full"] {
            assert!(ToolProfile::parse(spec).is_err(), "{spec:?}");
        }
    }

    #[test]
    fn matching_is_exact_case_and_whitespace() {
        for spec in ["Broker", "BROKER", " broker", "broker ", "core ", "Full"] {
            assert!(ToolProfile::parse(spec).is_err(), "{spec:?}");
        }
    }
}
