//! Seahawk configuration: policy as data.
//!
//! Example:
//!
//! ```toml
//! [server]
//! agent_token = "…"        # required, non-empty
//! operator_token = "…"     # optional; without it execute is impossible
//! require_token_for_list = false
//!
//! [downstream]
//! url = "http://127.0.0.1:8123/mcp"   # loopback only, enforced
//! timeout_secs = 120
//!
//! [policy]
//! execute_enabled = ["AutomationTestToolset.AutomationTestToolset.RunTests"]
//! actuate_enabled = ["gui.blender.actuate"]
//! class_overrides = { "Some.Toolset.Tool" = "write" }
//!
//! [[gui.apps]]
//! name = "blender"
//! display_name = "Blender"
//! window_match = ["Blender"]
//!
//! [vision]
//! grounder = "ollama"          # ollama | agent | none
//! ollama_url = "http://127.0.0.1:11434"   # loopback only
//! ollama_model = "hf-glimmer-30b-vision:latest"
//! min_confidence = 0.5
//!
//! [oplog]
//! path = "seahawk-oplog.jsonl"
//! ```
//!
//! The config is read exactly once, at startup, and is never
//! re-read: editing the file under a running server changes
//! nothing until a restart, at which point the edit *is* the
//! operator's policy (the operator is the trust root for this
//! file — see GATE-REPORT-S4 §S4.3 for the tamper posture).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::model::{GuiApp, ToolClass};

pub const DEFAULT_DOWNSTREAM_TIMEOUT_SECS: u64 = 120;
pub const MAX_DOWNSTREAM_TIMEOUT_SECS: u64 = 3600;
/// Bounds for GUI registrations (S4): policy data is operator
/// input, but it is still validated and bounded before use.
pub const MAX_GUI_APPS: usize = 32;
pub const MAX_GUI_APP_NAME_CHARS: usize = 32;
pub const MAX_WINDOW_MATCHES_PER_APP: usize = 8;
pub const MAX_WINDOW_MATCH_CHARS: usize = 128;

#[derive(Debug, Deserialize)]
struct RawConfig {
    server: RawServer,
    #[serde(default)]
    downstream: RawDownstream,
    #[serde(default)]
    policy: RawPolicy,
    #[serde(default)]
    gui: RawGui,
    #[serde(default)]
    vision: RawVision,
    #[serde(default)]
    tooling: Vec<RawTooling>,
    #[serde(default)]
    feedback: RawFeedback,
    #[serde(default)]
    oplog: RawOplog,
}

/// The S5 vision-grounder route (policy data, read once at
/// startup like everything else). `agent` is the protocol route:
/// the calling agent answers grounding requests itself, so it
/// needs no configuration and is available unless the operator
/// sets `grounder = "none"`. `ollama` is a local vision model
/// served over loopback HTTP — the broker is model-agnostic; the
/// model choice is the operator's, benchmarked in GATE-REPORT-S5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VisionRoute {
    /// Local model via Ollama's loopback HTTP API.
    Ollama,
    /// The calling agent supplies coordinates through the
    /// `gui.ground` ticket protocol.
    Agent,
    /// Grounding is disabled: `gui.ground` refuses, and
    /// `gui.act_verified` accepts raw coordinates only.
    None,
}

#[derive(Debug, Default, Deserialize)]
struct RawVision {
    #[serde(default)]
    grounder: Option<String>,
    #[serde(default)]
    ollama_url: Option<String>,
    #[serde(default)]
    ollama_model: Option<String>,
    #[serde(default)]
    min_confidence: Option<f64>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

/// Validated S5 vision configuration.
#[derive(Clone, Debug)]
pub struct VisionConfig {
    pub route: VisionRoute,
    /// Loopback Ollama base URL (route Ollama only).
    pub ollama_url: String,
    /// Model name served by Ollama (route Ollama only).
    pub ollama_model: String,
    /// Grounding hits below this confidence are refused
    /// (`seahawk_gui_ground_failed`) rather than acted on.
    pub min_confidence: f64,
    /// Per-request grounder timeout, seconds.
    pub timeout_secs: u64,
}

impl Default for VisionConfig {
    fn default() -> Self {
        Self {
            route: VisionRoute::Agent,
            ollama_url: "http://127.0.0.1:11434".to_string(),
            ollama_model: String::new(),
            min_confidence: DEFAULT_MIN_CONFIDENCE,
            timeout_secs: DEFAULT_VISION_TIMEOUT_SECS,
        }
    }
}

pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.5;
pub const DEFAULT_VISION_TIMEOUT_SECS: u64 = 120;
pub const MAX_VISION_TIMEOUT_SECS: u64 = 600;

/// One `[[tooling]]` entry (D-230 wiring): a stdio MCP server
/// Seahawk acts as a *client* of for `code.feedback`. Entries
/// are operator policy data — the shipped example config carries
/// the section commented out; wiring is opt-in per deployment.
#[derive(Debug, Deserialize)]
struct RawTooling {
    id: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    /// Theodolite only: file extension → theodolite server id
    /// that answers diagnostics for it (mirrors the server
    /// diver's `lsp/<lang>_ls.lua` selects for the language).
    #[serde(default)]
    diagnostics_servers: HashMap<String, String>,
}

/// The `[feedback]` bounds for `code.feedback` (SPEC §3.2):
/// how many files one call may cover, how many feedback calls
/// one episode (workspace + file set) may contain inside the
/// window, and the registered engine project roots a workspace
/// must live inside.
#[derive(Debug, Default, Deserialize)]
struct RawFeedback {
    #[serde(default)]
    max_files: Option<usize>,
    #[serde(default)]
    max_iterations_per_episode: Option<usize>,
    #[serde(default)]
    episode_window_secs: Option<u64>,
    #[serde(default)]
    project_roots: Vec<String>,
}

/// Which tooling server a `[[tooling]]` entry names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ToolingId {
    Theodolite,
    Periscope,
}

impl ToolingId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Theodolite => "theodolite",
            Self::Periscope => "periscope",
        }
    }
}

/// Validated `[[tooling]]` entry.
#[derive(Clone, Debug)]
pub struct ToolingEntry {
    pub id: ToolingId,
    pub command: String,
    pub args: Vec<String>,
    pub timeout_secs: u64,
    pub diagnostics_servers: HashMap<String, String>,
}

/// Validated `[feedback]` configuration.
#[derive(Clone, Debug)]
pub struct FeedbackConfig {
    pub max_files: usize,
    pub max_iterations_per_episode: usize,
    pub episode_window_secs: u64,
    pub project_roots: Vec<PathBuf>,
}

pub const DEFAULT_FEEDBACK_MAX_FILES: usize = 16;
pub const MAX_FEEDBACK_FILES: usize = 16;
pub const DEFAULT_FEEDBACK_MAX_ITERATIONS: usize = 3;
pub const DEFAULT_FEEDBACK_EPISODE_WINDOW_SECS: u64 = 600;
pub const DEFAULT_TOOLING_TIMEOUT_SECS: u64 = 120;
pub const MAX_TOOLING_TIMEOUT_SECS: u64 = 600;
pub const MAX_TOOLING_ENTRIES: usize = 4;
pub const MAX_PROJECT_ROOTS: usize = 32;

impl Default for FeedbackConfig {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_FEEDBACK_MAX_FILES,
            max_iterations_per_episode: DEFAULT_FEEDBACK_MAX_ITERATIONS,
            episode_window_secs: DEFAULT_FEEDBACK_EPISODE_WINDOW_SECS,
            project_roots: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct RawGui {
    #[serde(default)]
    apps: Vec<RawGuiApp>,
}

#[derive(Debug, Deserialize)]
struct RawGuiApp {
    name: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    window_match: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawServer {
    agent_token: String,
    #[serde(default)]
    operator_token: Option<String>,
    #[serde(default)]
    require_token_for_list: bool,
}

#[derive(Debug, Deserialize)]
struct RawDownstream {
    #[serde(default = "default_downstream_url")]
    url: String,
    #[serde(default = "default_downstream_timeout")]
    timeout_secs: u64,
}

impl Default for RawDownstream {
    fn default() -> Self {
        Self {
            url: default_downstream_url(),
            timeout_secs: default_downstream_timeout(),
        }
    }
}

fn default_downstream_url() -> String {
    // Epic's defaults: port 8000, path /mcp (SURFACE.md §2).
    "http://127.0.0.1:8000/mcp".to_string()
}

fn default_downstream_timeout() -> u64 {
    DEFAULT_DOWNSTREAM_TIMEOUT_SECS
}

#[derive(Debug, Default, Deserialize)]
struct RawPolicy {
    #[serde(default)]
    execute_enabled: Vec<String>,
    #[serde(default)]
    actuate_enabled: Vec<String>,
    #[serde(default)]
    class_overrides: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct RawOplog {
    #[serde(default = "default_oplog_path")]
    path: PathBuf,
}

impl Default for RawOplog {
    fn default() -> Self {
        Self {
            path: default_oplog_path(),
        }
    }
}

fn default_oplog_path() -> PathBuf {
    PathBuf::from("seahawk-oplog.jsonl")
}

/// Validated configuration, ready to serve.
#[derive(Debug)]
pub struct Config {
    /// SHA-256 of the agent token. Raw tokens are compared as
    /// digests in constant time and never stored beyond startup.
    pub agent_token_digest: [u8; 32],
    pub operator_token_digest: Option<[u8; 32]>,
    pub require_token_for_list: bool,
    pub downstream_url: String,
    pub downstream_timeout_secs: u64,
    /// Execute-class tools the operator has enabled, lowercased for
    /// case-insensitive matching.
    pub execute_enabled: HashSet<String>,
    /// Actuate-class tools the operator has enabled (`gui.<app>.
    /// actuate` names, or downstream tools overridden to actuate),
    /// lowercased for case-insensitive matching.
    pub actuate_enabled: HashSet<String>,
    /// Per-tool class overrides, lowercased name → class.
    pub class_overrides: HashMap<String, ToolClass>,
    /// GUI applications registered for the S4 host-GUI provider,
    /// in policy order.
    pub gui_apps: Vec<GuiApp>,
    /// S5 vision-grounder configuration.
    pub vision: VisionConfig,
    /// D-230 wiring: configured tooling servers (client side).
    pub tooling: Vec<ToolingEntry>,
    /// D-230 wiring: `code.feedback` bounds + project roots.
    pub feedback: FeedbackConfig,
    pub oplog_path: PathBuf,
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Loopback check: the downstream is Epic's unauthenticated editor
/// server; Seahawk refuses to broker to anything but loopback.
fn is_loopback_url(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    else {
        return false;
    };
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let raw: RawConfig = toml::from_str(text).context("config is not valid TOML")?;
        if raw.server.agent_token.is_empty() {
            bail!("config: server.agent_token is required and must be non-empty");
        }
        if let Some(op) = &raw.server.operator_token
            && op.is_empty()
        {
            bail!("config: server.operator_token must be non-empty when present");
        }
        if !is_loopback_url(&raw.downstream.url) {
            bail!(
                "config: downstream.url must be a loopback http(s) URL (got {}); \
                 Seahawk brokers only to Epic's localhost editor server",
                raw.downstream.url
            );
        }
        if raw.downstream.timeout_secs == 0
            || raw.downstream.timeout_secs > MAX_DOWNSTREAM_TIMEOUT_SECS
        {
            bail!(
                "config: downstream.timeout_secs must be within 1..={MAX_DOWNSTREAM_TIMEOUT_SECS}"
            );
        }
        let mut class_overrides = HashMap::new();
        for (name, class) in &raw.policy.class_overrides {
            let Some(class) = ToolClass::parse(class) else {
                bail!(
                    "config: policy.class_overrides[{name:?}] = {class:?} is not \
                     read|write|actuate|execute"
                );
            };
            class_overrides.insert(name.to_lowercase(), class);
        }
        let gui_apps = parse_gui_apps(&raw.gui)?;
        let vision = parse_vision(&raw.vision)?;
        let tooling = parse_tooling(&raw.tooling)?;
        let feedback = parse_feedback(&raw.feedback)?;
        Ok(Self {
            agent_token_digest: digest(&raw.server.agent_token),
            operator_token_digest: raw.server.operator_token.as_deref().map(digest),
            require_token_for_list: raw.server.require_token_for_list,
            downstream_url: raw.downstream.url,
            downstream_timeout_secs: raw.downstream.timeout_secs,
            execute_enabled: raw
                .policy
                .execute_enabled
                .iter()
                .map(|n| n.to_lowercase())
                .collect(),
            actuate_enabled: raw
                .policy
                .actuate_enabled
                .iter()
                .map(|n| n.to_lowercase())
                .collect(),
            class_overrides,
            gui_apps,
            vision,
            tooling,
            feedback,
            oplog_path: raw.oplog.path,
        })
    }

    /// The effective class of a downstream tool: operator override
    /// first, then the compiled-in S0 table.
    pub fn class_of(&self, tool_name: &str) -> Option<ToolClass> {
        if let Some(class) = self.class_overrides.get(&tool_name.to_lowercase()) {
            return Some(*class);
        }
        crate::model::default_class(tool_name)
    }

    pub fn execute_is_enabled(&self, tool_name: &str) -> bool {
        self.execute_enabled.contains(&tool_name.to_lowercase())
    }

    pub fn actuate_is_enabled(&self, tool_name: &str) -> bool {
        self.actuate_enabled.contains(&tool_name.to_lowercase())
    }

    /// A configured tooling entry by id (D-230 wiring).
    pub fn tooling_entry(&self, id: ToolingId) -> Option<&ToolingEntry> {
        self.tooling.iter().find(|entry| entry.id == id)
    }

    /// A registered GUI application by registration name
    /// (case-insensitive).
    pub fn gui_app(&self, name: &str) -> Option<&GuiApp> {
        self.gui_apps
            .iter()
            .find(|app| app.name.eq_ignore_ascii_case(name))
    }
}

/// Validates one GUI registration name: it becomes part of tool
/// names (`gui.<name>.observe`), so it must be a lowercase
/// identifier — ASCII letter first, then letters, digits, `-`,
/// `_`. Uppercase is refused rather than normalized: policy is the
/// operator's signed-off data and a silent rewrite would hide a
/// typo that changes which tools exist.
fn valid_gui_app_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() || name.chars().count() > MAX_GUI_APP_NAME_CHARS {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Validates the `[[tooling]]` entries. Commands are operator
/// policy (the operator is the trust root for this file, as
/// everywhere in this config); what validation guarantees is
/// shape: known ids, no duplicates, bounded fields, sane
/// timeouts — a typo fails at load, not mid-feedback.
fn parse_tooling(raw: &[RawTooling]) -> anyhow::Result<Vec<ToolingEntry>> {
    if raw.len() > MAX_TOOLING_ENTRIES {
        bail!(
            "config: [[tooling]] carries {} entries; the bound is {MAX_TOOLING_ENTRIES}",
            raw.len()
        );
    }
    let mut entries: Vec<ToolingEntry> = Vec::with_capacity(raw.len());
    for entry in raw {
        let id = match entry.id.as_str() {
            "theodolite" => ToolingId::Theodolite,
            "periscope" => ToolingId::Periscope,
            other => bail!("config: [[tooling]] id {other:?} is not one of theodolite | periscope"),
        };
        if entries.iter().any(|e: &ToolingEntry| e.id == id) {
            bail!("config: [[tooling]] id {:?} is configured twice", entry.id);
        }
        if entry.command.is_empty() || entry.command.chars().count() > 512 {
            bail!(
                "config: [[tooling]] {:?} command must be 1..=512 characters",
                entry.id
            );
        }
        if entry.args.len() > 16 || entry.args.iter().any(|arg| arg.chars().count() > 512) {
            bail!(
                "config: [[tooling]] {:?} args must be at most 16 entries of at most 512 characters",
                entry.id
            );
        }
        let timeout_secs = entry.timeout_secs.unwrap_or(DEFAULT_TOOLING_TIMEOUT_SECS);
        if timeout_secs == 0 || timeout_secs > MAX_TOOLING_TIMEOUT_SECS {
            bail!(
                "config: [[tooling]] {:?} timeout_secs must be within 1..={MAX_TOOLING_TIMEOUT_SECS}",
                entry.id
            );
        }
        if entry.diagnostics_servers.len() > 32
            || entry.diagnostics_servers.iter().any(|(ext, server)| {
                ext.is_empty() || ext.len() > 16 || server.is_empty() || server.len() > 64
            })
        {
            bail!(
                "config: [[tooling]] {:?} diagnostics_servers must map at most 32 short extensions to server ids",
                entry.id
            );
        }
        entries.push(ToolingEntry {
            id,
            command: entry.command.clone(),
            args: entry.args.clone(),
            timeout_secs,
            diagnostics_servers: entry.diagnostics_servers.clone(),
        });
    }
    Ok(entries)
}

/// Validates the `[feedback]` section.
fn parse_feedback(raw: &RawFeedback) -> anyhow::Result<FeedbackConfig> {
    let mut feedback = FeedbackConfig::default();
    if let Some(max_files) = raw.max_files {
        if max_files == 0 || max_files > MAX_FEEDBACK_FILES {
            bail!("config: feedback.max_files must be within 1..={MAX_FEEDBACK_FILES}");
        }
        feedback.max_files = max_files;
    }
    if let Some(max_iterations) = raw.max_iterations_per_episode {
        if max_iterations == 0 || max_iterations > 10 {
            bail!("config: feedback.max_iterations_per_episode must be within 1..=10");
        }
        feedback.max_iterations_per_episode = max_iterations;
    }
    if let Some(window) = raw.episode_window_secs {
        if !(10..=86400).contains(&window) {
            bail!("config: feedback.episode_window_secs must be within 10..=86400");
        }
        feedback.episode_window_secs = window;
    }
    if raw.project_roots.len() > MAX_PROJECT_ROOTS {
        bail!(
            "config: feedback.project_roots carries {}; the bound is {MAX_PROJECT_ROOTS}",
            raw.project_roots.len()
        );
    }
    for root in &raw.project_roots {
        let path = PathBuf::from(root);
        if !path.is_absolute() {
            bail!("config: feedback.project_roots entries must be absolute paths (got {root:?})");
        }
        feedback.project_roots.push(path);
    }
    Ok(feedback)
}

fn parse_gui_apps(raw: &RawGui) -> anyhow::Result<Vec<GuiApp>> {
    if raw.apps.len() > MAX_GUI_APPS {
        bail!(
            "config: [gui] registers {} apps; the bound is {MAX_GUI_APPS}",
            raw.apps.len()
        );
    }
    let mut apps: Vec<GuiApp> = Vec::with_capacity(raw.apps.len());
    for raw_app in &raw.apps {
        if !valid_gui_app_name(&raw_app.name) {
            bail!(
                "config: gui app name {:?} is invalid: use 1..={MAX_GUI_APP_NAME_CHARS} \
                 lowercase ASCII chars, letter first, then letters/digits/-/_",
                raw_app.name
            );
        }
        if apps.iter().any(|app: &GuiApp| app.name == raw_app.name) {
            bail!("config: gui app {:?} is registered twice", raw_app.name);
        }
        if raw_app.window_match.is_empty()
            || raw_app.window_match.len() > MAX_WINDOW_MATCHES_PER_APP
        {
            bail!(
                "config: gui app {:?} needs 1..={MAX_WINDOW_MATCHES_PER_APP} window_match strings",
                raw_app.name
            );
        }
        for matcher in &raw_app.window_match {
            if matcher.is_empty() || matcher.chars().count() > MAX_WINDOW_MATCH_CHARS {
                bail!(
                    "config: gui app {:?} has an empty or over-long window_match string",
                    raw_app.name
                );
            }
        }
        apps.push(GuiApp {
            display_name: raw_app
                .display_name
                .clone()
                .unwrap_or_else(|| raw_app.name.clone()),
            name: raw_app.name.clone(),
            window_match: raw_app.window_match.clone(),
        });
    }
    Ok(apps)
}

/// Validates the `[vision]` section. The Ollama endpoint is held
/// to the same loopback rule as the downstream: the broker speaks
/// HTTP only to loopback services, so a grounder URL pointing off
/// the machine is refused at load, not discovered at call time.
fn parse_vision(raw: &RawVision) -> anyhow::Result<VisionConfig> {
    let route = match raw.grounder.as_deref() {
        None | Some("agent") => VisionRoute::Agent,
        Some("ollama") => VisionRoute::Ollama,
        Some("none") => VisionRoute::None,
        Some(other) => {
            bail!("config: vision.grounder = {other:?} is not one of ollama | agent | none")
        }
    };
    let mut vision = VisionConfig {
        route,
        ..VisionConfig::default()
    };
    if let Some(url) = &raw.ollama_url {
        if !is_loopback_url(url) {
            bail!(
                "config: vision.ollama_url must be a loopback http(s) URL (got {url}); \
                 the vision grounder is a local service by contract"
            );
        }
        vision.ollama_url = url.clone();
    }
    if let Some(model) = &raw.ollama_model {
        if model.is_empty() || model.chars().count() > 128 {
            bail!("config: vision.ollama_model must be 1..=128 characters");
        }
        vision.ollama_model = model.clone();
    }
    if route == VisionRoute::Ollama && vision.ollama_model.is_empty() {
        bail!(
            "config: vision.grounder = \"ollama\" requires vision.ollama_model \
             (the broker is model-agnostic; the operator names the model)"
        );
    }
    if let Some(min) = raw.min_confidence {
        if !(0.0..=1.0).contains(&min) {
            bail!("config: vision.min_confidence must be within 0.0..=1.0");
        }
        vision.min_confidence = min;
    }
    if let Some(timeout) = raw.timeout_secs {
        if timeout == 0 || timeout > MAX_VISION_TIMEOUT_SECS {
            bail!("config: vision.timeout_secs must be within 1..={MAX_VISION_TIMEOUT_SECS}");
        }
        vision.timeout_secs = timeout;
    }
    Ok(vision)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "[server]\nagent_token = \"agent-secret\"\n";

    #[test]
    fn minimal_config_parses_with_defaults() {
        let cfg = Config::parse(MINIMAL).expect("minimal config");
        assert_eq!(cfg.downstream_url, "http://127.0.0.1:8000/mcp");
        assert_eq!(cfg.downstream_timeout_secs, 120);
        assert!(cfg.operator_token_digest.is_none());
        assert!(!cfg.require_token_for_list);
    }

    #[test]
    fn empty_agent_token_is_refused() {
        assert!(Config::parse("[server]\nagent_token = \"\"\n").is_err());
    }

    #[test]
    fn missing_agent_token_is_refused() {
        assert!(Config::parse("[server]\n").is_err());
    }

    #[test]
    fn non_loopback_downstream_is_refused() {
        let text =
            "[server]\nagent_token = \"x\"\n[downstream]\nurl = \"http://192.168.1.10:8000/mcp\"\n";
        assert!(Config::parse(text).is_err());
        let text =
            "[server]\nagent_token = \"x\"\n[downstream]\nurl = \"http://example.com:8000/mcp\"\n";
        assert!(Config::parse(text).is_err());
    }

    #[test]
    fn loopback_variants_are_accepted() {
        for url in [
            "http://127.0.0.1:8123/mcp",
            "http://localhost:8000/mcp",
            "http://[::1]:8000/mcp",
        ] {
            let text = format!("[server]\nagent_token = \"x\"\n[downstream]\nurl = \"{url}\"\n");
            assert!(Config::parse(&text).is_ok(), "{url}");
        }
    }

    #[test]
    fn bad_override_class_is_refused() {
        let text = "[server]\nagent_token = \"x\"\n[policy]\nclass_overrides = { \"A.B\" = \"sideways\" }\n";
        assert!(Config::parse(text).is_err());
    }

    #[test]
    fn gui_apps_parse_and_actuate_list_is_case_insensitive() {
        let text = "[server]\nagent_token = \"x\"\n\
                    [policy]\nactuate_enabled = [\"GUI.Blender.Actuate\"]\n\
                    [[gui.apps]]\nname = \"blender\"\ndisplay_name = \"Blender\"\n\
                    window_match = [\"Blender\"]\n\
                    [[gui.apps]]\nname = \"aseprite\"\nwindow_match = [\"Aseprite\", \"aseprite\"]\n";
        let cfg = Config::parse(text).expect("config");
        assert_eq!(cfg.gui_apps.len(), 2);
        assert_eq!(
            cfg.gui_app("BLENDER").map(|a| a.name.as_str()),
            Some("blender")
        );
        assert_eq!(cfg.gui_app("aseprite").unwrap().display_name, "aseprite");
        assert!(cfg.actuate_is_enabled("gui.blender.actuate"));
        assert!(!cfg.actuate_is_enabled("gui.aseprite.actuate"));
    }

    #[test]
    fn gui_app_names_are_validated() {
        for bad in ["Blender", "9blender", "blen der", "gui.blender", ""] {
            let text = format!(
                "[server]\nagent_token = \"x\"\n[[gui.apps]]\nname = \"{bad}\"\nwindow_match = [\"X\"]\n"
            );
            assert!(
                Config::parse(&text).is_err(),
                "name {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn gui_app_duplicates_and_missing_matches_are_refused() {
        let dup = "[server]\nagent_token = \"x\"\n\
                   [[gui.apps]]\nname = \"blender\"\nwindow_match = [\"Blender\"]\n\
                   [[gui.apps]]\nname = \"blender\"\nwindow_match = [\"Blender\"]\n";
        assert!(Config::parse(dup).is_err());
        let no_match = "[server]\nagent_token = \"x\"\n[[gui.apps]]\nname = \"blender\"\n";
        assert!(Config::parse(no_match).is_err());
    }

    #[test]
    fn actuate_is_a_valid_override_class() {
        let text = "[server]\nagent_token = \"x\"\n[policy]\nclass_overrides = { \"A.B\" = \"actuate\" }\n";
        let cfg = Config::parse(text).expect("config");
        assert_eq!(cfg.class_of("a.b"), Some(ToolClass::Actuate));
    }

    #[test]
    fn overrides_and_execute_list_are_case_insensitive() {
        let text = "[server]\nagent_token = \"x\"\n[policy]\nexecute_enabled = [\"Some.Toolset.RunIt\"]\nclass_overrides = { \"Other.Tool\" = \"execute\" }\n";
        let cfg = Config::parse(text).expect("config");
        assert!(cfg.execute_is_enabled("some.toolset.runit"));
        assert_eq!(cfg.class_of("OTHER.TOOL"), Some(ToolClass::Execute));
    }

    #[test]
    fn tooling_and_feedback_parse_and_validate() {
        let text = "[server]\nagent_token = \"x\"\n\
                    [[tooling]]\nid = \"theodolite\"\ncommand = \"/usr/bin/theodolite\"\n\
                    diagnostics_servers = { rs = \"bacon-ls\", py = \"basedpyright\" }\n\
                    [[tooling]]\nid = \"periscope\"\ncommand = \"/usr/bin/periscope\"\ntimeout_secs = 30\n\
                    [feedback]\nmax_files = 8\nproject_roots = [\"/srv/project\"]\n";
        let cfg = Config::parse(text).expect("config");
        assert_eq!(cfg.tooling.len(), 2);
        let theo = cfg
            .tooling_entry(ToolingId::Theodolite)
            .expect("theodolite");
        assert_eq!(
            theo.diagnostics_servers.get("rs").map(String::as_str),
            Some("bacon-ls")
        );
        assert_eq!(cfg.feedback.max_files, 8);
        assert_eq!(
            cfg.feedback.max_iterations_per_episode,
            DEFAULT_FEEDBACK_MAX_ITERATIONS
        );
        assert_eq!(cfg.feedback.project_roots.len(), 1);
        // Unknown id, duplicate id, relative root, over-bound files: refused.
        let bad_id =
            "[server]\nagent_token = \"x\"\n[[tooling]]\nid = \"ardor\"\ncommand = \"/x\"\n";
        assert!(Config::parse(bad_id).is_err());
        let dup = "[server]\nagent_token = \"x\"\n[[tooling]]\nid = \"periscope\"\ncommand = \"/x\"\n[[tooling]]\nid = \"periscope\"\ncommand = \"/y\"\n";
        assert!(Config::parse(dup).is_err());
        let rel_root =
            "[server]\nagent_token = \"x\"\n[feedback]\nproject_roots = [\"relative/path\"]\n";
        assert!(Config::parse(rel_root).is_err());
        let too_many = "[server]\nagent_token = \"x\"\n[feedback]\nmax_files = 99\n";
        assert!(Config::parse(too_many).is_err());
    }

    #[test]
    fn vision_defaults_to_the_agent_route() {
        let cfg = Config::parse(MINIMAL).expect("config");
        assert_eq!(cfg.vision.route, VisionRoute::Agent);
        assert_eq!(cfg.vision.min_confidence, DEFAULT_MIN_CONFIDENCE);
    }

    #[test]
    fn vision_ollama_route_requires_a_model_and_loopback() {
        let ok = "[server]\nagent_token = \"x\"\n[vision]\ngrounder = \"ollama\"\n\
                  ollama_model = \"some-vision-model\"\nmin_confidence = 0.7\n";
        let cfg = Config::parse(ok).expect("config");
        assert_eq!(cfg.vision.route, VisionRoute::Ollama);
        assert_eq!(cfg.vision.ollama_model, "some-vision-model");
        assert_eq!(cfg.vision.min_confidence, 0.7);
        // No model named: refused at load.
        let no_model = "[server]\nagent_token = \"x\"\n[vision]\ngrounder = \"ollama\"\n";
        assert!(Config::parse(no_model).is_err());
        // Off-loopback grounder endpoint: refused at load.
        let remote = "[server]\nagent_token = \"x\"\n[vision]\ngrounder = \"ollama\"\n\
                      ollama_model = \"m\"\nollama_url = \"http://192.168.1.10:11434\"\n";
        assert!(Config::parse(remote).is_err());
        // Unknown route and out-of-range confidence: refused.
        let bad_route = "[server]\nagent_token = \"x\"\n[vision]\ngrounder = \"cloud\"\n";
        assert!(Config::parse(bad_route).is_err());
        let bad_conf = "[server]\nagent_token = \"x\"\n[vision]\nmin_confidence = 1.5\n";
        assert!(Config::parse(bad_conf).is_err());
    }
}
