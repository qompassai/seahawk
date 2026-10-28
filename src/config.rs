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
    oplog: RawOplog,
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
}
