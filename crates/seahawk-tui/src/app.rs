//! The event loop and screen state machine.
//!
//! State is an explicit [`Screen`] enum plus bounded collections
//! — invalid states (a staged call with no tool, a selection past
//! the end of a list) are clamped at the transition that could
//! create them. The staging rule lives here, in one place, so the
//! full-screen loop and the line mode share exactly one execute
//! path (DESIGN §D2):
//!
//! - **Plan mode** stages the call (exact tool + args shown) and
//!   makes **no facade call** until the operator approves.
//! - **Auto mode** runs read/write-class calls directly.
//! - **Actuate/execute-class calls are plan-only in rung 1:**
//!   auto mode refuses them with the reason shown, mirroring
//!   Seahawk's own execute-class default-deny
//!   (`seahawk::policy::decide`). Approval in plan mode still
//!   only *stages the TUI's consent* — the broker's own
//!   `decide()` gate (policy enablement + operator token) remains
//!   the authority on the live path.

use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::path::Path;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use serde_json::{Value, json};

use seahawk::model::ToolClass;

use crate::facade::{FacadeError, SeahawkFacade, ToolInfo, class_of_tool_name, is_gated_class};
use crate::oplog::{
    ClassFilter, OPLOG_TAIL_DEFAULT, ParseReport, filtered_entries, load_oplog_file,
    parse_oplog_text, report_from_values,
};
use crate::panels;
use crate::triggers::{TriggerAudit, TriggerLoad};

/// Maximum retained event lines (Log / Live screen + audit feed).
pub const EVENT_LINES_MAX: usize = 512;
/// Maximum bytes of one line-mode input line.
pub const INPUT_LINE_BYTES_MAX: usize = 8_192;
/// Maximum characters of one rendered result in line mode.
pub const LINE_RESULT_CHARS_MAX: usize = 4_000;

/// The five screens. No Media screen (not applicable, DESIGN §D2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Screen {
    /// Broker status, registered apps, downstream reachability.
    #[default]
    Overview,
    /// Registered apps, broker session state, workflow staging.
    Sessions,
    /// The append-only op-log viewer (centrepiece).
    OpLog,
    /// Bounded live event stream.
    Log,
    /// Trigger rules (empty by design) + audit.
    Fleet,
}

impl Screen {
    /// All screens in tab order.
    pub const ALL: [Screen; 5] = [
        Screen::Overview,
        Screen::Sessions,
        Screen::OpLog,
        Screen::Log,
        Screen::Fleet,
    ];

    /// The screen's title.
    pub fn title(&self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Sessions => "Sessions",
            Self::OpLog => "OpLog",
            Self::Log => "Log",
            Self::Fleet => "Fleet",
        }
    }

    /// Parse a screen name (line mode).
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "overview" => Some(Self::Overview),
            "sessions" | "session" => Some(Self::Sessions),
            "oplog" | "op-log" => Some(Self::OpLog),
            "log" | "live" => Some(Self::Log),
            "fleet" => Some(Self::Fleet),
            _ => None,
        }
    }

    fn next(&self) -> Self {
        let index = Self::ALL.iter().position(|item| item == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    fn prev(&self) -> Self {
        let index = Self::ALL.iter().position(|item| item == self).unwrap_or(0);
        Self::ALL[(index + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Run mode for workflow staging (DESIGN §D2 screen 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RunMode {
    /// Stage the call, show exact tool + args, wait for approval.
    #[default]
    Plan,
    /// Execute declared read/write operations directly.
    Auto,
}

impl RunMode {
    /// `plan` or `auto`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Auto => "auto",
        }
    }

    /// The other mode.
    pub fn toggle(&self) -> Self {
        match self {
            Self::Plan => Self::Auto,
            Self::Auto => Self::Plan,
        }
    }
}

/// One staged call awaiting approval (plan mode).
#[derive(Clone, Debug, PartialEq)]
pub struct StagedCall {
    /// Tool name.
    pub tool: String,
    /// Exact arguments that approval would send.
    pub args: Value,
    /// The tool's class at staging time.
    pub tool_class: Option<ToolClass>,
    /// Mode the call was staged under (always plan for gated
    /// classes; auto never stages gated calls — it refuses).
    pub mode: RunMode,
}

impl StagedCall {
    /// One-line staging summary shown on the Sessions screen.
    pub fn summary(&self) -> String {
        format!(
            "{} {} args={}",
            self.tool,
            self.tool_class
                .map(|class| class.as_str())
                .unwrap_or("unclassified"),
            self.args
        )
    }
}

/// What a stage/run request did.
#[derive(Clone, Debug, PartialEq)]
pub enum StageOutcome {
    /// Plan mode: staged, **no call made**.
    Staged(StagedCall),
    /// The call ran; carries the result.
    Executed(Value),
    /// Refused before any call (or the call itself refused);
    /// carries the typed code and the human reason.
    Refused {
        /// Refusal code (`tui_execute_auto_refused`, a broker
        /// code, or a facade error label).
        code: String,
        /// Human-facing reason, shown on screen.
        reason: String,
    },
}

/// The refusal code for the rung-1 plan-only rule.
pub const CODE_EXECUTE_AUTO_REFUSED: &str = "tui_execute_auto_refused";

/// One event-stream line (Log / Live).
#[derive(Clone, Debug, PartialEq)]
pub struct EventLine {
    /// started / progress / done / failed / log.
    pub kind: &'static str,
    /// The line text.
    pub text: String,
}

impl EventLine {
    fn render(&self) -> String {
        format!("[{}] {}", self.kind, self.text)
    }
}

/// The TUI application state, generic over the facade so tests
/// drive it with [`crate::facade::FakeFacade`].
pub struct App<F: SeahawkFacade> {
    /// The broker facade (real or fake).
    pub facade: F,
    /// Current screen.
    pub screen: Screen,
    /// Current run mode.
    pub mode: RunMode,
    /// The staged call, if any.
    pub staged: Option<StagedCall>,
    /// Bounded event stream.
    pub events: VecDeque<EventLine>,
    /// Cached tool list (Sessions screen).
    pub tools_cache: Vec<ToolInfo>,
    /// Selected tool index (Sessions screen), clamped on use.
    pub selected_tool: usize,
    /// Cached broker status (Overview screen).
    pub status_cache: Option<Value>,
    /// Cached registered apps.
    pub apps_cache: Vec<Value>,
    /// The op-log parse report (OpLog screen).
    pub oplog: ParseReport,
    /// Op-log class filter.
    pub oplog_filter: ClassFilter,
    /// Op-log search text.
    pub oplog_search: String,
    /// Selected index into the *filtered* op-log entries.
    pub oplog_selected: usize,
    /// Trigger rules + provenance (Fleet screen).
    pub triggers: TriggerLoad,
    /// TUI-local audit log (Fleet screen).
    pub audit: TriggerAudit,
    /// Last call result, for the Log screen / line mode.
    pub last_result: Option<Value>,
}

impl<F: SeahawkFacade> App<F> {
    /// New app state on the Overview screen, plan mode.
    pub fn new(facade: F, triggers: TriggerLoad) -> Self {
        Self {
            facade,
            screen: Screen::Overview,
            mode: RunMode::Plan,
            staged: None,
            events: VecDeque::new(),
            tools_cache: Vec::new(),
            selected_tool: 0,
            status_cache: None,
            apps_cache: Vec::new(),
            oplog: ParseReport::default(),
            oplog_filter: ClassFilter::All,
            oplog_search: String::new(),
            oplog_selected: 0,
            triggers,
            audit: TriggerAudit::new(),
            last_result: None,
        }
    }

    /// Append one event line, evicting the oldest beyond the bound.
    pub fn push_event(&mut self, kind: &'static str, text: String) {
        if self.events.len() >= EVENT_LINES_MAX {
            self.events.pop_front();
        }
        self.events.push_back(EventLine { kind, text });
    }

    /// The event stream as rendered strings, oldest first.
    pub fn event_strings(&self) -> Vec<String> {
        self.events.iter().map(EventLine::render).collect()
    }

    /// Refresh status + apps from the facade. Failures land in
    /// the event stream; the last good cache is kept.
    pub fn refresh_status(&mut self) {
        match self.facade.status() {
            Ok(status) => self.status_cache = Some(status),
            Err(error) => self.push_event("failed", format!("status: {error}")),
        }
        match self.facade.registered_apps() {
            Ok(apps) => self.apps_cache = apps,
            Err(error) => self.push_event("failed", format!("apps: {error}")),
        }
    }

    /// Refresh the tool list.
    pub fn refresh_tools(&mut self) {
        match self.facade.tools() {
            Ok(tools) => {
                self.tools_cache = tools;
                if self.selected_tool >= self.tools_cache.len() {
                    self.selected_tool = self.tools_cache.len().saturating_sub(1);
                }
            }
            Err(error) => self.push_event("failed", format!("tools: {error}")),
        }
    }

    /// Refresh the op log through the facade (values path).
    pub fn refresh_oplog(&mut self) {
        match self.facade.oplog_entries(OPLOG_TAIL_DEFAULT) {
            Ok(values) => {
                self.oplog = report_from_values(&values);
                self.clamp_oplog_selection();
            }
            Err(error) => self.push_event("failed", format!("oplog: {error}")),
        }
    }

    /// Load the op log from a file (full-fidelity path: line
    /// level facts — truncation, oversized — are preserved).
    pub fn refresh_oplog_path(&mut self, path: &Path) {
        match load_oplog_file(path) {
            Ok(report) => {
                self.oplog = report;
                self.clamp_oplog_selection();
            }
            Err(error) => self.push_event("failed", format!("oplog {}: {error}", path.display())),
        }
    }

    /// Set the op log from raw text (tests, pipes).
    pub fn set_oplog_text(&mut self, text: &str) {
        self.oplog = parse_oplog_text(text);
        self.clamp_oplog_selection();
    }

    fn clamp_oplog_selection(&mut self) {
        let count = filtered_entries(&self.oplog, self.oplog_filter, &self.oplog_search).len();
        if self.oplog_selected >= count {
            self.oplog_selected = count.saturating_sub(1);
        }
    }

    /// The class of a tool: cached list first, then the
    /// by-construction / census lookup.
    pub fn class_for(&self, tool: &str) -> Option<ToolClass> {
        if let Some(info) = self
            .tools_cache
            .iter()
            .find(|info| info.name.eq_ignore_ascii_case(tool))
        {
            return info.class;
        }
        class_of_tool_name(tool)
    }

    /// Stage or run one call under the current mode. This is the
    /// single execute path both modes share.
    ///
    /// Gated classes (actuate/execute) in auto mode are refused
    /// here, before any facade call, with
    /// [`CODE_EXECUTE_AUTO_REFUSED`]. Plan mode stages without
    /// calling. Auto mode with a read/write class calls at once.
    pub fn stage_or_run(&mut self, tool: &str, args: Value) -> StageOutcome {
        let tool_class = self.class_for(tool);
        if is_gated_class(tool_class) && self.mode == RunMode::Auto {
            let reason = format!(
                "{tool} is {}-class: actuate/execute-class operations are plan-only in \
                 seahawk-tui rung 1 (mirrors Seahawk's execute-class default-deny); \
                 auto mode refused — switch to plan mode to stage it",
                tool_class
                    .map(|class| class.as_str())
                    .unwrap_or("unclassified")
            );
            self.push_event("failed", format!("auto-refused {tool}: {reason}"));
            self.audit.push(format!(
                "stage auto-refused tool={tool} code={CODE_EXECUTE_AUTO_REFUSED}"
            ));
            return StageOutcome::Refused {
                code: CODE_EXECUTE_AUTO_REFUSED.to_string(),
                reason,
            };
        }
        if self.mode == RunMode::Plan {
            let staged = StagedCall {
                tool: tool.to_string(),
                args,
                tool_class,
                mode: self.mode,
            };
            self.push_event(
                "log",
                format!("staged {} (plan mode — no call made)", staged.summary()),
            );
            self.audit.push(format!(
                "stage plan tool={tool} class={}",
                staged_summary_class(&staged)
            ));
            self.staged = Some(staged.clone());
            return StageOutcome::Staged(staged);
        }
        self.execute(tool, args)
    }

    /// Approve the staged call: exactly one facade call, with
    /// the exact staged tool + args. Returns `None` when nothing
    /// is staged. Note the scope of approval: this is the TUI
    /// operator's consent to *send* the call; on the live path
    /// the broker's own `decide()` gate still applies.
    pub fn approve_staged(&mut self) -> Option<StageOutcome> {
        let staged = self.staged.take()?;
        self.push_event(
            "log",
            format!("approved staged {}; sending to broker", staged.tool),
        );
        self.audit.push(format!("approve tool={}", staged.tool));
        Some(self.execute(&staged.tool, staged.args))
    }

    /// Abort the staged call without calling. Returns whether
    /// there was anything to abort.
    pub fn abort_staged(&mut self) -> bool {
        match self.staged.take() {
            Some(staged) => {
                self.push_event(
                    "log",
                    format!("aborted staged {} — no call made", staged.tool),
                );
                self.audit.push(format!("abort tool={}", staged.tool));
                true
            }
            None => false,
        }
    }

    fn execute(&mut self, tool: &str, args: Value) -> StageOutcome {
        self.push_event("started", format!("call {tool} args={args}"));
        match self.facade.call(tool, &args) {
            Ok(value) => {
                self.push_event("done", format!("call {tool} ok"));
                self.last_result = Some(value.clone());
                StageOutcome::Executed(value)
            }
            Err(error) => {
                self.push_event("failed", format!("call {tool}: {error}"));
                let (code, reason) = match &error {
                    FacadeError::Refused { code, message } => (code.clone(), message.clone()),
                    FacadeError::ServerDied(message) => {
                        ("server_died".to_string(), message.clone())
                    }
                    FacadeError::Unavailable(message) => {
                        ("unavailable".to_string(), message.clone())
                    }
                    FacadeError::Invalid(message) => ("invalid".to_string(), message.clone()),
                };
                StageOutcome::Refused { code, reason }
            }
        }
    }

    /// Stage/run the Sessions screen's selected tool with empty
    /// arguments (the full-screen Enter key).
    pub fn activate_selected_tool(&mut self) -> Option<StageOutcome> {
        let tool = self.tools_cache.get(self.selected_tool)?.name.clone();
        Some(self.stage_or_run(&tool, json!({})))
    }

    /// Handle one key in the full-screen loop. Returns `false`
    /// when the loop should exit (`q` / Esc).
    pub fn handle_key(&mut self, key: KeyCode) -> bool {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => return false,
            KeyCode::Char('1') => self.screen = Screen::Overview,
            KeyCode::Char('2') => self.screen = Screen::Sessions,
            KeyCode::Char('3') => self.screen = Screen::OpLog,
            KeyCode::Char('4') => self.screen = Screen::Log,
            KeyCode::Char('5') => self.screen = Screen::Fleet,
            KeyCode::Tab => self.screen = self.screen.next(),
            KeyCode::BackTab => self.screen = self.screen.prev(),
            KeyCode::Char('m') => {
                self.mode = self.mode.toggle();
                self.push_event("log", format!("run mode -> {}", self.mode.as_str()));
            }
            KeyCode::Char('f') if self.screen == Screen::OpLog => {
                self.oplog_filter = self.oplog_filter.next();
                self.oplog_selected = 0;
            }
            KeyCode::Char('r') => {
                self.refresh_status();
                self.refresh_tools();
                self.refresh_oplog();
            }
            KeyCode::Char('y') => {
                let _ = self.approve_staged();
            }
            KeyCode::Char('n') => {
                let _ = self.abort_staged();
            }
            KeyCode::Enter if self.screen == Screen::Sessions => {
                let _ = self.activate_selected_tool();
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            _ => {}
        }
        true
    }

    fn move_selection(&mut self, delta: i64) {
        match self.screen {
            Screen::Sessions => {
                let len = self.tools_cache.len();
                if len > 0 {
                    let current = i64::try_from(self.selected_tool).unwrap_or(0);
                    let next = (current + delta).clamp(0, i64::try_from(len - 1).unwrap_or(0));
                    self.selected_tool = usize::try_from(next).unwrap_or(0);
                }
            }
            Screen::OpLog => {
                let count =
                    filtered_entries(&self.oplog, self.oplog_filter, &self.oplog_search).len();
                if count > 0 {
                    let current = i64::try_from(self.oplog_selected).unwrap_or(0);
                    let next = (current + delta).clamp(0, i64::try_from(count - 1).unwrap_or(0));
                    self.oplog_selected = usize::try_from(next).unwrap_or(0);
                }
            }
            _ => {}
        }
    }

    /// Execute one line-mode command and return its output text.
    /// Shares the staging path with the full-screen loop.
    pub fn execute_line(&mut self, line: &str) -> String {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return String::new();
        }
        let mut parts = trimmed.splitn(2, char::is_whitespace);
        let command = parts.next().unwrap_or_default().to_ascii_lowercase();
        let rest = parts.next().unwrap_or("").trim();
        match command.as_str() {
            "help" => HELP_TEXT.to_string(),
            "status" => {
                self.refresh_status();
                match &self.status_cache {
                    Some(status) => {
                        crate::screens::overview_lines(status, &self.apps_cache).join("\n")
                    }
                    None => "status unavailable (see events)".to_string(),
                }
            }
            "tools" => {
                self.refresh_tools();
                crate::screens::sessions_lines(
                    &self.tools_cache,
                    self.selected_tool,
                    self.mode.as_str(),
                    self.staged.as_ref().map(StagedCall::summary).as_deref(),
                    &self.apps_cache,
                    self.status_cache
                        .as_ref()
                        .and_then(|status| {
                            status
                                .get("downstream_surface_built")
                                .and_then(Value::as_bool)
                        })
                        .unwrap_or(false),
                )
                .join("\n")
            }
            "apps" => {
                self.refresh_status();
                if self.apps_cache.is_empty() {
                    "(no registered apps)".to_string()
                } else {
                    self.apps_cache
                        .iter()
                        .map(|app| {
                            format!(
                                "{} — {}",
                                app.get("name").and_then(Value::as_str).unwrap_or("?"),
                                app.get("display_name")
                                    .and_then(Value::as_str)
                                    .unwrap_or("?")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
            "oplog" => self.line_oplog(rest),
            "call" => self.line_call(rest),
            "plan" => {
                self.mode = RunMode::Plan;
                "mode: plan (calls stage; nothing runs until `approve`)".to_string()
            }
            "auto" => {
                self.mode = RunMode::Auto;
                "mode: auto (read/write run directly; actuate/execute are REFUSED — plan-only in rung 1)"
                    .to_string()
            }
            "mode" => format!("mode: {}", self.mode.as_str()),
            "approve" => match self.approve_staged() {
                Some(outcome) => format_outcome(&outcome),
                None => "nothing staged".to_string(),
            },
            "abort" => {
                if self.abort_staged() {
                    "staged call aborted — no call was made".to_string()
                } else {
                    "nothing staged".to_string()
                }
            }
            "staged" => match &self.staged {
                Some(staged) => staged.summary(),
                None => "(nothing staged)".to_string(),
            },
            "screen" => {
                if rest.is_empty() {
                    let lines = self.current_screen_lines();
                    lines.join("\n")
                } else {
                    match Screen::parse(rest) {
                        Some(screen) => {
                            self.screen = screen;
                            self.current_screen_lines().join("\n")
                        }
                        None => {
                            format!("unknown screen {rest:?} (overview|sessions|oplog|log|fleet)")
                        }
                    }
                }
            }
            "triggers" | "fleet" => {
                crate::screens::fleet_lines(&self.triggers, &self.audit).join("\n")
            }
            "events" | "log" => crate::screens::log_lines(&self.event_strings()).join("\n"),
            _ => format!("unknown command {command:?} — try `help`"),
        }
    }

    fn line_oplog(&mut self, rest: &str) -> String {
        let mut words = rest.split_whitespace();
        match words.next() {
            Some("class") => {
                let name = words.next().unwrap_or("");
                match ClassFilter::parse(name) {
                    Some(filter) => {
                        self.oplog_filter = filter;
                        self.oplog_selected = 0;
                        format!("oplog filter: {}", filter.as_str())
                    }
                    None => format!("unknown class filter {name:?}"),
                }
            }
            Some("search") => {
                self.oplog_search = words.collect::<Vec<_>>().join(" ");
                self.oplog_selected = 0;
                format!("oplog search: {:?}", self.oplog_search)
            }
            Some("clear") => {
                self.oplog_filter = ClassFilter::All;
                self.oplog_search = String::new();
                self.oplog_selected = 0;
                "oplog filter/search cleared".to_string()
            }
            _ => {
                self.refresh_oplog();
                crate::screens::oplog_lines(
                    &self.oplog,
                    self.oplog_filter,
                    &self.oplog_search,
                    self.oplog_selected,
                )
                .join("\n")
            }
        }
    }

    fn line_call(&mut self, rest: &str) -> String {
        let mut split = rest.splitn(2, char::is_whitespace);
        let tool = split.next().unwrap_or_default();
        if tool.is_empty() {
            return "usage: call <tool> [json-args]".to_string();
        }
        let args_text = split.next().unwrap_or("{}").trim();
        let args: Value = match serde_json::from_str(args_text) {
            Ok(args) => args,
            Err(error) => return format!("invalid JSON args: {error}"),
        };
        let outcome = self.stage_or_run(tool, args);
        format_outcome(&outcome)
    }

    /// The current screen's text lines (line mode `screen`).
    pub fn current_screen_lines(&mut self) -> Vec<String> {
        match self.screen {
            Screen::Overview => {
                if self.status_cache.is_none() {
                    self.refresh_status();
                }
                let status = self.status_cache.clone().unwrap_or(Value::Null);
                crate::screens::overview_lines(&status, &self.apps_cache)
            }
            Screen::Sessions => crate::screens::sessions_lines(
                &self.tools_cache,
                self.selected_tool,
                self.mode.as_str(),
                self.staged.as_ref().map(StagedCall::summary).as_deref(),
                &self.apps_cache,
                self.status_cache
                    .as_ref()
                    .and_then(|status| {
                        status
                            .get("downstream_surface_built")
                            .and_then(Value::as_bool)
                    })
                    .unwrap_or(false),
            ),
            Screen::OpLog => crate::screens::oplog_lines(
                &self.oplog,
                self.oplog_filter,
                &self.oplog_search,
                self.oplog_selected,
            ),
            Screen::Log => crate::screens::log_lines(&self.event_strings()),
            Screen::Fleet => crate::screens::fleet_lines(&self.triggers, &self.audit),
        }
    }
}

fn staged_summary_class(staged: &StagedCall) -> &'static str {
    staged
        .tool_class
        .map(|class| class.as_str())
        .unwrap_or("unclassified")
}

/// Render a stage/run outcome for line mode.
pub fn format_outcome(outcome: &StageOutcome) -> String {
    match outcome {
        StageOutcome::Staged(staged) => format!(
            "staged (no call made): {}\nrun `approve` to send it, `abort` to drop it",
            staged.summary()
        ),
        StageOutcome::Executed(value) => {
            let text = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string());
            format!(
                "ok: {}",
                crate::truncate_chars(&text, LINE_RESULT_CHARS_MAX)
            )
        }
        StageOutcome::Refused { code, reason } => format!("refused:{code}: {reason}"),
    }
}

/// What the line loop should do with one input line.
#[derive(Debug, PartialEq, Eq)]
pub enum LineAction {
    /// End the session.
    Quit,
    /// Ignore (empty line).
    Skip,
    /// Execute as a command.
    Execute(String),
}

/// Classify one raw input line for the line loop.
pub fn classify_line(line: &str) -> LineAction {
    let text = line.trim();
    if text.is_empty() {
        LineAction::Skip
    } else if text == "quit" || text == "exit" {
        LineAction::Quit
    } else {
        LineAction::Execute(text.to_string())
    }
}

/// The line-mode help text.
pub const HELP_TEXT: &str = "\
commands:
  status                 broker status + registered apps (Overview)
  tools                  tool list with classes (Sessions)
  apps                   registered GUI applications
  oplog                  op-log tail (viewer state)
  oplog class <filter>   all|observe|read|write|actuate|execute|refused|errors
  oplog search <text>    substring search over tool/class/outcome/error
  oplog clear            reset filter + search
  call <tool> [json]     stage (plan) or run (auto) one call
  plan | auto | mode     run-mode control (actuate/execute: plan-only)
  approve | abort        send / drop the staged call
  staged                 show the staged call
  screen [name]          render a screen (overview|sessions|oplog|log|fleet)
  triggers               fleet panel: rules (empty by design) + audit
  events                 the live event stream
  quit                   exit";

/// Run the non-TTY line mode over stdin/stdout, sharing the
/// execute path with the full-screen loop.
pub fn run_line_mode<F: SeahawkFacade>(app: &mut App<F>) -> io::Result<()> {
    println!("Seahawk TUI (line mode) — broker console, rung 1");
    println!("Type `help` for commands. `quit` or Ctrl-D to exit.");
    app.refresh_status();
    app.refresh_tools();
    app.refresh_oplog();
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        print!("seahawk > ");
        io::stdout().flush()?;
        let Some(line) = lines.next() else {
            break;
        };
        let line = line?;
        if line.len() > INPUT_LINE_BYTES_MAX {
            println!(
                "input line exceeds INPUT_LINE_BYTES_MAX {INPUT_LINE_BYTES_MAX} bytes; ignored"
            );
            continue;
        }
        match classify_line(&line) {
            LineAction::Quit => break,
            LineAction::Skip => continue,
            LineAction::Execute(text) => {
                let output = app.execute_line(&text);
                if !output.is_empty() {
                    println!("{output}");
                }
            }
        }
    }
    Ok(())
}

/// Run the full-screen ratatui loop (TTY only). Keys: 1-5 / Tab
/// switch screens, j/k move, `m` toggles plan/auto, Enter stages
/// or runs the selected tool, `y` approves, `n` aborts, `f`
/// cycles the op-log filter, `r` refreshes, `q` quits.
pub fn run_fullscreen<F: SeahawkFacade>(app: &mut App<F>) -> io::Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    app.refresh_status();
    app.refresh_tools();
    app.refresh_oplog();
    let result = fullscreen_loop(app, &mut terminal);
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    result
}

fn fullscreen_loop<F: SeahawkFacade>(
    app: &mut App<F>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| {
            let area = frame.area();
            let staged_summary = app.staged.as_ref().map(StagedCall::summary);
            match app.screen {
                Screen::Overview => {
                    let status = app.status_cache.clone().unwrap_or(Value::Null);
                    frame.render_widget(panels::overview_panel(&status, &app.apps_cache), area);
                }
                Screen::Sessions => {
                    let surface_built = app
                        .status_cache
                        .as_ref()
                        .and_then(|status| {
                            status
                                .get("downstream_surface_built")
                                .and_then(Value::as_bool)
                        })
                        .unwrap_or(false);
                    frame.render_widget(
                        panels::sessions_panel(
                            &app.tools_cache,
                            app.selected_tool,
                            app.mode.as_str(),
                            staged_summary.as_deref(),
                            &app.apps_cache,
                            surface_built,
                        ),
                        area,
                    );
                }
                Screen::OpLog => frame.render_widget(
                    panels::oplog_panel(
                        &app.oplog,
                        app.oplog_filter,
                        &app.oplog_search,
                        app.oplog_selected,
                    ),
                    area,
                ),
                Screen::Log => frame.render_widget(panels::log_panel(&app.event_strings()), area),
                Screen::Fleet => {
                    frame.render_widget(panels::fleet_panel(&app.triggers, &app.audit), area)
                }
            }
        })?;
        if event::poll(std::time::Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && !app.handle_key(key.code)
        {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facade::FakeFacade;
    use crate::triggers::load_trigger_rules;

    const EXECUTE_TOOL: &str =
        "editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script";
    const READ_TOOL: &str = "EditorToolset.EditorAppToolset.GetSelectedActors";
    const WRITE_TOOL: &str = "EditorToolset.EditorAppToolset.SetActorTransform";

    fn test_app() -> App<FakeFacade> {
        let mut app = App::new(FakeFacade::with_default_surface(), load_trigger_rules(None));
        app.refresh_tools();
        app
    }

    #[test]
    fn execute_class_auto_refusal_makes_no_call() {
        // Adversarial (the rung-1 centrepiece rule): auto mode +
        // execute-class must refuse with the reason, and the
        // facade must record ZERO calls.
        let mut app = test_app();
        app.mode = RunMode::Auto;
        let outcome = app.stage_or_run(EXECUTE_TOOL, json!({"script": "print(1)"}));
        match outcome {
            StageOutcome::Refused { code, reason } => {
                assert_eq!(code, CODE_EXECUTE_AUTO_REFUSED);
                assert!(reason.contains("plan-only"), "{reason}");
                assert!(reason.contains("default-deny"), "{reason}");
            }
            other => panic!("expected refusal, got {other:?}"),
        }
        assert!(
            app.facade.calls.is_empty(),
            "auto-refusal must not call the facade: {:?}",
            app.facade.calls
        );
        assert!(app.staged.is_none(), "a refused call is never staged");
        assert!(
            app.audit
                .lines()
                .any(|line| line.contains(CODE_EXECUTE_AUTO_REFUSED)),
            "the refusal lands in the fleet audit"
        );
    }

    #[test]
    fn actuate_class_auto_refusal_makes_no_call() {
        let mut app = test_app();
        app.mode = RunMode::Auto;
        let outcome = app.stage_or_run("gui.blender.actuate", json!({"action": "click"}));
        assert!(
            matches!(outcome, StageOutcome::Refused { .. }),
            "{outcome:?}"
        );
        assert!(app.facade.calls.is_empty());
    }

    #[test]
    fn plan_mode_stages_with_no_call_until_approval() {
        // Plan-mode proof: staging an execute-class call records
        // no facade call; approval sends exactly one, with the
        // exact staged args.
        let mut app = test_app();
        assert_eq!(app.mode, RunMode::Plan);
        let outcome = app.stage_or_run(EXECUTE_TOOL, json!({"script": "print(1)"}));
        assert!(matches!(outcome, StageOutcome::Staged(_)), "{outcome:?}");
        assert!(
            app.facade.calls.is_empty(),
            "plan mode must not call before approval"
        );
        let approved = app.approve_staged().expect("staged call approves");
        assert!(
            matches!(approved, StageOutcome::Executed(_)),
            "{approved:?}"
        );
        assert_eq!(app.facade.calls.len(), 1, "exactly one call on approval");
        assert_eq!(app.facade.calls[0].0, EXECUTE_TOOL);
        assert_eq!(app.facade.calls[0].1, json!({"script": "print(1)"}));
        assert!(app.staged.is_none());
    }

    #[test]
    fn plan_mode_abort_makes_no_call_ever() {
        let mut app = test_app();
        let _ = app.stage_or_run(READ_TOOL, json!({}));
        assert!(app.abort_staged());
        assert!(app.facade.calls.is_empty());
        assert!(app.approve_staged().is_none(), "aborted staging is gone");
        assert!(app.facade.calls.is_empty());
    }

    #[test]
    fn auto_mode_runs_read_and_write_directly() {
        let mut app = test_app();
        app.mode = RunMode::Auto;
        let read = app.stage_or_run(READ_TOOL, json!({}));
        assert!(matches!(read, StageOutcome::Executed(_)), "{read:?}");
        let write = app.stage_or_run(WRITE_TOOL, json!({"x": 1}));
        assert!(matches!(write, StageOutcome::Executed(_)), "{write:?}");
        assert_eq!(app.facade.calls.len(), 2);
    }

    #[test]
    fn server_death_mid_call_is_a_typed_refusal_with_event() {
        // Adversarial: the broker dies mid-call. The outcome is a
        // refusal carrying server_died, the event stream records
        // the death, and nothing panics.
        let mut app = test_app();
        app.mode = RunMode::Auto;
        app.facade.die_on_call = Some(READ_TOOL.to_string());
        let outcome = app.stage_or_run(READ_TOOL, json!({}));
        match outcome {
            StageOutcome::Refused { code, reason } => {
                assert_eq!(code, "server_died");
                assert!(reason.contains("exited"), "{reason}");
            }
            other => panic!("expected server_died refusal, got {other:?}"),
        }
        assert!(
            app.event_strings()
                .iter()
                .any(|line| line.contains("server died")),
            "{:?}",
            app.event_strings()
        );
    }

    #[test]
    fn approval_then_abort_is_not_possible() {
        // Adversarial ordering: approve consumes the staging;
        // a later abort finds nothing and calls nothing more.
        let mut app = test_app();
        let _ = app.stage_or_run(READ_TOOL, json!({}));
        let _ = app.approve_staged();
        assert!(!app.abort_staged());
        assert_eq!(app.facade.calls.len(), 1);
    }

    #[test]
    fn key_navigation_and_mode_toggle() {
        let mut app = test_app();
        assert!(app.handle_key(KeyCode::Char('2')));
        assert_eq!(app.screen, Screen::Sessions);
        assert!(app.handle_key(KeyCode::Tab));
        assert_eq!(app.screen, Screen::OpLog);
        assert!(app.handle_key(KeyCode::Char('m')));
        assert_eq!(app.mode, RunMode::Auto);
        assert!(app.handle_key(KeyCode::Char('f')));
        assert_eq!(app.oplog_filter, ClassFilter::Observe);
        assert!(!app.handle_key(KeyCode::Char('q')), "q quits");
    }

    #[test]
    fn enter_in_sessions_stages_selected_in_plan_mode() {
        let mut app = test_app();
        app.screen = Screen::Sessions;
        app.selected_tool = 0; // seahawk_status, read class
        assert!(app.handle_key(KeyCode::Enter));
        assert!(app.staged.is_some(), "plan mode stages on Enter");
        assert!(app.facade.calls.is_empty());
        assert!(app.handle_key(KeyCode::Char('y')));
        assert_eq!(app.facade.calls.len(), 1, "y approves the staging");
    }

    #[test]
    fn line_mode_shares_the_staging_gate() {
        // The line mode must refuse execute-class auto calls
        // exactly like the full-screen path (one execute path).
        let mut app = test_app();
        let out = app.execute_line("auto");
        assert!(out.contains("REFUSED"), "{out}");
        let out = app.execute_line(&format!("call {EXECUTE_TOOL} {{}}"));
        assert!(out.contains(CODE_EXECUTE_AUTO_REFUSED), "{out}");
        assert!(app.facade.calls.is_empty());
        let out = app.execute_line("plan");
        assert!(out.contains("plan"), "{out}");
        let out = app.execute_line(&format!("call {EXECUTE_TOOL} {{\"a\":1}}"));
        assert!(out.contains("staged (no call made)"), "{out}");
        assert!(app.facade.calls.is_empty());
        let out = app.execute_line("approve");
        assert!(out.contains("ok:"), "{out}");
        assert_eq!(app.facade.calls.len(), 1);
    }

    #[test]
    fn line_oplog_filter_and_search_commands() {
        let mut app = test_app();
        app.set_oplog_text(
            "{\"ts\":1,\"seq\":0,\"tool\":\"gui.blender.observe\",\"class\":\"read\",\"args_bytes\":0,\"outcome\":\"ok\"}\n{\"ts\":2,\"seq\":1,\"tool\":\"x.y\",\"class\":\"execute\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
        );
        // execute_line("oplog") refreshes through the facade
        // (empty in the fake), so drive the sub-commands that do
        // not refresh and check state transitions directly.
        let out = app.execute_line("oplog class execute");
        assert!(out.contains("execute"), "{out}");
        assert_eq!(app.oplog_filter, ClassFilter::Execute);
        let out = app.execute_line("oplog search blender");
        assert!(out.contains("blender"), "{out}");
        assert_eq!(app.oplog_search, "blender");
        app.screen = Screen::OpLog;
        let lines = app.current_screen_lines();
        assert!(lines.iter().any(|line| line.contains("filter: execute")));
    }

    #[test]
    fn events_are_bounded() {
        let mut app = test_app();
        for index in 0..(EVENT_LINES_MAX + 25) {
            app.push_event("log", format!("event {index}"));
        }
        assert_eq!(app.events.len(), EVENT_LINES_MAX);
        assert!(app.event_strings()[0].contains("event 25"));
    }

    #[test]
    fn classify_line_covers_quit_skip_execute() {
        assert_eq!(classify_line("quit"), LineAction::Quit);
        assert_eq!(classify_line("  "), LineAction::Skip);
        assert_eq!(
            classify_line("status"),
            LineAction::Execute("status".to_string())
        );
        assert_eq!(Screen::parse("oplog"), Some(Screen::OpLog));
        assert_eq!(Screen::parse("bogus"), None);
    }
}
