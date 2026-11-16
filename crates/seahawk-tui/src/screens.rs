//! Pure text builders, one per screen.
//!
//! Each builder takes plain data and returns display lines — no
//! terminal, no I/O, no facade. The full-screen panels
//! ([`crate::panels`]) render these lines; the line mode prints
//! them; tests assert on them directly. Truncation bounds are
//! named here and applied uniformly.

use serde_json::Value;

use seahawk::model::ToolClass;

use crate::facade::ToolInfo;
use crate::oplog::{ClassFilter, OpEntryView, ParseReport, entry_detail, filtered_entries};
use crate::triggers::{TriggerAudit, TriggerLoad};
use crate::truncate_chars;

/// Maximum characters of one rendered screen line.
pub const SCREEN_LINE_CHARS_MAX: usize = 120;
/// Maximum tool rows on the Sessions screen.
pub const SESSION_ROWS_MAX: usize = 64;
/// Maximum op-log rows on the Op-log screen.
pub const OPLOG_ROWS_MAX: usize = 40;
/// Maximum event lines on the Log screen.
pub const LOG_ROWS_MAX: usize = 60;

fn line(text: &str) -> String {
    truncate_chars(text, SCREEN_LINE_CHARS_MAX)
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "-".to_string(),
        other => other.to_string(),
    }
}

/// Screen 1 — Overview: broker status, registered apps,
/// downstream editor reachability.
pub fn overview_lines(status: &Value, apps: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    out.push(line(&format!(
        "Seahawk {} — authenticated broker for Unreal Engine 5.8's editor MCP server",
        scalar_text(status.get("version").unwrap_or(&Value::Null))
    )));
    out.push(line(&format!(
        "server: {}   source: {}   config_loaded: {}",
        scalar_text(status.get("server").unwrap_or(&Value::Null)),
        scalar_text(status.get("source").unwrap_or(&Value::Null)),
        scalar_text(status.get("config_loaded").unwrap_or(&Value::Null)),
    )));
    if let Some(error) = status.get("config_error").and_then(Value::as_str) {
        out.push(line(&format!("config_error: {error}")));
    }
    out.push(line(&format!(
        "downstream (editor MCP): {}",
        scalar_text(status.get("downstream_url").unwrap_or(&Value::Null))
    )));
    out.push(line(&format!(
        "downstream reachability: {}",
        scalar_text(
            status
                .get("downstream_reachability")
                .unwrap_or(&Value::Null)
        )
    )));
    out.push(line(&format!(
        "surface built: {}   operator token configured: {}",
        scalar_text(
            status
                .get("downstream_surface_built")
                .unwrap_or(&Value::Null)
        ),
        scalar_text(
            status
                .get("operator_token_configured")
                .unwrap_or(&Value::Null)
        ),
    )));
    out.push(line(&format!(
        "execute_enabled: {}   actuate_enabled: {}",
        scalar_text(status.get("execute_enabled").unwrap_or(&Value::Null)),
        scalar_text(status.get("actuate_enabled").unwrap_or(&Value::Null)),
    )));
    out.push(line(&format!(
        "oplog: {}",
        scalar_text(status.get("oplog_path").unwrap_or(&Value::Null))
    )));
    out.push(String::new());
    out.push(line(&format!("registered apps ({}):", apps.len())));
    if apps.is_empty() {
        out.push(line("  (none registered in policy)"));
    }
    for app in apps {
        out.push(line(&format!(
            "  {} — {} (observe: {}, actuate: {}, enabled: {})",
            scalar_text(app.get("name").unwrap_or(&Value::Null)),
            scalar_text(app.get("display_name").unwrap_or(&Value::Null)),
            scalar_text(app.get("observe_tool").unwrap_or(&Value::Null)),
            scalar_text(app.get("actuate_tool").unwrap_or(&Value::Null)),
            scalar_text(app.get("actuate_enabled").unwrap_or(&Value::Null)),
        )));
    }
    out
}

/// Screen 2 — Sessions: registered apps summary line, broker
/// session state, and the tool list with the staging area.
pub fn sessions_lines(
    tools: &[ToolInfo],
    selected: usize,
    mode: &str,
    staged: Option<&str>,
    apps: &[Value],
    surface_built: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    out.push(line(&format!(
        "broker session: surface_built={}   registered apps: {}",
        surface_built,
        apps.len()
    )));
    out.push(line(&format!(
        "run mode: {mode}   (plan = stage + approve; auto = run declared read/write directly)"
    )));
    out.push(line(
        "rung-1 rule: actuate/execute-class are PLAN-ONLY — auto refuses them, reason shown, no call made",
    ));
    match staged {
        Some(text) => out.push(line(&format!("staged: {text}"))),
        None => out.push(line(
            "staged: (nothing — select a tool and press Enter to stage/run)",
        )),
    }
    out.push(String::new());
    for (index, tool) in tools.iter().take(SESSION_ROWS_MAX).enumerate() {
        let marker = if index == selected { ">" } else { " " };
        out.push(line(&format!(
            "{marker} {:<10} {}",
            tool.class_str(),
            tool.name
        )));
    }
    if tools.len() > SESSION_ROWS_MAX {
        out.push(line(&format!(
            "  ... {} more tools (SESSION_ROWS_MAX {SESSION_ROWS_MAX})",
            tools.len() - SESSION_ROWS_MAX
        )));
    }
    out
}

/// One op-log row, shared by the screen builder and tests.
pub fn oplog_row(entry: &OpEntryView) -> String {
    let order_flag = if entry.out_of_order { " !order" } else { "" };
    line(&format!(
        "L{:<5} seq {:<5} ts {:<14} {:<9} {:<44} {}{}",
        entry.line_no,
        entry
            .seq
            .map(|seq| seq.to_string())
            .unwrap_or_else(|| "-".to_string()),
        entry.ts,
        entry.class.as_deref().unwrap_or("-"),
        truncate_chars(&entry.tool, 44),
        truncate_chars(&entry.outcome, 36),
        order_flag,
    ))
}

/// Screen 3 — Op-log viewer: tail with filter/search state, the
/// filtered rows, and the selected entry's detail.
pub fn oplog_lines(
    report: &ParseReport,
    filter: ClassFilter,
    search: &str,
    selected: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    out.push(line(&format!(
        "op log: {} entries ({} lines)   filter: {}   search: {:?}",
        report.entries.len(),
        report.total_lines,
        filter.as_str(),
        search
    )));
    out.push(line(&format!(
        "integrity: malformed={} oversized={} truncated_final={} out_of_order={} run_boundaries={} head_bytes_dropped={}",
        report.malformed_lines,
        report.oversized_entries,
        report.truncated_final_line,
        report.out_of_order_entries,
        report.run_boundaries,
        report.head_bytes_dropped
    )));
    let issues = crate::oplog::verify_log(report);
    if issues.is_empty() {
        out.push(line("log verification: no sequence/integrity issues"));
    } else {
        for issue in &issues {
            out.push(line(&format!("log verification: {issue}")));
        }
    }
    out.push(String::new());
    let filtered = filtered_entries(report, filter, search);
    if filtered.is_empty() {
        out.push(line("  (no entries match the filter/search)"));
        return out;
    }
    let selected = selected.min(filtered.len() - 1);
    for (index, entry) in filtered.iter().take(OPLOG_ROWS_MAX).enumerate() {
        let marker = if index == selected { ">" } else { " " };
        out.push(format!("{marker} {}", oplog_row(entry)));
    }
    if filtered.len() > OPLOG_ROWS_MAX {
        out.push(line(&format!(
            "  ... {} more matching entries (OPLOG_ROWS_MAX {OPLOG_ROWS_MAX})",
            filtered.len() - OPLOG_ROWS_MAX
        )));
    }
    out.push(String::new());
    out.push(line("selected entry detail:"));
    for detail_line in entry_detail(filtered[selected]).lines() {
        out.push(line(&format!("  {detail_line}")));
    }
    out
}

/// Screen 4 — Log / Live: the bounded event stream.
pub fn log_lines(events: &[String]) -> Vec<String> {
    let mut out = vec![line(&format!("live events ({}):", events.len()))];
    for event in events.iter().rev().take(LOG_ROWS_MAX).rev() {
        out.push(line(&format!("  {event}")));
    }
    if events.is_empty() {
        out.push(line("  (no events yet — runs and staging land here)"));
    }
    out
}

/// Screen 5 — Fleet: trigger rules (empty by design in rung 1)
/// and the TUI-local audit tail.
pub fn fleet_lines(load: &TriggerLoad, audit: &TriggerAudit) -> Vec<String> {
    let mut out = Vec::new();
    out.push(line("fleet / trigger rules (DESIGN D4)"));
    out.push(line(&format!("source: {}", load.source)));
    out.push(line(&format!(
        "evaluation: {} — rung 1 evaluates and fires NOTHING; rules are display-only",
        if load.evaluation_enabled {
            "enabled"
        } else {
            "disabled"
        }
    )));
    if let Some(error) = &load.error {
        out.push(line(&format!("load error: {error}")));
    }
    if load.rules.is_empty() {
        out.push(line(
            "rules: (empty by design — broker events feeding other MCPs is an Owner design question)",
        ));
    }
    for rule in &load.rules {
        out.push(line(&format!(
            "  {} [{}:{}] on {} -> {}.{} mode={} max_depth={}",
            rule.id,
            rule.origin_lane,
            rule.content_label,
            rule.on_event,
            rule.target_mcp,
            rule.target_tool,
            rule.mode,
            rule.max_depth
        )));
    }
    out.push(String::new());
    out.push(line(&format!(
        "audit (TUI-local, {} lines; the broker's own record is the op log):",
        audit.len()
    )));
    if audit.is_empty() {
        out.push(line("  (no audit lines yet)"));
    }
    for audit_line in audit.lines() {
        out.push(line(&format!("  {audit_line}")));
    }
    out
}

/// The class glyph used in summaries: `R`/`W`/`A`/`X`/`-`.
pub fn class_glyph(class: Option<ToolClass>) -> &'static str {
    match class {
        Some(ToolClass::Read) => "R",
        Some(ToolClass::Write) => "W",
        Some(ToolClass::Actuate) => "A",
        Some(ToolClass::Execute) => "X",
        None => "-",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn overview_shows_reachability_and_apps() {
        let status = json!({
            "version": "1.0.0", "server": "seahawk", "source": "lib",
            "config_loaded": true, "downstream_url": "http://127.0.0.1:8000/mcp",
            "downstream_reachability": "unknown (lib facade)",
            "downstream_surface_built": false, "operator_token_configured": false,
            "execute_enabled": [], "actuate_enabled": [],
            "oplog_path": "seahawk-oplog.jsonl",
        });
        let apps = vec![json!({
            "name": "blender", "display_name": "Blender",
            "observe_tool": "gui.blender.observe", "actuate_tool": "gui.blender.actuate",
            "actuate_enabled": false,
        })];
        let lines = overview_lines(&status, &apps);
        let text = lines.join("\n");
        assert!(text.contains("downstream reachability: unknown"));
        assert!(text.contains("blender"));
        assert!(
            lines
                .iter()
                .all(|l| l.chars().count() <= SCREEN_LINE_CHARS_MAX)
        );
    }

    #[test]
    fn fleet_lines_state_empty_by_design() {
        let load = crate::triggers::load_trigger_rules(None);
        let audit = TriggerAudit::new();
        let text = fleet_lines(&load, &audit).join("\n");
        assert!(text.contains("empty by design"));
        assert!(text.contains("fires NOTHING"));
    }

    #[test]
    fn class_glyphs_are_stable() {
        assert_eq!(class_glyph(Some(ToolClass::Read)), "R");
        assert_eq!(class_glyph(Some(ToolClass::Execute)), "X");
        assert_eq!(class_glyph(None), "-");
    }
}
