//! Pure ratatui widget constructors.
//!
//! Every panel is a pure function from data to widget — no
//! terminal access, no I/O. The interactive loop in
//! [`crate::app`] renders them; tests render them into a
//! [`TestBackend`] and assert on the buffer text. All embedded
//! text passes through the screen builders' named truncation
//! bounds ([`crate::screens::SCREEN_LINE_CHARS_MAX`]).

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Wrap};

use serde_json::Value;

use crate::facade::ToolInfo;
use crate::oplog::{ClassFilter, ParseReport};
use crate::screens;
use crate::triggers::{TriggerAudit, TriggerLoad};

/// Wrap a screen's text lines in a bordered, titled panel.
pub fn text_panel(title: &str, lines: &[String], color: Color) -> Paragraph<'static> {
    let style = Style::default().fg(color).add_modifier(Modifier::BOLD);
    Paragraph::new(lines.join("\n"))
        .block(
            Block::bordered()
                .title(Line::from(title.to_string()).style(style))
                .border_style(style),
        )
        .wrap(Wrap { trim: false })
}

/// The Overview panel (broker status, apps, reachability).
pub fn overview_panel(status: &Value, apps: &[Value]) -> Paragraph<'static> {
    text_panel(
        "Seahawk — Overview",
        &screens::overview_lines(status, apps),
        Color::Green,
    )
}

/// The Sessions panel (tool list + staging state).
pub fn sessions_panel(
    tools: &[ToolInfo],
    selected: usize,
    mode: &str,
    staged: Option<&str>,
    apps: &[Value],
    surface_built: bool,
) -> Paragraph<'static> {
    text_panel(
        "Seahawk — Sessions",
        &screens::sessions_lines(tools, selected, mode, staged, apps, surface_built),
        Color::Cyan,
    )
}

/// The Op-log panel (the centrepiece viewer).
pub fn oplog_panel(
    report: &ParseReport,
    filter: ClassFilter,
    search: &str,
    selected: usize,
) -> Paragraph<'static> {
    text_panel(
        "Seahawk — Op Log",
        &screens::oplog_lines(report, filter, search, selected),
        Color::Yellow,
    )
}

/// The Log / Live panel.
pub fn log_panel(events: &[String]) -> Paragraph<'static> {
    text_panel(
        "Seahawk — Log / Live",
        &screens::log_lines(events),
        Color::Magenta,
    )
}

/// The Fleet panel (trigger rules + audit).
pub fn fleet_panel(load: &TriggerLoad, audit: &TriggerAudit) -> Paragraph<'static> {
    text_panel(
        "Seahawk — Fleet",
        &screens::fleet_lines(load, audit),
        Color::Blue,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use crate::facade::FakeFacade;
    use crate::facade::SeahawkFacade as _;
    use crate::oplog::parse_oplog_text;

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn overview_panel_renders_status() {
        let mut fake = FakeFacade::with_default_surface();
        let status = fake.status().expect("status");
        let apps = fake.registered_apps().expect("apps");
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                frame.render_widget(overview_panel(&status, &apps), frame.area());
            })
            .expect("draw");
        let text = buffer_text(&terminal);
        assert!(text.contains("Seahawk"), "{text}");
        assert!(text.contains("Overview"), "{text}");
    }

    #[test]
    fn oplog_panel_renders_entries_and_detail() {
        let report = parse_oplog_text(
            "{\"ts\":1000,\"seq\":0,\"tool\":\"gui.blender.observe\",\"class\":\"read\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
        );
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                frame.render_widget(oplog_panel(&report, ClassFilter::All, "", 0), frame.area());
            })
            .expect("draw");
        let text = buffer_text(&terminal);
        assert!(text.contains("gui.blender.observe"), "{text}");
        assert!(text.contains("integrity"), "{text}");
    }

    #[test]
    fn fleet_panel_renders_empty_by_design() {
        let load = crate::triggers::load_trigger_rules(None);
        let audit = TriggerAudit::new();
        let backend = TestBackend::new(110, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                frame.render_widget(fleet_panel(&load, &audit), frame.area());
            })
            .expect("draw");
        let text = buffer_text(&terminal);
        assert!(text.contains("empty"), "{text}");
    }

    #[test]
    fn sessions_panel_names_the_plan_only_rule() {
        let mut fake = FakeFacade::with_default_surface();
        let tools = fake.tools().expect("tools");
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                frame.render_widget(
                    sessions_panel(&tools, 0, "plan", None, &[], false),
                    frame.area(),
                );
            })
            .expect("draw");
        let text = buffer_text(&terminal);
        assert!(text.contains("PLAN-ONLY"), "{text}");
    }
}
