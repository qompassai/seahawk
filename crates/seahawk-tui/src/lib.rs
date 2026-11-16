//! Seahawk TUI — the broker console for Seahawk, the estate's
//! authenticated broker for Unreal Engine 5.8's built-in MCP server.
//!
//! Fleet TUI pattern (programme DESIGN §D2), rung 1:
//!
//! - [`facade`] — the narrow trait the UI programs against
//!   ([`facade::SeahawkFacade`]): a library facade over the
//!   `seahawk` lib where it is reachable (config, class table,
//!   op log), an MCP stdio client facade that spawns the broker
//!   binary as the fallback transport, and a scripted
//!   [`facade::FakeFacade`] used by every test.
//! - [`app`] — the event loop and screen state machine, including
//!   the rung-1 staging rule: actuate- and execute-class calls are
//!   **plan-only**; auto mode refuses them with the reason shown
//!   and no call made (the TUI mirror of Seahawk's own
//!   execute-class default-deny in `seahawk::policy::decide`).
//! - [`oplog`] — the append-only op-log viewer core: a bounded,
//!   honest parser for the broker's JSONL audit record (the
//!   product's centrepiece) plus per-entry integrity verification.
//! - [`panels`] — pure ratatui widget constructors with named
//!   truncation bounds, tested through `TestBackend`.
//! - [`screens`] — pure text builders, one per screen, shared by
//!   the full-screen panels and the non-TTY line mode.
//! - [`triggers`] — the D4 trigger-rule surface: rung 1 ships
//!   **no outbound rules by design** (broker events feeding other
//!   MCPs is an Owner design question); the Fleet panel shows the
//!   rule list (empty) and the audit log.
//!
//! There is no Media screen: Seahawk's use case has no media
//! surface tonight (DESIGN §D2 screen 5 applies only where the
//! member's work involves images/video/diagrams as operator
//! material; Seahawk's screenshots are broker evidence, already
//! digest-referenced in the op log).
//!
//! # Bounds
//!
//! Every queue, buffer, line, and render carries a named `*_MAX`
//! constant in its owning module: [`app::EVENT_LINES_MAX`],
//! [`app::INPUT_LINE_BYTES_MAX`], [`oplog::OPLOG_FILE_BYTES_MAX`],
//! [`oplog::OPLOG_ENTRY_BYTES_MAX`], [`oplog::OPLOG_ENTRIES_MAX`],
//! [`facade::CALL_ARGS_BYTES_MAX`], [`triggers::TRIGGER_RULES_MAX`].

#![forbid(unsafe_code)]

pub mod app;
pub mod facade;
pub mod oplog;
pub mod panels;
pub mod screens;
pub mod triggers;

/// Truncate `text` to at most `max_chars` characters, appending
/// `...` when truncated. Character-based, never byte-based, so a
/// multi-byte character is never split.
pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let keep = max_chars.saturating_sub(3);
    let mut out: String = text.chars().take(keep).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::truncate_chars;

    #[test]
    fn truncate_is_char_safe_and_bounded() {
        assert_eq!(truncate_chars("hello", 10), "hello");
        assert_eq!(truncate_chars("hello world", 8), "hello...");
        // Multi-byte characters count as one and are never split.
        let out = truncate_chars("éééééééé", 6);
        assert_eq!(out.chars().count(), 6);
        assert_eq!(out, "ééé...");
    }
}
