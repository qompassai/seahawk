//! The op-log viewer core: a bounded, honest parser for
//! Seahawk's append-only op log, plus integrity verification.
//!
//! The log is the product's audit core: one JSON line per
//! brokered call or guard refusal —
//! `{ts, seq, tool, class, args_sha256, args_bytes, outcome,
//! downstream_ms, error, ...}` (see `seahawk::oplog`). Raw
//! argument values are never logged; only the SHA-256 of their
//! canonical JSON form. That shapes what "verification" can mean
//! here, and this module is explicit about it:
//!
//! - **Verifiable from the log alone:** field presence and shape
//!   (`args_sha256` is a 64-char hex digest, `ts` is non-zero,
//!   the class is a known class word, the outcome is present),
//!   sequence discipline within one broker run (monotonic `seq`,
//!   gaps named), and timestamp ordering.
//! - **Not verifiable from the log alone:** that `args_sha256`
//!   matches the original arguments (they are deliberately not
//!   in the log), and any cross-run ordering. The detail view
//!   says so instead of implying a stronger check.
//!
//! Honesty rules (adversarial cases are first-class):
//! - A truncated final line (a crash mid-append) is reported as
//!   `truncated_final_line`, never silently dropped or parsed
//!   as if complete.
//! - Oversized lines are counted and replaced by a bounded
//!   placeholder; the parser never buffers one without limit.
//! - Out-of-order timestamps are **displayed in file order**
//!   with the out-of-order entries flagged — the viewer never
//!   re-sorts the audit record into a prettier lie.

use std::path::Path;

use serde_json::Value;

/// Maximum bytes of op-log file read in one load.
pub const OPLOG_FILE_BYTES_MAX: usize = 8_388_608;
/// Maximum bytes of one op-log line; longer lines are oversized.
pub const OPLOG_ENTRY_BYTES_MAX: usize = 16_384;
/// Maximum entries retained in one parse report (the tail).
pub const OPLOG_ENTRIES_MAX: usize = 5_000;
/// Maximum characters of one search query.
pub const SEARCH_CHARS_MAX: usize = 128;
/// Default tail size for the viewer.
pub const OPLOG_TAIL_DEFAULT: usize = 200;

/// One parsed op-log entry, in file order.
#[derive(Clone, Debug, PartialEq)]
pub struct OpEntryView {
    /// 1-based line number in the file.
    pub line_no: usize,
    /// Milliseconds since the Unix epoch (0 when absent).
    pub ts: u128,
    /// Per-run sequence number, when present.
    pub seq: Option<u64>,
    /// Tool name (`?` when absent).
    pub tool: String,
    /// Class word, when the entry carries one.
    pub class: Option<String>,
    /// `ok`, `error`, or `refused:<code>`.
    pub outcome: String,
    /// SHA-256 hex of the canonical arguments, when logged.
    pub args_sha256: Option<String>,
    /// Canonical argument byte count.
    pub args_bytes: u64,
    /// Downstream latency, milliseconds, when logged.
    pub downstream_ms: Option<u64>,
    /// Error text, when logged.
    pub error: Option<String>,
    /// This entry's `ts` is earlier than its predecessor's.
    pub out_of_order: bool,
    /// The raw line exceeded [`OPLOG_ENTRY_BYTES_MAX`]; this is
    /// a bounded placeholder, not the entry's content.
    pub oversized: bool,
    /// The raw JSON value (`Null` for placeholders).
    pub raw: Value,
}

/// The outcome of parsing an op-log text.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParseReport {
    /// Entries in file order (the tail, bounded).
    pub entries: Vec<OpEntryView>,
    /// Total lines seen, including malformed and oversized.
    pub total_lines: usize,
    /// Non-final lines that failed to parse as JSON objects.
    pub malformed_lines: usize,
    /// Lines over [`OPLOG_ENTRY_BYTES_MAX`].
    pub oversized_entries: usize,
    /// The final line was incomplete (no trailing newline and
    /// unparseable) — a crash mid-append, reported honestly.
    pub truncated_final_line: bool,
    /// Entries whose `ts` is earlier than their predecessor's.
    pub out_of_order_entries: usize,
    /// Times `seq` reset or repeated — each marks a new broker
    /// run's numbering (seq is per-process in `seahawk::oplog`).
    pub run_boundaries: usize,
    /// Bytes dropped from the front when the file exceeded
    /// [`OPLOG_FILE_BYTES_MAX`] before parsing.
    pub head_bytes_dropped: usize,
}

/// Parse op-log text (JSONL) into a [`ParseReport`].
pub fn parse_oplog_text(text: &str) -> ParseReport {
    let mut report = ParseReport::default();
    if text.is_empty() {
        return report;
    }
    let ends_with_newline = text.ends_with('\n');
    let lines: Vec<&str> = text.lines().collect();
    let last_index = lines.len().saturating_sub(1);
    let mut prev_ts: Option<u128> = None;
    let mut prev_seq: Option<u64> = None;
    for (index, line) in lines.iter().enumerate() {
        report.total_lines += 1;
        let line_no = index + 1;
        if line.len() > OPLOG_ENTRY_BYTES_MAX {
            report.oversized_entries += 1;
            report.entries.push(OpEntryView {
                line_no,
                ts: 0,
                seq: None,
                tool: "<oversized entry>".to_string(),
                class: None,
                outcome: "oversized".to_string(),
                args_sha256: None,
                args_bytes: 0,
                downstream_ms: None,
                error: Some(format!(
                    "line is {} bytes, over OPLOG_ENTRY_BYTES_MAX {OPLOG_ENTRY_BYTES_MAX}; \
                     content not retained",
                    line.len()
                )),
                out_of_order: false,
                oversized: true,
                raw: Value::Null,
            });
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Result<Value, _> = serde_json::from_str(line);
        let value = match parsed {
            Ok(value) if value.is_object() => value,
            _ => {
                if index == last_index && !ends_with_newline {
                    report.truncated_final_line = true;
                } else {
                    report.malformed_lines += 1;
                }
                continue;
            }
        };
        let ts = value.get("ts").and_then(Value::as_u64).unwrap_or(0) as u128;
        let seq = value.get("seq").and_then(Value::as_u64);
        let out_of_order = matches!(prev_ts, Some(prev) if ts < prev && ts != 0);
        if out_of_order {
            report.out_of_order_entries += 1;
        }
        if ts != 0 {
            prev_ts = Some(ts);
        }
        if let (Some(prev), Some(current)) = (prev_seq, seq)
            && current <= prev
        {
            report.run_boundaries += 1;
        }
        if seq.is_some() {
            prev_seq = seq;
        }
        report.entries.push(OpEntryView {
            line_no,
            ts,
            seq,
            tool: value
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string(),
            class: value
                .get("class")
                .and_then(Value::as_str)
                .map(str::to_string),
            outcome: value
                .get("outcome")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            args_sha256: value
                .get("args_sha256")
                .and_then(Value::as_str)
                .map(str::to_string),
            args_bytes: value.get("args_bytes").and_then(Value::as_u64).unwrap_or(0),
            downstream_ms: value.get("downstream_ms").and_then(Value::as_u64),
            error: value
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_string),
            out_of_order,
            oversized: false,
            raw: value,
        });
    }
    if report.entries.len() > OPLOG_ENTRIES_MAX {
        let excess = report.entries.len() - OPLOG_ENTRIES_MAX;
        report.entries.drain(..excess);
    }
    report
}

/// Build a report from already-parsed JSON values (the stdio
/// facade path, where the broker returns entries as values).
/// Line-level facts (truncation, oversized) are not available on
/// this path and stay at their defaults — the report does not
/// pretend otherwise.
pub fn report_from_values(values: &[Value]) -> ParseReport {
    let mut text = String::new();
    for value in values.iter().take(OPLOG_ENTRIES_MAX) {
        if let Ok(line) = serde_json::to_string(value) {
            text.push_str(&line);
            text.push('\n');
        }
    }
    parse_oplog_text(&text)
}

/// Load and parse an op-log file, bounded to the last
/// [`OPLOG_FILE_BYTES_MAX`] bytes (aligned to a line boundary).
pub fn load_oplog_file(path: &Path) -> std::io::Result<ParseReport> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    let mut head_bytes_dropped = 0usize;
    if metadata.len() > OPLOG_FILE_BYTES_MAX as u64 {
        let skip = metadata.len() - OPLOG_FILE_BYTES_MAX as u64;
        head_bytes_dropped = usize::try_from(skip).unwrap_or(usize::MAX);
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(skip))?;
    }
    let mut bytes = Vec::new();
    file.take(OPLOG_FILE_BYTES_MAX as u64)
        .read_to_end(&mut bytes)?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if head_bytes_dropped > 0 {
        // Drop the partial first line created by the byte skip.
        if let Some(newline) = text.find('\n') {
            text = text[newline + 1..].to_string();
        }
    }
    let mut report = parse_oplog_text(&text);
    report.head_bytes_dropped = head_bytes_dropped;
    Ok(report)
}

/// The class filter for the viewer. `Observe` is the operator's
/// word for the read-class observation surface (`gui.*.observe`,
/// `gui.observe`, `seahawk_oplog`, screenshots-as-evidence).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClassFilter {
    /// Every entry.
    #[default]
    All,
    /// Read-class observation tools.
    Observe,
    /// `read` class.
    Read,
    /// `write` class.
    Write,
    /// `actuate` class.
    Actuate,
    /// `execute` class.
    Execute,
    /// Any `refused:<code>` outcome.
    Refused,
    /// Any `error` outcome or error field.
    Errors,
}

impl ClassFilter {
    /// All filters in cycle order (the `f` key cycles).
    pub const ALL: [ClassFilter; 8] = [
        ClassFilter::All,
        ClassFilter::Observe,
        ClassFilter::Read,
        ClassFilter::Write,
        ClassFilter::Actuate,
        ClassFilter::Execute,
        ClassFilter::Refused,
        ClassFilter::Errors,
    ];

    /// Parse a filter name (line mode / CLI).
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().as_str() {
            "all" => Some(Self::All),
            "observe" => Some(Self::Observe),
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "actuate" => Some(Self::Actuate),
            "execute" => Some(Self::Execute),
            "refused" => Some(Self::Refused),
            "errors" | "error" => Some(Self::Errors),
            _ => None,
        }
    }

    /// The filter's display name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Observe => "observe",
            Self::Read => "read",
            Self::Write => "write",
            Self::Actuate => "actuate",
            Self::Execute => "execute",
            Self::Refused => "refused",
            Self::Errors => "errors",
        }
    }

    /// The next filter in cycle order.
    pub fn next(&self) -> Self {
        let index = Self::ALL.iter().position(|item| item == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    /// Whether one entry passes this filter.
    pub fn matches(&self, entry: &OpEntryView) -> bool {
        match self {
            Self::All => true,
            Self::Observe => {
                entry.class.as_deref() == Some("read")
                    && (entry.tool.ends_with(".observe")
                        || entry.tool == "gui.observe"
                        || entry.tool == "seahawk_oplog")
            }
            Self::Read => entry.class.as_deref() == Some("read"),
            Self::Write => entry.class.as_deref() == Some("write"),
            Self::Actuate => entry.class.as_deref() == Some("actuate"),
            Self::Execute => entry.class.as_deref() == Some("execute"),
            Self::Refused => entry.outcome.starts_with("refused:"),
            Self::Errors => entry.outcome == "error" || entry.error.is_some(),
        }
    }
}

/// Whether one entry matches a search query (case-insensitive
/// substring over tool, class, outcome, and error). The query is
/// bounded to [`SEARCH_CHARS_MAX`] characters by the caller;
/// longer queries are truncated here as a second line of defence.
pub fn matches_search(entry: &OpEntryView, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let needle: String = query
        .chars()
        .take(SEARCH_CHARS_MAX)
        .collect::<String>()
        .to_lowercase();
    let haystacks = [
        entry.tool.as_str(),
        entry.class.as_deref().unwrap_or(""),
        entry.outcome.as_str(),
        entry.error.as_deref().unwrap_or(""),
    ];
    haystacks
        .iter()
        .any(|text| text.to_lowercase().contains(&needle))
}

/// Entries passing both the class filter and the search query,
/// in file order.
pub fn filtered_entries<'a>(
    report: &'a ParseReport,
    filter: ClassFilter,
    search: &str,
) -> Vec<&'a OpEntryView> {
    report
        .entries
        .iter()
        .filter(|entry| filter.matches(entry) && matches_search(entry, search))
        .collect()
}

/// Verify one entry's integrity fields against what the log
/// format itself guarantees. Returns human-readable issues; an
/// empty vec means the entry is well-formed *as a record* (see
/// the module docs for what that does and does not prove).
pub fn verify_entry(entry: &OpEntryView) -> Vec<String> {
    let mut issues = Vec::new();
    if entry.oversized {
        issues.push("entry exceeded OPLOG_ENTRY_BYTES_MAX; content not retained".to_string());
        return issues;
    }
    if entry.seq.is_none() {
        issues.push("missing seq".to_string());
    }
    if entry.ts == 0 {
        issues.push("timestamp is zero or missing".to_string());
    }
    if entry.outcome.is_empty() {
        issues.push("missing outcome".to_string());
    }
    if let Some(class) = &entry.class
        && !matches!(
            class.as_str(),
            "read" | "write" | "actuate" | "execute" | "acquire"
        )
    {
        issues.push(format!("unknown class {class:?}"));
    }
    match &entry.args_sha256 {
        Some(digest) => {
            if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
                issues.push(format!(
                    "args_sha256 is not a 64-char hex digest ({} chars)",
                    digest.chars().count()
                ));
            }
        }
        None => {
            if entry.args_bytes > 0 {
                issues.push("args_bytes > 0 but no args_sha256 recorded".to_string());
            }
        }
    }
    issues
}

/// Verify sequence discipline across a whole report: within one
/// run, `seq` must increase by exactly 1 per entry; a reset or
/// repeat starts a new run (counted in the report) and is not
/// itself an issue. Gaps inside a run are issues — entries are
/// missing from the record, or the record was edited.
pub fn verify_log(report: &ParseReport) -> Vec<String> {
    let mut issues = Vec::new();
    let mut prev_seq: Option<u64> = None;
    for entry in &report.entries {
        let Some(seq) = entry.seq else {
            continue;
        };
        if let Some(prev) = prev_seq
            && let Some(expected) = prev.checked_add(1)
            && seq > expected
        {
            issues.push(format!(
                "line {}: seq gap {prev} -> {seq} ({} missing)",
                entry.line_no,
                seq - expected
            ));
        }
        prev_seq = Some(seq);
    }
    if report.truncated_final_line {
        issues.push(
            "final line is truncated (crash mid-append?); the record ends mid-entry".to_string(),
        );
    }
    if report.malformed_lines > 0 {
        issues.push(format!(
            "{} malformed line(s) in the body of the log",
            report.malformed_lines
        ));
    }
    issues
}

/// Render one entry's detail: every field, the per-entry
/// verification, and the honest limits of that verification.
pub fn entry_detail(entry: &OpEntryView) -> String {
    let mut out = String::new();
    out.push_str(&format!("line:       {}\n", entry.line_no));
    out.push_str(&format!("ts:         {} (ms since epoch)\n", entry.ts));
    out.push_str(&format!(
        "seq:        {}\n",
        entry
            .seq
            .map(|seq| seq.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    out.push_str(&format!("tool:       {}\n", entry.tool));
    out.push_str(&format!(
        "class:      {}\n",
        entry.class.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!("outcome:    {}\n", entry.outcome));
    out.push_str(&format!(
        "args_sha256: {}\n",
        entry.args_sha256.as_deref().unwrap_or("-")
    ));
    out.push_str(&format!("args_bytes: {}\n", entry.args_bytes));
    out.push_str(&format!(
        "downstream_ms: {}\n",
        entry
            .downstream_ms
            .map(|ms| ms.to_string())
            .unwrap_or_else(|| "-".to_string())
    ));
    if let Some(error) = &entry.error {
        out.push_str(&format!("error:      {error}\n"));
    }
    if entry.out_of_order {
        out.push_str("ordering:   OUT OF ORDER — ts is earlier than the previous entry; shown in file order, not re-sorted\n");
    }
    let issues = verify_entry(entry);
    if issues.is_empty() {
        out.push_str("integrity:  fields well-formed (digest shape, seq, ts, class, outcome)\n");
    } else {
        out.push_str("integrity:  ISSUES:\n");
        for issue in &issues {
            out.push_str(&format!("  - {issue}\n"));
        }
    }
    out.push_str(
        "note:       args_sha256 cannot be re-checked against the original arguments \
         (raw values are never logged, by design); verification covers the record's \
         own field and sequence integrity only.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = concat!(
        "{\"ts\":1000,\"seq\":0,\"tool\":\"seahawk_status\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
        "{\"ts\":1005,\"seq\":1,\"tool\":\"gui.blender.observe\",\"class\":\"read\",\"args_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"args_bytes\":12,\"outcome\":\"ok\",\"downstream_ms\":7}\n",
        "{\"ts\":1010,\"seq\":2,\"tool\":\"EditorToolset.X.Run\",\"class\":\"execute\",\"args_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"args_bytes\":30,\"outcome\":\"refused:seahawk_execute_disabled\"}\n",
    );

    #[test]
    fn parses_well_formed_log_in_file_order() {
        let report = parse_oplog_text(SAMPLE);
        assert_eq!(report.entries.len(), 3);
        assert_eq!(report.total_lines, 3);
        assert!(!report.truncated_final_line);
        assert_eq!(report.malformed_lines, 0);
        assert_eq!(report.entries[1].tool, "gui.blender.observe");
        assert_eq!(report.entries[2].class.as_deref(), Some("execute"));
        assert!(verify_log(&report).is_empty());
    }

    #[test]
    fn truncated_final_line_is_reported_not_dropped_silently() {
        // Adversarial: a crash mid-append leaves a partial line
        // with no trailing newline.
        let text = format!("{SAMPLE}{{\"ts\":2000,\"seq\":3,\"tool\":\"gui.blen");
        let report = parse_oplog_text(&text);
        assert!(report.truncated_final_line, "{report:?}");
        assert_eq!(report.entries.len(), 3, "partial entry must not parse");
        assert!(
            verify_log(&report)
                .iter()
                .any(|issue| issue.contains("truncated"))
        );
    }

    #[test]
    fn complete_final_line_without_newline_is_not_truncation() {
        let text = SAMPLE.trim_end_matches('\n');
        let report = parse_oplog_text(text);
        assert!(!report.truncated_final_line);
        assert_eq!(report.entries.len(), 3);
    }

    #[test]
    fn malformed_middle_line_is_counted() {
        let text = format!("{SAMPLE}not json at all\n{SAMPLE}");
        let report = parse_oplog_text(&text);
        assert_eq!(report.malformed_lines, 1);
        assert_eq!(report.entries.len(), 6);
    }

    #[test]
    fn oversized_entry_is_bounded_and_flagged() {
        // Adversarial: one gigantic line must not be retained.
        let big_tool = "x".repeat(OPLOG_ENTRY_BYTES_MAX + 100);
        let text = format!(
            "{{\"ts\":1,\"seq\":0,\"tool\":\"{big_tool}\",\"args_bytes\":0,\"outcome\":\"ok\"}}\n{SAMPLE}"
        );
        let report = parse_oplog_text(&text);
        assert_eq!(report.oversized_entries, 1);
        assert!(report.entries[0].oversized);
        assert!(report.entries[0].tool.chars().count() < 64);
        assert_eq!(report.entries.len(), 4);
        assert!(
            !verify_entry(&report.entries[0]).is_empty(),
            "oversized placeholder must carry an integrity issue"
        );
    }

    #[test]
    fn out_of_order_timestamps_stay_in_file_order_and_are_flagged() {
        // Adversarial: clock skew / a hand-edited log. The viewer
        // must show file order and flag it, never re-sort.
        let text = concat!(
            "{\"ts\":5000,\"seq\":0,\"tool\":\"a.first\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
            "{\"ts\":4000,\"seq\":1,\"tool\":\"b.second\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
            "{\"ts\":6000,\"seq\":2,\"tool\":\"c.third\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
        );
        let report = parse_oplog_text(text);
        assert_eq!(report.out_of_order_entries, 1);
        assert!(!report.entries[0].out_of_order);
        assert!(report.entries[1].out_of_order);
        assert_eq!(
            report
                .entries
                .iter()
                .map(|entry| entry.tool.as_str())
                .collect::<Vec<_>>(),
            vec!["a.first", "b.second", "c.third"],
            "file order preserved"
        );
        assert!(entry_detail(&report.entries[1]).contains("OUT OF ORDER"));
    }

    #[test]
    fn seq_gap_and_run_boundary_are_distinguished() {
        let gapped = concat!(
            "{\"ts\":1,\"seq\":0,\"tool\":\"a\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
            "{\"ts\":2,\"seq\":3,\"tool\":\"b\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
        );
        let report = parse_oplog_text(gapped);
        assert!(
            verify_log(&report)
                .iter()
                .any(|issue| issue.contains("seq gap 0 -> 3")),
            "{:?}",
            verify_log(&report)
        );
        // A reset to 0 is a new broker run, not a gap.
        let restarted = concat!(
            "{\"ts\":1,\"seq\":7,\"tool\":\"a\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
            "{\"ts\":2,\"seq\":0,\"tool\":\"b\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
            "{\"ts\":3,\"seq\":1,\"tool\":\"c\",\"args_bytes\":0,\"outcome\":\"ok\"}\n",
        );
        let report = parse_oplog_text(restarted);
        assert_eq!(report.run_boundaries, 1);
        assert!(verify_log(&report).is_empty(), "{:?}", verify_log(&report));
    }

    #[test]
    fn verify_entry_catches_bad_digest_and_missing_fields() {
        let text = "{\"ts\":0,\"tool\":\"a\",\"class\":\"bogus\",\"args_sha256\":\"xyz\",\"args_bytes\":5,\"outcome\":\"\"}\n";
        let report = parse_oplog_text(text);
        let issues = verify_entry(&report.entries[0]);
        assert!(
            issues.iter().any(|i| i.contains("missing seq")),
            "{issues:?}"
        );
        assert!(issues.iter().any(|i| i.contains("zero")), "{issues:?}");
        assert!(
            issues.iter().any(|i| i.contains("64-char hex")),
            "{issues:?}"
        );
        assert!(
            issues.iter().any(|i| i.contains("unknown class")),
            "{issues:?}"
        );
    }

    #[test]
    fn class_filters_cover_observe_and_execute() {
        let report = parse_oplog_text(SAMPLE);
        let observe = filtered_entries(&report, ClassFilter::Observe, "");
        assert_eq!(observe.len(), 1);
        assert_eq!(observe[0].tool, "gui.blender.observe");
        let execute = filtered_entries(&report, ClassFilter::Execute, "");
        assert_eq!(execute.len(), 1);
        assert_eq!(execute[0].class.as_deref(), Some("execute"));
        let refused = filtered_entries(&report, ClassFilter::Refused, "");
        assert_eq!(refused.len(), 1);
        assert_eq!(ClassFilter::parse("observe"), Some(ClassFilter::Observe));
        assert_eq!(ClassFilter::parse("execute"), Some(ClassFilter::Execute));
        assert_eq!(ClassFilter::parse("bogus"), None);
        assert_eq!(ClassFilter::All.next(), ClassFilter::Observe);
    }

    #[test]
    fn search_matches_tool_outcome_and_error_case_insensitively() {
        let report = parse_oplog_text(SAMPLE);
        assert_eq!(
            filtered_entries(&report, ClassFilter::All, "BLENDER").len(),
            1
        );
        assert_eq!(
            filtered_entries(&report, ClassFilter::All, "execute_disabled").len(),
            1
        );
        assert_eq!(filtered_entries(&report, ClassFilter::All, "nope").len(), 0);
    }

    #[test]
    fn report_from_values_round_trips() {
        let values: Vec<Value> = vec![
            serde_json::json!({"ts": 5, "seq": 0, "tool": "a", "args_bytes": 0, "outcome": "ok"}),
        ];
        let report = report_from_values(&values);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].tool, "a");
    }

    #[test]
    fn empty_and_blank_logs_parse_clean() {
        assert_eq!(parse_oplog_text("").entries.len(), 0);
        assert_eq!(parse_oplog_text("\n\n").entries.len(), 0);
    }
}
