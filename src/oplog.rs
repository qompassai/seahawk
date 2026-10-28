//! The append-only op log: the non-idempotency record.
//!
//! Every brokered call and every guard refusal appends one JSON line:
//! `{ts, seq, tool, class, args_sha256, args_bytes, outcome,
//! downstream_ms, error}`. Raw argument values are never logged —
//! only the SHA-256 of their canonical JSON form, which is enough to
//! prove *what* was applied, in order, without turning the log into
//! a copy of the project.
//!
//! Opening the log at startup is fatal on failure (a broker that
//! cannot keep its record must not run). A write failure mid-run is
//! counted and surfaced via `seahawk_status`, never silent, but does
//! not wedge in-flight work.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// One op-log entry (serialized as one JSON line).
#[derive(Debug, Serialize)]
pub struct OpEntry {
    /// Milliseconds since the Unix epoch.
    pub ts: u128,
    /// Monotonic sequence number within this process run.
    pub seq: u64,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_sha256: Option<String>,
    pub args_bytes: usize,
    /// `ok`, `error`, or `refused:<code>`.
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downstream_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// S4 observe evidence: SHA-256 of the returned frame's PNG
    /// bytes (the image itself is never logged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_height: Option<u32>,
    /// S4 actuation bracketing: screenshot digests taken
    /// immediately before and after the action — a click cannot be
    /// undone, so the record shows what the screen held on both
    /// sides of it (GATE-REPORT S4 design).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_sha256: Option<String>,
    /// S4 actuation target: window identity + coordinates or keys,
    /// e.g. `click 640,512 window 0x2a00007 "Blender"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// The S4 evidence fields of an op-log entry. All optional; the
/// brokered (Unreal) path leaves them empty.
#[derive(Debug, Default)]
pub struct LogExtra {
    pub frame_sha256: Option<String>,
    pub frame_width: Option<u32>,
    pub frame_height: Option<u32>,
    pub pre_sha256: Option<String>,
    pub post_sha256: Option<String>,
    pub target: Option<String>,
}

pub struct OpLog {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
    seq: AtomicU64,
    write_failures: AtomicU64,
}

impl OpLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: Mutex::new(BufWriter::new(file)),
            seq: AtomicU64::new(0),
            write_failures: AtomicU64::new(0),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_failures(&self) -> u64 {
        self.write_failures.load(Ordering::Relaxed)
    }

    /// Appends one entry. Returns the sequence number assigned.
    pub fn record(
        &self,
        tool: &str,
        class: Option<&str>,
        args: Option<&Value>,
        outcome: &str,
        downstream_ms: Option<u64>,
        error: Option<&str>,
    ) -> u64 {
        self.record_with(
            tool,
            class,
            args,
            outcome,
            downstream_ms,
            error,
            LogExtra::default(),
        )
    }

    /// Appends one entry with S4 GUI evidence fields attached.
    #[allow(clippy::too_many_arguments)]
    pub fn record_with(
        &self,
        tool: &str,
        class: Option<&str>,
        args: Option<&Value>,
        outcome: &str,
        downstream_ms: Option<u64>,
        error: Option<&str>,
        extra: LogExtra,
    ) -> u64 {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let (args_sha256, args_bytes) = match args {
            Some(value) => {
                let canonical = canonical_json(value);
                (
                    Some(hex(&Sha256::digest(canonical.as_bytes()))),
                    canonical.len(),
                )
            }
            None => (None, 0),
        };
        let entry = OpEntry {
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            seq,
            tool: tool.to_string(),
            class: class.map(str::to_string),
            args_sha256,
            args_bytes,
            outcome: outcome.to_string(),
            downstream_ms,
            error: error.map(str::to_string),
            frame_sha256: extra.frame_sha256,
            frame_width: extra.frame_width,
            frame_height: extra.frame_height,
            pre_sha256: extra.pre_sha256,
            post_sha256: extra.post_sha256,
            target: extra.target,
        };
        let line = serde_json::to_string(&entry).unwrap_or_else(|_| "{}".to_string());
        let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        if writeln!(writer, "{line}")
            .and_then(|()| writer.flush())
            .is_err()
        {
            self.write_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!("seahawk: op-log write failed (entry seq {seq} for {tool})");
        }
        seq
    }

    /// Reads the last `limit` entries back (newest last). Used by the
    /// `seahawk_oplog` tool; entries contain digests only, never raw
    /// argument values.
    pub fn read_recent(&self, limit: usize) -> Vec<Value> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        let lines: Vec<&str> = text.lines().collect();
        let start = lines.len().saturating_sub(limit);
        lines[start..]
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}

/// SHA-256 hex digest of arbitrary bytes (frame evidence).
pub fn bytes_digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Canonical JSON: object keys sorted recursively, so the digest is
/// stable across producers that order keys differently.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap_or_default());
                out.push(':');
                out.push_str(&canonical_json(&map[*key]));
            }
            out.push('}');
            out
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        scalar => serde_json::to_string(scalar).unwrap_or_else(|_| "null".to_string()),
    }
}

pub fn args_digest(value: &Value) -> String {
    hex(&Sha256::digest(canonical_json(value).as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_is_key_order_invariant() {
        let a = json!({"b": 1, "a": {"y": [1, 2], "x": true}});
        let b = json!({"a": {"x": true, "y": [1, 2]}, "b": 1});
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(args_digest(&a), args_digest(&b));
    }

    #[test]
    fn digest_changes_with_values() {
        assert_ne!(args_digest(&json!({"a": 1})), args_digest(&json!({"a": 2})));
    }

    #[test]
    fn record_and_read_back() {
        let dir = tempfile_dir();
        let path = dir.join("op.jsonl");
        let log = OpLog::open(&path).expect("open");
        log.record(
            "A.B.C",
            Some("read"),
            Some(&json!({"x": 1})),
            "ok",
            Some(7),
            None,
        );
        log.record(
            "A.B.D",
            None,
            None,
            "refused:seahawk_unauthorized",
            None,
            None,
        );
        let recent = log.read_recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0]["tool"], "A.B.C");
        assert_eq!(recent[0]["downstream_ms"], 7);
        assert!(recent[0]["args_sha256"].as_str().unwrap().len() == 64);
        assert_eq!(recent[1]["outcome"], "refused:seahawk_unauthorized");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn record_with_writes_gui_evidence_fields() {
        let dir = tempfile_dir();
        let path = dir.join("op.jsonl");
        let log = OpLog::open(&path).expect("open");
        log.record_with(
            "gui.blender.actuate",
            Some("actuate"),
            Some(&json!({"action": "click", "x": 10, "y": 10})),
            "ok",
            Some(42),
            None,
            LogExtra {
                pre_sha256: Some("a".repeat(64)),
                post_sha256: Some("b".repeat(64)),
                target: Some("click 10,10 window 0x1 \"Blender\"".to_string()),
                ..Default::default()
            },
        );
        log.record("A.B.C", Some("read"), None, "ok", None, None);
        let recent = log.read_recent(10);
        assert_eq!(recent[0]["pre_sha256"], "a".repeat(64));
        assert_eq!(recent[0]["post_sha256"], "b".repeat(64));
        assert!(recent[0]["target"].as_str().unwrap().contains("Blender"));
        // Plain entries omit the S4 fields entirely (serde skip).
        let text = std::fs::read_to_string(&path).expect("read log");
        let second = text.lines().nth(1).expect("second line");
        assert!(!second.contains("pre_sha256"), "{second}");
        assert_eq!(bytes_digest(b"abc").len(), 64);
        std::fs::remove_dir_all(dir).ok();
    }

    fn tempfile_dir() -> PathBuf {
        // Unique per call: tests run in parallel threads of one
        // process, and two tests sharing one op-log file race
        // (observed when the S4 evidence test landed beside the
        // S1 record test — same pid-derived path, interleaved
        // entries).
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seahawk-oplog-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }
}
