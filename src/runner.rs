//! Bounded subprocess execution for the target adapters whose
//! transport is a local program (Unity Editor batchmode, Godot
//! headless, the generic floor's hyprctl / grim / ydotool).
//!
//! Discipline: no shell is ever spawned — argv goes to the
//! program as an array, so an argument can never become shell
//! syntax. Every run is bounded by a wall-clock timeout and by
//! a per-stream capture cap; a run that crosses the time bound
//! is killed and the outcome says so, and a stream that crosses
//! the cap is marked capped — output is never silently
//! truncated into a false success.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Per-stream capture cap. Adapter results quote tails, not
/// whole streams; the cap exists so a chatty child cannot grow
/// broker memory without bound.
pub const MAX_STREAM_BYTES: usize = 256 * 1024;

/// What one bounded run produced.
#[derive(Clone, Debug)]
pub struct RunOutcome {
    /// The child's exit code; `None` when it died by signal or
    /// was killed at the timeout.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub stdout_capped: bool,
    pub stderr_capped: bool,
    pub elapsed_ms: u64,
}

impl RunOutcome {
    /// A one-line human summary for adapter result payloads.
    pub fn summary(&self) -> String {
        format!(
            "exit {:?} in {} ms{}",
            self.exit_code,
            self.elapsed_ms,
            if self.timed_out {
                " (timed out, killed)"
            } else {
                ""
            }
        )
    }
}

/// Drains one stream on a thread, keeping at most
/// `MAX_STREAM_BYTES` and reporting whether more arrived.
fn drain(stream: impl Read + Send + 'static) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut stream = stream;
        let mut kept = Vec::new();
        let mut capped = false;
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = MAX_STREAM_BYTES.saturating_sub(kept.len());
                    if room > 0 {
                        kept.extend_from_slice(&chunk[..n.min(room)]);
                    }
                    if n > room {
                        capped = true;
                    }
                }
            }
        }
        let _ = tx.send((kept, capped));
    });
    rx
}

/// Runs `program` with `args` (array form, never a shell), the
/// given extra environment pairs, and a wall-clock bound.
pub fn run_bounded(
    program: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
) -> std::io::Result<RunOutcome> {
    let started = Instant::now();
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn()?;
    let stdout_rx = drain(child.stdout.take().expect("piped stdout"));
    let stderr_rx = drain(child.stderr.take().expect("piped stderr"));
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break Some(status),
            None => {
                if started.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    };
    let (stdout, stdout_capped) = stdout_rx.recv().unwrap_or_default();
    let (stderr, stderr_capped) = stderr_rx.recv().unwrap_or_default();
    Ok(RunOutcome {
        exit_code: if timed_out {
            None
        } else {
            status.and_then(|s| s.code())
        },
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        timed_out,
        stdout_capped,
        stderr_capped,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

/// The calling process's real uid, read from /proc — the
/// adapters need it to address the user's session runtime dir
/// without a libc dependency.
pub fn current_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// The session runtime dir adapters should address:
/// `$XDG_RUNTIME_DIR` when set, else `/run/user/<uid>`.
pub fn default_runtime_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR")
        && !dir.is_empty()
    {
        return Some(PathBuf::from(dir));
    }
    current_uid().map(|uid| PathBuf::from(format!("/run/user/{uid}")))
}

/// The last `max_lines` lines of a text — log tails for adapter
/// result payloads.
pub fn tail_lines(text: &str, max_lines: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_a_program_and_captures_output() {
        let outcome = run_bounded(
            "/bin/echo",
            &["hello", "world"],
            &[],
            Duration::from_secs(5),
        )
        .expect("echo runs");
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.stdout.trim(), "hello world");
        assert!(!outcome.timed_out);
    }

    #[test]
    fn arguments_are_never_shell_syntax() {
        // Adversarial: a metacharacter-laden argument must arrive
        // as data, not as a command.
        let outcome = run_bounded(
            "/bin/echo",
            &["$(touch /tmp/seahawk-runner-pwned); `id`"],
            &[],
            Duration::from_secs(5),
        )
        .expect("echo runs");
        assert!(outcome.stdout.contains("$(touch"));
        assert!(!PathBuf::from("/tmp/seahawk-runner-pwned").exists());
    }

    #[test]
    fn timeout_kills_and_reports() {
        let outcome = run_bounded("/bin/sleep", &["30"], &[], Duration::from_millis(200))
            .expect("sleep runs");
        assert!(outcome.timed_out);
        assert_eq!(outcome.exit_code, None);
    }

    #[test]
    fn missing_program_is_an_error_not_a_panic() {
        let result = run_bounded(
            "/nonexistent/seahawk-no-such-program",
            &[],
            &[],
            Duration::from_secs(5),
        );
        assert!(result.is_err());
    }

    #[test]
    fn tail_lines_keeps_the_end() {
        assert_eq!(tail_lines("a\nb\nc\nd", 2), "c\nd");
        assert_eq!(tail_lines("a\nb", 5), "a\nb");
        assert_eq!(tail_lines("", 3), "");
    }
}
