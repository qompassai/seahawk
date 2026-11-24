//! The Unity target adapter: drives Unity Editors on this
//! host through the routes the estate has proven (the
//! custom.unity connector): the `unity` CLI for inventory and
//! connected-Editor state, and Editor batchmode for running
//! one named Editor method.
//!
//! Batchmode is the only execution route: the CLI's `command`
//! and `eval` verbs execute arbitrary code inside a connected
//! Editor and are deliberately not wrapped (the connector's
//! standing rule). A batchmode run is bounded by the runner's
//! timeout and output caps, takes its argv as an array (never
//! a shell), and reports the Editor's log tail alongside the
//! exit code — on this host an Editor that finished its work
//! can still crash in its own shutdown path, so the log is the
//! primary evidence and the code is reported, not worshipped
//! (the connector's measured guidance).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::UnityConfig;
use crate::policy::codes;
use crate::runner::{default_runtime_dir, run_bounded, tail_lines};
use crate::target::{
    TargetAdapter, TargetCaps, TargetDepth, TargetError, TargetInfo, TargetResult,
};

/// The CLI inventory/state bound: those verbs answer in
/// seconds; a minute is generous and keeps a wedged Hub from
/// holding a broker call open.
const CLI_TIMEOUT: Duration = Duration::from_secs(120);

/// Log-tail lines returned with a batchmode run.
const LOG_TAIL_LINES: usize = 40;

pub struct UnityAdapter {
    config: UnityConfig,
}

impl UnityAdapter {
    pub fn new(config: UnityConfig) -> Self {
        Self { config }
    }

    fn cli(&self, args: &[&str]) -> TargetResult<String> {
        let outcome = run_bounded(
            &self.config.cli_path.to_string_lossy(),
            args,
            &[],
            CLI_TIMEOUT,
        )
        .map_err(|error| {
            TargetError::unavailable(format!(
                "unity CLI at {} cannot be started: {error}",
                self.config.cli_path.display()
            ))
        })?;
        if outcome.timed_out {
            return Err(TargetError::unavailable(format!(
                "unity CLI {} timed out after {} s",
                args.join(" "),
                CLI_TIMEOUT.as_secs()
            )));
        }
        Ok(outcome.stdout)
    }

    /// Installed Editor versions, from the Hub install dir
    /// (the connector's route: `ls ~/Unity/Hub/Editor`).
    fn editors(&self) -> TargetResult<Vec<String>> {
        let home = std::env::var("HOME").map_err(|_| {
            TargetError::unavailable("HOME is not set; cannot locate the Unity Hub installs")
        })?;
        let dir = PathBuf::from(home).join("Unity/Hub/Editor");
        let mut versions: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|error| {
                TargetError::unavailable(format!(
                    "cannot list Unity Editor installs at {}: {error}",
                    dir.display()
                ))
            })?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().is_dir())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        versions.sort();
        Ok(versions)
    }

    /// The Editor version a project declares, from
    /// `ProjectSettings/ProjectVersion.txt`.
    fn project_version(project: &Path) -> TargetResult<String> {
        let path = project.join("ProjectSettings/ProjectVersion.txt");
        let text = std::fs::read_to_string(&path).map_err(|error| {
            TargetError::new(
                codes::BAD_ARGUMENTS,
                format!(
                    "project {} has no readable ProjectVersion.txt ({}): {error}",
                    project.display(),
                    path.display()
                ),
            )
        })?;
        text.lines()
            .find_map(|line| line.strip_prefix("m_EditorVersion:"))
            .map(|version| version.trim().to_string())
            .filter(|version| !version.is_empty())
            .ok_or_else(|| {
                TargetError::failed(format!("{} declares no m_EditorVersion", path.display()))
            })
    }

    /// The Editor binary for a project's declared version.
    fn editor_binary(&self, project: &Path) -> TargetResult<(String, PathBuf)> {
        let version = Self::project_version(project)?;
        let home = std::env::var("HOME").map_err(|_| {
            TargetError::unavailable("HOME is not set; cannot locate the Unity Hub installs")
        })?;
        let binary = PathBuf::from(home)
            .join("Unity/Hub/Editor")
            .join(&version)
            .join("Editor/Unity");
        if !binary.is_file() {
            return Err(TargetError::unavailable(format!(
                "project declares Unity {version} but no Editor binary exists at {}",
                binary.display()
            )));
        }
        Ok((version, binary))
    }

    /// `unity.status`: CLI version, installed Editors, and the
    /// CLI's connected-Editor state.
    pub fn status(&self) -> TargetResult<Value> {
        let version = self.cli(&["version"])?;
        let editors = self.editors()?;
        let connected = self.cli(&["--no-banner", "--non-interactive", "status"])?;
        Ok(json!({
            "cli_path": self.config.cli_path.display().to_string(),
            "cli_version": version.trim(),
            "editors_installed": editors,
            "connected_editors": connected.trim(),
        }))
    }

    /// `unity.projects`: the Hub registry's project list, as
    /// the CLI reports it.
    pub fn projects(&self) -> TargetResult<Value> {
        let list = self.cli(&["--no-banner", "--non-interactive", "projects", "list"])?;
        Ok(json!({
            "projects_list": list.trim(),
        }))
    }

    /// `unity.inspect`: one project's declared version and the
    /// Editor binary that would serve it.
    pub fn inspect_project(&self, project: &Path) -> TargetResult<Value> {
        let (version, binary) = self.editor_binary(project)?;
        let scenes = count_files_with_extensions(&project.join("Assets"), &["unity"], 6, 512);
        Ok(json!({
            "project": project.display().to_string(),
            "editor_version": version,
            "editor_binary": binary.display().to_string(),
            "scene_files_under_assets": scenes,
        }))
    }

    /// `unity.run_method`: run one public static Editor method
    /// in batchmode and return the log tail + exit code.
    pub fn run_method(
        &self,
        project: &Path,
        method: &str,
        log_file: Option<&Path>,
    ) -> TargetResult<Value> {
        if !valid_method_name(method) {
            return Err(TargetError::new(
                codes::BAD_ARGUMENTS,
                format!(
                    "method {method:?} is not a dotted identifier path \
                     (Class.Method, letters/digits/underscore/dots only)"
                ),
            ));
        }
        let (version, binary) = self.editor_binary(project)?;
        let log_path = log_file
            .map(Path::to_path_buf)
            .unwrap_or_else(|| project.join("seahawk-run.log"));
        let runtime_dir = default_runtime_dir()
            .map(|dir| dir.display().to_string())
            .unwrap_or_else(|| "/run/user/1000".to_string());
        let project_text = project.display().to_string();
        let log_text = log_path.display().to_string();
        let outcome = run_bounded(
            &binary.to_string_lossy(),
            &[
                "-batchmode",
                "-projectPath",
                &project_text,
                "-executeMethod",
                method,
                "-logFile",
                &log_text,
            ],
            &[("XDG_RUNTIME_DIR", &runtime_dir), ("DISPLAY", ":0")],
            Duration::from_secs(self.config.timeout_secs),
        )
        .map_err(|error| {
            TargetError::unavailable(format!(
                "Unity Editor at {} cannot be started: {error}",
                binary.display()
            ))
        })?;
        let log_tail = std::fs::read_to_string(&log_path)
            .map(|text| tail_lines(&text, LOG_TAIL_LINES))
            .unwrap_or_else(|error| format!("<log unreadable: {error}>"));
        Ok(json!({
            "project": project_text,
            "method": method,
            "editor_version": version,
            "editor_exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "elapsed_ms": outcome.elapsed_ms,
            "log_file": log_text,
            "log_tail": log_tail,
            "note": "judge the run by its log and declared outputs first: on this \
                     host an Editor that finished its work can still crash in its \
                     own shutdown path (custom.unity connector, measured)",
        }))
    }
}

/// A dotted method path (`Class.Method`, deeper nesting
/// allowed): identifier characters and dots only, no leading,
/// trailing, or doubled dots. Anything else is refused before
/// an Editor is started — the value reaches an argv slot, and
/// the shape check is the broker's half of that contract.
fn valid_method_name(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 256
        && method.contains('.')
        && !method.starts_with('.')
        && !method.ends_with('.')
        && !method.contains("..")
        && method
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
}

/// Counts files under `root` whose extension is in
/// `extensions`, bounded by depth and by a total-entry budget
/// (inspection must never become an unbounded walk).
fn count_files_with_extensions(
    root: &Path,
    extensions: &[&str],
    max_depth: usize,
    budget: usize,
) -> usize {
    let mut count = 0usize;
    let mut seen = 0usize;
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > budget * 16 {
                return count;
            }
            let path = entry.path();
            if path.is_dir() {
                if depth < max_depth {
                    stack.push((path, depth + 1));
                }
            } else if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| extensions.contains(&ext))
            {
                count += 1;
                if count >= budget {
                    return count;
                }
            }
        }
    }
    count
}

/// The `project` argument of a unity call, as a path.
fn project_arg(args: &Value) -> TargetResult<PathBuf> {
    let Some(project) = args.get("project").and_then(Value::as_str) else {
        return Err(TargetError::new(
            codes::BAD_ARGUMENTS,
            "argument \"project\" is required (an absolute Unity project path)",
        ));
    };
    let path = PathBuf::from(project);
    if !path.is_absolute() || !path.is_dir() {
        return Err(TargetError::new(
            codes::BAD_ARGUMENTS,
            format!("project {project:?} is not an existing absolute directory"),
        ));
    }
    Ok(path)
}

impl TargetAdapter for UnityAdapter {
    fn info(&self) -> TargetInfo {
        TargetInfo {
            id: "unity",
            display_name: "Unity — Editor batchmode + unity CLI",
            depth: TargetDepth::ScriptedDeep,
            caps: TargetCaps::scripted(),
        }
    }

    fn attach(&self) -> TargetResult<Value> {
        self.status()
    }

    fn execute(&self, op: &str, args: &Value) -> TargetResult<Value> {
        match op {
            "run_method" => {
                let project = project_arg(args)?;
                let Some(method) = args.get("method").and_then(Value::as_str) else {
                    return Err(TargetError::new(
                        codes::BAD_ARGUMENTS,
                        "argument \"method\" is required (Class.Method)",
                    ));
                };
                let log_file = args.get("log_file").and_then(Value::as_str).map(Path::new);
                self.run_method(&project, method, log_file)
            }
            _ => Err(TargetError::new(
                codes::UNKNOWN_TOOL,
                format!("unknown unity operation {op:?}; the adapter's verb is run_method"),
            )),
        }
    }

    fn inspect(&self, args: &Value) -> TargetResult<Value> {
        if args.get("project").is_some() {
            let project = project_arg(args)?;
            self.inspect_project(&project)
        } else {
            self.status()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_names_validate_by_shape() {
        assert!(valid_method_name("TestAnimSetup.Build"));
        assert!(valid_method_name("A.B.C"));
        assert!(valid_method_name("My_Class.Method2"));
    }

    // -- adversarial -------------------------------------------

    #[test]
    fn method_names_refuse_shell_and_path_shapes() {
        for bad in [
            "",
            "NoDot",
            ".A.B",
            "A.B.",
            "A..B",
            "A.B; rm -rf /",
            "A.B$(id)",
            "A/B.C",
            "A.B C",
            "A.B`id`",
        ] {
            assert!(!valid_method_name(bad), "{bad:?} must refuse");
        }
    }

    #[test]
    fn project_arg_requires_an_existing_absolute_dir() {
        let error = project_arg(&json!({})).expect_err("missing project");
        assert_eq!(error.code, codes::BAD_ARGUMENTS);
        let error =
            project_arg(&json!({"project": "relative/path"})).expect_err("relative project");
        assert_eq!(error.code, codes::BAD_ARGUMENTS);
        let error = project_arg(&json!({"project": "/nonexistent/seahawk-no-project"}))
            .expect_err("missing dir");
        assert_eq!(error.code, codes::BAD_ARGUMENTS);
    }

    #[test]
    fn unknown_unity_op_is_refused() {
        let adapter = UnityAdapter::new(UnityConfig {
            cli_path: PathBuf::from("/bin/true"),
            timeout_secs: 60,
        });
        let error = adapter
            .execute("eval", &json!({}))
            .expect_err("eval is not a wrapped verb");
        assert_eq!(error.code, codes::UNKNOWN_TOOL);
    }
}
