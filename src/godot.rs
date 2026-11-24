//! The Godot target adapter: headless editor/script
//! execution against the installed Godot (4.7.2.stable on
//! primo at commission time).
//!
//! Routes: `godot --version` for attach/status; a read of the
//! project's `project.godot` plus a bounded scene/script
//! census for inspection; and `godot --headless --path
//! <project> --script <script>` for execution — a script that
//! extends `SceneTree` (or `MainLoop`) runs standalone and its
//! stdout/stderr are the result. Execution is bounded by the
//! runner (timeout, output caps, argv array — never a shell),
//! and the script path is held inside the project lexically
//! before the engine is started: a script outside the project
//! is refused broker-side, so the verb cannot be aimed at
//! arbitrary files on the host.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::{GodotConfig, normalize_path};
use crate::policy::codes;
use crate::runner::{run_bounded, tail_lines};
use crate::target::{
    TargetAdapter, TargetCaps, TargetDepth, TargetError, TargetInfo, TargetResult,
};

/// Stdout/stderr lines quoted in a run result.
const RUN_TAIL_LINES: usize = 60;

pub struct GodotAdapter {
    config: GodotConfig,
}

impl GodotAdapter {
    pub fn new(config: GodotConfig) -> Self {
        Self { config }
    }

    /// The engine's version string (first line of
    /// `godot --version`).
    pub fn version(&self) -> TargetResult<String> {
        let outcome = run_bounded(
            &self.config.binary.to_string_lossy(),
            &["--version"],
            &[],
            Duration::from_secs(30),
        )
        .map_err(|error| {
            TargetError::unavailable(format!(
                "godot binary at {} cannot be started: {error}",
                self.config.binary.display()
            ))
        })?;
        let version = outcome
            .stdout
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        if version.is_empty() {
            return Err(TargetError::unavailable(format!(
                "godot at {} answered --version with no version line (stderr: {})",
                self.config.binary.display(),
                tail_lines(&outcome.stderr, 5)
            )));
        }
        Ok(version)
    }

    /// `godot.status`: binary + version.
    pub fn status(&self) -> TargetResult<Value> {
        Ok(json!({
            "binary": self.config.binary.display().to_string(),
            "version": self.version()?,
        }))
    }

    /// `godot.inspect`: the project's declared identity from
    /// `project.godot`, plus a bounded census of its scenes
    /// and scripts.
    pub fn inspect_project(&self, project: &Path) -> TargetResult<Value> {
        let godot_file = project.join("project.godot");
        let text = std::fs::read_to_string(&godot_file).map_err(|error| {
            TargetError::new(
                codes::BAD_ARGUMENTS,
                format!(
                    "project {} has no readable project.godot ({}): {error}",
                    project.display(),
                    godot_file.display()
                ),
            )
        })?;
        let setting = |key: &str| -> Option<String> {
            text.lines().find_map(|line| {
                let line = line.trim();
                let rest = line.strip_prefix(key)?.strip_prefix('=')?.trim();
                Some(rest.trim_matches('"').to_string())
            })
        };
        Ok(json!({
            "project": project.display().to_string(),
            "name": setting("config/name"),
            "main_scene": setting("run/main_scene"),
            "features": setting("config/features"),
            "scene_files": count_files(project, &["tscn", "scn"], 8, 512),
            "script_files": count_files(project, &["gd"], 8, 512),
            "engine_version": self.version()?,
        }))
    }

    /// `godot.run_script`: run one GDScript inside the project,
    /// headless, and return its output.
    pub fn run_script(&self, project: &Path, script: &Path) -> TargetResult<Value> {
        if !project.join("project.godot").is_file() {
            return Err(TargetError::new(
                codes::BAD_ARGUMENTS,
                format!(
                    "project {} has no project.godot; not a Godot project",
                    project.display()
                ),
            ));
        }
        let script_abs = if script.is_absolute() {
            script.to_path_buf()
        } else {
            project.join(script)
        };
        let Some(normalized) = normalize_path(&script_abs) else {
            return Err(TargetError::new(
                codes::BAD_ARGUMENTS,
                format!("script path {} does not normalize", script_abs.display()),
            ));
        };
        let Some(project_normalized) = normalize_path(project) else {
            return Err(TargetError::new(
                codes::BAD_ARGUMENTS,
                format!("project path {} does not normalize", project.display()),
            ));
        };
        if !normalized.starts_with(&project_normalized) {
            return Err(TargetError::new(
                codes::TARGET_CAPABILITY,
                format!(
                    "script {} is outside project {} — refused before the engine \
                     started; godot.run_script only runs scripts the project holds",
                    normalized.display(),
                    project_normalized.display()
                ),
            ));
        }
        if normalized.extension().and_then(|ext| ext.to_str()) != Some("gd") {
            return Err(TargetError::new(
                codes::BAD_ARGUMENTS,
                format!("script {} is not a .gd GDScript file", normalized.display()),
            ));
        }
        if !normalized.is_file() {
            return Err(TargetError::new(
                codes::BAD_ARGUMENTS,
                format!("script {} does not exist", normalized.display()),
            ));
        }
        let outcome = run_bounded(
            &self.config.binary.to_string_lossy(),
            &[
                "--headless",
                "--path",
                &project.display().to_string(),
                "--script",
                &normalized.display().to_string(),
            ],
            &[],
            Duration::from_secs(self.config.timeout_secs),
        )
        .map_err(|error| {
            TargetError::unavailable(format!(
                "godot binary at {} cannot be started: {error}",
                self.config.binary.display()
            ))
        })?;
        Ok(json!({
            "project": project.display().to_string(),
            "script": normalized.display().to_string(),
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "elapsed_ms": outcome.elapsed_ms,
            "stdout": tail_lines(&outcome.stdout, RUN_TAIL_LINES),
            "stderr": tail_lines(&outcome.stderr, RUN_TAIL_LINES),
            "stdout_capped": outcome.stdout_capped,
            "stderr_capped": outcome.stderr_capped,
        }))
    }
}

/// Bounded file census by extension (shared shape with the
/// Unity adapter's walk: depth- and budget-bounded).
fn count_files(root: &Path, extensions: &[&str], max_depth: usize, budget: usize) -> usize {
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

/// The `project` argument of a godot call, as a path.
fn project_arg(args: &Value) -> TargetResult<PathBuf> {
    let Some(project) = args.get("project").and_then(Value::as_str) else {
        return Err(TargetError::new(
            codes::BAD_ARGUMENTS,
            "argument \"project\" is required (an absolute Godot project path)",
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

impl TargetAdapter for GodotAdapter {
    fn info(&self) -> TargetInfo {
        TargetInfo {
            id: "godot",
            display_name: "Godot — headless editor/script execution",
            depth: TargetDepth::ScriptedDeep,
            caps: TargetCaps::scripted(),
        }
    }

    fn attach(&self) -> TargetResult<Value> {
        self.status()
    }

    fn execute(&self, op: &str, args: &Value) -> TargetResult<Value> {
        match op {
            "run_script" => {
                let project = project_arg(args)?;
                let Some(script) = args.get("script").and_then(Value::as_str) else {
                    return Err(TargetError::new(
                        codes::BAD_ARGUMENTS,
                        "argument \"script\" is required (a .gd path, absolute or \
                         project-relative)",
                    ));
                };
                self.run_script(&project, Path::new(script))
            }
            _ => Err(TargetError::new(
                codes::UNKNOWN_TOOL,
                format!("unknown godot operation {op:?}; the adapter's verb is run_script"),
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

    // -- adversarial -------------------------------------------

    #[test]
    fn script_escaping_the_project_is_refused_before_the_engine() {
        let adapter = GodotAdapter::new(GodotConfig {
            binary: PathBuf::from("/bin/true"),
            timeout_secs: 10,
        });
        // /tmp stands in for a project that does not exist as a
        // Godot project: the project.godot check fires first.
        let error = adapter
            .run_script(Path::new("/tmp"), Path::new("/etc/passwd.gd"))
            .expect_err("non-project must refuse");
        assert_eq!(error.code, codes::BAD_ARGUMENTS);
    }

    #[test]
    fn script_traversal_out_of_a_real_project_is_refused() {
        let dir = std::env::temp_dir().join(format!("seahawk-godot-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("project.godot"), "; test fixture\n").expect("write");
        let adapter = GodotAdapter::new(GodotConfig {
            binary: PathBuf::from("/bin/true"),
            timeout_secs: 10,
        });
        let error = adapter
            .run_script(&dir, Path::new("../outside.gd"))
            .expect_err("a script escaping the project must refuse");
        assert_eq!(error.code, codes::TARGET_CAPABILITY);
        let error = adapter
            .run_script(&dir, Path::new("/etc/evil.gd"))
            .expect_err("an absolute script outside the project must refuse");
        assert_eq!(error.code, codes::TARGET_CAPABILITY);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_godot_op_is_refused() {
        let adapter = GodotAdapter::new(GodotConfig {
            binary: PathBuf::from("/bin/true"),
            timeout_secs: 10,
        });
        let error = adapter
            .execute("eval", &json!({}))
            .expect_err("eval is not a wrapped verb");
        assert_eq!(error.code, codes::UNKNOWN_TOOL);
    }
}
