//! Seahawk binary: the era guard owns the real stdin/stdout; the
//! rmcp service sits behind a tokio duplex (fleet template). The
//! guard task ending (stdin EOF) drops the duplex write half, which
//! ends the service; `waiting()` — never dropping the
//! RunningService — is what keeps the broker alive across requests.
//!
//! Usage: `seahawk [--profile <spec>] [config.toml]` — config
//! path from the positional argument, else `$SEAHAWK_CONFIG`,
//! else `./seahawk.toml`. The tool-surface profile (D-934)
//! resolves `--profile` → `$SEAHAWK_TOOL_PROFILE` → the config
//! file's `tool_profile` → default `core`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use rmcp::ServiceExt;

use seahawk::config::Config;
use seahawk::downstream::Downstream;
use seahawk::guard::{GuardAuth, Ordering, guard_incoming, pump_responses};
use seahawk::oplog::OpLog;
use seahawk::server::SeahawkServer;

/// Launch arguments: the config path plus the optional
/// `--profile` tool-surface selector (D-934).
struct LaunchArgs {
    config_path: PathBuf,
    profile: Option<String>,
}

/// Parses the launch line: `seahawk [--profile <spec>] [config.toml]`.
/// The config path falls back to `$SEAHAWK_CONFIG`, then to
/// `./seahawk.toml`, exactly as before profiles existed.
/// Unknown or repeated arguments are refused (fail-closed): a
/// mistyped launch line must never silently start a differently
/// scoped broker.
fn parse_launch_args() -> anyhow::Result<LaunchArgs> {
    let mut config_path: Option<PathBuf> = None;
    let mut profile_spec: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--profile" {
            let Some(value) = args.next() else {
                bail!(
                    "--profile requires a value (valid: {})",
                    seahawk::profile::VALID_WORDS
                );
            };
            if profile_spec.replace(value).is_some() {
                bail!("--profile given more than once");
            }
        } else if let Some(value) = arg.strip_prefix("--profile=") {
            if value.is_empty() {
                bail!(
                    "--profile requires a non-empty value (valid: {})",
                    seahawk::profile::VALID_WORDS
                );
            }
            if profile_spec.replace(value.to_string()).is_some() {
                bail!("--profile given more than once");
            }
        } else if arg.starts_with("--") {
            bail!(
                "unknown argument {arg:?} \
                 (usage: seahawk [--profile <spec>] [config.toml])"
            );
        } else if config_path.is_none() {
            config_path = Some(PathBuf::from(arg));
        } else {
            bail!(
                "unexpected extra argument {arg:?} \
                 (usage: seahawk [--profile <spec>] [config.toml])"
            );
        }
    }
    let config_path = match config_path {
        Some(path) => path,
        None => resolve_config_path()?,
    };
    Ok(LaunchArgs {
        config_path,
        profile: profile_spec,
    })
}

fn resolve_config_path() -> anyhow::Result<PathBuf> {
    if let Ok(path) = std::env::var("SEAHAWK_CONFIG")
        && !path.is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    let local = PathBuf::from("seahawk.toml");
    if local.exists() {
        return Ok(local);
    }
    bail!(
        "no config found: pass a config path as an argument, set SEAHAWK_CONFIG, \
         or place seahawk.toml in the working directory"
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let launch = parse_launch_args()?;
    let config_path = launch.config_path;
    let mut config =
        Config::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?;
    // Tool-surface profile resolution (D-934), highest
    // precedence first: `--profile`, then
    // `$SEAHAWK_TOOL_PROFILE`, then the config file's
    // `tool_profile` (already parsed into `config`; default
    // `core`). A malformed selector at any layer is a startup
    // error — fail-closed, never a silent fallback.
    if let Ok(spec) = std::env::var("SEAHAWK_TOOL_PROFILE")
        && !spec.is_empty()
    {
        config.tool_profile = seahawk::profile::ToolProfile::parse(&spec)
            .map_err(|e| anyhow::anyhow!("SEAHAWK_TOOL_PROFILE: {e}"))?;
    }
    if let Some(spec) = &launch.profile {
        config.tool_profile = seahawk::profile::ToolProfile::parse(spec)
            .map_err(|e| anyhow::anyhow!("--profile: {e}"))?;
    }
    let config = Arc::new(config);
    let oplog = Arc::new(
        OpLog::open(&config.oplog_path)
            .with_context(|| format!("opening op log {}", config.oplog_path.display()))?,
    );
    let downstream = Arc::new(Downstream::new(
        &config.downstream_url,
        config.downstream_timeout_secs,
    )?);
    let server = SeahawkServer::new(config.clone(), downstream, oplog.clone());

    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let ordering = Arc::new(Ordering::new());
    let (sdk_side, guard_side) = tokio::io::duplex(64 * 1024);
    let (read_half, write_half) = tokio::io::split(guard_side);
    let auth = Arc::new(GuardAuth {
        agent_token_digest: config.agent_token_digest,
        require_token_for_list: config.require_token_for_list,
        oplog: oplog.clone(),
    });
    tokio::spawn(pump_responses(read_half, ordering.clone(), stdout.clone()));
    tokio::spawn(guard_incoming(
        tokio::io::stdin(),
        write_half,
        ordering,
        stdout,
        auth,
    ));

    let service = server
        .serve(sdk_side)
        .await
        .context("seahawk service failed to start")?;
    service.waiting().await.context("seahawk service error")?;
    Ok(())
}
