//! Seahawk binary: the era guard owns the real stdin/stdout; the
//! rmcp service sits behind a tokio duplex (fleet template). The
//! guard task ending (stdin EOF) drops the duplex write half, which
//! ends the service; `waiting()` — never dropping the
//! RunningService — is what keeps the broker alive across requests.
//!
//! Usage: `seahawk [config.toml]` — config path from argv[1], else
//! `$SEAHAWK_CONFIG`, else `./seahawk.toml`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, bail};
use rmcp::ServiceExt;

use seahawk::config::Config;
use seahawk::downstream::Downstream;
use seahawk::guard::{GuardAuth, Ordering, guard_incoming, pump_responses};
use seahawk::oplog::OpLog;
use seahawk::server::SeahawkServer;

fn resolve_config_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::args().nth(1) {
        return Ok(PathBuf::from(path));
    }
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
        "no config found: pass a config path as argv[1], set SEAHAWK_CONFIG, \
         or place seahawk.toml in the working directory"
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = resolve_config_path()?;
    let config = Arc::new(
        Config::load(&config_path).with_context(|| format!("loading {}", config_path.display()))?,
    );
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
