//! Seahawk TUI binary: parse args, build the real facade, run.
//!
//! Facade selection:
//! - default: [`LibFacade`] over the `seahawk` lib (config,
//!   class table, op log on disk; no downstream connection).
//! - `--broker <path>`: [`StdioFacade`] spawning that broker
//!   binary (the MCP stdio client fallback). The broker config
//!   path follows `--config`; the agent token, when needed, is
//!   read from `SEAHAWK_AGENT_TOKEN` and never logged.
//!
//! Mode selection: full-screen ratatui when stdout is a TTY,
//! the non-TTY line mode otherwise (or with `--line`). The op
//! log is loaded from its file path when known, so the viewer
//! keeps line-level fidelity (truncation / oversized detection).

#![forbid(unsafe_code)]

use std::io::IsTerminal;
use std::path::PathBuf;

use seahawk_tui::app::{App, run_fullscreen, run_line_mode};
use seahawk_tui::facade::{LibFacade, SeahawkFacade, StdioFacade};
use seahawk_tui::triggers::load_trigger_rules;

struct Args {
    config: Option<PathBuf>,
    oplog: Option<PathBuf>,
    broker: Option<String>,
    triggers: Option<PathBuf>,
    force_line: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        config: None,
        oplog: None,
        broker: None,
        triggers: None,
        force_line: false,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--config" => {
                args.config = Some(PathBuf::from(iter.next().ok_or("--config needs a path")?));
            }
            "--oplog" => {
                args.oplog = Some(PathBuf::from(iter.next().ok_or("--oplog needs a path")?));
            }
            "--broker" => {
                args.broker = Some(iter.next().ok_or("--broker needs a binary path")?);
            }
            "--triggers" => {
                args.triggers = Some(PathBuf::from(iter.next().ok_or("--triggers needs a path")?));
            }
            "--line" => args.force_line = true,
            "--help" | "-h" => {
                println!(
                    "usage: seahawk-tui [--config <seahawk.toml>] [--oplog <oplog.jsonl>] \
                     [--broker <seahawk-binary>] [--triggers <triggers.toml>] [--line]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?} (try --help)")),
        }
    }
    Ok(args)
}

fn main() -> std::io::Result<()> {
    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("seahawk-tui: {error}");
            std::process::exit(2);
        }
    };
    // Default trigger file: beside the config when one is given,
    // else ./triggers.toml (absent = empty by design).
    let triggers_path = args.triggers.clone().or_else(|| {
        args.config
            .as_ref()
            .and_then(|config| config.parent().map(|dir| dir.join("triggers.toml")))
            .or_else(|| Some(PathBuf::from("triggers.toml")))
    });
    let triggers = load_trigger_rules(triggers_path.as_deref());

    if let Some(broker) = &args.broker {
        let mut broker_args: Vec<String> = Vec::new();
        if let Some(config) = &args.config {
            broker_args.push(config.display().to_string());
        }
        let agent_token = std::env::var("SEAHAWK_AGENT_TOKEN")
            .ok()
            .filter(|token| !token.is_empty());
        match StdioFacade::spawn(broker, &broker_args, agent_token) {
            Ok(facade) => return run_with(App::new(facade, triggers), &args),
            Err(error) => {
                eprintln!(
                    "seahawk-tui: stdio facade unavailable ({error}); \
                     falling back to the lib facade"
                );
            }
        }
    }
    let facade = LibFacade::new(args.config.clone(), args.oplog.clone());
    let oplog_path = facade.oplog_path().to_path_buf();
    let mut app = App::new(facade, triggers);
    app.refresh_oplog_path(&oplog_path);
    run_mode(&mut app, &args)
}

fn run_with<F: SeahawkFacade>(mut app: App<F>, args: &Args) -> std::io::Result<()> {
    app.refresh_oplog();
    run_mode(&mut app, args)
}

fn run_mode<F: SeahawkFacade>(app: &mut App<F>, args: &Args) -> std::io::Result<()> {
    if args.force_line || !std::io::stdout().is_terminal() {
        run_line_mode(app)
    } else {
        run_fullscreen(app)
    }
}
