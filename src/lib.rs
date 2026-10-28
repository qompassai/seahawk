//! Seahawk — the estate's authenticated broker for Unreal Engine's
//! built-in MCP server.
//!
//! Agent side: modern-era MCP (2026-07-28) over stdio, behind the
//! fleet era guard + sequencer, with per-call token authentication
//! enforced in the guard. Downstream: a client of Epic's
//! ModelContextProtocol plugin server (legacy era, Streamable HTTP,
//! loopback only). Tools are curated by a compiled-in class table
//! (read / write / actuate / execute) refined by operator policy;
//! actuate- and execute-class calls are default-deny and
//! additionally require a per-call operator token. Every brokered
//! call and every guard refusal lands in an append-only op log.
//!
//! S4 adds a built-in host-GUI provider (`gui` module): GUI
//! applications the operator registers in policy (Blender, Unity,
//! ComfyUI, Aseprite, …) appear as `gui.<app>.observe` (read) and
//! `gui.<app>.actuate` (actuate) tools, driven over X11 by Seahawk
//! itself. Registration exists only as operator-edited policy data;
//! there is no agent-callable registration path.

pub mod config;
pub mod downstream;
pub mod guard;
pub mod gui;
pub mod model;
pub mod oplog;
pub mod policy;
pub mod server;
