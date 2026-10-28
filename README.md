# conn

<a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>

An authenticated rmcp broker fronting Unreal Engine 5.8's built-in MCP server.

Nothing steers the editor except through the holder of the conn. AI agents
talk to conn over MCP (modern era only, 2026-07-28); conn authenticates the
connection, exposes a curated tool surface instead of everything the editor
offers, and brokers calls to Unreal's own MCP server — which is never exposed
raw to an agent. Unreal's raw server ships with no authentication model and
includes executing Python inside the editor at full strength; conn exists so
that surface can be used without being trusted.

## Properties

- **Authenticated, lab-only.** Token authentication on the agent side;
  localhost-only downstream to the editor.
- **Curated surface.** Read and write tools are brokered under explicit
  policy (policy-as-data, decided server-side); the full Epic surface is not
  passed through by default.
- **Execute-class default-deny.** Python-in-editor and equivalent execution
  tools are refused unless policy enables them per tool and a separate
  per-call operator token is presented.
- **Op log.** Every brokered call is recorded in an append-only log — tool,
  argument digest, outcome, order — because editor operations are stateful
  and non-idempotent, and a timed-out call may already have applied.
- **Modern era only.** Born on rmcp serving the 2026-07-28 protocol era;
  legacy clients are refused.

## Status

In build. This repository is the project's home; the broker lands here as its
stages gate.
