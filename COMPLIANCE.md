# Spec compliance — seahawk

Seahawk's standing against the Model Context Protocol
specification (modern era, 2026-07-28) and the estate's safety
charter, as of the 1.0.0 gate (2026-10-29).

**Standing.** Seahawk is a **modern-only** server by design
(the D-113 fleet standardization): it answers
`server/discover`, carries the protocol version in
per-request `_meta`, and refuses a legacy `initialize` with
the typed `-32022` (supported versions listed). Legacy-era
checklist rows are therefore *Not applicable by design*, not
gaps. MCP Inspector 2.12.0 `--cli --protocol-era modern
--method tools/list --strict`: **exit 0**, 15 tools, on the
final 1.0.0 tree (dead-downstream lab config).

## Protocol surface

| Area | Standing |
| --- | --- |
| `server/discover` | Implemented; result carries supported versions, capabilities, server identity |
| Per-request version `_meta` | Required and validated on every request |
| Legacy `initialize` | Refused `-32022` with supported versions; connection stays up |
| Transport | stdio only; NDJSON framing; nothing but protocol frames on stdout |
| Tools | 15 native tools, all with titles, descriptions, complete input schemas, and annotations (read/write/destructive/open-world hints set from the class lattice) |
| Output schemas | Not declared (results are structured JSON text payloads); recorded honestly — no row claims otherwise |
| tools/list size | 4,539 cl100k tokens ≤ 6,000 (D-247 cap) — see `EFLO.md` |
| Cancellation / progress | rmcp transport defaults; no server-initiated requests |

## Safety charter (binding, unchanged at 1.0.0)

| Control | Standing |
| --- | --- |
| Agent authentication | Every `tools/call` carries the agent token in `_meta`; SHA-256 digest, constant-time compare; missing/wrong → typed `-32001`, refusal op-logged |
| Execute class | Default-deny via `decide()`; an execute call needs named policy enablement **and** the distinct operator token (two-key rule) |
| Actuate class (GUI) | Same two-key rule; coordinates confined to the registered window's rectangle; pre/post frame digests in the op log |
| Class curation | Downstream tools served only if classified read/write/execute from the verified census; unclassified tools are withheld and refused |
| Op log | Append-only JSON lines: tool, class, argument digest (never raw values), outcome, latency; feedback summaries for `code.feedback` |
| Loopback discipline | Downstream URL must be loopback; tooling subprocesses are operator-configured local commands |
| Lab-only | No publication authorized at 1.0.0; crates.io publish dry-run only; MCP registry entry prepared, publish held (coordinator ruling J-4) |

## Known honest limits

- Seahawk cannot firewall Epic's editor port against a local
  process that bypasses the broker (see `SURFACE.md` threat
  model). The mitigation is lab discipline, stated, not code.
- `code.feedback` reports what the tooling servers report; a
  route that cannot serve a check answers
  `seahawk_tooling_unavailable` rather than a clean verdict.
- Visual verification follows `BENCH-VISUAL.md` (frozen v1):
  numeric proxies never carry a visual verdict.
