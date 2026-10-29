# GATE REPORT — Seahawk 1.0.0 (fleet-to-1.0 close-out, G-S1..G-S4)

Date: 2026-10-29. Worker: night-seahawk. Authorization: Owner
D-315/D-316 (fleet-to-1.0 program). Safety charter throughout:
token auth, execute/actuate default-deny via `decide()`,
append-only op log, lab-only — nothing in this round weakens
any of them; the two-key rule, class curation, and loopback
discipline are byte-for-byte the S3/S4 posture.

## G-S1 — S5 curative round + FROZEN benchmark re-run

**Diagnosis (from the S5 gate decomposition).** The S5 frozen
benchmark's grounding misses were not wrong-element errors:
all 11 scored points landed on the described element; 4 of 11
sat 3–19 px past the OCR *text extent* while inside the
element, and single-shot re-grounds never recovered a miss.
Mechanism: the grounder estimated a centre point directly,
and its estimate drifted to the trailing/bottom edge of the
text it had just read. A1's failures were verify-side: the
`changed` check diffed a fixed 241×241 region around the
action point (or window centre for point-less actions) while
real effects land elsewhere (menus anchor top-left; Blender's
F3 search spans a wide top strip). T1's Unity failure was an
instrument failure (default-settings OCR); the typed text was
in fact exact under the G-5 pipeline.

**Curative fixes (code, not bars — the harness
`tools/smoke5.py` is byte-unchanged and its bars untouched):**

- **C1 bbox grounding** — grounders return the element's bbox;
  the act point is its derived centre (both edges localized,
  centre is arithmetic). Point-only replies degrade honestly
  (`bbox_source: point_only`); agent answers accept a bbox
  with the same derivation; below-floor refusals carry the
  bbox. Unit-proven: a bbox whose centre differs from the
  model's point aims at the centre.
- **C2 strategy-changing correction loop** — retries re-ground
  with the prior point + failed check in the description; the
  final attempt escalates (local route: crop-zoom grounding
  around the last point; agent route: local grounder where
  configured). An identical re-ground (±2 px) stops early as
  `verify: "mismatch:strategy"` — the loop can no longer burn
  its budget re-asking the same question (S5: 0/4 recovered).
- **C3 effect-anchored checks** — `expect.changed_around
  {x, y}` and `expect.full_frame`; a point-less action's
  `changed` check diffs the full frame by default (menus,
  dialogs, mode switches are global effects; the S5 text says
  the region default was wrong for exactly these).
- **C4 blank-frame screen + window identity** — the
  >99%-single-colour screen (BENCH-VISUAL v1 §3) with a
  bounded content poll inside `act_verified`; persistent
  blank refuses `seahawk_gui_suspect_blank`. Observe/act
  results carry `window_id` + title; a caller pin that no
  longer resolves refuses `seahawk_gui_window_mismatch`,
  never a silent title re-match.

**Frozen re-run:** PENDING — primo (the lab host for the
Xvfb :98 session and the Ollama vision model) was unreachable
from the sandbox for the whole window (SSH tunnel refused,
repeated attempts logged). Before numbers (frozen harness,
2026-10-28): G1 7/11, G2 7/11, A1 4/7, T1 0/2, R1 5/5,
verdict FAIL. The re-run executes the byte-identical harness
against the 1.0.0 broker the moment the lab host is back; this
report will be amended with the per-family table, the adopted
BENCH-VISUAL scoring alongside (element-bounds grading,
G-5 OCR for T1), and a plain verdict. No bar moves either way.

## G-S2 — R-4 disposition

PENDING the same primo outage: the evidence lives in the Epic
install's plugin source on primo (`/opt/Unreal`). Disposition
(rule pre-committed): if the plugin source shows the script
tool-API reaching registered tools generically, R-4 CLOSES —
the reach exists and `decide()` already covers it, because
`execute_tool_script` and `AssetTools.write_file` are each
independently execute-class and default-denied; the script
sandbox fences only direct Python I/O, which was never the
classification basis. If the source is ambiguous, R-4 is
formally DEFERRED in the 1.0 record with the lab-discipline
mitigation restated (throwaway projects, editor up only
during brokered sessions, nonstandard port, execute class
default-deny). Either text lands in `SURFACE.md` §7.

## G-S3 — Phase W: `code.feedback` (D-230)

LANDED. One new tool, read class, through the same
`decide()` discipline:

- New `tooling` module: a bounded stdio MCP client of
  theodolite/periscope (modern-era handshake, worker thread,
  dead session dropped + respawned). Pure routing per SPEC
  R1–R5 with no silent reroutes; the dispatch table contains
  **no write/apply call** — `code_action_apply`,
  `rename_apply`, `edit_file`, `write_file`,
  `execute_tool_script`, `run_command` are refused at the
  client (SPEC R6, unit-asserted).
- `code.feedback{workspace, files[], checks[], route?,
  include_text?}`: workspace must sit under an operator
  `[feedback] project_roots` entry; files are relative,
  escape-proof, size-capped; per-file diagnostics (bounded
  item list + exact counts), lint verdicts, format `changed`
  flags with periscope's catalog snapshot digest as
  provenance; file-hash staleness re-check (one re-pass, then
  `seahawk_feedback_stale`); episode bound 3 per
  workspace+file-set per window, the next refused
  `seahawk_code_feedback_unresolved` carrying the last counts
  (the *fix* between calls is the caller's actuation or a
  human edit — the tool itself never writes); a route that
  cannot serve answers `seahawk_tooling_unavailable`, never
  assumed-clean. Every call op-logs a `feedback` summary —
  counts and provenance only, never file contents.
- Wiring is opt-in policy data (`[[tooling]]`, `[feedback]`);
  unconfigured, the tool refuses typed. 9 wire tests against
  a fake modern-era tooling fixture cover the refusal
  vocabulary, exact counts, provenance, routing refusals, and
  the episode bound.

Deferred with reasons (parent task scoped Phase W to the one
tool): `canon.context` (SPEC W5 — additionally Owner-ruling
lane-sensitive per the closeout filings), the D-246 context
acquisition verb pair (no Owner disposition on record), and
the D-234 lessons pair (program G-S5/G-S6, separate tranche).

## G-S4 — Utilization

PENDING primo (same outage): the driver
(`tools/utilization_live.py` — broker-driven Blender observe
on :98 + a seeded-error → feedback → fix → clean loop +
op-log excerpt) is written and ready; `UTILIZATION.md` files
from its output the moment the lab host returns, stating the
tooling mode (real theodolite/periscope vs fixture) verbatim.

## Tools/list + EFLO (final tree, sandbox-measured)

15 native tools · 20,554 canonical chars · **4,539 cl100k
tokens** (tiktoken) ≤ 6,000 D-247 cap. See `EFLO.md`.
Inspector 2.12.0 `--cli --protocol-era modern --method
tools/list --strict`: **exit 0**, 15 tools, all annotated.

## Gates — sandbox (staging copy, RUSTC_WRAPPER=, JOBS=2)

| Gate | Result |
| --- | --- |
| `cargo test` | **107/107 PASS** — 57 lib + 9 feedback_wire + 10 gui_wire + 14 vision_wire + 17 wire |
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | clean — clippy **0.1.100 (f7575a9da8 2026-09-24)**, nightly-2026-09-25 |
| `cargo publish --dry-run` | **PASS** (exit 0, "aborting upload due to dry run") on the idle re-run; the first attempt's verify-build test step hit the documented 25 s harness deadline under parallel load (see flake note) — dry-run only, NO publish |

Flake note (honest): under full parallel load, one wire suite
intermittently hits the harness's 25 s startup deadline (the
S4 report records the same character at S4). Solo and paired
re-runs of every suite are green; the gated full-suite run is
green. The deadline is the test harness's own and was not
touched (no verify-line edits).

## Gates — primo

PENDING (outage above): in-tree test/fmt/clippy + the Diver
gate (headless nvim, live config, diagnostics must settle to
0) run on the primo mirror at the first reachable window;
this report amends with the numbers.

## Landing + registry state

- Landing: PENDING primo gates (the estate order is gates on
  both machines, then land). Local commits are prepared in
  the S5 repo on top of origin/main 8193077 (FF path).
- `server.json` (`ai.qompass/seahawk`) at 1.0.0: PREPARED +
  validated against the official registry schema (0 errors);
  package entry references the locally built MCPB bundle
  (sha256 326b31e4…c32fe2, built from the final tree, held in
  the S5 workspace). Registry publish: **HELD** per
  coordinator ruling J-4 (lab-only charter vs blanket
  authorization) — not attempted.
- crates.io: dry-run only; NO publish attempted (window
  cooling; rides the program's resume-5).

## Bloch delta

PENDING primo (the estate bloch binary lives on primo):
roadmap init + the four work items (S5 curative, R-4,
code.feedback, 1.0.0 landing) are recorded at the first
reachable window and copied into the repo's `.ai/` before the
docs commit lands.
