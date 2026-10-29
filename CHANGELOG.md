# Changelog — seahawk

## 1.0.0 — 2026-10-29

The fleet-to-1.0 close-out. Safety charter unchanged and
binding throughout: token auth, execute- and actuate-class
default-deny via `decide()`, append-only op log, lab-only.

### Added

- **`code.feedback`** (read class; D-230 wiring): structured
  LSP/lint/format feedback for brokered engine code work,
  through a new stdio tooling client of the estate's tooling
  servers — theodolite for headless diagnostics (GDScript via
  periscope, whose language server is editor-hosted),
  periscope for diver's own format/lint pipelines, with the
  periscope catalog snapshot as provenance. Bounded episodes
  (3 calls per workspace + file set per window; the next is
  refused `seahawk_code_feedback_unresolved` with the last
  counts), staleness re-check (`seahawk_feedback_stale`), and
  typed unavailability (`seahawk_tooling_unavailable`) instead
  of assumed-clean results. The client's dispatch table holds
  no write/apply call (rule R6, unit-asserted). New policy
  data: `[[tooling]]` + `[feedback]` (opt-in; the shipped
  example carries it commented out).
- **Visual Benchmark v1** (`BENCH-VISUAL.md`): the D-221
  protocol frozen as Seahawk's standing visual gate.

### Changed (S5 curative round — fixes, not bar moves)

- **C1 bbox grounding.** Grounders return the element's bbox;
  the act point is its derived centre. Fixes the S5 frozen
  benchmark's trailing-edge aim bias (points landed on the
  right element but 3–19 px past its text extent). Point-only
  answers still parse, labelled `point_only`. Agent answers
  accept an optional bbox with the same derivation.
- **C2 strategy-changing correction loop.** `gui.act_verified`
  retries re-ground with the prior attempt's outcome in the
  description, then escalate (crop-zoom grounding on the local
  route; local grounder on the agent route where configured).
  An identical re-ground stops early as a strategy failure.
- **C3 effect-anchored verify checks.** `expect.changed_around
  {x, y}` and `expect.full_frame` anchor the `changed` diff
  where the effect actually appears (S5 finding G-1); a
  point-less action's `changed` check now diffs the full frame
  by default instead of a window-centre region.
- **C4 blank-frame screen + window identity.** Frames inside
  `gui.act_verified` pass the >99%-one-colour screen; a
  post-action frame that stays suspect-blank through a bounded
  content poll refuses as `seahawk_gui_suspect_blank`.
  Observe/act results carry the resolved window identity;
  callers may pin `window_id` (a dead or different pin refuses
  `seahawk_gui_window_mismatch`, never a silent re-match).

### Notes

- Native surface: 15 tools, 20,554 canonical chars, **4,539
  cl100k tokens** — within the D-247 native cap of 6,000
  (see `EFLO.md`). The brokered Unreal surface (830 tools)
  stays outside the native budget under curation, unchanged.
- R-4 (whether `execute_tool_script` reaches
  `AssetTools.write_file` through the tool API) is dispositioned
  in `SURFACE.md` §7 with its evidence.
- Publication is held: crates.io publish is a dry-run only in
  this release's gate; the MCP registry entry
  (`ai.qompass/seahawk`) is prepared and validated but NOT
  published — coordinator ruling J-4 holds it for the Owner
  (lab-only charter vs blanket authorization).

## 0.3.0 — 2026-10-28 (S5, landed with 1.0.0)

Vision grounding: `gui.observe` / `gui.ground` /
`gui.act_verified`, a pluggable grounder (local Ollama vision
model or the agent ticket protocol), frames referenced by
SHA-256, bounded correction. Frozen benchmark verdict at the
time: G1/G2/A1/T1 FAIL on measurement definitions with the
decomposition recorded in GATE-REPORT-S5; the curative round
above is its answer, re-run frozen in the 1.0 gate report.

## 0.2.0 — 2026-10-28 (S4)

Computer-use broker: actuate class (`read < write < actuate <
execute`), built-in X11 GUI provider, policy-only registration,
four estate media-GUI registrations (Blender, Unity,
ComfyUI, Aseprite), bracket-digest op-log evidence.

## 0.1.0 — 2026-10-27 (S0–S3)

The Unreal broker: S0 census of Epic's UE 5.8 MCP surface
(52 toolsets, 830 tools, classified read/write/execute),
modern-era agent surface with token auth and class curation,
execute-class default-deny with the two-key rule, append-only
op log, live lab smokes against the real editor.
