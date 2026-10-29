# Seahawk Visual Benchmark v1 — FROZEN

Adopted 2026-10-28 under D-230 (wiring SPEC §6), codifying
D-221 (the light-show visual-evaluation doctrine). This rubric
is **frozen**: any change is a new version plus an
Owner-visible note in the gate report that carries it — never
an in-place edit that makes a run pass.

## Protocol (per visual check)

1. **SHOULD statement first.** Before any capture, the check
   carries a written statement of what should be seen: the
   element/state, where in the frame, at what size. No
   statement, no check.
2. **Capture from the final presented artifact.** The frame
   judged is the frame the application actually presented —
   the `gui.observe` frame, referenced by its SHA-256 — at
   presented size. Never a pre-composite render buffer, never
   a re-render at a different size. Crops are cut at native
   resolution and upscaled ≥3× with NEAREST resampling for the
   review sheet.
3. **Blank-frame screen.** Every post-actuation frame passes
   a content check before any verdict: if >99% of pixels fall
   within a small channel tolerance of a single colour, the
   frame is typed `suspect_blank`. Verification polls for
   content (bounded: up to 5 captures over 10 s) and either
   proceeds on a contentful frame or refuses with typed
   `seahawk_gui_suspect_blank`. A suspect frame can never
   verify an action; the suspicion is op-logged with the
   frame digest.
4. **Window identity.** `gui.observe` results and every
   actuation result carry the resolved window's stable
   identity (X window id + title + app). `gui.act_verified`
   records the resolved window in its pre-action record; a
   caller may pin `window_id` from a prior observe; a pinned
   id that no longer resolves is a typed refusal, never a
   silent re-match by title.
5. **Grounding to bbox.** `gui.ground` returns the element's
   bbox alongside the point; the act point is the bbox
   centre. `gui.act_verified` refuses to act when confidence
   is below the configured floor, with the bbox and confidence
   in the refusal. Grading is against **element bounds**, not
   OCR text extent — text extent is systematically narrower
   than the widget carrying the word; text-extent containment
   is still measured and reported as advisory.
6. **Vision evaluation (the operative verdict).** A
   vision-capable evaluator reviews the numbered sheet (full
   frame + crops, SHOULD statement printed with each item)
   and answers, per item, under this rubric: (a) is the stated
   element/state present and legible at viewing size? (b) is
   it the *correct* element/state (not a neighbour, not a
   stale frame)? (c) are there artifacts — smearing, doubling,
   blank wash, wrong-window content? (d) does the frame match
   the SHOULD statement? Per-item **PASS/FAIL**, recorded
   verbatim in the gate report.
7. **Numeric proxies are supporting evidence only.** Pixel-
   diff percentages, OCR readbacks, MAD — printed alongside
   the verdict, never carrying one. Where OCR is used as a
   proxy it runs the G-5 pipeline (3× upscale + autocontrast +
   `--psm 11`); default-settings OCR readbacks are
   inadmissible (S5 T1 lesson).

## Freezing, bars, and controls

- Bars are stated **before** any run, per line, in the S5
  table's form (grounding / act-verified / text / refusals
  lines with explicit thresholds). A re-run of the frozen S5
  benchmark after a curative round uses the **original bars
  unchanged** — the bar does not move. The original S5
  scorings are printed alongside any adopted-benchmark
  rescoring, not replaced.
- **Controls**: each benchmark re-run includes a known-good
  control (a frame set verified by eye to show the stated
  content) and a known-bad control (a blank/wrong-window frame
  set). A benchmark that passes the bad control or fails the
  good one is itself wrong; the benchmark gets fixed, not the
  expectation.
- BLOCKED_ENV and UNGRADEABLE keep their S5 meanings: excluded
  from denominators, reported, never scored as hit or miss.

## Scope

Every `gui.act_verified` visual outcome in Unreal (via the
GUI surface where applicable), Unity, Godot, and Blender
sessions; every render/frame claim a Seahawk consumer files;
and S5 benchmark re-runs. Headless code feedback
(`code.feedback`) is not visual and is not judged here.
