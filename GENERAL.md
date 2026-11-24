# Seahawk generalization — branch record (2026-11-24)

Branch `pax/seahawk-general` (off `main` 18760af), worktree
`~/.local/share/pax/seahawk-general-wt` on primo. No push, no
release, no version bump; the deployed `~/.local/bin/seahawk`
and the standing Blender provider session (port 8471) were
never touched.

## Stage 1 — reconcile

The eight `pax/seahawk-anim` commits cherry-picked with zero
conflicts (bf6628a→d223285, cf2d8b2→96daf09, 51eddf7→1066e89,
bff2240→1114655, 60c743e→3ca8632, b7b2000→21428fa,
67a1f0a→a0d9679, 3ac9838→661b909). Commit b7b2000 was
reworded: its original message claims a `take_export`
semantics change that is not in the diff — the diff is purely
rustfmt/clippy normalization of `take.rs`. Gate at the time:
221 tests passed / 0 failed.

## Stage 2 — adapter core

`src/target.rs`: `TargetAdapter` (attach / execute / inspect /
observe / actuate), `TargetInfo` + `TargetCaps` capability
declarations, `TargetDepth` (`scripted-deep` vs
`generic-floor`), and `TargetRegistry`, which refuses any
operation outside a target's declaration with
`seahawk_target_capability` *before* the adapter is touched
(unit-proven with a touch-counting fake: unknown target and
floor-execute refusals land with zero adapter touches).
Unreal and Blender refit as adapters over the existing
clients; their agent-facing dispatch (`brokered_call`,
`blender_call`) is unchanged. `target.list` (broker core)
reports every declaration; `seahawk_status` carries the same
array under `targets`.

New modules: `runner` (bounded subprocess execution — argv
array, never a shell, timeout kill, per-stream caps),
`unity`, `godot`, `floor`. New config sections `[unity]`,
`[godot]`, `[floor]` (all optional; an unconfigured adapter's
tools are not listed). New profile packs `unity` and `godot`;
`gui.floor_*` rides the `gui` pack; `target.list` is core.
Class tables in `model.rs` follow the Blender discipline
(compiled-in, raise-only operator overrides).

Live regression (new binary + a copy of the standing config,
own oplog): tools/list = 34 (the deployed baseline's 20 names
all present, + 13 animation tools, + `target.list`);
`blender.session_status` round-tripped through the standing
provider on 8471 (Blender 5.3.0, provider 1.0.0);
`blender.scene_census` returned digest/objects/scene;
`blender.artifact_validate` refused a malformed artifact
broker-side. `seahawk_surface` against the standing downstream
(127.0.0.1:8123) returns the typed
`seahawk_downstream_unavailable` — no Unreal editor is running
on primo, so no live UE smoke was possible; the brokered path
is covered by the pre-existing wire suite against its mock
downstream and is byte-unchanged by the refit.

## Stage 3 — Unity (live)

Lane config `~/.local/share/pax/seahawk-general/lane.toml`
(test tokens, own oplog, all three adapter sections).

- `unity.status`: CLI 1.0.0-beta.13, editors installed
  [6000.6.6f1, 7000.0.0a10].
- `unity.projects`: the Hub list (`/home/phaedrus/My project`).
- `unity.inspect` on the real project
  `/home/phaedrus/.GH/NTRanch/Strobe/game`: version 6000.6.6f1,
  editor binary resolved. On `redlight` (declares 6000.0.0f1,
  not installed): honest `seahawk_target_unavailable` naming
  the missing binary path.
- `unity.run_method`: a throwaway project was created in the
  lane area (`unity-probe-project`, Editor 6000.6.6f1
  `-createProject`, exit 0) with `Assets/Editor/SeahawkProbe.cs`;
  the call ran `SeahawkProbe.Run` in batchmode and the method's
  declared output, `seahawk-probe-marker.txt`, exists with the
  exact expected content (written 2026-11-24 11:30:46 primo)
  — the method executed in a real Editor through the broker.
  CORRECTION (same day): an interim delivery of the probe
  reported Editor exit 0 / 230 s / `SEAHAWK_PROBE_RAN` in the
  log tail. The probe's terminal output, the lane oplog, and
  the on-disk logs contradict those figures and are the record
  of truth: the surviving run's Editor reached its exit path
  but did not exit within the bound, so the runner killed it
  at the configured 1200 s timeout and the adapter reported
  timed_out=true with exit null (oplog downstream_ms 1200055);
  that run's log (which overwrote the first run's) shows the
  `-executeMethod SeahawkProbe.Run` invocation but no
  `SEAHAWK_PROBE_RAN` line, and the marker was not rewritten
  in it. A third recorded invocation returned in 652 ms. Net:
  method execution is proven by the first run's marker; a
  clean Editor exit is NOT claimed — consistent with the unity
  connector's standing warning that batchmode Editors can hang
  in shutdown and must be judged by log and declared outputs.

One anomaly, not reproduced: the interim delivery of the
first probe run also reported `target.list` including
`blender` under the lane config (which has no `[blender]`
section). The terminal output of the same run lists the
correct four targets, and the lane oplog, two direct
re-probes, a full probe re-run, and the wire suite all
corroborate the terminal output; the source gates Blender's
adapter on the provider client existing. Both anomalies are
confined to that one interim delivery; no on-disk record
reproduces either. Recorded here rather than silently
dropped.

## Stage 4 — Godot (live)

Godot on primo: `/usr/bin/godot` = 4.7.2.stable.arch_linux
(pre-installed; nothing installed). Minimal project in the
lane area (`godot-probe-project`: project.godot +
main.tscn + probe.gd).

- `godot.status`: version 4.7.2.stable.arch_linux.ed1daf0bf.
- `godot.inspect`: name `SeahawkProbe`, main scene
  `res://main.tscn`, scene_files 1, script_files 1.
- `godot.run_script` (execute-class, operator token): exit 0;
  stdout carries `SEAHAWK_GODOT_PROBE project=SeahawkProbe`
  and `SEAHAWK_GODOT_CENSUS scenes=1 scripts=1` — the engine's
  own census agrees with the broker's inspect numbers.

## Stage 5 — generic-GUI floor (live)

`ydotoold` was **not running** on primo; it was started for
this proof (pid 732687, socket `/run/user/1000/.ydotool_socket`)
and left running — the floor's documented dependency.

Target app: a throwaway kitty window titled
`SEAHAWK-FLOOR-PROBE` (address 0x5589dd5e5570), launched for
the proof and closed after; no other window was touched.

- Declaration: `generic-floor`, execute=false, ops
  [attach, inspect, actuate, observe].
- `gui.floor_windows`: 7 windows; the probe window identified
  by title with geometry + focus state.
- `gui.floor_screenshot` (before): sha256
  c22281deb6f6ee5deb870e9f5e153df25fec95c196231ddd31dcb64282e65cca,
  328,277 bytes (saved as `floor-before.png` in the lane dir).
- `gui.floor_act` focus (click centre [9605, 1089]), type
  (90 chars — the command line is visible at the prompt in
  `floor-after.png`), key.
- Defect found and fixed: this ydotool build speaks **raw
  keycodes only** (`<keycode>:<pressed>`, e.g. `28:1 28:0`);
  symbolic names like `KEY_ENTER` are silently ignored by
  ydotool (its own help: non-interpretable values "will only
  cause a delay"), so the first Enter no-op'd while reporting
  success. The floor now refuses non-keycode key specs with
  `seahawk_bad_arguments` stating the grammar (unit tests +
  live re-verification), and the tool description documents
  the form.
- With `28:1 28:0` the typed command executed:
  `floor-proof.txt` contains `SEAHAWK_FLOOR_PROOF`;
  `floor-after2.png` (sha256
  5efbbe8edba41844a689781bf98c9aec048fa469f601da361b90e8dd38dd1f27)
  shows the executed line and fresh prompts.

Floor limits, as declared: no script execution; no state
guarantee beyond the window list and screenshots; focus is a
click into the window's centre; no scroll, no drag.

## Stage 6 — gates

- `cargo test --all-targets`: **259 passed / 0 failed** across
  12 suites (Stage-1 baseline 221; +27 lib unit tests, +11 in
  the new `tests/target_wire.rs`). The new wire suite is half
  validation (listing shape, honest declarations, fake-CLI
  round-trips, pack scoping) and half adversarial (execute
  without an operator token → `seahawk_operator_required`;
  shell-shaped Unity method names → `seahawk_bad_arguments`;
  Godot scripts escaping their project →
  `seahawk_target_capability`; out-of-vocabulary floor action
  → `seahawk_gui_unknown_action`; `unity.eval` →
  `seahawk_unknown_tool`; unconfigured adapter →
  `seahawk_target_unavailable`). Three pre-existing wire
  suites had their pinned core list updated for `target.list`,
  and one pinned the new profile valid-words string.
- `cargo clippy --all-targets`: clean. `cargo fmt --check`:
  clean.
- Theodolite (bacon-ls route, producer-first per the estate
  rule): a planted `error[E0308]` in `src/runner.rs` was
  reported by the bridge (count=2) as the positive control;
  the file was restored byte-identical (md5
  2fd08e0ce3d3b2a0b490cb336397ad35) and a fresh session then
  reported **0 diagnostics** for all 15 changed files and 0
  workspace-wide.
- Tools/list delta: deployed baseline **20** → new binary with
  the standing config **34** (+13 animation, +1 target.list) →
  all sections configured **44** (+4 unity, +3 godot,
  +3 floor). Lane config (no `[blender]`): 19.

Evidence lives in the lane dir
`~/.local/share/pax/seahawk-general/`: lane.toml,
standing-copy.toml, combined.toml, probe_live.py,
probe_unity.py, probe_godot.py, probe_floor.py,
probe_floor2.py, floor-before.png, floor-after.png,
floor-after2.png, floor-proof.txt, the Unity probe project
(with its run log + marker) and the Godot probe project.
