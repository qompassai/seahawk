# SURFACE.md — Epic's MCP surface in Unreal Engine 5.8.0, verified on the real install

Seahawk S0 deliverable (build commission D-169; the broker was renamed
from conn, D-171). Everything below was measured against the actual
install at primo `/opt/Unreal` (UE 5.8.0, source build) and a live
throwaway lab project — not taken from documentation alone. Raw
evidence: `s0-evidence/` in this workspace (initialize response,
tools/list, list_toolsets output, 55 describe responses, and
`classes.json`, the machine-readable class table).

## 1. Verdict, and the design-fork question answered head-on

Epic's MCP **is** an in-editor plugin: the `ModelContextProtocol`
plugin (Experimental, `EnabledByDefault: false`, `Installed: false`)
hosts a Streamable-HTTP MCP server **inside the UnrealEditor
process**. There is no standalone server binary and no daemon.

The commission's stop condition was "no separate server process to
broker — an in-editor-only plugin model". S0's judgment: **the fork
does not trigger, and the broker shape survives intact**, because
the plugin is not in-editor-*only*: Epic themselves expose the
surface as a standard, client-connectable MCP endpoint on
`http://127.0.0.1:<port>/mcp`, and even ship a client-config
generator (`ModelContextProtocolClientConfig.cpp`) that writes
`.mcp.json` / Cursor / VS Code / Gemini / Codex configs pointing
external clients at that URL. Seahawk's briefed downstream shape —
"connects to Epic's server as a client, localhost only" — is
exactly the consumption model Epic built for. What in-editor
hosting changes is *lifecycle*, not architecture: the server exists
only while an editor with the plugin enabled is running, starts on
demand, and dies with the editor. Seahawk is designed for that
(lazy downstream session, re-initialization on loss).

One honest consequence, carried into §6: Seahawk cannot firewall
Epic's port. Its guarantees cover the agent path through Seahawk;
a local process that bypasses Seahawk and speaks to the editor
directly is outside them (mitigations are lab discipline, §6).

**S0 verdict: surface verified; proceed to S1 as designed.**

## 2. The server, mechanically

| Fact | Value (measured) |
|---|---|
| Plugin | `Engine/Plugins/Experimental/ModelContextProtocol` ("Unreal MCP", v1.0, Experimental) |
| Modules | `ModelContextProtocol` + `ModelContextProtocolEngine` (Runtime), `ModelContextProtocolEditor` (Editor) |
| Transport | Streamable HTTP: POST (JSON-RPC, JSON or SSE-framed responses), GET (SSE stream), DELETE (session end), one route |
| Endpoint | `http://127.0.0.1:<port>/mcp` — **bind measured loopback-only** (`ss`: `127.0.0.1:8123` in the lab) |
| Port | Config `ServerPortNumber`, default **8000**; the lab ran on 8123 from project config alone |
| URL path | Config `ServerUrlPath`, default `/mcp` |
| Sessions | Stateful: `Mcp-Session-Id` header (32 hex chars), issued at `initialize`; missing/unknown session → HTTP 400 |
| Protocol versions | **Legacy era only**: `2025-11-25`, `2025-06-18`, `2024-11-05` (negotiated down from the client's request). No 2026-07-28 — Seahawk bridges eras, as the fleet's brokers do |
| Handshake | Classic `initialize` → `notifications/initialized`; `serverInfo` name/title/version are **empty strings** |
| Auth | **None.** Zero Authorization/Bearer/token handling exists in the plugin source (grep-verified). The only request filter is an Origin check: a request *carrying* an Origin header whose host is not localhost/127.0.0.1/[::1] is 403'd — browser-rebinding hygiene that does nothing against non-browser local clients, which send no Origin |
| Launch paths | (a) setting `bAutoStartServer` (default **false**) starts it at module startup; (b) editor console command `ModelContextProtocol.StartServer [port]` / `.StopServer` (cheat-flagged); (c) command line `-ModelContextProtocolPort=N` overrides the port |
| Tool discovery | Config `bEnableToolSearch` default **true**: `tools/list` returns exactly 3 meta-tools — `list_toolsets`, `describe_toolset{toolset_name}`, `call_tool{toolset_name?, tool_name, arguments}` — and every real tool is reached through `call_tool`. With it **false**, toolset tools register natively instead (Seahawk handles the toolsearch shape; native shape is a documented residual, §7) |
| Tool naming | Fully-qualified `Toolset.Tool` names from `describe_toolset` (which returns strict JSON: name, version, description, per-tool input/output schemas). `call_tool` wants `tool_name` *without* the toolset prefix |
| Tool lookup | **Case-insensitive** downstream (`FindTool` uses `Equals(..., IgnoreCase)`) — any name-based filtering done downstream is case-bypassable; Seahawk matches its class table case-insensitively and dispatches the canonical casing |

## 3. The census (full-catalog lab)

Lab: `TP_BlankBP` copy + `ModelContextProtocol` + `AllToolsets`
enabled, editor headless (`-nullrhi`, Xvfb), server auto-started on
port 8123. Census taken live through the meta-tools.

- **52 real toolsets, 830 tools.**
- Toolsets are contributed per enabled plugin; the surface of a
  minimal project (MCP plugin only) is far smaller. The census is
  the *full-catalog* worst case, which is what a class table must
  cover.
- Registration is **not atomic**: three toolsets
  (`…sequencer.SequencerCustomBindingTools`,
  `…sequencer.SequencerImportExportTools`,
  `aimodule…BehaviorTreeTools`) registered minutes after the server
  began answering. A surface snapshot can legitimately grow;
  Seahawk rebuilds its surface whenever it establishes a new
  downstream session and offers an explicit refresh.
- The `list_toolsets` output is prose; three lines in it are tool
  names mentioned inside a toolset description, not toolsets
  (`GetAssetDiscoveryInfo`, `FindNiagaraScripts`,
  `GetNiagaraScriptDigest`). Their `describe_toolset` calls return
  errors. Seahawk treats any "toolset" whose describe does not
  parse as a toolset document as nonexistent and logs it —
  the census parser and the broker share this rule.
- Several shipped toolset plugins registered **nothing** in the
  lab (LiveCoding, MCPClient, MVVM, MetaHuman, ChaosCloth,
  AnimationAssistant, SequencerAnimMixer among them — they need
  project features the blank lab lacks). Any tool from them that
  ever appears downstream is *unclassified* to Seahawk and refused
  until an operator classifies it (§5).
- Two implementation families coexist: C++ toolsets
  (`EditorToolset.EditorAppToolset`, …) and **Python-implemented
  toolsets** (`editor_toolset.toolsets.*`, `animation_toolset.*`,
  `state_tree_toolset.*`, `conversation_toolset.*`,
  `aimodule_toolset.*`) — same wire shape, same classes.

## 4. Classification method

Classes: **read** = no state change; **write** = mutates
editor/project state inside the editor's domain model (actors,
assets, graphs, settings of content); **execute** = runs code or
crosses a plane where per-tool granularity stops meaning anything
(code execution, code loading, arbitrary file write, environment
mutation, UI input injection, agent-instruction persistence,
starting play/test sessions that run project logic).

Method: verb/shape rules over all 830 tools, description scan,
then a human override pass (every override carries its reason in
`s0-evidence/classes.json`), then an adversarial keyword sweep
(file/disk, level loads, PIE, Python, console, shell, network) over
the classified table. Result: **395 read, 409 write, 26 execute,
0 unclassified.**

## 5. The execute class (26) — the whole point of the broker

| Tool | Why it is execute-class |
|---|---|
| `editor_toolset.toolsets.programmatic.ProgrammaticToolset.execute_tool_script` | **The center of the threat model.** Runs a Python script that batches calls to *all* toolset APIs — one call reaches every write in the surface with no per-tool granularity. Epic calls the interpreter "sandboxed… tool orchestration, not general Python execution"; a broker must treat any scriptable driver of 800+ mutating tools as code execution regardless |
| `editor_toolset.toolsets.asset.AssetTools.write_file` | Arbitrary text write to any path the editor process can write |
| `editor_toolset.toolsets.blueprint.BlueprintTools.write_graph_dsl` | Authors Blueprint logic from a DSL script and compiles it |
| `editor_toolset.toolsets.blueprint.BlueprintTools.compile_blueprint` | Compilation activates authored logic as executable bytecode |
| `UMGToolSet.UMGToolSet.CompileWidgetBlueprint` | Same, for widget Blueprints |
| `PluginToolset.PluginToolset.CreatePlugin` | Creates a plugin from a template **and loads it**; templates can carry post-create Python script paths |
| `PluginToolset.PluginToolset.SetPluginEnabled` | Enables/disables plugin code in project config (loads on restart) |
| `GameFeaturesToolset.GameFeaturesToolset.RequestActivateGameFeature` / `RequestDeactivateGameFeature` | Loads/unloads game-feature plugin content and code |
| `ConfigSettingsToolset.ConfigSettingsToolset.SetSectionProperties` / `SaveSection` / `ResetSectionToDefaults` | Arbitrary settings-section mutation **persisted to disk** — includes the MCP server's own section (port, autostart, tool search) |
| `ToolsetRegistry.AgentSkillToolset.CreateSkill` / `UpdateSkill` | Writes AgentSkill *instruction files that agents consume* — a prompt-persistence surface (Epic's own descriptions say "ONLY… after explicit direction or permission from the user") |
| `SlateInspectorToolset.SlateInspectorToolset.Click` / `Type` / `PressKey` / `FillForm` | Input injection into the full editor UI — arbitrary command reach through menus, dialogs, and text fields (up to typing into a Python console widget) |
| `EditorToolset.EditorAppToolset.StartPIE` | Starts Play-In-Editor: runs the project's Blueprint/C++ game logic |
| `animation_toolset.toolsets.sequencer.SequencerTools.play` / `play_to` | Starts sequence playback; evaluation can fire authored event tracks |
| `AutomationTestToolset.AutomationTestToolset.RunTests` / `RunTestsByFilter` | Executes the project's automation test code in-editor |
| `GASToolsets.GameplayCueToolset.ExecuteCueOnSelectedActor` | Executes gameplay-cue logic (ability-system code paths) on an actor |
| `PCGToolset.PCGToolset.ExecuteGraphInstance` / `PCGToolset.PCGSpatialToolset.RunPCGInstantGraph` | Executes a PCG graph — a procedural program that mutates the world |

Notable boundary calls (full reasons in `classes.json`):
material `recompile` is **write** (shader recompile of an existing
data asset creates no new logic); Niagara script *readers* are
read (the word "script" names an asset type); generic property
writers (`editor_toolset.toolsets.object.ObjectTools`) are write
but flagged — a property write can reach almost any UObject,
including settings objects; exports are write (format-constrained
file output — only `write_file` is the unconstrained primitive).

## 6. Threat model — the raw server, as shipped

**Attacker:** any process running as any user on the same host
that can open a TCP connection to 127.0.0.1:<port> (bind is
loopback-only, so the network is *not* in scope by default;
the host's local users and processes are). No credential exists
to steal or guess: a fresh `initialize` is always accepted, and
the session id it returns is the only token — issued to anyone
who asks.

**What that attacker gets, unauthenticated, the moment an editor
with the plugin enabled starts the server:**

1. The full 830-tool surface of whatever project is open,
   including the 26 execute-class tools above.
2. `execute_tool_script` → scripted reach over every toolset API
   in one call; combined with `AssetTools.write_file` and the
   editor's own Python environment this is, in substance,
   arbitrary code execution as the editor's user, plus arbitrary
   file write.
3. Persistence levers: `ConfigSettings` can rewrite the MCP
   server's own configuration (e.g. turn `bAutoStartServer` on,
   move the port); AgentSkill create/update plants instructions
   future agent sessions will consume; plugin create/enable loads
   new code at next start.
4. Session/project destruction within the editor's domain: asset
   deletion, level edits, graph rewrites — the whole write class,
   non-idempotent and (except the editor's own undo) irreversible.

**Seahawk's control mapping:** token auth on the agent path
(constant-time compare, per call) removes anonymous agent-side
access; class-table curation means unclassified tools simply do
not exist to agents; execute-class is default-deny with a typed
refusal, enableable per-tool in policy *and* requiring a distinct
per-call operator token; the append-only op log records every
brokered call (tool, args digest, outcome, latency) and every
guard refusal — the non-idempotency record. The residual Seahawk
cannot close: **the raw port remains reachable by local processes
that bypass Seahawk.** Mitigations are operational and are stated
as lab rules, not code claims: editors run the MCP server only in
throwaway lab projects during brokered sessions, on a nonstandard
port, and never on a real project tree.

## 7. Residuals and open notes

- **Minimal posture, measured in S3:** a project with only the
  ModelContextProtocol plugin enabled exposes exactly **1
  toolset** — `ToolsetRegistry.AgentSkillToolset` (ListSkills,
  GetSkills read; CreateSkill, UpdateSkill execute). There is no
  posture of Epic's server without execute-class tools.
- **Native registration mode** (`bEnableToolSearch=false`)
  remains unmeasured: the probe editor did not reach MCP-listen
  within ~11 minutes on restart (its first start took ~3.5 min)
  and the probe was bounded off. Seahawk v1 speaks the toolsearch
  shape (Epic's default). If a downstream answers `tools/list`
  without the meta-tools, Seahawk reports the mode mismatch as a
  typed downstream error rather than guessing.
- **Epic's script sandbox fences direct file I/O:**
  `execute_tool_script` scripts cannot `open(..., 'w')`
  (measured in S3; allowed modes are read-only). The execute
  classification rests on tool-reach — one script orchestrating
  the editor's tool APIs in a single call; whether scripts can
  invoke write-capable tools such as `AssetTools.write_file`
  through the tool API was not verified (GATE-REPORT R-4).
- **Editor latency (measured):** the headless lab editor
  processes downstream calls at ~14 s each; a cold full surface
  build takes ~13 minutes. The snapshot is cached per session.
- The census is a snapshot of UE 5.8.0 with `AllToolsets`. Epic
  can add toolsets in any update; anything new arrives
  unclassified and refused until an operator extends the policy —
  the intended failure direction.
- `describe_toolset` for the largest toolset
  (Niagara System, 46 tools) returns ~278 KB of schemas; the
  surface snapshot is correspondingly large and is cached per
  downstream session, never per call.
- crates.io (informational only, nothing published): the name
  `conn` is taken (an unrelated 2023 TCP crate); `seahawk` is
  available per the Owner's D-171 verification. The crate in this
  build is `seahawk` from birth.

## 8. The broker's native surface at 1.0.0

Sections 1–7 describe the *downstream* surface Seahawk
brokers. Seahawk's own (native) surface at 1.0.0 is 15 tools
— 20,554 canonical chars, 4,539 cl100k tokens, within the
D-247 native cap of 6,000 (`EFLO.md`):

| Tool | Class | Notes |
| --- | --- | --- |
| `seahawk_status` | read | broker state, incl. vision + tooling + feedback sections |
| `seahawk_surface` | read | the curated downstream surface (classified subset) |
| `seahawk_oplog` | read | the append-only op log, read back |
| `gui.<app>.observe` ×4 | read | per registered app (Blender, Unity, ComfyUI, Aseprite in the shipped example) |
| `gui.<app>.actuate` ×4 | actuate | two-key rule; window-rectangle confinement; bracket digests |
| `gui.observe` | read | broker frame + geometry; window identity; blank-frame verdict |
| `gui.ground` | read | bbox + derived-centre point; local grounder or agent ticket |
| `gui.act_verified` | actuate | act + verify; anchored/full-frame checks; strategy-changing retries; window pinning |
| `code.feedback` | read | D-230: theodolite/periscope diagnostics, lint, format; bounded episodes; no write path (R6) |

**S5 outcome at 1.0.0.** The S5 frozen benchmark failed at
0.3.0 on a trailing-edge aim bias (mechanism and decomposition
in the S5 gate report); the 1.0.0 curative round (C1 bbox
grounding, C2 strategy-changing retries, C3 effect-anchored
checks, C4 blank-frame screening + window identity) is its
answer, re-run frozen under the original bars with the adopted
Visual Benchmark v1 (`BENCH-VISUAL.md`) alongside — numbers in
the 1.0 gate report (`GATE-REPORT-1.0.md`).

**R-4 disposition.** See the R-4 bullet in §7 as amended at
1.0.0.
