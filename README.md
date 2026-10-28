# Seahawk

The estate's authenticated broker for Unreal Engine's built-in MCP
server (Epic's `ModelContextProtocol` plugin in UE 5.8). Named for
Rafael Sabatini's *The Sea Hawk* (Owner, D-171; renamed from conn).

Epic's editor MCP server is powerful and completely
unauthenticated: any local process that can reach its loopback
port gets the editor's full tool surface, including in-editor
Python execution. Seahawk exists so agents never touch that raw
server. It serves modern-era MCP (2026-07-28) over stdio to
agents, and downstream it speaks to Epic's legacy-era server as a
client, localhost only.

## Controls

- **Era guard + sequencer** (fleet template): legacy `initialize`
  is refused with the typed `-32022`; forwarded requests apply one
  settle at a time, in order, against the stateful editor session.
- **Agent authentication**: every `tools/call` must carry the agent
  token in `_meta["seahawk/agent_token"]`. The guard verifies it
  (SHA-256 digests, constant-time compare), strips it from the
  frame, and logs refusals. Missing/wrong token: typed `-32001`.
- **Class curation**: every downstream tool is classified
  read / write / execute from the verified S0 census of UE 5.8's
  surface (830 tools; see the build workspace's `SURFACE.md`).
  Unclassified tools are withheld from `tools/list` and refused
  on call.
- **Execute default-deny**: execute-class tools (in-editor Python,
  arbitrary file write, Blueprint compilation, plugin loading,
  PIE, UI input injection, settings persistence, skill authoring,
  …) are listed with destructive annotations but refused unless
  the operator enables the specific tool in policy **and** the
  call carries a distinct operator token in
  `_meta["seahawk/operator_token"]`.
- **Op log**: every brokered call and guard refusal appends one
  JSON line — tool, class, SHA-256 of the canonical arguments,
  outcome, downstream latency. Raw argument values are never
  logged. This is the non-idempotency record: exactly what was
  applied, in order.
- **Policy as data**: tokens, downstream URL (loopback enforced),
  execute enablements, and per-tool class overrides live in a
  TOML config — see `seahawk.example.toml`.

## Computer use (S4)

Beyond the Unreal broker, Seahawk drives GUI applications on
its own X11 display through a built-in provider. The class
lattice is `read < write < actuate < execute`; classification
follows reach, not mechanism (Epic's Slate UI-injection tools
stay execute for exactly that reason).

- **Registration is policy data only**: `[[gui.apps]]` entries
  in the config name an application and the window-match strings
  (WM_CLASS / instance equality, or title substring) that
  identify its windows. There is no agent-callable registration
  and no runtime re-registration; the config is read once at
  startup. The estate's media-GUI registrations ship in
  `seahawk.example.toml`: Blender, Unity (Editor + Hub),
  ComfyUI (browser-hosted; matched by window title), Aseprite.
- **Per app, two tools**: `gui.<app>.observe` (read class —
  screenshot, window list, focus state; screenshots return a PNG
  and are op-logged by digest + dimensions, never by content)
  and `gui.<app>.actuate` (actuate class — focus, click,
  double-click, key chords, text entry, scroll, drag).
- **Actuate is default-deny with the execute two-key rule**: the
  tool must be named in `policy.actuate_enabled` *and* each call
  must carry the operator token. Actuation is confined to the
  registered window's rectangle (coordinates are validated
  against it before anything is injected), and every actuation
  is bracketed by screenshots whose digests land in the op log
  alongside the target description — a click cannot be undone,
  so the record shows what the screen held on both sides of it.
- **Honest caution**: input into an application that hosts
  scripting (Blender's Python console, Unity's editor, Aseprite
  scripts, ComfyUI custom nodes) can compose into code execution
  through the UI. The actuate class records the mechanism; the
  two-key gate prices the risk. Treat enabling
  `gui.<app>.actuate` with the same gravity as enabling an
  execute-class tool for that application.

## Honest limits

Seahawk cannot firewall Epic's port: a local process that bypasses
Seahawk and speaks to the editor directly is outside its
guarantees. The operating discipline is lab-only use — throwaway
projects, editor up only during brokered sessions, nonstandard
port. The full threat model is in `SURFACE.md`.

## Status

Lab-only (Owner ruling, D-146/D-169). No publication is
authorized; the repository home is
<https://github.com/qompassai/seahawk> pending a landing decision.
