# EFLO — native tools/list size (fleet-to-1.0, G-S3)

Measured 2026-10-29 on the final 1.0.0 tree, dead downstream,
default vision off, the shipped example's four GUI apps
registered (Blender, Unity, ComfyUI, Aseprite) — the surface a
fresh operator gets. Tokenizer: **tiktoken cl100k_base** (real
tokenizer, not a chars/4 estimate). Canonical form: JSON,
sorted keys, compact separators — the same canonicalization
the S5 gate used.

| Measure | Value |
| --- | --- |
| Native tools | 15 |
| Canonical chars | 20,554 |
| **cl100k tokens** | **4,539** |
| D-247 native cap | 6,000 |
| Headroom | 1,461 tokens (24%) |

## Disposition

**Within cap — no waiver, no trigger-scoping needed at 1.0.**
The 15th tool (`code.feedback`, D-230) plus the S5 curative
schema growth (bbox fields, `changed_around` / `full_frame`,
`window_id`) added 3,384 canonical chars over the S5 surface
(17,170 chars / 14 tools). The binding constraint is the token
cap, and it holds with margin.

The brokered downstream surface (Epic's UE 5.8 census: 830
tools across 52 toolsets) is **not** part of this number and
never has been: it is served only through the curated,
class-filtered downstream list when an editor session is
configured, and D-247 scopes the cap to the native surface by
design (Seahawk holds the fleet's one 6,000-token exception
for exactly this reason).

Watch item for post-1.0: each additional registered GUI app
adds an observe+actuate pair (~450 tokens). Registration is
policy data, so surface growth is an operator act, not code
growth; if a deployment registers more than ~3 extra apps,
re-measure and consider trigger-scoping the per-app pairs.
