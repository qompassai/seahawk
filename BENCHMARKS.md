# Benchmarks — seahawk

Measured 2026-11-27 (batch B1) on primo: 13th Gen Intel Core i7-13620H,
16 threads, 62 GiB RAM, cargo/rustc 1.100.0. The bench harness
(`benches/hot_paths.rs`, hand-rolled on `std::time`, `harness = false`)
drives the **debug** server binary over stdio; numbers are single-run
and primo is a shared machine, so treat them as orientation, not
lab-grade. Reproduce with:

```sh
cargo build --examples --benches
cargo bench --bench hot_paths
cargo run --example stdio_session   # the session the bench drives
```

## Workloads

| Workload | Definition |
| --- | --- |
| `cold_start_discover` | Spawn the server, send `server/discover` (modern era 2026-07-28), await the response; averaged over 5 spawns. |
| `tools_list` | `tools/list` on a warm session; 20 warmup calls, then 200 measured calls. |
| `tool_call` | Representative read-only call `seahawk_status` on a warm session; 20 warmup calls, then 200 measured calls. |

Session setup: Config uses a loopback downstream URL on an unused port with a 2 s timeout and a temp op log; the native status tool needs no live Unreal editor. Note: seahawk does not exit promptly on stdin EOF (its own wire tests kill the broker), so the harness closes stdin, allows a 3 s grace, then kills and reaps.

Tool surface seen by the example: 4 core-profile tools (seahawk_status, seahawk_surface, seahawk_oplog, target.list).

## Results (2026-11-27 run)

| Workload | Result |
| --- | --- |
| cold start → discover | 20.74 ms per spawn (avg of 5) |
| tools/list | 1,482,305 ns/op (674.6 ops/s) |
| tools/call `seahawk_status` | 839,199 ns/op (1,191.6 ops/s) |

## Gates at the same commit

- `cargo build --examples` — clean
- `cargo run --example stdio_session` — green (`stdio_session: ok`)
- `cargo bench --bench hot_paths` — runs to the numbers above
- `cargo test` — 259 passed, 0 failed
- `cargo clippy --examples --benches` — no errors or warnings on the added files

Base commit: `66f9046` (main). Branch: `pax/benchmarks-examples-20261127`.
