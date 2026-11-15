# Architecture refactor status

This work is a behavior-preserving maintainability pass. It must not change proxy protocol mappings, benchmark scoring, Xray transfer behavior, managed-process ownership, or the TUN safety gate.

## Phase 1 — core-owned adapters

**Implemented on `main`; user-reported verification passed on 2026-11-15.**

- Native config generation and benchmark batch serialization live in each core adapter.
- Per-core capability profiles are declared beside the adapter that owns the native schema.
- Core contract tests assert activation, benchmark, and TUN configuration invariants.
- Benchmark selection/default settings live in `services/benchmark/options.rs`.
- `CoreAdapter` is now a contract and shared adapter code no longer selects native config fields through a `CoreId` switch.

## Phase 2 — responsibility boundaries and bounded operations

**Implemented on `main`; user-reported local verification passed on 2026-11-15.**

- `process.rs` centralizes bounded subprocess execution with file-backed stdout/stderr capture, a deadline, and a 64 KiB returned-output cap. Native config validation and installed/staged version checks use this common runner.
- Release metadata requests have a 20-second global deadline and a 10 MiB response cap. Release artifact requests have a 300-second global deadline and retain the 256 MiB byte cap.
- Benchmark orchestration delegates bounded latency/TCP probes to `services/benchmark/probes.rs` and sample creation/persistence/cancellation wiring to `services/benchmark/samples.rs`.
- Managed activation delegates process identity/pidfd operations to `services/activation/identity.rs`; gated TUN service/runtime helpers live in `services/activation/tun_runtime.rs`.
- CLI command dispatch and presentation are separated into `cli/handlers.rs` and `cli/presentation.rs`.
- TUN transaction journal validation/recovery planning lives in `tun/journal.rs`; private filesystem primitives live in `tun/manifest_fs.rs`, leaving manifest lifecycle persistence in `tun/manifest_store.rs`.
- The report-row helper has module-private visibility because it is only used inside the presentation module.

The shared process runner kills and reaps the direct child on timeout. It does not currently promise process-group termination of arbitrary descendants; callers must use commands whose child process identity is the process being supervised (as the existing core validators/version commands do).

## Phase 3 — contract review and verification

**Completed on 2026-11-15; user reported all local checks passed.**

- Reviewed adapter contracts and native-config ownership, benchmark execution and HTTP measurement boundaries, managed process lifecycle, CLI parsing/dispatch/presentation, database persistence, updater operations, and the offline TUN foundation.
- Review conclusions and remaining targeted improvements are recorded in `docs/ARCHITECTURE_REVIEW.md`.
- No generic dependency-injection framework or interfaces that merely mirror one implementation were added.
- No proxy mappings, benchmark scoring, Xray transfer behavior, process ownership, or TUN activation policy were changed by this review.

Verification reported by the user:

```fish
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

All passed according to the user's local output.

## Next sequence

1. Run the separately documented, user-controlled real-network benchmark smoke test using one known-good node and one managed core. The ordinary test suite remains offline.
2. Review the real measurements and failure diagnostics before changing benchmark methodology.
3. Implement the approved Quick and Accurate benchmark profiles in separate batches, then add offline tests for their settings, accounting, and persistence.

## Deliberately not included

- No live core startup, public benchmark endpoint traffic, or real-data speed test in automated tests.
- No system proxy, DNS, route, firewall, or TUN mutation. TUN activation remains disabled.
- No changes to the working Xray download/upload transport path.
- No large dependency-injection framework. Add narrow runtime/repository ports only where a concrete substitution or deterministic test needs them; avoid interfaces that merely mirror one implementation.
