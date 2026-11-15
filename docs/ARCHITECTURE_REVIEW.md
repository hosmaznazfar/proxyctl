# Architecture and SOLID review

> Review date: 2026-11-15  
> Scope: current `main` source after architecture refactor Phase 2  
> Method: static source/module-boundary review plus user-reported local verification  
> Verification: `cargo fmt --all -- --check`, strict Clippy, locked tests, and locked release build were reported passing by the user. This review does not claim independent execution.

## Executive assessment

The current architecture is a sound foundation for adding cores and protocols without rewriting benchmark orchestration or CLI handlers. The strongest improvement is the adapter boundary: each core owns its native schema and capability profile, while shared normalization owns protocol semantics and compatibility outcomes. Benchmark options, probe scheduling, sample persistence, process identity, CLI dispatch, and TUN journal validation now have clearer homes.

The project does not need a general-purpose dependency-injection framework. The existing static adapter dispatch is explicit, cheap, and appropriate for three compile-time core implementations. Add interfaces only when there is a second implementation, a real substitution point, or a deterministic test seam.

No critical SOLID violation was found that justifies a broad rewrite before real-network validation. The remaining items below are targeted maintainability improvements, not blockers to the current verified behavior.

## SOLID review

### Single Responsibility

**Good boundaries**
- `CoreAdapter` implementations own sing-box, Xray, and Mihomo serialization and native validation.
- Shared adapter modules separate protocol, TLS, transport, options, capabilities, and XHTTP normalization.
- `services/benchmark/options.rs`, `probes.rs`, and `samples.rs` separate settings, bounded probes, and persistence/sample bookkeeping from the main orchestration.
- `services/activation/identity.rs` owns process identity and pidfd operations; TUN-only runtime helpers are isolated.
- `updates/release.rs`, `artifact.rs`, and `installer.rs` separate release selection, artifact verification/download, and executable replacement.
- `tun/journal.rs` separates journal invariants and recovery planning from private file operations.

**Remaining concentration points**
1. `database/nodes.rs` owns node CRUD, schema initialization/migration, benchmark run/sample persistence, history retention, and deletion state. This is the clearest remaining SRP concern. A future behavior-preserving extraction should move benchmark persistence into a sibling database module while keeping a single database handle/transaction boundary.
2. `tun/manifest_store.rs` persists two distinct durable records: the lifecycle manifest and the write-ahead transaction journal. The operations share directory ownership and atomic-file guarantees, but their storage APIs can be separated into manifest and journal stores over shared private-file primitives. This is a medium-priority cleanup because the journal lifecycle is already independently modeled.
3. `cli/mod.rs` still combines Clap command definitions with shell-completion generation/install helpers and interactive prompts. Parsing definitions can remain centralized; completion installation and prompt workflows should move to a focused CLI support module when touched next.
4. `services/activation.rs` still owns the activation orchestration, runtime lock/state persistence, and process launch/stop flow. These are related lifecycle responsibilities, but state serialization and atomic state-file operations are a plausible future extraction if the module grows further.

### Open/Closed

- Adding a new core currently requires a new adapter implementation and explicit updates to `CoreId`/adapter dispatch and core metadata. That is a small, visible compile-time change rather than a hidden runtime registry. This is acceptable for the current fixed core set; avoid a dynamic plugin registry unless third-party core plugins become a real requirement.
- Adding protocol semantics is correctly centered in the normalized domain model and shared capability/normalization logic, with per-core support decisions in adapter profiles.
- Adding benchmark metrics still touches the metric enum, settings/measurement persistence, reporting/sorting, and CLI display metadata. This is expected for a cross-cutting persisted feature; future metrics should use a documented conformance checklist so no layer is missed.

### Liskov Substitution

- The three adapters implement one contract and expose the same compatibility/configuration operations while preserving core-specific support outcomes.
- Unsupported or invalid combinations are explicit rather than silently emitted as partial configs.
- Keep adapter contract tests parameterized across all adapters wherever semantics are shared; retain core-specific native config tests for genuinely different schemas.

### Interface Segregation

- `CoreAdapter` is intentionally broad because each managed core currently participates in check, benchmark, loopback activation, and the gated TUN config contract. It is not yet worth splitting into several capability traits: all current adapters implement these operations and the extra trait-object plumbing would add complexity without a real optional implementation.
- Revisit this only if a future core genuinely lacks one operation or if optional features become independently installable.

### Dependency Inversion

- Services depend on domain types and explicit adapters rather than native JSON/YAML structures.
- The updater and process runner use concrete implementations, but there is no demonstrated need for replaceable HTTP/process backends across production targets today.
- For deterministic testing, prefer narrow ports around the exact external effect (for example, a release source or process launcher) only when tests currently need brittle global state or expensive real dependencies. Do not introduce interfaces that simply duplicate every method on a concrete struct.

## Reliability and safety review

- The shared bounded process runner centralizes deadlines and caps captured output; it explicitly supervises the direct child only. Callers must not assume arbitrary descendant process-tree termination.
- Updater metadata/artifact requests have explicit time and byte limits; staged executable validation uses the bounded runner.
- Benchmark process startup/readiness, child cleanup, HTTP request deadlines, response caps, sample status mapping, and bounded concurrency have distinct test seams.
- The HTTP measurement client is cohesive as one benchmark transport component. Its latency/download/upload methods share endpoint validation, local proxy configuration, deadlines, and failure classification; splitting it merely to reduce line count would weaken cohesion.
- The TUN implementation remains offline scaffolding. Kernel mutation, privilege execution, detached recovery, and live readiness are not complete; the CLI exposes status only and activation remains gated.
- Existing Xray transfer behavior is a regression baseline and should not be refactored during unrelated architecture work.

## Prioritized follow-up

| Priority | Area | Recommended action | Timing |
|---|---|---|---|
| P1 | Database | Separate benchmark persistence from node CRUD/schema concerns without changing redb schema or transaction semantics | After real-network benchmark validation |
| P2 | TUN storage | Separate journal persistence API from manifest lifecycle storage; reuse the existing secure file primitives | Before implementing live TUN recovery |
| P2 | CLI | Move completion generation/installation and interactive prompts out of command-definition module | When next changing CLI completion/setup |
| P3 | Activation | Consider extracting persisted runtime-state encoding/atomic writes if more activation features are added | Before expanding activation |
| P3 | Benchmark | Keep current HTTP client cohesive; split only if a new transport backend or independent measurement policy is introduced | No immediate change |
| P3 | Adapters | Keep static dispatch; add conformance tests/checklist for every new core/protocol capability | Ongoing |

## Recommended next work

1. Use the real-world validation runbook with a known-good node and one core. This validates actual network behavior without contaminating the offline unit suite.
2. Compare the recorded latency/download/upload samples and diagnostics. Do not tune defaults from one node or one run.
3. Implement Quick and Accurate benchmark profiles with persisted methodology/settings and deterministic offline tests.
4. Address the P1 database boundary as a separate behavior-preserving batch; then handle the TUN journal store before any TUN activation work.

## Non-goals

- No broad rewrite, generic plugin architecture, async-runtime migration, or dependency-injection framework.
- No benchmark transport rewrite based only on file size.
- No real TUN activation, system proxy, DNS, route, or firewall changes.
- No weakening of compatibility checks or secret masking.
