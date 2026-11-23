# Native TUN lifecycle code review

## Scope and workflow
- Review the Linux managed TUN lifecycle, persistent interface ownership, broker authorization/framing, journal/manifest persistence, recovery, process identity, and systemd supervision.
- Review live `main` source, apply code and necessary regression-test source changes, and commit review improvements directly.
- Do not run tests, formatting, CI, or activate/change host TUN/network state in this review phase. The maintainer will run local formatting and tests afterward.
- Review prioritizes fail-closed behavior, identity binding, race resistance, durable recovery, bounded resources, separation of responsibilities, and SOLID design.
- Keep this record current as the review proceeds; findings are not marked resolved without a code change or documented reason.

## Applied fixes
- `src/tun/native_core_launcher.rs`: require systemd ActiveState=active and SubState=running before capturing the service MainPID.
- `src/tun/process.rs`: treat pidfd_open file descriptor 0 as a valid success, not as a failure/special case. (The syscall returns any nonnegative descriptor.)

## Deferred verification
- Tests, formatting, and CI are intentionally not executed during this phase.
- Regression tests will be added or updated in source where practical; they remain unexecuted until maintainer validation.
- No host networking or TUN state has been activated or changed by this review.

## Maintainer validation feedback and compile fixes

The maintainer ran `cargo fmt --all -- --check`, `cargo test --all-targets`, and `cargo clippy --all-targets --all-features -- -D warnings` on 2026-11-21. Formatting emitted no diagnostics; test and Clippy compilation failed before tests executed.

Applied source corrections for the reported diagnostics:
- Corrected the Unix `AsRawFd` import path and removed unused `AsFd` / `Context` imports.
- Corrected adapter contract test references to the parent `adapters` module.
- Routed Xray end-to-end activation through the core-dispatch method, propagated runtime-directory errors correctly, and corrected route-policy references in request tests.
- Added an IPv4/IPv6-aware link-local predicate for readiness target validation.
- Preserved reserved `sockaddr_nl` padding validation through bounded ABI-byte inspection rather than accessing libc's private field; kernel family, PID, group, and sockaddr-length checks remain enforced.
- Fixed the netlink test's overlapping mutable/immutable borrow and the descriptor-transfer test's mutable stream binding.
- Fixed the moved-error handling in managed activation and removed unused variables/mutability.
- Removed unreachable code after the pidfd signal retry loop and corrected the Xray socket file-type extension import and attachment-wait error handling.

## Verification status

- `cargo fmt --all -- --check`: no diagnostics in the maintainer-provided run.
- `cargo test --all-targets`: compilation failed before test execution; the single native-adapter integration test was reported ignored because all three managed core binaries were unavailable.
- `cargo clippy --all-targets --all-features -- -D warnings`: compilation failed on the same diagnostics.
- The above compile fixes have been committed to `main`, but they are **not verified** until the maintainer reruns formatting, tests, and Clippy against the latest commit.
- No tests, formatting, Clippy, CI, or host TUN/network mutations were run by this review pass.

## Recovery integration review — compatibility activation boundary

- `ActivationOrchestrator::activate` previously delegated to a compatibility composition that prepared and committed Running without starting the independent generation-bound recovery service at this orchestration boundary.
- Updated it to prepare/adopt the exact generation, start the supervisor while the durable manifest remains Prepared, and then bind/commit the captured process identity. Supervisor startup failure triggers exact-generation stop/recovery compensation. Commit failure attempts the same generation-bound compensation while the independently started supervisor remains available if cleanup is incomplete.
- This source change has not been locally compiled, formatted, or tested. TUN remains gated. The service executable installation contract and runtime service startup still need host validation.

### Current review execution policy

- Source review and code/test/documentation updates are committed incrementally directly to `main`.
- Local validation is deferred until the review checklist is exhausted, as requested.
- No host network/TUN state was changed.

## Broker authorization and transport review (source inspection)

- The persistent mutation broker authenticates Unix peers with peer credentials and accepts requests only from the effective-UID owner. Activation owner UID/GID are required to match the authenticated peer. Descriptor-export requests are generation-bound to a live broker backend.
- Requests and responses use bounded length-prefixed frames, strict typed JSON request variants, protocol-version checks, monotonic I/O deadlines, and error envelopes bounded to avoid unbounded attacker-controlled diagnostics.
- The persistent server isolates per-connection handling failures and continues accepting connections; malformed or unauthorized requests do not directly terminate its service loop.
- The helper launcher validates private runtime directory ownership/mode and a root-owned helper executable before connecting/starting. Existing unresponsive socket paths are not unlinked blindly.
- No confirmed code change was applied in this review slice. Remaining runtime/package boundary verification includes helper capability installation, socket creation/removal ownership, service process lifetime, and fault injection under concurrent/replayed requests. These remain blockers for activation enablement.


## Kernel cleanup compare/delete limitation

The Linux journal backend performs a fresh resource inventory, compares canonical fingerprints, issues narrowly typed route/rule/interface deletion requests, and verifies the post-delete inventory before recording durable cleanup progress. However, the inspected route/rule delete selectors are not a kernel-atomic conditional operation against the entire previously observed fingerprint. An external actor can theoretically change a matching resource between inspection and deletion. `src/tun/kernel_transaction.rs` now documents this limitation instead of claiming atomic compare-and-delete. This remains a critical unresolved race and an explicit activation blocker; source inspection is not sufficient to declare it safe.

## Native attachment and end-to-end readiness review

- The source has an Xray broker descriptor handoff/launch path, bounded attachment wait, kernel fdinfo/interface verification, and composable readiness checks. This remains dependent on the separately packaged systemd shim/core launcher and host behavior; source-level evidence is not live end-to-end validation.
- sing-box and Mihomo currently use native named-device creation rather than the broker-owned external-descriptor contract. Their configuration and capability-confined launch code do not establish independent broker exclusive ownership or fully verified dataplane readiness for this review's intended model.
- AttachmentEvidence is structurally validated and generation/process-bound but remains caller-supplied evidence; it cannot substitute for independently verified adoption and traffic checks.
- The CLI/public activation gate remains closed. Live core attachment, actual traffic/routing/DNS/firewall invariants, failure handling under core/service crashes, and packaging integration remain incomplete verification requirements.

## Architecture/SOLID review and phase closeout

### Architectural findings

- The state-transition model is pure and backend-independent; the production supervisor delegates mutation to the persistent broker and process identity is pidfd-bound. This separation is worth preserving.
- Activation orchestration, managed activation, core launchers, readiness, supervisor service lifecycle, and kernel transaction responsibilities are separated into modules, but orchestration still has broad multi-argument APIs and cross-module coordination. A later API refactor should introduce validated request/context structs without changing lifecycle behavior or weakening the gated boundary.
- Three targeted Clippy allowances for argument counts remain documented in the recent code history. They are architectural debt, not grounds for broad lint suppression.
- The systemd transient service implementation and packaging contract have not been exercised in the target host. The compatibility activation now starts the recovery supervisor before Running, but cannot prove service startup/crash recovery in the real environment.

### Review completion summary

Source-level passes covered recovery lifecycle/generation binding, activation handoff, systemd supervisor contract, broker transport/authorization, journal ordering, kernel cleanup identity/fingerprint behavior, attachment/readiness composition, and architectural boundaries. The review made one activation-handoff code change and documented the rtnetlink compare/delete race and other host-validation blockers. No test, formatter, Clippy, CI, core-launch, or host networking/TUN operation was performed during this review phase, per maintainer workflow.

### Required local validation after review changes

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets`
- Focused TUN tests and native adapter integration validation once all managed core binaries are installed.

### Activation gate status

**Keep TUN activation disabled.** The rtnetlink cleanup race, end-to-end host/runtime proof, attachment/dataplane integration, packaging, and crash/fault-injection coverage remain unresolved. Source review and green unit tests alone cannot close these blockers.


## Generation-bound startup resume hardening

- Startup recovery now passes the supervisor's expected activation ID and generation into the same resume entrypoint that loads the durable manifest and binds its process identity.
- The resume entrypoint rejects a manifest whose activation token differs from that expected identity before process monitoring or recovery is initiated. The general CLI resume path remains available without an explicit expected identity.
- This narrows a check-to-resume race in the standalone recovery service. Kernel cleanup selector race limitations and live service-manager verification remain separate unresolved concerns.
- Tests for this change are authored in the source workflow but have not been run locally in this implementation phase.
