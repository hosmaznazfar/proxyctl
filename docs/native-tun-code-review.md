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
- No new automated regression test has yet been added for this narrow change; the existing test suite remains unexecuted during this implementation phase.


## Prepared-startup cleanup race hardening

- Found a race in orphan cleanup: the supervisor could read a Prepared manifest, then terminate its recorded core after a concurrent lifecycle coordinator had committed that same activation to Running.
- Added a lifecycle-lock-protected `claim_prepared_cleanup` transition. It atomically verifies the exact activation token and changes Prepared to CleanupPending before any process termination is attempted. The normal bind/commit path accepts only Prepared, so a late startup commit is now rejected once cleanup owns the generation.
- Added a regression test asserting that claiming cleanup persists CleanupPending and prevents a subsequent process bind.
- The process termination and broker cleanup remain separate operations after the durable claim; failures preserve CleanupPending for retry.
- This change and its regression test have not been compiled, formatted, or executed locally. Runtime process/service and kernel cleanup validation remain outstanding.
- Follow-up hardening: cleanup now also rechecks and stops the persisted process identity when resuming an already-CleanupPending manifest. This covers a crash after the durable cleanup claim but before process termination completes; a failed stop leaves the manifest pending rather than allowing broker resource removal to proceed.


### Generation-specific systemd supervisor identity

The transient systemd recovery unit name now includes both the complete activation UUID and its generation (`proxyctl-tun-<uuid>-g<generation>.service`). Previously the unit name omitted generation even though the process arguments and manifest checks included it. Reusing an activation UUID with a later generation could therefore cause startup to mistake an older generation's active unit for the requested supervisor. The unit name, identity validator, and regression tests now bind both dimensions. This source change has not yet been run through local compilation, formatting, Clippy, or tests.


### Activation API evidence gate

The evidence-free `ActivationOrchestrator::activate` entrypoint is now private to the TUN module. External callers must use `activate_with_attachment_evidence`, which validates activation UUID, generation, interface, and pinned process binding before activation. This narrows the public API bypass, but the current `AttachmentEvidence` remains caller-supplied structural evidence; it is not yet an unforgeable receipt from the core-side adoption acknowledgement and must not be described as independent proof of attachment.
- Follow-up attachment gate: `activate_with_attachment_evidence` now performs the live Linux Xray descriptor/interface check itself after validating the generation and process binding. A caller cannot activate merely by setting the structural `descriptor_transfer_confirmed` flag; the exact process must hold a TUN fd whose kernel fdinfo names the requested interface, and the live ifindex must match. This is Xray external-descriptor verification, not a universal sing-box/Mihomo adoption proof.


### Broker-side live-core recovery guard

Privileged broker recovery now independently checks the process identity persisted in the ownership manifest and refuses route/interface cleanup while that exact core process is still live. This closes the direct-helper-call gap: callers cannot bypass the managed supervisor's systemd stop step and ask the broker to remove active resources. A stale/reused PID does not block recovery because the check is tied to the persisted process start time and executable identity. Added a regression test covering rejection while the child is live and acceptance after it exits. The test is authored but has not yet been run locally.

## Kernel cleanup ownership selector hardening (2026-11-23)

Proxyctl now tags routes and policy rules it creates with a dedicated locally assigned protocol marker (99). Route deletion includes the same route protocol in its typed rtnetlink selector; rule creation and deletion carry the corresponding `FRA_PROTOCOL` attribute. The marker is included in the fresh `ip -j` canonical fingerprint, so a route/rule whose protocol or any other inventoried attribute changes is rejected before cleanup. This narrows accidental selector collisions and makes ownership visible in diagnostics. Kernels that do not support the rule protocol attribute fail closed rather than silently dropping the marker.

This is an ownership discriminator, not a cryptographic capability: another privileged network manager can deliberately reuse protocol 99 and an identical selector. Linux rtnetlink does not expose an atomic full-fingerprint compare-and-delete primitive for routes/rules. The backend therefore retains the journal and reports a conflict whenever its fresh full fingerprint differs; the narrow protocol-tagged delete selector and post-delete inventory are defense in depth, not a proof against a malicious concurrent privileged actor replacing an entry with an identical selector in the inspection/delete window. That kernel limitation remains explicit.

## Independent sing-box and Mihomo TUN attachment gate (2026-11-23)

Native-device activation now waits for the exact launched systemd MainPID to expose an `iff:` entry for the requested interface in `/proc/<pid>/fdinfo`. The verifier pins the process with pidfd, checks the recorded PID/start-time/executable identity, confirms the interface is a kernel TUN device and its current ifindex equals the Prepared manifest's ifindex, and rechecks that the process remains the same and alive after inspection. The wait is bounded to five seconds. A timeout or mismatch stops the exact generation-bound core service and requests exact-generation broker recovery before activation can proceed.

The gate applies to both sing-box and Mihomo after their generated native configuration has been validated and the broker-created persistent TUN exists. Caller readiness callbacks and end-to-end traffic checks still run afterwards; fdinfo adoption proves the process holds the requested TUN descriptor, not that traffic, DNS, IPv4/IPv6 routing, or physical-egress invariants are correct. Those remain mandatory readiness checks and require host-level validation.

### rtnetlink selector ABI correction

The protocol-tagging change also corrected the raw fib-rule attribute identifiers against the Linux UAPI: `FRA_FWMASK` is attribute 16 and `FRA_PROTOCOL` is attribute 19. The previous mask constant (11) did not encode a mark mask; it addressed a different fib-rule attribute. Regression assertions now pin the ABI values and the protocol-marker attribute encoding. The rule marker is applied on both creation and deletion, and the route protocol marker is applied on both route creation and deletion.

### Upgrade behavior for pre-marker journals

Journals/manifests created by earlier builds have no protocol-99 ownership marker on their route/rule entries. The new cleanup path intentionally does not infer ownership from the old table/priority selectors alone: it preserves those entries and retains the journal rather than deleting an untagged resource. Upgrading with an active legacy TUN activation therefore requires stopping the matching core and manually reviewing/cleaning the old resources before starting a new activation. This is a deliberate fail-closed compatibility boundary, not an automatic migration.


## Phase 3 and 4 follow-up implementation (2026-11-23)

### Dual-stack dataplane readiness

- Added a shared validator requiring exactly one valid IPv4 and one valid IPv6 numeric HTTP target.
- Added a native-core readiness composition that independently runs the existing route lookup, bounded TUN-routed HTTP exchange, listener/process verification, outbound socket-mark observation, physical-egress check, and DNS/firewall snapshot comparison for both families.
- Added Xray dual-stack readiness using the same generation-bound live checks.
- Added orchestration entrypoints for dual-stack Xray and sing-box/Mihomo activation. They keep the manifest Prepared until both family probes pass; any error follows the existing exact-generation stop and broker-recovery path.
- Added regression coverage for missing, duplicate, and same-family target sets.

The DNS assertion remains a preservation check against pre-activation state. These numeric-address HTTP probes do not perform a DNS query through the proxy and do not prove resolver, split-DNS, or DNS-over-TCP/UDP behavior. Those remain explicit host integration requirements.

### Recovery supervisor logout safety

- The systemd recovery supervisor runs in the activation user's manager, while the managed core is a system-level service. If the user manager stops at logout, the core and routes could outlive the recovery process.
- The production systemd supervisor constructor now queries the current UID's Linger property with loginctl and requires an exact yes. The query is bounded to two seconds and fails closed on command errors, malformed output, or disabled lingering.
- The existing activation rollback path handles supervisor-construction failure after kernel preparation. User-facing setup guidance is: sudo loginctl enable-linger $(id -un).
- Added unit tests for explicit yes/no/empty/unknown linger-state values.

### Current scope and verification

- Systemd is the only implemented automatic recovery backend. Other detected init managers remain unsupported and activation must remain rejected there.
- Unit/source changes are committed, but this follow-up has not been compiled, formatted, run through Clippy, or tested locally. The maintainer must validate the latest main before any live TUN activation.
- Host-level proof is still required for IPv4 and IPv6 external reachability, DNS resolution behavior, logout with lingering enabled, supervisor restart, core crash, system shutdown, and recovery under concurrent startup/cleanup.
- The default CLI activation gate remains closed. These orchestration APIs are not a declaration of production readiness.
