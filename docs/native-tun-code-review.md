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

This section records the earlier direct route/rule deletion design and is superseded by the 2026-11-23 link-owned route teardown redesign below. The direct RTM_DELROUTE primitive has been removed. Policy-rule cleanup remains selector-based and is still not a full canonical-fingerprint compare-and-delete against every possible rule attribute.

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


### Maintainer-owned validation policy

- The maintainer runs formatting, Clippy, Rust tests, privileged namespace tests, and host integration checks locally.
- Do not trigger, poll, or report GitHub Actions CI for routine implementation commits unless the maintainer explicitly asks for hosted CI.
- Do not repeat validation instructions or report hosted CI status in progress updates. Record the latest maintainer-reported local result here and request only the next test whose result is still missing.

### Remaining local validation

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets`
- Focused TUN tests and native adapter integration validation once all managed core binaries are installed.

### Activation gate status

**Keep Xray TUN experimental and restricted to controlled maintainer testing; do not treat it as production-ready.** The explicit Xray CLI path exists, but the kernel cleanup ownership limitations, IPv4 global dead-route flush side effects, systemd/helper host behavior, crash/reboot recovery, DNS semantics, and real VMess/VLESS dataplane results remain unresolved. sing-box and Mihomo TUN activation remain disabled. Source review and green unit tests alone cannot close these blockers.


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

Proxyctl tags routes and policy rules it creates with the locally assigned protocol marker 99. The marker is included in fresh `ip -j` canonical fingerprints and in policy-rule creation/deletion through `FRA_PROTOCOL`. Route deletion has since been removed: routes are now expected to disappear through unregistering the exact owned TUN link, followed by fresh inventory verification. The route protocol marker remains useful for identifying and diagnosing journaled route records; it is not used in a direct delete request.

For policy rules, the marker is an ownership discriminator, not a cryptographic capability: another privileged network manager can deliberately reuse protocol 99 and the same selector. Linux `fib_rule_find()` matches only selector fields represented in the delete request; omitted attributes are wildcards. The unmarked all-traffic proxy rule necessarily omits fwmark and other optional selectors, so an otherwise identical same-marker rule with extra selectors can still match. A fresh full-fingerprint comparison detects changes before deletion but cannot close the snapshot-to-delete interval or make omitted fields exact. The journal is retained whenever the observed full fingerprint differs; even so, this is defense in depth rather than a guarantee against a concurrent privileged actor reproducing the selector.

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


### Hosted CI verification (2026-11-23)


## Phase 5 — privileged mutation-helper security audit (2026-11-23)

### Source audit

Reviewed the installed helper, capability installation script, persistent mutation broker, Unix socket binding, request/response framing, peer credentials, descriptor export, and recovery request handling.

- The helper is installed root-owned, non-setuid, and with only the file capability `cap_net_admin=ep`; the ordinary Proxyctl executable and core/supervisor launchers are checked to have no file capabilities.
- The helper refuses to run unless its effective and permitted capability sets contain exactly CAP_NET_ADMIN and its inheritable set is empty. It enables `no_new_privs`, disables dumpability, and does not spawn child processes or act as a generic privilege trampoline.
- The mutation socket is created under a caller-owned private directory with mode 0600. The helper records the socket device/inode and removes only that exact socket on exit. The launcher serializes startup with a no-follow, private, single-link lock file and does not unlink an unresponsive socket.
- The broker reads kernel-provided SO_PEERCRED before decoding request bytes and accepts only its effective UID. Activation owner UID/GID must also match the authenticated peer. Descriptor export is limited to an in-memory backend for the exact activation ID and generation.
- Requests use a strict tagged enum with unknown fields denied, version and identity validation, a 16 KiB frame cap, bounded allocation, and monotonic three-second read/write deadlines. Responses are bounded and the client requires a complete valid success envelope before accepting a descriptor or reporting success.
- Per-connection parse/authentication/execution errors are isolated; the persistent accept loop continues. Recovery verifies manifest and journal identity, refuses to mutate while the manifest-bound core process is live, and retains the backend/journal when recovery or finalization fails.

### New regression coverage

- Extracted the helper capability-set validation into a testable parser. Tests require exactly CAP_NET_ADMIN in effective/permitted sets, zero inheritable capabilities, and reject missing, duplicate, malformed, extra, or inheritable capability values.
- Extracted the mutation broker's peer authorization into a single policy function used before request decoding. Tests cover same-UID acceptance, foreign-UID rejection, and invalid peer PID rejection.

### Explicit security boundaries

The helper's authority is intentionally limited to Linux network administration, but CAP_NET_ADMIN is still powerful within the host network namespace. The broker is a same-user privilege boundary, not a boundary against malicious code already running as the same UID. A same-UID process can invoke the typed helper operations and can deny service by occupying the sequential broker connection loop; this does not grant a different UID access or provide arbitrary command execution.

The broker has no per-UID rate limit or concurrent worker pool. Its fixed frame and I/O deadlines bound each connection, but repeated same-user connections can delay legitimate requests. This is an availability limitation, not an authorization bypass.

The source audit and added unit tests do not prove installed file capabilities, systemd service confinement, socket lifecycle behavior under process crashes, or kernel/network behavior on the target host. The default CLI TUN activation gate remains closed pending local CI-equivalent checks and host-level integration. No live network/TUN state was modified during this phase.


## Phase 6 — failure injection and concurrency regression coverage

- Reviewed the existing transaction fake-backend matrix: it injects failures before and after each route/rule mutation, ambiguous interface creation, invalid/empty fingerprints, failed rollback, failed journal retention, manifest commit failure, and journal finalization failure. The expected invariant is preservation of unresolved resources and recovery journal; ambiguous mutation errors never trigger speculative rollback.
- Reviewed durable journal reopen/recovery tests for unresolved intents, wrong generations, incomplete removals, duplicate keys, and inventory uncertainty. Reviewed broker framing tests for oversized, truncated, malformed, unknown-field, and version-mismatched messages.
- Added a cross-instance concurrency regression test to `src/tun/lifecycle_coordinator.rs`. Two independently opened coordinators race to create the first activation manifest in the same runtime directory. The test requires exactly one winner, one rejected activation, and a durable Prepared manifest belonging to the winner. This exercises the filesystem lifecycle lock rather than merely serializing calls through one in-memory coordinator.
- Existing lifecycle tests also cover lock exclusion/release, symlink and hard-link rejection, stale-token rejection when generations are reused, and preventing a late core bind after cleanup has claimed a Prepared activation.
- These are deterministic unit/fake-backend tests. They do not simulate power loss, kernel netlink races, actual helper process termination, systemd restart ordering, or live namespace dataplane behavior. Those remain host/integration validation requirements.

## Phase 7 — final source audit and release-readiness boundary

### CI and compatibility contract
- CI runs formatting, Clippy with warnings denied, and all-target/all-feature tests on Ubuntu using Rust 1.100.0, matching the package's declared `rust-version = "1.100"`. This verifies the declared compiler floor rather than silently relying on a different toolchain.
- The TUN helper remains a separately installed root-owned executable with the narrowly scoped file capability contract described above. Packaging scripts and installed systemd units still require validation on a clean CachyOS host.
- No automatic recovery backend other than systemd is implemented. Unsupported service managers must remain fail-closed.
- The public TUN activation gate remains closed. Route cleanup now relies on kernel netdevice-unregister cleanup rather than a separate RTM_DELROUTE request; the backend verifies route absence afterwards. Policy-rule cleanup remains a protocol-tagged selector operation with the documented omitted-attribute wildcard limitation. IPv4 unregister can flush unrelated already-dead routes and, with multipath enabled, a whole multipath route containing the TUN as one nexthop. Both behaviours require namespace/host validation and explicit acceptance.

### Required release validation
- Run formatting, all-target/all-feature Clippy, all-target/all-feature tests, and a release build on the target machine.
- Validate helper installation/removal and exact file capabilities from a clean install.
- Exercise IPv4 and IPv6 external traffic, DNS behavior, firewall preservation, core crash, helper crash, supervisor restart, logout with lingering, shutdown, and recovery after interrupted journal operations.
- Run concurrent activation/deactivation/recovery tests against isolated Linux network namespaces and verify foreign routes/rules/interfaces are never removed.
- Do not describe managed TUN as production-ready or enable the default activation gate until the policy-rule cleanup boundary is accepted, kernel side effects are validated, and the host-level matrix passes.


### Release artifact completeness
- The tagged release workflow now builds all declared binaries and packages the CLI, privileged TUN helper, core launcher, and recovery supervisor as separate Linux executables with a combined SHA-256 manifest. This matches the executable set expected by the helper installer rather than publishing only the CLI.
- The helper installer remains an explicit root-run packaging step; publishing the helper binary does not install file capabilities or enable TUN automatically. The separate install/remove scripts must still be exercised on the target host.

- The helper remover now validates all three installed bundle paths (regular files, no symlinks, root ownership) before deleting any of them, preventing a later invalid path from leaving an avoidable partial uninstall. CI also performs a POSIX shell syntax check on both packaging scripts.

## Kernel cleanup redesign — link-owned routes (2026-11-23)

The direct route deletion path has been removed from `src/tun/rtnetlink_mutations.rs`. Cleanup now follows this order:

1. Delete the protocol-tagged policy rules.
2. Release the exact generation-owned TUN descriptor or persistent device.
3. Re-inspect the kernel and mark each journaled route absent only after the route is gone. A surviving route is preserved as a conflict; there is no direct-delete fallback.

This avoids the separate route inventory/RTM_DELROUTE race for Proxyctl's direct-OIF routes. Linux IPv4 unregister handling marks nexthops dead and can run fib_flush; IPv6 fib6_ifdown removes routes whose nexthop device is the unregistered interface. The route forms created here use RTA_OIF rather than shared RTA_NH_ID objects. Kernel references are recorded in docs/TUN_DESIGN.md.

The recovery executor now processes journal operations in cleanup dependency order (rules, interface, routes), and rollback uses the same order. Added tests cover the ordering and route-verification-after-interface-teardown contract. The opt-in `tests/tun-link-cleanup-netns.sh` script checks IPv4/IPv6 TUN-route cleanup, foreign rule and route preservation, and (when supported by the kernel/iproute2) the documented IPv4 multipath side effect: a foreign multipath route with one TUN nexthop is expected to disappear on unregister even though another nexthop remains. It uses `ip -details rule show` to verify protocol markers, accepting both numeric 99 and iproute2's `openr` name for RTPROT_OPENR while matching other marker values exactly. It prints the detailed dump if a marker precondition fails. It prints an explicit `OK` result to stderr and indicates whether the multipath case ran or was skipped. CI checks shell syntax only; it does not execute the privileged test.

### Residual limitations

- Policy-rule deletion is narrower than a blind priority delete but is not a full-fingerprint compare-and-delete. Linux `fib_rule_find()` compares only fields represented by the delete request; omitted attributes are wildcards. The ordinary proxy-traffic rule omits fwmark and interface/UID/port/suppressor selectors, so a foreign rule with the same family/action/priority/table/protocol 99 but additional selectors can match. Marked core-bypass rules include their fwmark/mask and have a narrower selector. The full live JSON fingerprint is checked immediately before deletion, but this does not close the snapshot-to-delete race or change kernel wildcard semantics. Protocol 99 is a collision-reduction marker, not an authorization boundary against privileged actors. The namespace regression test verifies that a same-priority/table foreign rule using protocol 98 survives deletion of protocol 99; it does not prove protection against same-marker rules with additional selectors.
- IPv4 `NETDEV_UNREGISTER` runs `fib_disable_ip()` -> `fib_sync_down_dev()` and can trigger `fib_flush()` across all IPv4 FIB tables in the namespace. This can remove unrelated routes already marked dead. With `CONFIG_IP_ROUTE_MULTIPATH`, `fib_sync_down_dev()` also marks the entire multipath `fib_info` dead when any nexthop uses the unregistered device, even when alternate nexthops exist; such a route can be flushed too. Proxyctl itself creates only single-path direct-OIF routes, but another manager may have installed a multipath route that references the TUN. The namespace script explicitly exercises this multipath behavior when the test kernel supports constructing that route. The maintainer's latest run passed and confirmed that the entire foreign route is flushed. This documents rather than resolves the side effect; the broader host impact must still be explicitly assessed before activation. Kernel references and exact paths are recorded in `docs/TUN_DESIGN.md`.
- Maintainer-local test run (2026-11-23): `cargo test --all-targets --all-features` reported 654 passed and 0 failed in the main test binary; the core-launcher binary reported 1 passed; the helper binary reported 3 passed; the native-adapter integration test was ignored because all three managed core binaries were not installed. The maintainer confirmed the validation passed. The namespace cleanup script now prints exactly `OK` after all namespace assertions succeed; any failed assertion still exits nonzero with its diagnostic.
- The default TUN activation gate remains closed.



### Policy-rule request encoder regression coverage

The rule add/delete path now shares one validated payload builder, preventing the two operations from silently drifting in family, action, priority, table, protocol marker, or optional fwmark/mask encoding. Tests assert the marker and marked bypass selector bytes and explicitly pin the all-traffic proxy rule's lack of a mark selector. This makes the kernel wildcard limitation visible in the source test suite; it does not remove the limitation or establish atomic full-fingerprint deletion.

### Recovery parsing of policy-rule marks

A source review against current iproute2 `ip/iprule.c` found that JSON rule dumps emit `fwmark` and `fwmask` as separate fields; the mask is omitted when it is the full 32-bit mask. The previous journal cleanup parser expected a combined `value/mask` string and could therefore fail while reconstructing marked core-bypass rules. The parser now reads the separate fields, accepts string or unsigned-integer JSON forms, applies the full-mask default, and rejects malformed/out-of-mask values. Focused regression tests cover these cases. iproute2's JSON rule inventory also resolves protocol 99 to the symbolic string `openr`; the privileged cleanup backend now accepts numeric `99`, string `"99"`, and string `"openr"` as the same RTPROT_OPENR marker. Other protocol values remain foreign. A regression test pins the symbolic JSON form so cleanup does not reject its own rules on iproute2 versions that render the protocol name. This correction was included in the maintainer's subsequent successful local test run.

### Persistent TUN rollback identity

The native-device rollback path previously synthesized an interface fingerprint without the generation alias, while live persistent-interface observations include that alias. Because cleanup compares complete fingerprints, rollback could refuse to release its own persistent TUN and retain the journal unnecessarily. The path now uses the complete applied fingerprint persisted in the journal and separately validates the requested name, ifindex, and TUN kind before cleanup. Regression tests pin alias preservation and reject identity mismatches. This correction was included in the maintainer's subsequent successful local test run.

The `/dev/net/tun` open path now also checks the character device number is exactly Linux TUN major 10/minor 200 after `O_NOFOLLOW | O_CLOEXEC`; this prevents accepting an unrelated character device merely because it has the right file type. A pure device-number regression test was added.

## Maintainer-local validation record (2026-11-23)

The persistent-interface rollback fingerprint, policy-rule selector/recovery parsing, process-identity fixture synchronization, and TUN namespace cleanup changes were validated locally on CachyOS. The namespace script passed with the multipath side-effect assertion. Do not use hosted CI for this workflow.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
sudo sh tests/tun-link-cleanup-netns.sh
```

Run the first three commands from the repository root as the normal user. Run the namespace script separately with sudo; it creates and removes a temporary network namespace. If a command fails, provide its complete output and stop before running the remaining commands so the failure can be fixed first. This checkpoint does not authorize enabling TUN; host traffic, DNS, firewall, crash-recovery, and packaging validation remain outstanding.

### Process identity test-fixture exec synchronization (2026-11-23)

A maintainer-local test run exposed three failures in tests that launch short-lived fake child processes and immediately inspect `/proc/<pid>/exe`. Rust's `Command::spawn()` can return before the child completes `execve()`; an immediate executable lookup can therefore observe the transient pre-exec image. Capturing that path as the expected identity makes later pidfd verification correctly reject the process once its executable changes. This was a fixture synchronization race, not evidence that pidfd identity checks should be relaxed.

The broker and lifecycle fixtures now resolve the expected `sleep` executable independently, wait until the child reports that exact canonical executable and a stable start-time identity, and only then open the pidfd or bind the process. The service activation pidfd test likewise derives its expected executable from the resolved `sleep` binary instead of sampling `/proc` immediately after spawn. Production identity verification remains fail-closed. The maintainer's subsequent local Rust test run passed, including the fixture synchronization regressions.

### Maintainer-local validation update (2026-11-23)

The latest maintainer run reported 654 passed and 0 failed in the main test binary, plus 1 passed in the core-launcher binary and 3 passed in the helper binary. The native-adapter test remained ignored because all three managed core binaries were not installed. The namespace cleanup test passed on the maintainer's CachyOS host. The trace showed iproute2 rendering protocol 99 as `openr` (RTPROT_OPENR); the matcher accepts either representation while retaining exact matching for marker 98. The script completed all assertions and namespace teardown.

A follow-up source audit found that the privileged rule-cleanup backend also needed to recognize iproute2 JSON's symbolic `openr` representation of protocol 99. The backend now accepts numeric `99`, string `"99"`, or string `"openr"`, with a regression test; all other protocol values remain foreign. This source/test change is committed but awaits the next maintainer-local Rust validation.


### Maintainer validation update — broker live-core fixture (2026-11-23)

The maintainer confirmed that the focused `broker_recovery_refuses_to_mutate_while_manifest_core_is_live` test and the subsequent `cargo test --all-targets --all-features` run both passed after replacing the unstable `tail -f /dev/null` test process with a bounded `sleep 30` fixture. This was test-fixture stabilization only; production recovery guard behavior was unchanged. The symbolic `openr` rule-marker regression is included in the successful full suite. The earlier namespace cleanup script validation remains confirmed and was not rerun for this fixture-only change.



### Recovery supervisor unit sandboxing follow-up (2026-11-23)

Source review found an opportunity to reduce the recovery supervisor's privileges and network exposure independently of the CAP_NET_ADMIN mutation helper. The transient systemd user unit now requests `NoNewPrivileges=yes`, empty `CapabilityBoundingSet` and `AmbientCapabilities`, `RestrictSUIDSGID=yes`, `RestrictNamespaces=yes`, and `RestrictAddressFamilies=AF_UNIX`. The supervisor is intended to coordinate identity/state and broker requests, not directly perform privileged kernel networking. This is additional sandboxing, not a privilege-boundary proof. It is unvalidated: the next local checkpoint must confirm systemd accepts these properties and that the supervisor can still inspect pinned processes, interact with the user/system manager, access its private runtime directory, and communicate with the helper. TUN remains gated.


### Systemd command deadline hardening (2026-11-23)

Added a reusable bounded subprocess runner for systemd control operations. `systemctl is-active` and stop requests are bounded to two seconds; transient `systemd-run` startup invocation is bounded to three seconds. Timeout paths kill and reap the child before returning failure. These are code-level bounds, not proof of manager responsiveness or successful stop semantics; timeout/host behavior remains to be validated locally.


### Native/Xray launcher subprocess deadline review (2026-11-23)

The native-core launcher previously had an unbounded sudo authorization call and could return from service-state/MainPID inspection errors without requesting cleanup of the transient unit. Authorization is now bounded, ambiguous systemd-run outcomes trigger a bounded stop request, and any failed active-state/MainPID verification also requests a bounded stop for the exact activation/generation unit.

The Xray launcher now bounds sudo authorization, captures MainPID output through a size-limited temporary file with a 128-byte ceiling, and bounds startup/handoff failure stop requests. The direct unbounded `status()`/`output()` calls were removed from these launcher paths. Timeout handlers kill and reap the local child process before returning.

These are source-level guarantees for Proxyctl's command clients, not proof that the system manager cancels an already-submitted job or finishes cleanup. Local formatting, Clippy, and all-target tests must pass; actual systemd unit startup/stop and interrupted-start recovery remain host validation requirements. TUN activation remains disabled.


Regression tests in `src/tun/xray_launcher.rs` exercise bounded stdout capture, rejection of output above the configured byte ceiling, and timeout termination/reaping of the direct child. They do not emulate systemd manager job semantics or verify real unit cleanup.

### Maintainer-local validation update — launcher deadline fix (2026-11-23)

The maintainer reports that the latest local validation passed after the native-core authorization field-access correction:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

This validates the Rust code and regression tests, including bounded Xray/native-core launcher subprocess behavior. It does not validate systemd manager job cancellation, real helper installation/capabilities, or live TUN traffic.

### Mutation-helper and process-identity source audit (2026-11-23)

A follow-up review covered `src/tun/mutation_helper_launcher.rs` and `src/tun/process.rs`.

- Helper startup validates a private caller-owned runtime directory, serializes startup with a no-follow 0600 flock file, refuses to unlink an unresponsive socket, validates the root-owned helper executable, uses a bounded readiness deadline, and kills/reaps the directly spawned helper if readiness times out or child inspection fails.
- The helper probe checks socket type, owner, exact 0600 mode, special bits, link count, and performs a protocol Ping before reuse.
- Process monitoring pins a process instance with pidfd, validates start-time and canonical executable around procfs reads, bounds procfs reads, rejects divergent UID credentials, and uses pidfd signaling rather than numeric-PID signaling.
- No production change was justified by this pass. The remaining limitations are environmental: same-UID processes are not a security boundary, a successful Ping proves liveness only at probe time, and pidfd/procfs behavior must still be exercised on the target kernel.
- These source-level checks do not establish real VMess/VLESS connectivity or TUN dataplane correctness. The next acceptance stage must use the maintainer's locally stored VMess and VLESS nodes without copying credentials into logs, commits, or chat.

TUN remains gated pending the local host integration and real-node tests.

### Xray CLI readiness family enforcement (2026-11-23)

A service-to-orchestrator integration review found that the public Xray TUN command still called the single-target readiness API even though a dual-stack API already existed. The CLI now resolves the configured HTTP probe hostname before activation, selects one usable IPv4 and one usable IPv6 address, preserves the original Host header/path, and invokes the dual-stack orchestrator. Missing either family fails before kernel mutation. Loopback, link-local, unspecified, and multicast candidates are excluded. Regression tests cover family selection, missing-family rejection, and non-routable candidate filtering.

This is a fail-closed integration correction. Formatting, Clippy, and all-target tests must be rerun locally before any real-node activation attempt. The default connectivity-check hostname must resolve to both address families on the test host. This does not prove DNS traffic itself is tunneled; it proves the numeric IPv4/IPv6 HTTP datapaths after pre-activation resolution.

### Real VMess/VLESS host validation — pending

After the Rust checks pass, the maintainer should select one known-good VMess node and one known-good VLESS node already stored in the local database, verify Xray compatibility, and test each separately through `proxyctl use <ID> --core xray --tun`. Stop and verify cleanup after each node. The test must record only node type, command exit status, HTTP status, and cleanup result; never include node URLs, UUIDs, passwords, flow values, generated configs, or unmasked logs in the repository or chat. The explicit Xray TUN path is experimental; sing-box and Mihomo remain disabled. Do not interpret a successful activation as DNS-through-proxy validation or production approval.


### Maintainer-local validation update — dual-stack CLI wiring (2026-11-23)

The maintainer reports that formatting, Clippy, and the complete all-targets/all-features Rust test suite passed after the Xray CLI readiness service was switched to the dual-stack orchestrator and the native-core activation arm was corrected to pass both family targets. The formatted changes were pushed to `main`. This validates compilation and automated tests for the current source state; it does not validate the installed helper bundle, systemd service behavior, or live VMess/VLESS traffic.

The next acceptance step is host preparation followed by one local VMess Xray TUN test and, only after verified stop/cleanup, one VLESS test. Credentials and generated configurations must remain local and must not appear in logs shared to chat or committed. Xray TUN remains experimental; sing-box/Mihomo remain disabled.
