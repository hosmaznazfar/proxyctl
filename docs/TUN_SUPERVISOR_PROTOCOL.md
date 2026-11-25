# TUN supervisor acknowledgement and session commit protocol

This document defines the single-executable, sudo-only TUN migration boundary. The start path remains disabled and does not launch a core or create network state. The explicit `tun stop` path is connected to privileged, journal-verified cleanup and may remove only resources owned by its durable activation journal.

## One-way acknowledgement channel

The unprivileged front end sends the bounded versioned launch request to:

```text
sudo -- <current-proxyctl-executable> __tun-supervisor
```

The request remains on stdin so sudo's password prompt stays terminal-driven. Launch protocol version 5 includes the kernel-generated activation UUID used by the unprivileged preparation step to derive the core socket mark. The supervisor must use this exact UUID for the manifest, transaction journal, and session receipt; it must not generate a replacement UUID. The supervisor's stdout is reserved for one bounded JSON acknowledgement; diagnostics remain on stderr. The pipe is a per-invocation kernel object inherited across sudo, not a pathname that an unprivileged process must access below the root-owned mode-0700 runtime directory.

The reply schema is versioned and strict:

- `failed`: request rejected or startup failed; includes bounded diagnostic text;
- `not_started`: request validation completed, but no core/session was started;
- `started`: carries the validated root-owned `SessionRecord` containing the invoking UID, nonce, activation ID, generation, core kind and exact process identity.

Unknown fields, unsupported versions, empty/trailing data and replies beyond 16 KiB are rejected. The front end must accept success only for `started`, and only after validating the embedded session record. A zero sudo exit status or successful process creation is not a startup acknowledgement.

The current implementation deliberately emits `not_started` after request validation. The front-end transport parses the reply and rejects it as a non-start. It bounds the wait to 30 seconds, requires the supervisor to close stdout after the one-shot reply, and accepts a future `started` reply only while the supervisor process remains alive. The supervisor does not launch a core, daemonize, or keep a background lifecycle alive yet. The pipe framing and timeout are groundwork for the later startup handshake, not evidence that the handshake is operational end-to-end.

## Durable commit ordering

The root-owned lifecycle manifest and root-owned session receipt live in the same verified `/run/proxyctl/<uid>` directory. The privileged supervisor must not read the user's redb database or any user-owned manifest.

The Linux lifecycle coordinator now exposes `bind_core_session`, which enforces this order while holding the cross-process lifecycle lock:

1. Validate the session record and require its activation ID/generation to match the prepared activation token.
2. Require the session receipt and lifecycle manifest to share the same runtime directory.
3. Open a pidfd for the recorded process, verify the process identity remains live, and verify all process UID credentials match the privileged supervisor's effective UID (root in production); the receipt separately binds the invoking UID.
4. Persist the root-owned session receipt with no-clobber semantics.
5. Recheck the pinned process, then atomically transition the matching manifest from `Prepared` to `Running` with the identical process identity.

The session receipt is committed first. If the manifest write fails after that point, the receipt is intentionally retained; deleting it would destroy the only durable process-ownership evidence for that partial commit. Recovery must reconcile the receipt and manifest rather than treating either file as an independent instruction.

The coordinator also exposes a read-only reconciliation classifier for the manifest/receipt pair. It distinguishes idle, prepared-without-receipt, receipt-ahead-of-manifest, matching running, cleanup-pending, cleaned-awaiting-receipt-removal, orphan-receipt and inconsistent states. It takes the same lifecycle lock and performs no signaling, deletion or kernel operation. The process credential check is against the privileged supervisor's effective UID (root in production), not the invoking user's UID: the selected core intentionally runs elevated for the TUN session, while the receipt separately binds the non-root invoking UID.

## Crash-state reconciliation requirements

| Durable state | Required recovery interpretation |
|---|---|
| Prepared manifest, no session receipt | No committed core identity. Recover the journaled resources conservatively; do not guess a PID. |
| Prepared manifest plus session receipt | Partial commit. Verify the exact process identity and UID from the receipt, then stop/reconcile that exact process and recover the matching activation journal. |
| Running manifest plus matching session receipt | Normal committed session. Both records must agree on activation ID, generation, core kind and process identity. |
| Running manifest without a session receipt | Inconsistent state. Fail closed and preserve evidence; do not report a healthy session or silently discard the manifest. |
| Session receipt without a matching manifest | Orphan receipt. Preserve it for explicit reconciliation; do not infer which kernel resources may be removed. |
| Both records disagree | Treat as corruption or stale-generation conflict. Preserve both records and avoid signaling or deleting resources based on a partial match. |

The table is a recovery contract implemented by the lifecycle coordinator and journal recovery executor. The read-only classifier identifies the durable states; the recovery orchestrator pins and stops the exact recorded process, reconciles the matching resource journal through a typed backend, and finalizes records only after cleanup is durable. The orchestration is connected to the explicit `tun stop` recovery command through the hidden `__tun-recover` role.

## Readiness and background lifecycle gates

A future `started` reply is permitted only after all of the following are true:

- the selected core was spawned with the fixed argv and root-staged config;
- the supervisor captured and pidfd-pinned the exact child identity;
- the child credentials match the privileged supervisor's effective UID policy (root in production);
- the session receipt and matching `Running` manifest are durably committed;
- the core-specific readiness check succeeded;
- the supervisor has established a terminal-independent monitoring lifecycle and stop/recovery ownership.

The foreground path must use this same sequence. Background mode must not return merely because sudo spawned; it returns only after the supervisor sends the `started` reply, closes the acknowledgement pipe, and remains alive as the session owner. The front end's 30-second acknowledgement timeout is implemented; supervisor detachment, ongoing child-exit monitoring, stop requests and reboot recovery remain separate gates.

## Direct core-launch primitive (not yet wired)

A new Linux-only direct launcher now provides the process-creation primitive for the single-executable supervisor. It launches the selected managed binary directly from the privileged Proxyctl process; it does not invoke systemd, install or execute a helper, construct a shell command, or accept arbitrary argv/environment data.

The launcher re-resolves the executable from the closed `CoreKind` enum and invoking user's private managed-core tree immediately before spawn. It rechecks ownership, executable permissions and link count, requires the staged config to be a root-owned single-link 0600 regular file, and uses only fixed core-specific arguments:

- sing-box: `run -c <staged-config>`
- Xray: `run -c <staged-config>`, with the generation-bound descriptor supplied through `XRAY_TUN_FD`;
- Mihomo: `-f <staged-config>`.

The child receives a cleared environment with a minimal fixed `PATH`, `HOME` and locale, no stdin, and no inherited output streams. Xray's descriptor is duplicated CLOEXEC and made inheritable only in the forked child immediately before exec. The parent captures the exact executable/PID/start-time identity, pins it with pidfd, and verifies that all process UID credentials remain root. Any post-spawn verification failure kills and reaps that exact child.

This is deliberately only a launch primitive. It is not called by `__tun-supervisor` yet, does not create a kernel transaction, and does not make `tun start` available. The supervisor must still coordinate journaled interface/routing setup, core-specific readiness, durable session/manifest commit, acknowledgement, and ongoing child monitoring before startup can be enabled.

## Current safety boundary

- `tun stop` is connected to explicit privileged recovery; `tun start` and `use --tun` remain fail-closed.
- No managed core is launched by the hidden start supervisor.
- No TUN device, route, policy rule, DNS, firewall or forwarding state is created during startup; explicit stop may remove only journal-owned resources after fresh fingerprint comparison.
- The start acknowledgement protocol and coordinated durable commit method are not yet wired into a real launch.

## Exact core termination and final record cleanup

The lifecycle coordinator now has a pidfd-based stop operation. Under the lifecycle lock it first persists `CleanupPending`, then opens the recorded process instance and verifies its credentials against the privileged supervisor. It sends SIGTERM through `pidfd_send_signal`, waits for the bounded grace period, and escalates to SIGKILL only for that same pinned process. If the recorded PID has exited or been reused, it never signals the replacement.

The stop operation intentionally leaves the session receipt, manifest and transaction journal in place. It does not remove routes, rules or interfaces. This preserves the evidence required by the separate kernel-resource recovery executor.

A separate finalization operation is available only after the caller has completed resource cleanup and durably marked every journal operation `Removed` or `Absent`. Each resource in the ownership manifest must have a matching journal operation marked `Removed` with the exact original fingerprint. It then writes the `Cleaned` phase with no process identity, removes the completed transaction journal, removes the exact session receipt, and finally removes the cleaned manifest.

This order is restartable: a crash after the `Cleaned` write can resume from the remaining journal/receipt; a crash after journal removal can resume using the durable `Cleaned` marker; a crash after receipt removal leaves a `Cleaned` manifest with no receipt, which can be safely removed. Missing journals are not accepted for a `CleanupPending` manifest with owned resources.

The coordinator now also exposes a generic `recover_session` orchestration method. It classifies the durable state, claims an orphaned Prepared activation, stops a matching recorded core, invokes the existing compare-before-delete journal recovery executor under the lifecycle lock, and then finalizes the session records. The executor can retain its completed journal so the coordinator writes `Cleaned` before removing the journal and receipt. Orphan receipts, inconsistent records, missing journals for resource-bearing manifests, and fingerprint mismatches remain fail-closed.

`tun stop` now invokes `sudo -- <current-proxyctl-executable> __tun-recover` without a shell or caller-supplied paths. The privileged entry point derives the invoking UID from sudo/login credentials, opens only `/run/proxyctl/<uid>`, and runs the coordinator against the root-owned manifest, journal and session receipt. When a journal exists it supplies the concrete Linux compare-before-delete backend; when no journal exists it supplies a backend that fails if called, allowing only resource-free finalization. An orphan session receipt is preserved and reported as an error. A transaction journal without a manifest is recoverable only when no session receipt exists: this is the crash window after write-ahead journal creation and before the initial Prepared manifest is committed. The privileged stop path opens the journal's exact activation/generation and runs the existing fresh-inventory, compare-before-delete executor; it never infers a process identity or trusts a user path. A resource-bearing manifest without its journal remains a fail-closed error. This explicit stop path may remove only resources proven to match the durable journal fingerprints. It does not launch a core or start TUN; `tun start` and `use --tun` remain disabled.


## Read-only kernel transaction preflight

The single-executable migration now has a pure Linux activation-plan builder. It consumes one consistent read-only kernel snapshot, rejects an already-present `tun-proxyctl` interface, allocates a private routing table and consecutive dual-stack policy priorities, and derives the core outbound socket mark from the launch request's activation UUID. It returns the typed `KernelTransaction` with the invoking user's UID/GID.

This is preflight only, not a reservation and not a host mutation. The privileged journal backend must still re-check conflicts while applying each operation, persist write-ahead intents, and retain recovery evidence on ambiguity. The interface index in the plan is explicitly a placeholder; the transaction executor replaces it with the actual kernel-assigned index before installing routes.


## Journaled native kernel activation boundary

A Linux-only `supervisor_activation` boundary now composes the read-only activation planner with the existing `LinuxJournalBackend` and `KernelTransaction` executor. Its operation order is:

1. Require a non-zero generation and non-root interface owner, and verify that the journal store and lifecycle coordinator refer to the same runtime directory.
2. Refuse to proceed while a current activation manifest exists.
3. Capture a fresh read-only kernel snapshot and build the dual-stack native-device transaction.
4. Create the generation-bound write-ahead journal before any kernel mutation.
5. Apply the persistent named TUN interface, routes and policy rules through the typed journal backend. The executor binds the actual kernel-assigned ifindex and either completes rollback or preserves the journal on ambiguous/incomplete cleanup.
6. Adopt the exact committed `Prepared` manifest into the lifecycle coordinator.

A successful call means only that the native TUN resources and `Prepared` manifest are durably recorded. It does not launch a core, prove readiness, create a session receipt, bind `Running`, or send a `started` acknowledgement. The hidden supervisor does not call this boundary yet, and `tun start` remains fail-closed. The caller is responsible for authenticating the invoking UID and selecting the intended non-root UID/GID for the TUN device.


## Core-specific TUN attachment boundary

The journaled `supervisor_activation::apply_native_kernel_plan` API now requires an explicit `CoreKind` and accepts only sing-box and Mihomo. These two adapters use a persistent named TUN device, so their interface, routes and policy rules are created together through the native-device transaction.

Xray is rejected before the journal backend is opened. Its current adapter contract is `XRAY_TUN_FD` and its launcher requires a generation-bound broker descriptor; it must use the descriptor-backed transaction/attachment path rather than accidentally combining an externally supplied descriptor with a separately created persistent named device. The three core strategies must not be treated as interchangeable.

This guard is a migration safety boundary, not an Xray implementation. The hidden single-executable supervisor still does not launch any core, and `tun start` remains disabled.


## Native core startup and session commit boundary

A Linux-only `native_session` module now provides the next ordered step after journaled native-device preparation. It accepts only sing-box and Mihomo and validates that the launch request, activation token, and durable manifest all identify the same `Prepared` generation and persistent `tun-proxyctl` interface.

The startup sequence is fixed:

1. Re-read the root-owned Prepared manifest and verify its exact activation token.
2. Spawn the selected managed core directly with fixed argv, the root-staged config, and no external descriptor.
3. Wait a bounded five seconds for the exact process to open the exact persistent TUN interface (name and ifindex).
4. Run a mandatory caller-supplied end-to-end readiness verifier. There is no no-op/default readiness callback.
5. Construct a kernel-nonce session receipt binding the invoking UID, activation, generation, core kind, and exact process identity.
6. Commit the receipt first, then atomically bind the same process identity to the manifest's Running phase.

If any post-spawn step fails, the direct child is killed and reaped where possible. The Prepared manifest, journal, and any receipt already committed are retained as recovery evidence; this path never attempts ad-hoc kernel cleanup. The caller must invoke the existing explicit recovery path. The caller must also retain the staged config for the complete core lifetime.

This is a startup/commit primitive, not yet the production supervisor loop. It does not send the `started` acknowledgement, own the staged config beyond the caller's scope, monitor the child after commit, handle supervisor signals, or enable `tun start`. Those remain mandatory integration gates.


## Launch specification version 5: readiness inputs

Version 5 binds the activation generation and full dual-stack readiness inputs to the unprivileged launch request. The request carries one to eight resolved selected-node peer endpoints and exactly one numeric IPv4 plus one numeric IPv6 HTTP probe target. Targets retain the original HTTP Host header and path, and each expected response status must be a successful 2xx code. The privileged supervisor validates all fields again before use.

The supervisor captures its own pre-activation host-network baseline after authenticating the invoking UID; it never accepts a caller-supplied DNS or firewall baseline. Supplied numeric destinations are bounded data, not executable paths or commands. The generation, activation UUID, generated core configuration, peer candidates, and traffic targets are validated together before any privileged network mutation.
