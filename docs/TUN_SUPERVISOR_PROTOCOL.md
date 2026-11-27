# TUN supervisor acknowledgement and session commit protocol

This document records the supervisor protocol and its implementation history. Current native persistent-device startup supports sing-box, Mihomo, and Xray through `proxyctl use --tun` and `proxyctl tun start`; `proxyctl tun stop` performs privileged, journal-verified cleanup. All three cores attach by interface name to the supervisor-created persistent TUN device; the former Xray descriptor handoff is obsolete. Automatic reboot-time recovery remains out of scope. Historical sections below are retained as design history where they describe superseded intermediate states.

## One-way acknowledgement channel

The unprivileged front end sends the bounded versioned launch request to:

```text
sudo -- <current-proxyctl-executable> __tun-supervisor
```

The request remains on stdin so sudo's password prompt stays terminal-driven. Launch protocol version 6 includes the activation UUID, generation, foreground preference, resolved selected-node peer candidates, the exact resolved application TUN family, and one bounded numeric HTTP readiness target per selected family. The supervisor validates the request again and reuses the exact UUID/generation for the manifest, transaction journal, and session receipt; it does not generate replacement identities. The supervisor's stdout is reserved for one bounded JSON acknowledgement; diagnostics remain on stderr. The pipe is a per-invocation kernel object inherited across sudo, not a pathname that an unprivileged process must access below the root-owned mode-0700 runtime directory.

The reply schema is versioned and strict:

- `failed`: request rejected or startup failed; includes bounded diagnostic text;
- `not_started`: request validation completed, but no core/session was started;
- `started`: carries the validated root-owned `SessionRecord` containing the invoking UID, nonce, activation ID, generation, core kind and exact process identity.

Unknown fields, unsupported versions, empty/trailing data and replies beyond 16 KiB are rejected. The front end must accept success only for `started`, and only after validating the embedded session record. A zero sudo exit status or successful process creation is not a startup acknowledgement.

The supervisor emits `started` only after it has applied the journaled native-device transaction, launched the selected core, verified exact TUN attachment, passed end-to-end readiness for every selected application address family, and durably committed the session receipt plus Running manifest. It closes stdout after the one-shot reply and remains alive as the session monitor. The front-end waits up to 60 seconds for this acknowledgement and accepts it only while the supervisor is still alive. Foreground requests remain attached until the supervisor completes cleanup.

## Durable commit ordering

The root-owned lifecycle manifest and root-owned session receipt live in the same verified `/run/proxyctl/<uid>` directory. The privileged supervisor must not read the user's redb database or any user-owned manifest.

The Linux lifecycle coordinator now exposes `bind_core_session`, which enforces this order while holding the cross-process lifecycle lock:

1. Validate the session record and require its activation ID/generation to match the prepared activation token.
2. Require the session receipt and lifecycle manifest to share the same runtime directory.
3. Open a pidfd for the recorded process, verify the process identity remains live, and verify all process UID credentials match the privileged supervisor's effective UID (root in production); the receipt separately binds the invoking UID.
4. Persist the root-owned session receipt with no-clobber semantics (schema version 2 records the resolved TUN family; schema version 1 receipts remain readable for recovery).
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

A `started` reply is emitted only after all of the following are true:

- the selected core was spawned with the fixed argv and root-staged config;
- the supervisor captured and pidfd-pinned the exact child identity;
- the child credentials match the privileged supervisor's effective UID policy (root in production);
- the session receipt and matching `Running` manifest are durably committed;
- the core-specific readiness check succeeded;
- the supervisor has established a terminal-independent monitoring lifecycle and stop/recovery ownership.

The foreground path uses this same sequence and redirects core stdout to supervisor stderr so the protocol pipe remains unambiguous. Background mode returns only after the supervisor sends the `started` reply, closes the acknowledgement pipe, and remains alive as the session owner. The supervisor monitors the child, retains the staged config for its lifetime, and invokes generation-scoped journal recovery when the core exits. Explicit stop is supported; automatic reboot recovery remains out of scope.

## Direct core-launch primitive (wired for native persistent devices)

A new Linux-only direct launcher now provides the process-creation primitive for the single-executable supervisor. It launches the selected managed binary directly from the privileged Proxyctl process; it does not invoke systemd, install or execute a helper, construct a shell command, or accept arbitrary argv/environment data.

The launcher re-resolves the executable from the closed `CoreKind` enum and invoking user's private managed-core tree immediately before spawn. It rechecks ownership, executable permissions and link count, requires the staged config to be a root-owned single-link 0600 regular file, and uses only fixed core-specific arguments:

- sing-box: `run -c <staged-config>`
- Xray: `run -c <staged-config>`; its native TUN inbound attaches to the named persistent interface;
- Mihomo: `-f <staged-config>`.

The child receives a cleared environment with a minimal fixed `PATH`, `HOME` and locale, no stdin, and no inherited stdout protocol stream. Background output is sent to `/dev/null`; foreground core stdout and stderr are directed to the supervisor's stderr, keeping the one-shot JSON acknowledgement on supervisor stdout unambiguous. No TUN descriptor is inherited: sing-box, Mihomo, and Xray attach to the generation-owned persistent named interface through their native configuration. The parent captures the exact executable/PID/start-time identity, pins it with pidfd, and verifies that all process UID credentials remain root. Any post-spawn verification failure kills and reaps that exact child.

The native supervisor installs its signal guard before staging or privileged network mutation. Signals received before a child is attached are latched; startup checks abort before kernel changes where possible, and a signal received during kernel setup causes generation-scoped recovery immediately after the transaction returns. The direct launcher verifies the executable again immediately before spawn, captures the exact process identity, attaches a duplicated pidfd to the already-installed guard, and installs a parent-death signal so the privileged core cannot outlive a crashed supervisor. If a signal was latched during the spawn/attachment boundary, the new child is terminated and startup does not enter readiness. After attachment, supervisor-only signals are forwarded through the pinned pidfd. The native supervisor then performs attachment/readiness checks, durable session commit, acknowledgement, monitoring, and recovery.

The signal handler uses only lock-free atomic state and pidfd_send_signal; it does not allocate, log, or acquire locks. The pidfd used by the handler is duplicated from the process identity handle. When the guard is dropped, the handler is detached and its duplicate is retained until supervisor process exit so an in-flight handler can never race descriptor closure or descriptor-number reuse. This is one small descriptor retained by the one-session supervisor process, not a persistent service resource.

## Current safety boundary

- `tun start` transitions the verified active loopback session to native TUN mode; `use --tun` starts a new native TUN session directly. Both support sing-box, Mihomo, and Xray.
- The supervisor creates the persistent TUN interface and policy routes/rules through the generation-bound write-ahead journal. It does not modify DNS or firewall state.
- The selected managed core runs as root only for the lifetime of the explicitly requested TUN session; ordinary loopback activation remains unprivileged.
- `tun stop` and unexpected core exit use the same pidfd-safe process termination and compare-before-delete journal recovery. No separate helper executable, systemd service, or file capability is installed for new sessions.

## Exact core termination and final record cleanup

The lifecycle coordinator now has a pidfd-based stop operation. Under the lifecycle lock it first persists `CleanupPending`, then opens the recorded process instance and verifies its credentials against the privileged supervisor. It sends SIGTERM through `pidfd_send_signal`, waits for the bounded grace period, and escalates to SIGKILL only for that same pinned process. If the recorded PID has exited or been reused, it never signals the replacement.

The stop operation intentionally leaves the session receipt, manifest and transaction journal in place. It does not remove routes, rules or interfaces. This preserves the evidence required by the separate kernel-resource recovery executor.

A separate finalization operation is available only after the caller has completed resource cleanup and durably marked every journal operation `Removed` or `Absent`. Each resource in the ownership manifest must have a matching journal operation marked `Removed` with the exact original fingerprint. It then writes the `Cleaned` phase with no process identity, removes the completed transaction journal, removes the exact session receipt, and finally removes the cleaned manifest.

This order is restartable: a crash after the `Cleaned` write can resume from the remaining journal/receipt; a crash after journal removal can resume using the durable `Cleaned` marker; a crash after receipt removal leaves a `Cleaned` manifest with no receipt, which can be safely removed. Missing journals are not accepted for a `CleanupPending` manifest with owned resources.

The coordinator now also exposes a generic `recover_session` orchestration method. It classifies the durable state, claims an orphaned Prepared activation, stops a matching recorded core, invokes the existing compare-before-delete journal recovery executor under the lifecycle lock, and then finalizes the session records. The executor can retain its completed journal so the coordinator writes `Cleaned` before removing the journal and receipt. Orphan receipts, inconsistent records, missing journals for resource-bearing manifests, and fingerprint mismatches remain fail-closed.

`tun stop` now invokes `sudo -- <current-proxyctl-executable> __tun-recover` without a shell or caller-supplied paths. The privileged entry point derives the invoking UID from sudo/login credentials, opens only `/run/proxyctl/<uid>`, and runs the coordinator against the root-owned manifest, journal and session receipt. When a journal exists it supplies the concrete Linux compare-before-delete backend; when no journal exists it supplies a backend that fails if called, allowing only resource-free finalization. An orphan session receipt is preserved and reported as an error. A transaction journal without a manifest is recoverable only when no session receipt exists: this is the crash window after write-ahead journal creation and before the initial Prepared manifest is committed. The privileged stop path opens the journal's exact activation/generation and runs the existing fresh-inventory, compare-before-delete executor; it never infers a process identity or trusts a user path. A resource-bearing manifest without its journal remains a fail-closed error. This explicit stop path may remove only resources proven to match the durable journal fingerprints. New native TUN startup is handled by the single-executable supervisor described below.


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

A successful call means only that the native TUN resources and `Prepared` manifest are durably recorded. The production `native_supervisor` calls this boundary, then passes the exact manifest/token into `native_session` for core attachment, end-to-end readiness, receipt commit, and Running transition. The supervisor authenticates the invoking UID and resolves its primary GID from the system account database before assigning TUN device ownership.


## Core-specific TUN attachment boundary

The journaled `supervisor_activation::apply_native_kernel_plan` API validates the selected `CoreKind` against the native-device adapter contract. Sing-box, Mihomo, and Xray all use the persistent named TUN device, so the interface, routes, and policy rules are created together through the native-device transaction.

Xray no longer uses the former `XRAY_TUN_FD` descriptor handoff. Its Linux TUN inbound opens the already-created persistent interface by name, configures the link and gateway addresses, and closes its queue when the core exits; Proxyctl retains persistence ownership and performs journaled cleanup. The three adapter configurations remain core-specific even though their device-ownership strategy is now shared.


## Native core startup and session commit boundary

A Linux-only `native_session` module provides the ordered step after journaled native-device preparation. It accepts sing-box, Mihomo, and Xray and validates that the launch request, activation token, and durable manifest all identify the same `Prepared` generation and persistent TUN interface.

The startup sequence is fixed:

1. Re-read the root-owned Prepared manifest and verify its exact activation token.
2. Spawn the selected managed core directly with fixed argv, the root-staged config, and no external descriptor.
3. Wait a bounded five seconds for the exact process to open the exact persistent TUN interface (name and ifindex).
4. Run a mandatory caller-supplied end-to-end readiness verifier. There is no no-op/default readiness callback.
5. Construct a kernel-nonce session receipt binding the invoking UID, activation, generation, core kind, and exact process identity.
6. Commit the receipt first, then atomically bind the same process identity to the manifest's Running phase.

If any post-spawn step fails, the direct child is killed and reaped where possible. The Prepared manifest, journal, and any receipt already committed are retained as recovery evidence; the supervisor immediately invokes the existing journaled recovery path and preserves evidence if recovery cannot prove safe cleanup. The production supervisor retains the staged config for the complete core lifetime.

The `native_session` primitive is now composed by `native_supervisor`, which owns the staged config and child for the full session, sends the `started` acknowledgement only after commit, monitors child exit, and performs generation-scoped recovery. A parent-death signal terminates the core if the supervisor crashes; explicit `tun stop` remains the recovery path for any kernel resources left by an abrupt supervisor death.


## Launch specification version 6: resolved address-family inputs

Version 6 binds the activation generation, foreground preference, resolved TUN application family, and matching readiness inputs to the unprivileged launch request. The request carries one to eight resolved selected-node peer endpoints, the node protocol's TCP or UDP peer transport, and exactly one numeric HTTP probe target for each selected application family. `auto` is resolved before privilege escalation from the usable address families returned for the configured readiness endpoint; explicit single-family and dual-stack selections fail closed if their required target is absent. The resolved value is carried unchanged into native core config generation, journaled application routes, readiness, and the root-owned session receipt. Core-socket bypass rules remain dual-family so the selected core can use either upstream address family independently of the application TUN family. Targets retain the original HTTP Host header and path, and each expected response status must be a successful 2xx code. The privileged supervisor validates all fields again before use.

The supervisor captures its own pre-activation host-network baseline after authenticating the invoking UID; it never accepts a caller-supplied DNS or firewall baseline. Supplied numeric destinations are bounded data, not executable paths or commands. The generation, activation UUID, generated core configuration, peer candidates, and traffic targets are validated together before any privileged network mutation.


## In-process socket-mark readiness

The native persistent-device readiness path collects `INET_DIAG_MARK` data directly through the bounded `NETLINK_SOCK_DIAG` transport inside the already privileged Proxyctl supervisor. It snapshots the exact core process's socket inodes before and after collection, then joins those stable inodes to kernel-origin socket records and classifies the expected peer/transport. This path does not execute `/usr/libexec/proxyctl-tun-helper`, create a diagnostic Unix socket, or require a separately installed helper package. Missing mark attributes, incomplete netlink dumps, process identity changes, and ambiguous socket ownership remain hard failures.


## Loopback restoration around TUN mode

When `proxyctl tun start` transitions an active loopback session, the unprivileged activation runtime records a private 0600 restoration marker containing only the prior node ID, core kind, and listener port before stopping the exact verified loopback process. If TUN preparation/start fails, the foreground TUN session ends, or `proxyctl tun stop` completes journal recovery, Proxyctl restores that prior loopback session through the ordinary unprivileged activation path. Restoration is idle-only under the activation lock; it refuses to replace a concurrently started session. Direct `proxyctl use --tun` starts do not create a previous-loopback restoration marker. Every TUN handoff also writes a private user-owned session hint before sudo starts; `proxyctl stop` consults that hint and requests root recovery only when a TUN handoff/session is pending, then discards any saved loopback restoration marker as a full stop. `proxyctl tun stop` instead restores the prior loopback session when one was saved. Ordinary loopback stop remains unprivileged. Pending markers are visible through `proxyctl status`, and another TUN start is refused until the previous transition is recovered/restored.


## Timeout and retry contract

The native supervisor uses bounded startup stages; the front end allows up to 60 seconds for the one-shot acknowledgement. Process-to-TUN attachment is bounded to five seconds. The native readiness path bounds the managed-listener probe to five seconds and the end-to-end HTTP traffic probe to ten seconds per selected address family; the probe's TCP connect portion is capped at five seconds. Each HTTP probe has one aggregate deadline covering connection, request transmission, and response-header receipt.

These bounds are not retries. The HTTP probe is attempted once for each required target. Any startup, attachment, or readiness failure aborts the current generation, stops the exact child, and requests generation-scoped recovery. No `started` acknowledgement is sent until all required checks pass and the Running manifest/session receipt are committed.

A subsequent user-initiated start is a fresh activation only after the previous generation's cleanup is confirmed. Never retry core startup or mutate routes again while the previous generation's ownership state is ambiguous. If cleanup is incomplete, retain its manifest/journal for explicit recovery rather than deleting files or sweeping routes.
