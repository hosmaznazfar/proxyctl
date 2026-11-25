# TUN supervisor acknowledgement and session commit protocol

This document defines the next boundary in the single-executable, sudo-only TUN migration. It does not enable TUN activation, launch a core, or mutate host networking.

## One-way acknowledgement channel

The unprivileged front end sends the bounded versioned launch request to:

```text
sudo -- <current-proxyctl-executable> __tun-supervisor
```

The request remains on stdin so sudo's password prompt stays terminal-driven. The supervisor's stdout is reserved for one bounded JSON acknowledgement; diagnostics remain on stderr. The pipe is a per-invocation kernel object inherited across sudo, not a pathname that an unprivileged process must access below the root-owned mode-0700 runtime directory.

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

The table is a recovery contract implemented by the lifecycle coordinator and journal recovery executor. The read-only classifier identifies the durable states; the recovery orchestrator pins and stops the exact recorded process, reconciles the matching resource journal through a typed backend, and finalizes records only after cleanup is durable. The orchestration is not yet connected to CLI commands or the hidden supervisor.

## Readiness and background lifecycle gates

A future `started` reply is permitted only after all of the following are true:

- the selected core was spawned with the fixed argv and root-staged config;
- the supervisor captured and pidfd-pinned the exact child identity;
- the child credentials match the privileged supervisor's effective UID policy (root in production);
- the session receipt and matching `Running` manifest are durably committed;
- the core-specific readiness check succeeded;
- the supervisor has established a terminal-independent monitoring lifecycle and stop/recovery ownership.

The foreground path must use this same sequence. Background mode must not return merely because sudo spawned; it returns only after the supervisor sends the `started` reply, closes the acknowledgement pipe, and remains alive as the session owner. The front end's 30-second acknowledgement timeout is implemented; supervisor detachment, ongoing child-exit monitoring, stop requests and reboot recovery remain separate gates.

## Current safety boundary

- TUN start/stop CLI remains fail-closed.
- No managed core is launched by the hidden supervisor.
- No TUN device, route, policy rule, DNS, firewall or forwarding state is created or changed.
- The acknowledgement protocol and coordinated durable commit method are not yet wired into a real launch.

## Exact core termination and final record cleanup

The lifecycle coordinator now has a pidfd-based stop operation. Under the lifecycle lock it first persists `CleanupPending`, then opens the recorded process instance and verifies its credentials against the privileged supervisor. It sends SIGTERM through `pidfd_send_signal`, waits for the bounded grace period, and escalates to SIGKILL only for that same pinned process. If the recorded PID has exited or been reused, it never signals the replacement.

The stop operation intentionally leaves the session receipt, manifest and transaction journal in place. It does not remove routes, rules or interfaces. This preserves the evidence required by the separate kernel-resource recovery executor.

A separate finalization operation is available only after the caller has completed resource cleanup and durably marked every journal operation `Removed` or `Absent`. Each resource in the ownership manifest must have a matching journal operation marked `Removed` with the exact original fingerprint. It then writes the `Cleaned` phase with no process identity, removes the completed transaction journal, removes the exact session receipt, and finally removes the cleaned manifest.

This order is restartable: a crash after the `Cleaned` write can resume from the remaining journal/receipt; a crash after journal removal can resume using the durable `Cleaned` marker; a crash after receipt removal leaves a `Cleaned` manifest with no receipt, which can be safely removed. Missing journals are not accepted for a `CleanupPending` manifest with owned resources.

The coordinator now also exposes a generic `recover_session` orchestration method. It classifies the durable state, claims an orphaned Prepared activation, stops a matching recorded core, invokes the existing compare-before-delete journal recovery executor under the lifecycle lock, and then finalizes the session records. The executor can retain its completed journal so the coordinator writes `Cleaned` before removing the journal and receipt. Orphan receipts, inconsistent records, missing journals for resource-bearing manifests, and fingerprint mismatches remain fail-closed.

This orchestration method is not connected to a CLI stop path or the hidden supervisor yet. It requires a caller-supplied privileged recovery backend and does not launch a core. Network cleanup can occur only if a future caller deliberately invokes it with the concrete Linux backend; no network cleanup has been run as part of this implementation.
