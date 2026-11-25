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

The current implementation deliberately emits `not_started` after request validation. The front-end transport parses the reply and rejects it as a non-start. The supervisor does not launch a core, daemonize, or keep a background lifecycle alive yet. The pipe framing is groundwork for the later startup handshake, not evidence that the handshake is operational end-to-end.

## Durable commit ordering

The root-owned lifecycle manifest and root-owned session receipt live in the same verified `/run/proxyctl/<uid>` directory. The privileged supervisor must not read the user's redb database or any user-owned manifest.

The Linux lifecycle coordinator now exposes `bind_core_session`, which enforces this order while holding the cross-process lifecycle lock:

1. Validate the session record and require its activation ID/generation to match the prepared activation token.
2. Require the session receipt and lifecycle manifest to share the same runtime directory.
3. Open a pidfd for the recorded process, verify the process identity remains live, and verify all process UID credentials match the invoking UID.
4. Persist the root-owned session receipt with no-clobber semantics.
5. Recheck the pinned process, then atomically transition the matching manifest from `Prepared` to `Running` with the identical process identity.

The session receipt is committed first. If the manifest write fails after that point, the receipt is intentionally retained; deleting it would destroy the only durable process-ownership evidence for that partial commit. Recovery must reconcile the receipt and manifest rather than treating either file as an independent instruction.

## Crash-state reconciliation requirements

| Durable state | Required recovery interpretation |
|---|---|
| Prepared manifest, no session receipt | No committed core identity. Recover the journaled resources conservatively; do not guess a PID. |
| Prepared manifest plus session receipt | Partial commit. Verify the exact process identity and UID from the receipt, then stop/reconcile that exact process and recover the matching activation journal. |
| Running manifest plus matching session receipt | Normal committed session. Both records must agree on activation ID, generation, core kind and process identity. |
| Running manifest without a session receipt | Inconsistent state. Fail closed and preserve evidence; do not report a healthy session or silently discard the manifest. |
| Session receipt without a matching manifest | Orphan receipt. Preserve it for explicit reconciliation; do not infer which kernel resources may be removed. |
| Both records disagree | Treat as corruption or stale-generation conflict. Preserve both records and avoid signaling or deleting resources based on a partial match. |

The table is a recovery contract, not an implemented recovery engine. The existing recovery/journal code still needs an explicit root-owned reconciliation path that checks both records, handles process exit and PID reuse, and removes the receipt only after exact process cleanup and the matching resource journal are durably complete.

## Readiness and background lifecycle gates

A future `started` reply is permitted only after all of the following are true:

- the selected core was spawned with the fixed argv and root-staged config;
- the supervisor captured and pidfd-pinned the exact child identity;
- the child credentials match the invoking UID policy;
- the session receipt and matching `Running` manifest are durably committed;
- the core-specific readiness check succeeded;
- the supervisor has established a terminal-independent monitoring lifecycle and stop/recovery ownership.

The foreground path must use this same sequence. Background mode must not return merely because sudo spawned; it returns only after the supervisor sends the `started` reply. Supervisor detachment, bounded startup timeout, child-exit monitoring, stop requests and reboot recovery remain separate gates.

## Current safety boundary

- TUN start/stop CLI remains fail-closed.
- No managed core is launched by the hidden supervisor.
- No TUN device, route, policy rule, DNS, firewall or forwarding state is created or changed.
- The acknowledgement protocol and coordinated durable commit method are not yet wired into a real launch.
