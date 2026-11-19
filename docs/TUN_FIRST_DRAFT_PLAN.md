# Proxyctl TUN — first-draft implementation plan

> **Execution priority:** integrate working feature code first. Defer broad tests, edge-case matrices, and fault-injection until the first functional draft is connected.
> **Safety floor:** exact ownership, bounded operations, rollback, and fail-closed behavior for ambiguous resources remain mandatory. Development must not mutate the user's host network.
> **Status:** activation remains gated. Phases 1–3 are not complete.

## Goal

Deliver an initial Linux TUN mode that launches a managed core, routes traffic through a Proxyctl-owned interface and policy, checks readiness, and supports stop/recovery.

## Working scope

- Work on real integration, not test-only APIs or evidence scaffolding.
- Update related documents with implementation batches.
- User runs tests/builds/fmt/clippy; assistant does not run them, scripts, TUN activation, or host network mutations.
- Broad edge-case hardening is deferred, but essential ownership and rollback requirements are not.
- Never claim activation usable until the pipeline is connected and reviewed.

## Phase 1 — TUN ownership and core handoff

- Broker/backend creates and retains the TUN descriptor; core must attach to that exact interface rather than independently creating a competing device.
- The Linux TUN device is assigned to the activation UID/GID so the managed core can attach as the unprivileged user.
- Config adapters already emit `tun-proxyctl` with routing/DNS auto-management disabled and a marked proxy outbound (Sing-box and Xray); Mihomo TUN generation currently fails closed.
- **Integration gap:** no launch orchestrator yet orders broker allocation, interface identity capture, core attachment and rollback as one generation. Interface-name configuration alone is not proof of descriptor/device handoff.
- **Exit criterion:** actual code establishes and verifies one device owner, core attachment, identity binding, and exact teardown.

## Phase 2 — First-draft managed-core launcher

- Connect core selection, managed binary path, generated TUN config, and launch path.
- Launch as the activation UID, not as a privileged core process; the broker owns privileged kernel mutations.
- Apply proxy-outbound mark/bypass behavior, capture exact process identity, and bind it to the activation generation.
- Launch failure must invoke exact-generation cleanup.
- Begin with adapters whose TUN mark behavior is explicitly represented; Mihomo remains unsupported until verified.
- **Current state:** an isolated systemd TUN launcher exists, and native TUN config generation exists, but the actual public activation flow is gated and these parts are not connected to the broker transaction.

## Phase 3 — Routing transaction and activation pipeline

- Connect journal-backed transaction, routing-policy planning, broker TUN creation, managed launcher, and lifecycle operations in one orchestrated start path.
- Apply exact owned routes and rules using the allocated interface identity and core-mark bypass.
- Commit activation state only after preparation and required launch/readiness steps; rollback on startup failure.
- Stop must use the same activation identity/generation.
- **Current state:** typed broker transactions and journal/recovery are implemented in isolation; activation does not invoke them as part of a real TUN start/stop path.
- **Exit criterion:** actual start/stop uses the connected transaction and lifecycle code.

## Phase 4 — First-draft readiness and traffic check

Compose existing readiness probes into start; add bounded application-level proxied response verification and rollback on failure.

## Phase 5 — Recovery supervisor and service integration

Connect broker and managed-process monitoring independently of CLI lifetime; implement a supported service-manager backend and cleanup-pending recovery.

## Phase 6 — First-draft operational lifecycle

Connect user-facing start/status/stop and core/node selection; replacement and failure cleanup must use activation tokens.

## Phase 7 — Post-draft testing and hardening

Deferred until first draft: broad integration tests, fault injection, crash/reboot matrix, PID reuse/race/conflict cases, expanded core compatibility, and additional diagnostics.

## Release gate

Public TUN activation stays disabled until Phases 1–6 are connected, essential ownership/safety checks exist, the supported environment is documented, and the integration is reviewed. Do not delay integration with test-only batches; do not bypass essential safety for speed.
