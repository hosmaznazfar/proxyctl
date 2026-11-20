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
## Integration checkpoint (2026-11-20)

The typed mutation helper and broker client are implemented, including persistent backend ownership, peer credential checks, typed activation/recovery requests, and generation-bound journal recovery. The lifecycle coordinator can adopt a broker-committed Prepared manifest, bind a pinned process identity, and commit Running; managed supervision can monitor and request exact-generation recovery. These APIs still are not invoked from the public activation entry point.

**Additional hard blocker confirmed by source inspection:** both native TUN config adapters currently emit a native TUN inbound naming `tun-proxyctl`. The broker separately creates and retains an exclusive TUN descriptor. No verified adapter contract or handoff currently proves that either core attaches to that broker-owned device instead of attempting to create its own. Interface name, process identity, and interface presence alone do not prove attachment or traffic flow. The isolated systemd launcher is also a competing launch path, not the broker lifecycle orchestrator.

Accordingly, work must prioritize a single launch contract and device attachment proof, then connect generation-scoped broker activation, process binding, readiness/traffic evidence, stop/recovery, and a supervisor independent of the CLI. No public activation or automatic network mutation is enabled in this checkpoint. No tests/builds were run here; the user runs local verification.


## Draft orchestrator checkpoint (2026-11-20)

A draft unified orchestrator façade is now present in `src/tun/activation_orchestrator.rs` and exported from `src/tun/mod.rs`. It composes the existing broker activation, lifecycle adoption/process binding, generation-specific recovery, and supervision-resume APIs. The façade accepts an already-launched process identity and does not itself launch or configure the core.

Routing policy transaction integration is composed through the existing `MutationHelper::activate` request, whose broker path creates the interface, binds routes to the kernel-assigned ifindex, installs route/rule policy, and commits its ownership manifest. The façade provides recover/resume entry points for generation-bound cleanup and supervision.

This remains a draft integration layer, not a complete end-to-end activation pipeline: core launch/configuration ordering and native TUN attachment behavior are not reconciled here, nor are traffic-flow readiness checks connected. No tests or local builds were run.


## Integration continuation checkpoint (2026-11-20)

Repository access was re-established and the current main branch was inspected. The draft `ActivationOrchestrator` composes the typed broker transaction, Prepared-manifest adoption, core-process identity binding, Running transition, exact-generation recovery, and supervision-resume entry points. Its routing activation delegates to the mutation broker, which retains the TUN descriptor and applies the journal-backed route/rule transaction against kernel-assigned interface identity.

The orchestrator is not yet wired into `services::activation::activate`; that public path still rejects TUN mode before config generation. The device handoff is still a blocking integration issue: adapter-native TUN config requests a named interface while the broker separately creates an exclusive TUN attachment. There is no established descriptor transfer or attachment proof between those implementations. Simply enabling the public path or calling the orchestrator after launching the core would risk duplicate/conflicting interfaces and incorrect activation ordering. Therefore the next concrete integration must define and implement one attachment contract (or use a core-supported externally supplied TUN descriptor), then connect launch/stop/readiness around it. No local tests/builds or host networking actions were run.
