# Proxyctl TUN — first-draft implementation plan

> **Execution priority:** implement working feature code first. Do not spend batches on test-only scaffolding, exhaustive edge cases, or a broad fault-injection matrix until the first functional TUN draft is connected.
> **Safety floor:** basic ownership, bounded operations, exact cleanup identity, and fail-closed behavior around ambiguous resource ownership are still required. This is not permission to run TUN or mutate the user's host during development.
> **Status:** TUN activation remains disabled until the first-draft pipeline is implemented and reviewed.

## Goal

Deliver an initial Linux TUN mode for Proxyctl that can select and launch a supported managed core, establish a Proxyctl-owned TUN and routing policy, verify readiness, keep supervision/recovery, and stop/rollback through the owned lifecycle.

## Working scope

- Prioritize real code and end-to-end integration in small batches.
- Update related documentation as implementation changes.
- User runs builds/tests locally; assistant does not run builds, tests, fmt, clippy, scripts, network changes, or TUN activation.
- Do not treat standalone APIs or synthetic evidence as completed integration.
- Defer broad edge-case hardening and comprehensive tests to the post-first-draft phase.
- Do not claim activation is usable until the activation pipeline is connected and reviewed.

## Phase 1 — TUN ownership and core handoff

- Settle one device creation/ownership mechanism; avoid simultaneous interface creation by the backend and core.
- Make the core use the device created and retained by the broker/backend (or implement one alternative end-to-end handoff, with one clear owner).
- Pass interface name and required device parameters into supported core configuration.
- Connect device identity to the activation manifest and route policy.
- Keep routes/DNS/firewall behavior outside the core unless explicitly supported and owned.
- **Exit criterion:** device creation, core handoff, identity binding, and teardown are connected in actual feature code.

## Phase 2 — First-draft managed-core launcher

- Connect core selection and binary/config handling to an actual managed launch path.
- Generate native TUN config for the selected core using the owned device and routing policy; disable core auto-routing/auto-DNS behavior that conflicts with Proxyctl ownership.
- Configure required core outbound socket mark/bypass behavior.
- Capture exact process identity and bind it to the activation generation.
- Connect startup failure to exact-generation rollback.
- Start with the supported core(s) actually implementable; expand compatibility later.
- **Exit criterion:** the selected supported core launches through Proxyctl and its process identity/config are bound to the prepared activation.

## Phase 3 — Routing transaction and activation pipeline

- Connect existing journal-backed kernel transaction, routing-policy planning, TUN creation, and managed launcher in one orchestration path.
- Use exact owned table/rule/interface identities and the core-mark bypass.
- Apply and commit the route transaction before reporting the activation as prepared/running, with rollback on launch failure.
- Wire stop/cleanup to the same activation generation.
- **Exit criterion:** first-draft start and stop paths use the real connected transaction/lifecycle code, not isolated APIs.

## Phase 4 — First-draft readiness and traffic check

- Compose existing readiness probes into the actual start flow.
- Add bounded application-level proxied response verification.
- Fail startup and recover if required readiness evidence is not achieved.
- **Exit criterion:** the activation path gates its active state on concrete readiness evidence.

## Phase 5 — Recovery supervisor and initial service integration

- Connect persistent broker and managed process monitoring to a supervisor that can run independently of the CLI.
- Implement at least one supported service-manager backend or a verified portable mechanism.
- Handle core exit and cleanup-pending activation recovery.
- **Exit criterion:** core exit cleanup is independently supervised on the initially supported environment.

## Phase 6 — First-draft operational lifecycle

- Connect user-facing TUN start/status/stop and core/node selection.
- Make stop, replacement/switch and failure rollback use the activation token.
- Document supported environment and install requirements.
- **Exit criterion:** an initial end-to-end user workflow is connected.

## Phase 7 — Post-draft tests and hardening

Deferred until the first functional draft is connected:
- broad unit and integration tests;
- fault injection at every journal mutation and lifecycle transition;
- supervisor/CLI crash and reboot matrix;
- PID reuse, races, foreign-resource and conflict cases;
- multiple init-manager support;
- expanded core compatibility;
- additional diagnostics and safety review.

## Release gate

Public TUN activation stays disabled until Phases 1–6 have real code connected, essential safety/ownership checks are in place, the initial supported environment is explicit, and the first-draft integration is reviewed. Phase 7 expands confidence after that draft; it must not be used to indefinitely delay the feature by adding test-only batches before integration.
