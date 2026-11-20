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


## Orchestrator validation and recovery draft batch

The unified activation façade now validates request-local invariants (activation ID/generation, Linux interface-name length, positive and distinct policy priorities, table ID, and mark/mask constraints) before invoking broker mutations. It rejects an existing manifest before a new activation and offers explicit-current-generation recovery. Added compact unit checks for request validation. This remains a draft: the public activation service is still gated, and native core TUN attachment to the broker-retained descriptor is not established. No host networking changes, build, or tests were run by the authoring workflow.


## Orchestrator monitoring and allocation validation (2026-11-20)

The unified façade now exposes a monitor entrypoint that loads the persisted Running snapshot, pins its recorded process identity, and delegates exit-triggered exact-generation cleanup. Activation requests now validate canonical UUID identity, interface-name character/length constraints, and allocation-floor constraints for routing tables and policy priorities, in addition to the mark constraints. This still does not launch the core, verify native TUN attachment, or perform dataplane readiness evidence; public activation remains gated.


## Work batches applied in continuation (2026-11-20)

This continuation added façade-level monitoring, stricter request and recovery identity/allocation validation, and focused request tests, and updated the README, architecture review, and TUN documents. These are incremental integration components, not completion of Phases 1–6. Next work is ordered to avoid unsafe network activation:

1. Establish a core-specific externally supplied TUN attachment contract for broker-owned descriptors (or replace the competing allocation design with a supported single-owner mechanism).
2. Implement a launcher that coordinates descriptor/device handoff, generated config, outbound mark, process identity capture, and generation-scoped cleanup.
3. Connect readiness to a listener owned by the core and an actual bounded proxied response/traffic check; reject ambiguous evidence.
4. Connect public start/status/stop to the unified orchestrator without exposing host network mutations before safety checks pass.
5. Implement and validate CLI-independent recovery supervision for supported service manager(s), then revisit the release gate.

No local build, tests, host network mutation, or TUN activation was performed in this continuation.


## Descriptor evidence contract implementation

A Linux-only attachment evidence contract now represents a passed-descriptor mechanism and validates its structural fields. A second validator binds the evidence to the activation request and ProcessIdentity (activation ID, generation, interface name, process start ticks and live process verification). The orchestrator has an evidence-gated convenience entrypoint. The evidence remains caller-supplied and does not prove the fd was actually transferred; the ordinary façade path remains present and activation remains disabled at the public service layer. This is a contract seam, not a completed core integration.


## Descriptor-transfer primitive checkpoint (2026-11-20)

Added a Linux SCM_RIGHTS transport primitive that sends and receives exactly one file descriptor over a connected Unix stream. The receiver requests close-on-exec atomically and rejects missing, truncated, or unexpected control messages. Focused tests cover descriptor transfer and rejection of a marker-only frame.

This is a transport primitive, not a completed native-core attachment. It does not authenticate the peer, coordinate a child launch, prove that sing-box/Xray/Mihomo consumes the descriptor, or produce kernel-backed attachment evidence. A successful sendmsg is not an attachment receipt. Do not populate AttachmentEvidence from send success; require a child-side acknowledgement tied to the pinned process and activation generation, plus a core-specific supported way to consume the received descriptor. Public TUN activation remains gated. No host network changes or local tests/builds were run.


## Generation-bound child handoff protocol (2026-11-20)

Added a bounded attachment offer/acknowledgement protocol for the future core-side adapter. Offers bind a canonical activation UUID, positive generation, interface name, protocol version, and 256-bit kernel-random nonce. The socket peer can be checked with SO_PEERCRED against a captured ProcessIdentity. The receiver helper emits a positive acknowledgement only after its supplied core-adoption callback succeeds; the sender must match every offer field before accepting that acknowledgement.

The protocol is not wired to a real sing-box/Xray/Mihomo descriptor consumer. The callback is an integration seam, not proof that a particular core supports FD adoption. SO_PEERCRED authenticates the connected peer identity but does not replace private socket-directory permissions or an executable allowlist. Public TUN activation remains gated.


## Composed handoff entry points (2026-11-20)

The attachment protocol now includes parent- and child-side composition helpers. The sender checks the connected peer against the exact expected child process, sends the generation/nonce offer, transfers the descriptor, and waits for a matching positive receipt. The receiver checks the expected parent process, validates the exact offer before receiving the descriptor, calls the core-adoption callback, and acknowledges only after callback success.

These helpers do not select or implement a native core FD API. They are ready for a verified adapter to call, but no core is currently wired to them. Same-user SO_PEERCRED checks do not replace private socket path ownership, executable allowlisting, or adapter-level validation.


## Bounded handoff I/O (2026-11-20)

The composed parent/child handoff helpers now set five-second read and write timeouts before peer verification and protocol exchange. A stalled or non-responsive adapter therefore cannot block the activation caller indefinitely. The timeout is a transport bound, not a readiness guarantee; the public activation path remains gated.


## Core attachment capability inventory (2026-11-20)

The adapter trait now exposes a typed TUN attachment mode separate from native config generation. Xray declares its documented Linux `XRAY_TUN_FD` environment-variable path for an externally supplied descriptor. sing-box is explicitly classified as native device creation in the current standalone adapter; Mihomo remains unsupported for Proxyctl's marked TUN activation contract. This is capability metadata only: no broker descriptor export, child-process FD inheritance, Xray environment wiring, or end-to-end readiness/acknowledgement integration has been completed. The public TUN activation gate remains in place.


## Broker descriptor export (2026-11-20)

Added a typed `attach_descriptor` broker request and client API. The persistent broker exports the retained descriptor only for a matching live activation ID/generation and sends it with SCM_RIGHTS after a positive bounded response frame. The receiver owns the transferred fd with close-on-exec set. This closes the missing broker-to-client descriptor-export leg, but does not yet wire an Xray child launcher, descriptor inheritance, native-core acknowledgement, or readiness. Public activation remains gated.


## Xray Linux descriptor inheritance (2026-11-20)

The Xray adapter now has a Linux-only `XrayTunDescriptor` helper that duplicates an exported TUN fd, keeps the parent's copy CLOEXEC, supplies `XRAY_TUN_FD`, and makes the fd inheritable only in the spawned child via a pre-exec `fcntl`. This follows Project X's documented Linux FD input. It is not yet called by the managed TUN orchestrator; no readiness or traffic proof is claimed.


## Xray broker-to-child launch primitive (2026-11-20)

Added `tun::xray_launcher::spawn_xray_from_broker`. It obtains the exact generation's live descriptor through the typed broker export, prepares the documented `XRAY_TUN_FD` inheritance, launches Xray with the existing `run -c` command shape, and returns a captured process identity. It fails closed if the descriptor is unavailable or process identity capture fails (killing/reaping the child). It is not yet composed with route transaction preparation, lifecycle manifest adoption, readiness, or detached recovery. Public activation remains disabled.


## Xray kernel-backed attachment check (2026-11-20)

Added `verify_xray_tun_attachment`: it checks the expected kernel TUN interface and ifindex, pins the exact Xray process, and requires an `iff:` record for that interface in one of the process's fdinfo entries, followed by a second process-identity/pidfd check. This can verify that Xray actually holds the broker-created TUN device, not merely that a same-named interface exists. It is not yet wired into activation orchestration or combined with the bounded proxied-traffic check.


## Xray readiness composition (2026-11-20)

Added `verify_xray_readiness`: verifies the process holds the exact TUN interface, refreshes listener/interface/routing-policy evidence, validates the bounded traffic observation against activation ID/generation/process identity, and delegates socket-mark plus complete evidence validation to the common readiness gate. Caller-supplied host DNS/firewall and physical-egress evidence remain required; no field is synthesized from a successful connection alone. This is a post-launch gate, not public activation wiring.


Added `wait_for_xray_tun_attachment`, a process-pinned, five-second-bounded startup wait that returns only after the expected interface appears in Xray's kernel fdinfo. Early child exit fails immediately. This confirms attachment only and does not replace the complete readiness gate.


Added `spawn_xray_with_verified_attachment`: composes broker fd export, Xray launch, and the bounded kernel fdinfo wait. It returns the child/process identity only after attachment is observed; on failure it kills and reaps that child. Exact-generation broker rollback remains the caller's responsibility, and no Running transition occurs in this helper.


## Prepared-to-Running lifecycle staging (2026-11-20)

Refactored managed activation into `prepare_managed_activation` and `commit_managed_process`. The first applies the generation-scoped broker transaction and adopts Prepared; the second binds the exact launched process and commits Running. This creates the correct ordering seam for Xray: broker creates/retains TUN, Xray adopts it, readiness is verified, then process binding/Running occurs. The legacy composition remains but new integration should use staged APIs. Failed adoption/binding triggers exact-generation broker recovery.


## Xray staged activation orchestration (2026-11-20)

Added `activate_xray_with_readiness` to the unified orchestrator. Ordering is now broker prepare/manifest adoption → Xray launch with exported descriptor → kernel fdinfo attachment wait → mandatory readiness callback → process binding → Running transition. Failure paths request exact-generation recovery; readiness failure kills/reaps the spawned child. The callback is required at the type level, so this API cannot silently skip readiness. Public CLI TUN activation remains gated pending independent recovery supervision and release review.


The Xray staged entrypoint now reads the kernel-assigned interface index from the exact broker-adopted Prepared manifest and validates its token, phase, interface name, and routing table. This removes a caller-supplied ifindex guess from the activation boundary.


Xray child rollback now signals the pinned process through its pidfd, waits at most two seconds for exit, and then reaps the child. Failure to terminate is surfaced instead of risking an unbounded wait. This path is used for attachment failure, readiness failure, and failure to commit Running.


The Xray broker launcher now checks both paths with `symlink_metadata`: executable and config must be regular non-symlink files; the executable must have an execute bit; config ownership must match the current user and permissions must be private. Both paths are canonicalized before process launch.


Restart/resume now also recovers a persisted Prepared generation. This is the interrupted-start boundary between broker commit and process binding: the exact generation is sent to the broker for journal-backed cleanup rather than being rejected or left indefinitely. Running and CleanupPending behavior remains unchanged.


## Standalone recovery supervisor process entrypoint (2026-11-20)

Added `proxyctl-tun-supervisor`, a separate executable that accepts only an absolute private runtime-directory argument, validates the manifest store, starts/connects to the persistent mutation broker, and resumes the persisted activation. It is independent of the main CLI process and can be run under an init/service manager. Actual service unit/backend installation and automatic startup integration for supported init systems remain outstanding; this binary alone does not satisfy the detached-supervision release gate.


Added a fail-closed rollback branch for missing/stale/mismatched broker Prepared manifests in Xray activation. The exact generation is sent to broker recovery before returning the manifest validation error.


## Systemd recovery integration continuation (2026-11-20)

The Linux systemd user-service adapter now implements the RecoverySupervisor start/status/stop contract and is selected explicitly; OpenRC, runit, s6, dinit, and SysVinit remain unsupported. The staged Xray activation path starts the service after committing the exact generation to Running. Failure to start it terminates/reaps Xray and requests generation-scoped broker cleanup.

This is a code-level integration only. The systemd service has not been exercised on a host, crash/reboot recovery has not been verified, and a narrow crash window remains between the Running manifest commit and the service-start request. The public CLI activation path remains gated. Sing-box and Mihomo attachment are unresolved; Xray's descriptor path and readiness callback are implemented but not runtime-verified.


## Early recovery-supervisor startup continuation (2026-11-20)

The systemd recovery service is now started immediately after broker preparation and before Xray launch. Its command is bound to the exact activation UUID and generation. The standalone supervisor waits a bounded 30 seconds for Prepared to transition to Running; if the CLI disappears and the generation remains Prepared, it requests exact-generation broker recovery. If the manifest is gone or a newer generation replaced it, the stale service exits without touching the replacement.

The systemd transient unit has additional sandbox properties. The service stop operation is bounded and only permitted after durable cleanup. This reduces the previous crash window between Running commit and service startup, but does not eliminate the smaller interval between broker preparation and service-start acceptance. The supervisor service still needs live host verification, and the readiness callback must remain bounded by its caller. Public activation remains gated.
