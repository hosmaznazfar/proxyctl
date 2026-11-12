# Linux TUN design

> Status: **activation disabled**. Only read-only network inspection is available.
> Scope: Linux kernel networking across Linux distributions; service-manager integration is abstracted.
> Goal: use one selected managed core's native TUN implementation, with exact Proxyctl-owned routing resources and crash recovery.

## Safety incident and current decision

A live sing-box TUN run was associated with loss of internet connectivity. Review found that the previous implementation compared post-stop network state with a baseline but did not restore Proxyctl-created routes or rules. A forced core termination or application crash could therefore leave routing state behind.

TUN activation remains rejected before process start, privilege escalation, or network mutation. `proxyctl tun status` remains read-only. Ordinary loopback activation, setup, updates, and benchmarks must not change interfaces, routes, policy rules, DNS, resolver configuration, or firewall state.

## Cross-distribution compatibility contract

Proxyctl targets Linux kernel networking interfaces, not a particular distribution or package layout. Do not branch on distribution names (Arch, Debian, Fedora, Alpine, NixOS, etc.) when equivalent kernel capabilities are available. Detect capabilities and the active init/service manager at runtime.

The implementation must separate these layers:

1. **Kernel/network backend:** TUN device lifecycle, rtnetlink route/rule operations, interface identity, and exact ownership metadata. It must not depend on systemd, NetworkManager, nftables, or a distribution-specific path.
2. **Privilege broker:** a narrowly scoped helper with only the privileges needed for TUN and routing operations. Detect supported authorization mechanisms (for example sudo, doas, or polkit where usable); never assume one executable or prompt mechanism. Do not run the whole CLI or proxy core as root.
3. **Recovery supervisor:** survives the CLI process and the core process long enough to detect core exit and perform idempotent cleanup. Its lifecycle integration is selected through an init/service-manager backend.
4. **Core adapter:** generates native TUN configuration with core-managed automatic route installation disabled. The adapter must not independently install default routes or mutate DNS/firewall state.
5. **Readiness verifier:** proves local listener readiness, TUN interface identity, physical egress selection, route policy, and end-to-end proxied traffic before declaring TUN active.

The service-manager layer must use capability detection, not distribution-name detection. The design must support systemd, OpenRC, runit, s6, dinit, and SysVinit through focused backends or a portable supervisor mechanism. The absence of systemd must not by itself disable TUN. A manager without a verified recovery backend must fail closed with a clear explanation; it must never silently use systemd commands or fall back to core-managed automatic routes.

Do not claim universal support merely because a distro is Linux. A distro/init combination is supported only after its backend passes the same offline lifecycle and fault-injection contract. Keep the support matrix explicit in documentation and diagnostics. Unsupported init managers remain safe (TUN refused; normal loopback mode unaffected).

## Non-negotiable isolation requirements

1. Proxyctl may create, inspect, and remove only network resources positively identified by its activation manifest.
2. Never flush routing tables, reset DNS, replace resolver configuration, or remove interfaces/rules belonging to another application.
3. Coexist with V2rayN, NetworkManager, Docker, and other VPN clients. Foreign TUN interfaces and unrelated route changes are not Proxyctl-owned.
4. Only one Proxyctl-managed core may be active. Other applications' cores are never discovered, reused, stopped, updated, or renamed.
5. Core crash, SIGKILL, CLI crash, supervisor crash, startup failure, normal stop, and reboot each have a defined recovery path.
6. If ownership cannot be proven, stop and preserve diagnostics rather than mutating ambiguous host state.
7. No automatic DNS, nftables, iptables, firewall redirect, or system proxy changes in the initial TUN implementation.
8. A stale policy rule must never blackhole normal traffic if its dedicated route table or TUN interface disappears. The routing design must prove this property in offline tests.

## Routing ownership model

Use a dedicated Proxyctl routing table and a narrowly allocated policy-rule priority range per activation. Do not use a baseline-diff as a deletion strategy and do not ask the selected core to install host routes automatically.

Before the first mutation, persist and fsync a private, versioned manifest containing:
- activation UUID/generation;
- selected node/core and verified core process identity;
- dedicated table ID and rule priority/selector;
- exact route and rule attributes created;
- TUN interface name plus kernel link identity (ifindex and, where available, alias/owner marker);
- original values only for resources Proxyctl explicitly replaces (prefer not to replace any);
- recovery backend identity and supervisor process/service identity;
- manifest schema version and lifecycle phase.

Reserve identifiers without assuming a distribution-specific default routing layout. Detect collisions before mutation. Use rtnetlink or a carefully constrained iproute2 backend; never parse human-formatted output for destructive decisions. Add route protocol/ownership metadata where supported and verify every attribute before deletion.

The core's TUN interface should be created without automatic route/rule installation. Proxyctl owns route and policy-rule setup. Core-originated traffic must bypass the TUN routing rule through a narrowly scoped, verified selector to prevent routing loops. A missing route in the dedicated table must fall through to the ordinary routing policy, not blackhole traffic.

On cleanup, delete only exact resources still matching the manifest. Treat already-absent resources as success. If a resource changed or is now owned by another actor, do not delete it; report a conflict and retain the manifest for explicit recovery. Cleanup must be idempotent after every partial step.

## Recovery and lifecycle

A serialized operation coordinator uses activation generations to prevent concurrent start/stop/switch races. The recovery supervisor is independent of the CLI and monitors the exact core process instance (PID plus start time/pidfd and canonical executable). Core exit triggers cleanup.

The recovery path must not depend solely on the CLI receiving SIGINT/SIGTERM. It must cover CLI SIGKILL, core SIGKILL, supervisor failure, and machine reboot. Kernel teardown of a non-persistent TUN device should be used as a safety net; routing rules must be designed so an orphaned rule with an empty table falls through safely. At next Proxyctl startup, reconcile only stale resources whose exact ownership markers match a valid Proxyctl manifest. Never sweep a priority range or table based only on a numeric range.

Init/service-manager backends are responsible for starting/stopping the supervisor and ensuring cleanup hooks run on service teardown. Backends must not own or restart foreign processes. Where a manager cannot guarantee the required supervisor lifecycle, use a separately verified portable supervisor; otherwise refuse TUN. Reboot naturally removes ephemeral kernel routes/interfaces, but persistent service artifacts and stale manifests still require exact reconciliation.

## Privilege and distribution rules

- Keep the CLI and core running as the invoking user.
- Use a small privileged helper or equivalent constrained mechanism; never grant broad root execution to the entire Proxyctl process.
- Restrict capabilities to the minimum required (normally CAP_NET_ADMIN for the network helper). Do not assume systemd ambient-capability properties exist.
- Do not require NetworkManager, systemd-resolved, nftables, iptables, or a specific DNS manager.
- Do not hardcode `/usr/bin`, `/usr/sbin`, or distribution package names. Resolve required utilities or use kernel APIs; validate the resolved executable and its behavior.
- Detect kernel support for TUN, policy routing, required netlink attributes, pidfd/process identity, and capability operations. Report missing prerequisites before changing anything.
- Support common init managers through separate tested backends. A distro is not declared supported until its init backend and privilege broker pass the lifecycle matrix.
- If authorization cannot be obtained non-interactively or safely through the selected broker, cancel before stopping the current activation or changing networking.

## Core configuration requirements

- sing-box, Xray, and Mihomo use native TUN inbounds, but core automatic route/rule installation is disabled.
- The core must not alter DNS or firewall state.
- The adapter must expose enough information for Proxyctl's route manager to create the correct routes and bypass rule. If a core cannot operate safely with externally managed routing, that core is unsupported in TUN mode.
- Keep one active core only; do not introduce tun2socks, a second packet engine, or a permanent always-on daemon.

## Process identity

Normal activation presents the process as `proxyctl-core` in argv[0] and Linux's short `comm` name where permitted. This is a display identity only. `/proc/PID/exe` remains the canonical upstream binary path and is authoritative for ownership checks. Never fake executable identity or signal processes based only on display names.

## Implemented offline groundwork (not an activation backend)

The recovery-foundation batch adds a versioned route manifest model, exact resource fingerprints, a backend contract requiring compare-and-delete semantics, and a fake-backend test suite. Cleanup preflights every manifest entry before deleting, preserves changed/foreign resources, treats already-absent entries as success, and can be retried after partial backend failure. These are policy primitives only: there is not yet a production rtnetlink/iproute2 mutator or durable privileged manifest writer.

The recovery layer now has a typed supervisor contract and deterministic service-manager backend selection for systemd, OpenRC, runit, s6, dinit, and SysVinit. It does not yet start services. Detection on a systemd host is not evidence that recovery is operational.

A private manifest store now persists a generation-scoped lifecycle snapshot beside the route ownership manifest. It creates a user-owned 0700 runtime directory, writes 0600 files through same-directory atomic replacement, fsyncs the file and directory, rejects symlink manifest paths, bounds input size, validates schema/generation/ownership metadata, and refuses to overwrite or remove a different activation. The store now exposes a filesystem-only lifecycle API: a new activation must start in Prepared, events are checked against the active generation, phase changes are persisted before the caller performs the requested action, cleanup conflicts retain the pending manifest, and successful cleanup is marked Cleaned before removal. If removal fails, the Cleaned record remains available for a later recovery pass. The caller must still serialize lifecycle operations. This API does not start a supervisor, grant privileges, monitor processes, or change kernel networking.

A pure dual-stack routing-policy planner now defines the required default unicast routes, mark-based core-traffic bypass rules, and unmarked proxy-traffic rules. It validates table allocation, rule ordering, mark/mask consistency, exact interface identity, duplicate/missing resources, and collisions against a synthetic kernel inventory. It rejects terminal/blackhole routes so an empty dedicated table can fall through to later routing-policy rules. The planner is offline only: it does not inspect the live kernel, set socket marks, reserve IDs, create routes/rules, or prove physical egress. The later core adapters must explicitly set the matching socket mark, and live route behavior still requires kernel-level integration tests.

A read-only kernel inventory module now queries iproute2 using fixed JSON-only route and rule commands for IPv4 and IPv6. It records occupied route/lookup tables and rule priorities, deduplicates the snapshot, and fails closed on malformed JSON, missing rule priorities, or unknown named tables. This is inventory groundwork only: it does not reserve identifiers or mutate the kernel. It currently requires the `ip` executable on PATH; no human-formatted output is parsed and no shell is invoked.

A generation-scoped lifecycle transition function now models the offline sequence from prepared to running, cleanup-pending, and cleaned. Core exit requests exact manifest cleanup; the manifest is removed only after cleanup reports success. A cleanup conflict keeps the manifest pending for later recovery. Stale or zero-generation events are ignored, and a cleaned generation is terminal. This is a pure state-machine contract with unit tests only: it is not yet wired to a process monitor or service manager.

All three native TUN adapter configs now disable core-managed automatic route installation. sing-box sets auto_route to false; Xray supplies an empty autoSystemRoutingTable; Mihomo sets auto-route to false. DNS redirection and firewall auto-redirect remain disabled. This is a configuration contract for future external route ownership, not a runnable TUN setup.

## Verification gates

### Gate 1 — offline automated tests

Use fake processes, fake service-manager/privilege-broker adapters, a fake rtnetlink backend, and synthetic kernel resource inventories. Tests must cover:

- Runtime detection of supported/unsupported init managers without distribution-name assumptions.
- Exact table/rule/interface ownership and refusal to touch foreign resources.
- Route-table collision and rule-priority collision detection.
- Core traffic bypass and empty-table fallthrough (no blackhole).
- Cleanup after normal stop, startup failure, core crash, SIGKILL, CLI crash, supervisor failure, and simulated reboot.
- Idempotent cleanup after every partial mutation/cleanup phase.
- Third-party route/rule/interface/DNS/firewall preservation.
- Concurrent start/stop/switch serialization and stale-generation rejection.
- No real TUN device, route, rule, DNS, or firewall mutation in tests.

### Gate 2 — native configuration validation

Validate generated TUN configs with installed managed core binaries. Do not start a TUN core or create host network resources. Verify all three cores leave host route/rule management to Proxyctl.

### Gate 3 — controlled live test

Only after Gates 1 and 2 pass for the detected init backend should a live test be considered. Use one selected node/core, a recorded read-only baseline, an independently available recovery path, and end-to-end traffic checks. Prove exact cleanup and that foreign resources remain unchanged. The user must explicitly authorize this stage.

Until all gates pass, TUN activation remains unavailable. The offline groundwork above does not satisfy Gate 1 or Gate 2 by itself.
