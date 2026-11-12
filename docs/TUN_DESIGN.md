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

## Reference implementation review

The Linux TUN flows in v2rayN and Throne were reviewed as behavioral references, not copied as lifecycle designs.

### v2rayN

- The current `CoreManager` keeps the desktop process unprivileged and delegates Linux TUN core launches to `CoreAdminManager`; the main core and optional pre-service are separately tracked and stopped during normal shutdown. `CoreAdminManager` writes a temporary Bash script that invokes `sudo -S`, passes the password over the script's stdin, stores the returned wrapper `ProcessService` PID, and later invokes a separate sudo kill script. This is a useful example of keeping the UI unprivileged, but Proxyctl must not copy shell-interpolated launch scripts, password piping, or wrapper-PID-based ownership; its broker must accept structured validated requests and bind cleanup to the exact core process identity.
- The current startup path waits for the main proxy listener with a SOCKS5 greeting before starting the pre-service. This is a useful protocol-level readiness check, stronger than checking only whether a TCP port accepts connections. However, the timeout path logs and returns from the wait rather than aborting startup, after which the pre-service start is still attempted. Proxyctl must fail closed on readiness timeout and must not continue into route activation.
- A Linux TUN issue also documents the consequences of starting a pre-service before its upstream local SOCKS listener is ready. Another recent issue records a change between sing-box TUN and Xray TUN paths and a core asset-path/environment regression. These reinforce that readiness and per-core launch environments need explicit tests.
- The reference's privileged-process kill helper is not a substitute for a durable independent recovery supervisor: Proxyctl must retain exact process identity and recover after CLI termination, core SIGKILL, and reboot.

### Throne

- Throne explicitly keeps its GUI unprivileged and elevates only `ThroneCore` for Linux TUN, normally through `pkexec`/polkit and a SUID-root core. Its documentation also describes a five-capability alternative. This is simpler to integrate but grants a broad privilege set to the core binary; Proxyctl will keep the approved narrower broker model and will not adopt SUID or the five-capability bundle.
- Throne's Linux TUN settings include automatic route redirection through nftables (enabled by default in its documented settings), plus private-range bypass and optional IPv6. Its troubleshooting guide calls out systemd-resolved DNS-over-TLS interactions and conflicts with Docker, virtual machines, hotspots, and other VPNs. This validates Proxyctl's decision to keep firewall redirection and system DNS mutation disabled in the first implementation, especially on hosts with Docker bridges.
- Throne's documentation warns that force-closing while system proxy is enabled leaves the system proxy pointing at a stopped local proxy. This is a system-proxy failure rather than proof of a TUN route leak, but it demonstrates why every host mutation needs an independently recoverable owner and explicit rollback.
- Throne's user-facing status checks include an exit-location/latency test after startup. Proxyctl's readiness contract is stricter: it requires evidence for the exact TUN interface, route policy, physical-egress bypass, unchanged DNS/firewall, and a real proxied end-to-end request before declaring the tunnel active.

### Proxyctl decisions retained

Use these projects for useful patterns only: unprivileged controller, narrowly elevated networking component, SOCKS-level upstream readiness, one active core, and explicit user-visible connection checks. Do not copy SUID elevation, nftables auto-redirect, implicit DNS changes, or startup that continues after readiness timeout. Proxyctl additionally requires exact resource manifests, compare-and-delete cleanup, a detached recovery supervisor, generation-scoped coordination, and fault-injection coverage before enabling TUN.

## Implemented offline groundwork (not an activation backend)

The recovery-foundation batch adds a versioned route manifest model, exact resource fingerprints, a backend contract requiring compare-and-delete semantics, and a fake-backend test suite. Cleanup preflights every manifest entry before deleting, preserves changed/foreign resources, treats already-absent entries as success, and can be retried after partial backend failure. These are policy primitives only: there is not yet a production rtnetlink/iproute2 mutator or durable privileged manifest writer.

The recovery layer now has a typed supervisor contract and deterministic service-manager backend selection for systemd, OpenRC, runit, s6, dinit, and SysVinit. It does not yet start services. Detection on a systemd host is not evidence that recovery is operational.

A private manifest store now persists a generation-scoped lifecycle snapshot beside the route ownership manifest. It creates a user-owned 0700 runtime directory, writes 0600 files through same-directory atomic replacement, fsyncs the file and directory, rejects symlink manifest paths, bounds input size, validates schema/generation/ownership metadata, and refuses to overwrite or remove a different activation. The store now exposes a filesystem-only lifecycle API: a new activation must start in Prepared, events are checked against the active generation, phase changes are persisted before the caller performs the requested action, cleanup conflicts retain the pending manifest, and successful cleanup is marked Cleaned before removal. If removal fails, the Cleaned record remains available for a later recovery pass. The lifecycle coordinator adds a private advisory file lock for cross-process serialization. It holds the lock only around individual manifest reads and writes, uses a bounded wait, rejects symlink, foreign-owner, and permissive lock files, and relies on the OS to release the lock when a process exits. Its lock file is persistent by design: deleting it could split concurrent processes across different inodes. An opaque activation token checks both UUID and generation before accepting an event, so a stale supervisor cannot affect a later activation even if a numeric generation is reused. This remains filesystem-only coordination; it does not start a supervisor, grant privileges, monitor processes, or change kernel networking.

A pure dual-stack routing-policy planner now defines the required default unicast routes, mark-based core-traffic bypass rules, and unmarked proxy-traffic rules. It validates table allocation, rule ordering, mark/mask consistency, exact interface identity, duplicate/missing resources, and collisions against a synthetic kernel inventory. It rejects terminal/blackhole routes so an empty dedicated table can fall through to later routing-policy rules. The planner is offline only: it does not inspect the live kernel, set socket marks, reserve IDs, create routes/rules, or prove physical egress. The later core adapters must explicitly set the matching socket mark, and live route behavior still requires kernel-level integration tests.

A read-only kernel inventory module now queries iproute2 using fixed JSON-only route and rule commands for IPv4 and IPv6. It records occupied route/lookup tables and rule priorities, deduplicates the snapshot, and fails closed on malformed JSON, missing rule priorities, or unknown named tables. This is inventory groundwork only: it does not reserve identifiers or mutate the kernel. It currently requires the `ip` executable on PATH. Each fixed inspection process has a strict two-second timeout, writes output to a private temporary file (avoiding pipe backpressure), and is killed/reaped on timeout; no shell is invoked and no human-formatted output is parsed.

A generation-scoped lifecycle transition function now models the offline sequence from prepared to running, cleanup-pending, and cleaned. Core exit requests exact manifest cleanup; the manifest is removed only after cleanup reports success. A cleanup conflict keeps the manifest pending for later recovery. Stale or zero-generation events are ignored, and a cleaned generation is terminal. This is a pure state-machine contract with unit tests only: it is not yet wired to a process monitor or service manager.

All three native TUN adapter configs now disable core-managed automatic route installation. sing-box sets auto_route to false; Xray supplies an empty autoSystemRoutingTable; Mihomo sets auto-route to false. DNS redirection and firewall auto-redirect remain disabled. This is a configuration contract for future external route ownership, not a runnable TUN setup.



A Linux process-identity primitive now captures PID, procfs start-time ticks, and the canonical executable path. It opens a pidfd, revalidates the complete identity after opening, polls the pinned process instance for exit, and signals through pidfd only after a fresh identity check. Fake-child tests cover exact identity, altered start time/executable, exit monitoring, and pidfd signaling. This is a reusable process-monitoring primitive, not yet a surviving supervisor: no background supervisor process or init-manager integration is launched, and TUN remains disabled.



## Supervisor runtime (backend-injected; not yet activated)

The first runtime layer now monitors a pinned core process through its pidfd. When that exact process exits, it persists the generation-scoped CoreExited transition before attempting manifest cleanup. Cleanup uses the exact-resource backend contract; on any conflict/error it persists CleanupPending and retains the manifest. A restart-recovery entry point retries only manifests already in CleanupPending and refuses to clean Running manifests without independent core-exit evidence. Fake-child tests cover core exit, cleanup, conflict retention, restart retry, and stale activation tokens. Test setup pins the child with a bounded retry around transient procfs/pidfd acquisition races before binding its identity into the manifest.

This is not yet a detached or init-managed supervisor. The caller must provide the process handle and a concrete ownership backend. No concrete Linux kernel mutation backend, privilege broker, service-manager launcher, or reboot recovery exists yet. TUN activation remains disabled.



## Durable core-process identity and restart resumption

The ownership manifest now optionally persists the launched core's PID, procfs start-time ticks, and canonical executable path. Binding is serialized under the lifecycle lock, accepted only once while the manifest is Prepared, and requires the process identity to be live at write time. The supervisor can resume after its own restart: it revalidates the exact process instance, opens a pidfd and resumes monitoring when the core is still alive, or enters cleanup when the recorded process has exited or the PID now identifies a different process. Failure to inspect a still-matching process fails closed. Legacy manifests without process identity remain readable but cannot be automatically cleaned from a Running phase.

Tests cover durable identity binding, dead-core restart recovery, and refusal to recover a Running manifest without process identity. This is still a callable recovery runtime, not yet an independently launched supervisor service; it also has no production kernel backend or privilege broker. TUN activation remains disabled.

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


## Privilege-broker request boundary (offline contract)

A Linux-only discovery layer now enumerates executable `sudo`, `doas`, and `pkexec` candidates from the caller's PATH without invoking them. Discovery is informational only: finding a binary does not prove that authorization is configured, non-interactive, or safe. The versioned broker request is deliberately narrow: it carries an activation UUID, generation, the absolute private `tun-manifest.json` path, and one of two actions (apply a prepared manifest or clean it up). It has no arbitrary command, argv, shell text, route string, interface command, executable path, or firewall operation. A future privileged helper must reopen and validate the manifest and derive exact operations from its ownership records. No broker is launched and no privilege is acquired by this module; TUN remains disabled.


## Dataplane readiness evidence (offline contract)

A fail-closed readiness evaluator now requires evidence for the exact manifest-owned TUN interface name and ifindex, verified core process identity, local listener, installed route policy, physical-egress bypass, successful end-to-end proxied traffic, and unchanged DNS/firewall state. Process liveness or a listening local port alone can never mark TUN ready. The evaluator consumes evidence only; no live probes are wired yet, so this does not make TUN activation available.


### Fake-process test stability

Process-identity tests now use bounded retries when a freshly spawned fake child is not yet consistently visible through procfs/pidfd. The argv[0] test uses a long-lived fixture that preserves its argument storage and waits briefly for the expected procfs view. These are test-only synchronization measures; production identity checks remain strict and fail closed.


## Fixed kernel operation planning (not execution)

The Linux kernel backend now translates a validated dual-stack routing-policy plan into fixed-argument iproute2 operations: create the named TUN device for the invoking UID/GID, bring it up, add the exact IPv4/IPv6 default routes to the dedicated table, then add the exact marked-core bypass and proxy lookup rules. Cleanup is generated in reverse dependency order. The final link deletion removes the TUN interface and implicitly reverses its link-up operation, so cleanup contains one fewer command than setup; all independently-created rules and routes are deleted first. The planner has no shell strings and cannot execute commands or obtain privileges. It is not yet a production kernel backend: before any operation can run, the broker must inspect live state, bind the created interface index, persist exact fingerprints, and perform compare-and-delete for every resource. TUN remains disabled.
