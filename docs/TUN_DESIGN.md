# Linux TUN design

> Status: **activation disabled**. Only read-only network inspection is available.
> Scope: Linux kernel networking across Linux distributions; service-manager integration is abstracted.
> Goal: use one selected managed core's native TUN implementation, with exact Proxyctl-owned routing resources and crash recovery.

## Safety incident and current decision

A live sing-box TUN run was associated with loss of internet connectivity. Review found that the previous implementation compared post-stop network state with a baseline but did not restore Proxyctl-created routes or rules. A forced core termination or application crash could therefore leave routing state behind.

TUN activation remains rejected before process start, privilege escalation, or network mutation. `proxyctl tun status` remains read-only. Ordinary loopback activation, setup, updates, and benchmarks must not change interfaces, routes, policy rules, DNS, resolver configuration, or firewall state.

## Legacy activation-state recovery

Older development and TUN experiments could leave the ordinary activation state file pointing at a transient systemd unit after the core had never published a PID. That record is not an exact ownership manifest. Normal loopback activation must not be blocked forever by unrelated host changes such as Docker bridge removal, but it must not guess which route or interface to delete.

When stopping a legacy TUN record, Proxyctl may retire only the private runtime state/config (without changing kernel networking) if all of these checks pass: the recorded unit is in Proxyctl's validated unit namespace and systemd reports `not-found`; the saved process identity is exactly the never-started sentinel (PID and start ticks both zero); the saved baseline and current snapshot contain no TUN/TAP interface; and every currently observed IPv4/IPv6 route and policy rule already existed in the saved baseline. Unrelated interface, DNS, and removed-baseline-resource differences are not treated as Proxyctl ownership evidence. Any newly observed route/rule, TUN interface, active/unknown service, or non-zero process identity keeps the state/config and fails closed. This compatibility path is intentionally limited to the old PID-zero state format; it never removes a route, rule, interface, DNS setting, or firewall resource.

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

## Durable storage boundaries

The implementation separates two durable records and their APIs:

- `ManifestStore` owns the activation lifecycle snapshot: activation identity, generation, phase, route manifest, and exact managed-core process identity.
- `JournalStore` owns the write-ahead kernel transaction journal: ordered operation intents, observed resource fingerprints, and durable cleanup progress.
- Both stores reuse `manifest_fs.rs` for owner checks, private 0700 directories, private 0600 files, no-follow opens, atomic replacement, and directory fsync.

The lifecycle coordinator serializes both stores under the same activation lock. Journal intent must be durable before a kernel mutation; an applied fingerprint must be durable before the next dependent operation; cleanup progress is persisted only after exact compare-and-delete or confirmed absence. An unresolved intent is ambiguous and never authorizes deletion. The compatibility journal methods on `ManifestStore` delegate to `JournalStore` while transaction callers migrate; they do not create a second journal or weaker storage path.

This is a storage-boundary improvement only. It does not add a privileged executor, kernel mutation, recovery service, or TUN activation.

## Recovery and lifecycle

A serialized operation coordinator uses activation generations to prevent concurrent start/stop/switch races. The recovery supervisor is independent of the CLI and monitors the exact core process instance (PID plus start time/pidfd and canonical executable). Opening a pidfd is race-aware: if the pinned pidfd is already readable, the process has exited and recovery may proceed; otherwise the PID start-time and executable must still match. A PID reused by a live replacement is never accepted. If the process disappears between procfs inspection and pidfd opening, missing-process errors in the contextual error chain are treated as stale identity; permission, parsing, and other inspection failures remain hard errors. Core exit triggers cleanup.

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

## Managed-core listener ownership

The active loopback listener probe correlates the requested endpoint with Linux TCP listener tables and the exact managed core's open socket inodes. It pins the process with pidfd, snapshots its socket descriptors before and after the lookup, and verifies the process identity around the connection. The endpoint must be in TCP LISTEN state and its inode must belong to that process; a different local service accepting the connection is not sufficient. Both IPv4 and IPv6 procfs tables are parsed. Restricted procfs visibility, an absent endpoint, or changing socket ownership fails closed. This is point-in-time ownership evidence, not proof of successful proxying.

## Manifest-bound interface readiness probe

The Linux interface probe takes a fresh kernel snapshot, which cross-checks sysfs interface records against a NETLINK_ROUTE link dump. It requires exactly one interface with the manifest's exact name and ifindex and verifies that the kernel reports the TUN link kind. A reused interface name, changed ifindex, non-TUN link, missing record, or disagreement between the two inventories blocks readiness. The returned evidence is bound to that snapshot only; callers must refresh it after lifecycle transitions or relevant host-network changes. The probe is read-only.

## Live routing-policy readiness probe

Before readiness can be declared, the Linux probe captures a fresh read-only kernel snapshot and compares both address families with the activation's validated routing plan. It requires exactly one default unicast route in the dedicated table through the manifest-bound interface name, plus exactly one core-mark bypass rule to the main table and one unmarked proxy rule to the dedicated table at their planned priorities. Missing selectors, duplicate matches, incomplete inventory, or mismatches fail closed. The probe does not mutate routes or rules.

This evidence is deliberately narrower than end-to-end readiness: it does not prove that core sockets actually carry the configured mark, that marked traffic reaches physical egress, or that proxied traffic succeeds. Those remain separate probes. A successful snapshot is point-in-time evidence and must be refreshed after relevant host-network changes. This addition does not enable public TUN activation or implement service-manager supervision.

## Core configuration requirements

- sing-box, Xray, and Mihomo use native TUN inbounds, but core automatic route/rule installation is disabled.
- The core must not alter DNS or firewall state.
- The adapter must expose enough information for Proxyctl's route manager to create the correct routes and bypass rule. If a core cannot operate safely with externally managed routing, that core is unsupported in TUN mode.
- Keep one active core only; do not introduce tun2socks, a second packet engine, or a permanent always-on daemon.

## Process identity

Normal activation presents the process as `proxyctl-core` in argv[0] and Linux's short `comm` name where permitted. This is a display identity only. `/proc/PID/exe` remains the canonical upstream binary path and is authoritative for ownership checks. Never fake executable identity or signal processes based only on display names.

## Reference implementation review

The Linux TUN flows in v2rayN and Throne were reviewed as behavioral references, not copied as lifecycle designs.

Primary references: [v2rayN CoreManager](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Manager/CoreManager.cs), [v2rayN CoreAdminManager](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Manager/CoreAdminManager.cs), [Throne TUN Mode](https://throneproj.github.io/guides/tun_mode/), and [Throne proxy modes](https://throneproj.github.io/guides/proxy_modes/). These upstream references can evolve; re-check their privilege and routing behavior before borrowing future implementation details.

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

A read-only kernel inventory module now queries iproute2 using fixed JSON-only route and rule commands for IPv4 and IPv6. It records occupied route/lookup tables and rule priorities, deduplicates the snapshot, and fails closed on malformed JSON, missing rule priorities, or unknown named tables. This is inventory groundwork only: it does not reserve identifiers or mutate the kernel. It currently requires the `ip` executable on PATH. Each fixed inspection process has a strict two-second timeout, writes output to a private temporary file (avoiding pipe backpressure), and is killed/reaped on timeout; no shell is invoked and no human-formatted output is parsed. Output is capped at 4 MiB per command; oversized output and process-status polling errors fail closed after terminating and reaping the child. A detailed snapshot API also retains each IPv4/IPv6 route and policy-rule record as canonical JSON with its address family, table, and rule priority, so a future backend can compare complete observed attributes rather than relying only on occupied table/priority numbers. The snapshot remains read-only and is not yet used to authorize deletion.

A generation-scoped lifecycle transition function now models the offline sequence from prepared to running, cleanup-pending, and cleaned. Core exit requests exact manifest cleanup; the manifest is removed only after cleanup reports success. A cleanup conflict keeps the manifest pending for later recovery. Stale or zero-generation events are ignored, and a cleaned generation is terminal. This is a pure state-machine contract with unit tests only: it is not yet wired to a process monitor or service manager.

All three native TUN adapter configs now disable core-managed automatic route installation. sing-box sets auto_route to false; Xray supplies an empty autoSystemRoutingTable; Mihomo sets auto-route to false. DNS redirection and firewall auto-redirect remain disabled. This is a configuration contract for future external route ownership, not a runnable TUN setup.



A Linux process-identity primitive now captures PID, procfs start-time ticks, and the canonical executable path. It opens a pidfd, revalidates the complete identity after opening, polls the pinned process instance for exit, and signals through pidfd only after a fresh identity check. Fake-child tests cover exact identity, altered start time/executable, exit monitoring, and pidfd signaling. This is a reusable process-monitoring primitive, not yet a surviving supervisor: no background supervisor process or init-manager integration is launched, and TUN remains disabled.



## Supervisor runtime (backend-injected; not yet activated)

The first runtime layer now monitors a pinned core process through its pidfd. When that exact process exits, it persists the generation-scoped CoreExited transition before attempting manifest cleanup. Cleanup uses the exact-resource backend contract; on any conflict/error it persists CleanupPending and retains the manifest. A restart-recovery entry point retries only manifests already in CleanupPending and refuses to clean Running manifests without independent core-exit evidence. Fake-child tests cover core exit, cleanup, conflict retention, restart retry, and stale activation tokens. Test setup pins the child with a bounded retry around transient procfs/pidfd acquisition races before binding its identity into the manifest.

This is not yet a detached or init-managed supervisor. The caller must provide the process handle and a concrete ownership backend. No concrete Linux kernel mutation backend, privilege broker, service-manager launcher, or reboot recovery exists yet. TUN activation remains disabled.



## Durable core-process identity and restart resumption

The ownership manifest now optionally persists the launched core's PID, procfs start-time ticks, and canonical executable path. Binding is serialized under the lifecycle lock, accepted only once while the manifest is Prepared, and opens a pidfd before persisting. The pidfd pins the exact process instance across the durable write, preventing PID reuse from redirecting the check; an exit after the final liveness check is handled by the supervisor against that pinned identity. The supervisor can resume after its own restart: it revalidates the exact process instance, opens a pidfd and resumes monitoring when the core is still alive, or enters cleanup when the recorded process has exited or the PID now identifies a different process. Failure to inspect a still-matching process fails closed. Legacy manifests without process identity remain readable but cannot be automatically cleaned from a Running phase.

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


### Benchmark port test isolation

The loopback port reservation test asserts that the OS returned a non-zero ephemeral port. It deliberately does not attempt to bind that port a second time after the reservation socket is dropped, because a concurrent process may claim it in the intervening window. Production still reserves an OS-assigned loopback port immediately before generating and starting the benchmark core; the test does not claim that the port remains reserved across that handoff.


## Manifest-to-snapshot comparison (read-only)

A new offline comparison layer maps versioned manifest keys to exact IPv4/IPv6 route and policy-rule identities in a captured kernel snapshot. Route keys are accepted only for the manifest's dedicated table and the family default destination; they identify family, table, and destination. The complete canonical route JSON is the fingerprint, so gateway, device, metric, protocol, and other attribute changes are conflicts. Default-route aliases are normalized for identity matching, and a route fingerprint must still name the manifest's exact TUN interface. Rule keys identify family and priority, while the full canonical rule JSON retains fwmark, mask, source/destination selectors, lookup table, and other returned attributes.

A missing resource is reported as already absent; duplicate identities, changed fingerprints, and unknown key kinds fail closed. The comparison is read-only and **is not an authorization to delete**: a route or rule can change after the snapshot. The eventual privileged backend must perform an atomic compare-and-delete immediately before each mutation, then persist cleanup progress so interrupted cleanup can be retried. Interface name/index verification and link deletion remain separate exact-resource checks. No command is executed and TUN activation remains disabled.


## Read-only interface identity snapshot

The bounded Linux kernel snapshot now also inventories every interface from
`/sys/class/net`, retaining its exact name, numeric ifindex, and whether thekernel exposes TUN flags. Missing or malformed ifindex data and duplicate
indices fail the snapshot closed. The manifest comparator checks the recorded
interface name and ifindex together and requires the interface to be a TUN
device; a missing interface is treated as already absent, while a reused name,
reused index, or non-TUN replacement is a conflict. This remains read-only
evidence: it does not open the TUN device, create/delete links, or authorize
cleanup. The privileged backend must still verify the current link identity
atomically with each mutation.


### Process-identity test stability

The activation pidfd test uses a persistent fake child and waits for its
identity to become observable before exercising rejected and accepted signal
requests. This keeps the test focused on the ownership guarantee rather than
short-lived fixture startup timing. It does not launch a managed core or alter
host networking.


### Two-phase TUN interface identity gate

Kernel preparation is explicitly split around the kernel-assigned interface identity.
Before interface creation, the offline preflight rejects an occupied interface name,
an occupied expected ifindex, or any route-table / rule-priority collision in the
read-only snapshot. After creation, a second verifier requires exactly one interface
with the planned name and ifindex and confirms its TUN kind before any route command
may be considered. This prevents a stale or guessed ifindex from being used for
route installation. These are pure validation gates; no interface is created and no
route or rule is installed by this code.


### Interface deletion must be identity-bound

The offline kernel command planner does not emit `ip link delete dev NAME`. Interface removal is represented separately by an `InterfaceDeleteGuard` containing the manifest interface name and non-zero kernel ifindex. A production backend must re-read the link and atomically verify both values (and TUN kind / ownership metadata where available) at the mutation boundary before deleting it. A stale name, reused ifindex, or changed interface is a cleanup conflict; it must be preserved and the manifest retained. Route and rule command previews are also not authorization to delete: each requires full manifest fingerprint comparison immediately before mutation. This change is planner/test groundwork only; no rtnetlink mutation or privileged command execution exists.


### Typed cleanup identities (no destructive command previews)

The kernel planner now represents route/rule teardown as typed resource identities in reverse creation order rather than emitting `ip route del` or `ip rule del` strings. Each production deletion must resolve the exact live resource, compare its complete canonical fingerprint with the persisted manifest, and perform an atomic compare-and-delete. The interface remains a separate name+ifindex guard. These typed targets are not executable operations and do not authorize mutation; a concrete rtnetlink backend is still required.


### Detected init manager is not a supported recovery backend

Runtime detection and enum mapping identify which init system is present; they do not imply that Proxyctl can safely install, supervise, or recover a TUN service through it. The recovery backend contract now exposes an explicit implementation capability, currently false for systemd, OpenRC, runit, s6, dinit, SysVinit, and unknown managers. TUN must refuse activation until a concrete backend is implemented and passes the shared crash/reboot fault-injection suite. This prevents a detected manager from being reported as supported prematurely.


### Loopback-only readiness gate

Readiness now rejects wildcard, LAN, and other non-loopback listener addresses. Both IPv4 and IPv6 loopback are accepted. This makes the readiness contract enforce the same local-only exposure policy as ordinary Proxyctl activation; a listening socket on a non-loopback address can never satisfy the TUN readiness gate.


### Non-zero core bypass mark

The routing-policy validator now rejects a zero core socket mark. A zero-valued `fwmark` selector could also match ordinary unmarked traffic, causing the bypass rule to capture traffic that should enter the TUN table. The mark must be non-zero, fit its non-zero mask, and have a higher-priority bypass rule than the unmarked proxy rule.


- **Cleanup race hardening:** the supervisor now treats a resource that changes between the read-only preflight and atomic compare-and-delete as a cleanup conflict. It retains the CleanupPending manifest and never reports cleanup complete when any resource deletion conflicts. A fake backend test injects this race and verifies the foreign replacement survives.


- Readiness listener validation now requires both a loopback IP and a non-zero bound port. A configured-but-not-bound ephemeral port cannot be used as evidence that the core listener is ready.


## Offline hardening batch (seven increments)

The latest offline hardening increments add the following fail-closed checks:

1. Readiness requires a loopback listener with a non-zero bound port; a wildcard, LAN, or unbound port is not readiness evidence.
2. Ownership manifests cap the number and size of resource records and reject control characters in keys/fingerprints.
3. Privilege-broker requests are checked against the exact durable activation UUID, generation, and lifecycle phase. Applying is permitted only for Prepared; cleanup only for CleanupPending.
4. Proxyctl policy-rule priorities must be in the private range (at least 10,000), while the core-bypass rule remains ordered before the proxy rule.
5. Persisted process executable identities must be normalized absolute file paths, not paths containing dot or parent traversal components.
6. The lifecycle lock rejects hard-linked lock files so an external alias cannot bypass the private-lock assumption.
7. The recovery manifest rejects hard-linked files so modifying an external alias cannot silently mutate the durable ownership record.

These are local validation and filesystem hardening changes with synthetic tests only. They do not add a privileged helper, kernel mutation backend, detached supervisor, or live dataplane probes. TUN activation remains disabled.


### Pidfd-pinned manifest binding

Core-process identity binding now opens and retains a pidfd while the prepared manifest is updated, checks that the pinned process has not exited immediately before persistence, and relies on the supervisor to recover if the exact process exits after that check. The lifecycle test uses a persistent fake child and a bounded procfs visibility retry, so parallel test scheduling does not turn a fixture startup race into a false production failure. No real core is launched and no host networking is changed.

## Offline kernel transaction orchestration

The new `src/tun/kernel_transaction.rs` layer turns a validated dual-stack policy into a deterministic apply sequence: create the owned TUN interface, add the IPv4/IPv6 default routes, then add the marked-core bypass and unmarked-proxy rules. It validates the activation UUID before invoking an injected backend, checks the returned interface name/kind/index, and builds a typed ownership manifest from returned resource fingerprints.

If a route or rule operation fails, successfully recorded resources are removed in reverse order using exact fingerprints, followed by the exact interface identity. If rollback fails or detects a foreign resource, the backend is instructed to retain its recovery journal. The backend trait explicitly requires recoverable kernel-plus-journal operations, exact interface name+ifindex matching, non-empty resource fingerprints, atomic compare-and-delete, and atomic promotion of the completed journal to the active manifest before a core may start; those guarantees are not supplied by this orchestration module.

This is an offline execution contract with fake-backend tests, not a live Linux kernel backend. There is no iproute2 command execution, rtnetlink mutation, privilege escalation, or host network change. A concrete privileged backend and crash-window fault tests are still required before activation can be enabled.


## Kernel-assigned interface identity

The TUN ifindex is allocated by Linux when the device is created and must never be predicted during preflight. The policy constructor's non-zero index is only a planning placeholder. After the backend creates the exact named TUN device, it must return the kernel-assigned non-zero ifindex; the transaction binds that value into the policy and every IPv4/IPv6 route before adding routes or committing the manifest. Preflight checks interface-name availability and routing table/rule collisions, not a guessed ifindex. Post-creation verification requires one exact interface name, a unique non-zero ifindex, and TUN-kind evidence. Cleanup continues to use the committed actual name+ifindex identity. The backend contract and fake tests cover this sequencing; no real interface is created.


### Transaction failure paths must preserve truthful journal state

The offline transaction executor now explicitly retains its recovery journal when post-interface policy binding or final manifest validation fails. Rollback failures are no longer reported as journal-retained unless the backend confirms retention; a retention failure is surfaced as a separate error. If rollback succeeds but journal finalization fails, the executor again requires confirmed retention before returning. This tightens the backend contract and error reporting only; it does not supply a concrete durable journal or kernel mutator.


### Durable write-ahead transaction journal foundation

The private TUN runtime store now has a separate bounded transaction journal (256 KiB, at most 256 operations). It records generation-scoped operation intents before a future backend attempts interface/route/rule mutation, then records the observed fingerprint and cleanup completion as separate atomic, fsynced updates. Journal files use the same private directory, owner, no-symlink, no-hard-link, and 0600 protections as the active manifest. Cleanup cannot remove a journal until every recorded operation is marked removed. Invalid transitions, duplicate resource keys, wrong generations, malformed fingerprints, and oversized records fail closed. This paragraph records the original storage-only milestone. The concrete Linux rtnetlink backend is now implemented in `src/tun/linux_journal_backend.rs`; an Intent without an observed fingerprint remains deliberately ambiguous after a crash and is resolved only by exact absence evidence or preserved for manual recovery.


The journal recovery classifier now distinguishes unresolved intent, applied resource, removed resource, and an intent explicitly confirmed absent by exact kernel inspection. An unresolved intent never authorizes deletion. It can be closed only through the explicit absent-evidence transition; an applied resource requires fingerprint-based compare-and-delete before it can be marked removed. Journal deletion accepts only removed or confirmed-absent operations.


- **Offline journal recovery planner:** recovery now evaluates a fresh exact kernel-inventory map against the durable write-ahead journal in reverse creation order. An unresolved intent is marked absent only when the inventory explicitly contains that exact key as absent; an unobserved key or any present resource without a recorded fingerprint remains a conflict. Applied resources already absent can be marked removed; matching resources produce only a compare-and-delete decision carrying the recorded fingerprint; changed resources are preserved. The planner remains pure; it is now driven by the concrete Linux removal backend and the persistent mutation helper described in the later implementation milestones.

- **Typed journal resource identities:** journal validation now binds each operation kind to a constrained key format: interface creation keys carry a validated interface name, route keys carry address family/table/destination, and rule keys carry family/priority. Mismatched or malformed identities are rejected before recovery planning.

- Journal validation also enforces canonical operation order: at most one interface-create intent first, followed by routes, then rules. This makes reverse-order recovery deterministic and rejects reordered or duplicated interface operations.


## Marked physical-egress preflight evidence

A Linux read-only probe now resolves fixed IPv4 and IPv6 destinations with the planned core socket mark using bounded `ip -j route get` invocations. It accepts only one unambiguous result per family, requires the main routing table, resolves the output interface to the current sysfs name/ifindex inventory, rejects the planned TUN interface, loopback, TUN-kind links, and interfaces without a sysfs hardware-device association. The evidence records the mark/mask, destination, gateway, interface name/index, and table. This is a preflight snapshot only: it neither sends traffic nor proves that a core actually applies `SO_MARK`. Adapter generation now covers outbound-scoped marks for sing-box and Xray; Mihomo remains unsupported. Runtime observation of the mark on the actual core socket and live end-to-end readiness remain separate mandatory gates. IPv4 or IPv6 lookup failure blocks readiness; no family is silently skipped. Tests use synthetic JSON and temporary sysfs fixtures only.


## Core-scoped outbound socket marks

The adapter contract now requires a validated non-zero mark/mask as an argument to every TUN configuration request; the mark value is bounded to the common signed 32-bit range accepted by Xray's native socket option. There is no unmarked TUN-generation path in the adapter API; unsupported adapters fail closed by default when they lack a proven outbound-scoped native option.

- **sing-box:** the mark is written to `outbounds[proxy].routing_mark`, using its native outbound dial option. It is not added to inbound listeners or ordinary activation/benchmark configs.
- **Xray:** the mark is written to `outbounds[proxy].streamSettings.sockopt.mark`, using the outbound stream socket options. It is not written to inbound socket options.
- **Mihomo:** marked TUN configuration remains unsupported. The global routing-mark option has not yet been demonstrated to have the required proxy-outbound-only scope for the pinned native version, so Proxyctl deliberately does not guess or emit it.

Synthetic adapter tests assert the exact location and absence of marks on inbounds and ordinary configs. The opt-in `tests/native_adapter_validation.rs` integration test now also generates marked TUN configs and validates them with installed Proxyctl-managed sing-box and Xray binaries; it explicitly asserts that Mihomo remains fail-closed. Run it with `cargo test --locked --test native_adapter_validation -- --ignored --nocapture` after installing the managed cores. This native check does not start a core or alter networking. Runtime socket-mark observation is still required. A generated mark is not proof that the running process applied it. The readiness gate must remain closed until the mark can be observed on actual outbound sockets and both marked route lookups resolve to the intended physical egress. TUN activation remains disabled.

The ordinary activation service deliberately does not manufacture a placeholder mark or call the TUN adapter: it rejects TUN mode before configuration generation until a runtime-assigned mark is bound to the route policy and live readiness collector. This keeps the new mandatory adapter argument from being satisfied with an arbitrary constant while the feature is disabled.

### Readiness requires observed outbound-mark evidence

The pure readiness evaluator now requires an observed mark from the core's proxy outbound socket and compares it under the exact policy mask against the expected mark. Missing observations, zero/invalid expectations, and mismatches fail closed before physical-egress and end-to-end checks can pass. Synthetic tests include masked-value matching. The collector that obtains trustworthy mark evidence from a running core is not implemented; a generated config or a marked route lookup cannot populate this field by assumption.


## Runtime observation of core outbound socket marks

The readiness collector must verify the mark on a socket that belongs to the exact managed core process; generated JSON and a marked route lookup are not runtime evidence. Linux procfs TCP/UDP socket tables expose socket inodes but do not expose each socket's `SO_MARK`. The supported kernel interface for reading the mark is the INET socket-diagnostic netlink API (`NETLINK_SOCK_DIAG`, `SOCK_DIAG_BY_FAMILY`, `INET_DIAG_MARK`). The kernel UAPI explicitly limits the mark attribute to callers with `CAP_NET_ADMIN`; the legacy `inet_diag_req_v2.idiag_ext` byte cannot select this newer attribute because it is beyond the original eight requestable extensions. The collector must therefore treat lack of the privileged attribute as unavailable evidence, never as mark zero or a successful match.

A pure parser now exists in `src/tun/socket_diag_records.rs` for complete `inet_diag_msg` payloads and aligned netlink attributes. It validates IPv4/IPv6 family, non-zero socket inode, attribute lengths and padding, requires exactly one four-byte `INET_DIAG_MARK`, rejects duplicates/truncation, and skips well-formed unknown attributes. It consumes supplied bytes only; it does not open a netlink socket or issue a kernel request. The parser is not a collector and its synthetic fixtures do not prove the running kernel returns the attribute.

The unprivileged attribution half now exists in src/tun/socket_ownership.rs: it snapshots socket inode symlinks from the pinned process's /proc/<pid>/fd directory, checks PID/start-time/executable identity before and after enumeration, checks the pidfd for exit, deduplicates repeated descriptors, and rejects incomplete or malformed socket identities. It does not read marks and is not sufficient to open the readiness gate by itself.

The intended implementation is a narrowly scoped, read-only privilege-broker operation. It will enumerate IPv4 and IPv6 TCP and UDP diagnostic records, extract each record's inode and mark, map candidate inodes through `/proc/<pid>/fd` for the recorded core PID, and bind the result to the already verified pidfd process instance (PID, start ticks, and canonical executable). It must recheck process identity around collection, reject missing or duplicate/ambiguous ownership, and accept only sockets with the exact expected mark under the configured mask. TCP-only observation is insufficient because cores can use UDP for proxy transports and DNS. Unsupported diagnostic protocols, missing attributes, permission failures, truncated netlink dumps, inaccessible descriptors, and races all fail closed.

This design does not grant Proxyctl ambient `CAP_NET_ADMIN`, run the controller as root, change networking, or activate TUN. The broker executor, bounded netlink collector, inode-to-process attribution, and fault-injection tests are still unimplemented. Until they exist and are verified, runtime mark evidence cannot be populated and TUN activation remains disabled.


### Socket-diagnostic netlink framing

The Linux socket-diagnostic groundwork now includes a pure request builder, per-datagram decoder, and multipart accumulator for IPv4/IPv6 TCP and UDP dumps. Requests use the fixed `SOCK_DIAG_BY_FAMILY` operation, a non-zero sequence, and a wildcard socket identity; the decoder validates message lengths, alignment, sequence identity, kernel error messages, terminal completion, and per-datagram record counts. The accumulator enforces 4 MiB total bytes, 1,024 datagrams, and 65,536 total records, and exposes records only after an uninterrupted `NLMSG_DONE`. Each data record must pass the strict `inet_diag_msg`/attribute parser and contain exactly one `INET_DIAG_MARK`. It rejects `NLM_F_DUMP_INTR` on every message, including `NLMSG_DONE`, so interrupted multipart results cannot be accepted as complete evidence. This layer performs no netlink I/O, does not request privileges, and does not detect kernel receive-buffer truncation or enforce elapsed-time limits; those remain responsibilities of the future collector. No runtime socket-mark evidence is available yet, and TUN activation remains disabled.


### Kernel-origin validation and aggregate dump fault bounds

The pure netlink decoder now also requires every response message header to carry kernel sender port ID zero, in addition to the expected request sequence. This is defense in depth: the eventual collector must independently verify the sender address returned by `recvmsg` is the kernel (`sockaddr_nl.nl_pid == 0`) and reject `MSG_TRUNC`; a header field alone is not a substitute for transport-level sender validation. Synthetic tests cover forged non-kernel header IDs and the 1,024-datagram accumulator ceiling. The collector must additionally enforce a monotonic elapsed-time deadline and discard the entire collection after any receive, sender, truncation, or decode error. No netlink I/O or privilege handling has been added, and TUN remains disabled.


The accumulator also exposes a receive-metadata entry point that requires the collector to supply the `sockaddr_nl` sender port ID and `MSG_TRUNC` status from the same `recvmsg` operation. It rejects non-kernel senders and truncated datagrams before parsing. The lower-level byte-only method remains useful for deterministic parser tests; production collection must use the metadata-aware entry point.


### Race-checked process socket attribution

The unprivileged ownership layer now has a pure reconciliation function that compares the process socket-inode snapshots taken before and after a diagnostic dump, rejects any identity or inode-set change, rejects duplicate diagnostic inodes, and selects only records whose inode belongs to that stable process snapshot and whose mark matches the expected masked policy. Synthetic tests cover unrelated process sockets, snapshot races, duplicate records, missing matching marks, and invalid mark policies.

This output is intentionally only **candidate attribution**, not readiness evidence. A process may own inbound listeners, accepted connections, and outbound sockets; inode ownership and a matching mark alone do not prove that a record represents a proxy-outbound connection. The future collector must additionally classify protocol and peer direction, bind collection to the live pidfd identity, and prove that the selected socket is an actual core proxy-outbound socket. No privileged collector or TUN activation has been added.


- **Proxy-peer endpoint classification:** socket diagnostic records now retain local/remote IP addresses and ports from the Linux UAPI payload. A pure classifier accepts only exact configured upstream proxy IP/port matches, matching process-owned inodes, and the expected masked socket mark; TCP additionally must be ESTABLISHED. UDP uses connected-peer evidence without assuming TCP state semantics. Duplicate diagnostic inodes and invalid peer/mark policies fail closed. This remains candidate evidence only: it depends on a separately validated resolved endpoint and stable live pidfd-bound collection, and does not itself observe or prove that the core used the socket for a successful proxied request. No netlink I/O, privilege escalation, or TUN activation is added.

### Bounded socket-diagnostic collection orchestration

A new Linux-only collector orchestration layer now connects the pure request builder, receive-metadata validation, and multipart accumulator through a narrow injectable I/O contract. Each dump has a monotonic deadline capped at five seconds; receive calls are given the remaining budget, and a response arriving after the deadline is rejected. The collector requires kernel sender metadata and rejects MSG_TRUNC, transport errors, malformed/interrupted dumps, and missing NLMSG_DONE. The multi-family coordinator requests IPv4 TCP, IPv4 UDP, IPv6 TCP, and IPv6 UDP with distinct non-zero sequence identifiers and rejects sequence-space exhaustion before sending any request.

This is deliberately not yet the production netlink transport: no socket is opened, no CAP_NET_ADMIN is requested, and no privilege broker is executed. A future transport must implement the narrow send/recv contract with AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG, kernel sockaddr_nl destination/sender validation, recvmsg MSG_TRUNC handling, and bounded receive buffers. The broker must own that transport in a narrowly scoped process; the main Proxyctl process remains unprivileged. Synthetic transport tests cover complete/incomplete dumps, sender identity, truncation, timeout bounds, transport exhaustion, all four family/protocol combinations, and sequence exhaustion. No readiness evidence is populated and TUN activation remains disabled.

### Linux NETLINK_SOCK_DIAG transport boundary

Added a Linux-only, read-only NETLINK_SOCK_DIAG socket transport implementing the bounded collector I/O contract. It opens an AF_NETLINK/SOCK_RAW/SOCK_CLOEXEC socket, binds a local netlink address, sends requests only to kernel port ID 0, and receives with poll plus recvmsg. It validates the sender address family, rejects multicast-origin responses, returns the sender port ID and MSG_TRUNC metadata from the same receive operation, and bounds each receive buffer to 64 KiB. The collector's monotonic deadline and multipart accumulator remain responsible for total per-dump time, bytes, datagrams, records, sequence, and completion checks.

This transport does not request or acquire capabilities, perform privilege escalation, or alter host networking. Linux only includes INET_DIAG_MARK in diagnostic records for callers with CAP_NET_ADMIN; without it the strict parser rejects the missing mark. Therefore this transport must be instantiated only inside a narrowly scoped diagnostic broker with the minimum required capability. Do not run Proxyctl as root or grant the main process broad CAP_NET_ADMIN. The broker protocol/executor, pidfd-bound before/after process socket snapshots, live peer correlation, and readiness integration are still outstanding. The only transport test opens and closes the read-only netlink socket; it sends no diagnostic request and performs no network mutation. TUN activation remains disabled.

### Bounded socket-mark broker request protocol

The privilege-broker contract now defines a versioned, read-only socket-mark query containing only the exact process identity (PID, start ticks, canonical executable), configured proxy peer endpoint, TCP/UDP selector, and expected mark/mask. The Linux request validator rejects invalid process identities, unspecified/multicast peers, zero ports, zero/out-of-range marks, and masks that cannot represent the expected mark. Requests use a four-byte little-endian length prefix and bounded JSON payload (16 KiB maximum); decoding requires exactly one complete frame, rejects truncation, oversize lengths, trailing bytes, and unknown fields.

This is a serialization and validation boundary only. It does not open an IPC channel, invoke sudo/doas/pkexec, execute a helper, or collect socket diagnostics. Before any executor is added, the helper must authenticate the IPC peer (for example with Unix SO_PEERCRED), require that the target process belongs to the authenticated caller, open and pin the exact process with pidfd, recheck PID/start-time/executable identity before and after the four-dump collection, and return only exact matching candidate records. It must not accept arbitrary commands, paths, PIDs outside the caller's ownership, or kernel mutation requests. No privilege is granted to the main Proxyctl process. Broker execution, response framing, peer-credential enforcement, and live mark evidence remain incomplete; TUN activation stays disabled.

### Kernel-authenticated broker peer credentials

The socket-mark broker contract now includes a Linux Unix-stream peer credential reader backed by SO_PEERCRED. It obtains PID, UID, and GID from kernel socket metadata rather than trusting serialized request fields. A separate authorization policy requires a non-zero peer PID and exact equality between the authenticated peer UID and the target process owner's UID. The target UID must be read by the future helper from procfs only after it pins and verifies the requested process identity; it is never supplied by the request.

Tests use a local UnixStream pair to verify the kernel-reported credentials and synthetic ownership cases to verify same-UID allow / different-UID deny behavior. This is still an authentication and policy primitive, not a running broker: no listening socket, helper process, filesystem socket permissions, process-owner reader, pidfd-bound request handler, or response channel has been added. The main Proxyctl process receives no capability, and TUN activation remains disabled.


#### Pidfd-bound process owner inspection

The Linux process layer now reads the target's four procfs UID values only through an already-open ProcessHandle. It checks the exact start-time/executable identity and pidfd liveness before and after reading, requires real/effective/saved/filesystem UIDs to agree, and returns no request-supplied ownership data. This is a same-user authorization primitive, not a broker service; setuid or credential-divergent targets are rejected. No privilege is acquired, no socket diagnostics are run, and TUN activation remains disabled.


#### Bounded broker request stream framing

The broker protocol now has a Unix-stream reader for exactly one length-prefixed socket-mark request. It validates the four-byte length before allocation, caps payloads at 16 KiB, and enforces a single monotonic two-second deadline across header and payload reads to prevent slow-trickle clients. Truncated, oversized, timed-out, malformed, and invalid requests are rejected. The accepted connection must be closed after this one request; pipelining is not supported. This is only a framing primitive: no listener, helper process, response channel, or capability policy is installed, and TUN remains disabled.


#### Private Unix broker listener binding

A Linux listener-binding primitive now accepts only an absolute socket path beneath an existing real directory owned by the effective user and inaccessible to group/other users. It refuses symlink parents and any pre-existing or uninspectable socket path, binds without unlinking stale paths, sets the socket to mode 0600, and verifies socket type, owner, mode, and link count before returning the listener. The helper does not create directories or take ownership of existing paths. This is not yet an accept loop or installed service; accepted peers still require SO_PEERCRED authentication, pidfd-bound target ownership checks, bounded one-frame reads, and a narrowly packaged capability policy. TUN activation remains disabled.


#### Pidfd-bound broker authorization

A request authorization entry point now binds the serialized process identity to an already-open ProcessHandle, verifies that exact process is live, reads its owner UID through the pidfd-bound procfs helper, applies the kernel-authenticated SO_PEERCRED same-user policy, and rechecks identity/liveness after authorization. Synthetic coverage exercises the current process, mismatched start-time identity, and a different peer UID. This remains authorization only: it does not collect diagnostics, start a helper, acquire capabilities, or enable TUN.


#### Bounded socket-mark broker response protocol

Socket diagnostic records now support strict serde serialization, and the broker defines a versioned response carrying only the requested peer/transport/mark policy plus candidate records. Response validation caps the collection at 1,024 records and the framed JSON payload at 256 KiB, rejects unknown fields, duplicate/zero inodes, wrong address family, peer, port, mark, invalid local ports, and non-established TCP records. The decoder requires exactly one complete frame. These are transport/data-integrity guarantees only; a response is not proof of successful proxied traffic, and no helper or privileged collector is running.


#### Stable process-to-peer response assembly

A response assembly function now composes the existing before/after socket-inode reconciliation with exact configured peer, transport, and masked-mark classification. It requires both snapshots to match the request's complete process identity, rejects socket-set races and unrelated inodes, and validates the resulting bounded response before serialization. Tests use synthetic records and identities only. This is still offline candidate assembly: it does not execute netlink collection, establish successful traffic, populate readiness, or enable TUN.


#### Bounded broker listener acceptance

The private Unix listener now has a single-client accept primitive with a bounded poll deadline. It obtains SO_PEERCRED immediately after accept, then reads exactly one bounded request frame within the remaining deadline and returns the stream, kernel credentials, and validated request. Timeout, unexpected poll events, credential errors, malformed frames, and slow clients fail closed. The caller is still responsible for pidfd-bound target authorization before any diagnostic socket is opened. No helper process, capability, privileged collection, network mutation, or TUN activation is introduced.

### Authenticated diagnostic transaction executor

Added an isolated Linux broker transaction executor. It validates the narrow request, opens a pidfd for the exact requested process, authenticates the kernel-supplied Unix peer credentials, enforces same-UID ownership, and snapshots process socket inodes before opening the NETLINK_SOCK_DIAG transport. It then collects all four IPv4/IPv6 TCP/UDP dumps under the existing per-dump deadline, snapshots the process again, rechecks pidfd identity/liveness, and returns only exact peer/mark candidates. Any failed authorization, partial dump, process race, or attribution ambiguity aborts the transaction.

The executor is deliberately not connected to the CLI, does not launch a helper, and does not grant capabilities. It is intended to run only inside a separately packaged, narrowly privileged helper after its policy and lifecycle are implemented. Socket candidates remain diagnostic evidence, not proof of successful application traffic. TUN activation remains disabled.


### Bounded broker response stream

Added a one-response Unix-stream transport with a two-second maximum monotonic deadline, a 256 KiB pre-allocation frame ceiling, exact length validation, and the existing strict response schema/peer/mark/inode checks. Reads and writes recalculate the remaining deadline after partial progress; truncated and malformed frames fail closed. The transport does not authenticate peers itself and is only to be used on the private listener after the caller has authenticated the connection. The helper lifecycle and CLI remain disconnected, and TUN activation remains disabled.


- **Single-request broker server orchestration:** the Linux helper-side API now accepts one bounded private Unix-socket request, authenticates SO_PEERCRED, runs the pidfd-bound same-user diagnostic transaction, writes one bounded validated response, and shuts down the response write side. Errors drop the connection without emitting partial response data. This API is not launched by Proxyctl, no service or privilege policy is installed, and no capability is granted. TUN remains disabled.


- **Broker client exchange:** added the controller-side one-request Unix-stream exchange. It checks the connected helper's kernel-reported UID against an explicit expected UID, writes one validated bounded request, shuts down the request write side, and reads one bounded validated response. The socket path remains caller-supplied and must already be anchored in the private runtime directory; no helper discovery or execution is inferred from sudo/doas presence. This is transport groundwork only and is not wired into activation. The response reader now also requires EOF immediately after the single length-prefixed frame, rejecting appended bytes or a peer that keeps the response stream open past the bounded read deadline. This closes the one-frame boundary rather than merely decoding a valid prefix.


### Read-only recovery status reporting

`proxyctl tun status` now reports the detected PID 1 service manager, whether its recovery backend is actually implemented, and the explicit TUN activation gate. Detection is informational only: it does not invoke service-manager commands, install units, start a supervisor, or change host state. Every current backend remains reported as not implemented, so the command cannot imply recovery readiness.

### Dedicated diagnostic helper (first packaged privilege boundary)

A separate `proxyctl-tun-helper` binary now exposes only one operation: accept one bounded Unix-socket request and return same-UID, pidfd-bound socket-mark diagnostics. It accepts only `--socket PATH`; it has no shell, executable, route, link, DNS, firewall, or generic command interface. It requires its effective/permitted capability sets to equal exactly `CAP_NET_ADMIN`, requires an inheritable set of zero, enables `no_new_privs`, disables dumpability, verifies a caller-owned private runtime directory, serves one request, and exits. The helper is a separate Cargo binary. A Linux-only controller probe now launches only the fixed `/usr/libexec/proxyctl-tun-helper` path, verifies that it is a root-owned non-writable non-setuid executable, clears its environment, supplies only the private socket path, checks the helper-created socket identity/permissions, authenticates the helper UID, performs one bounded request/response exchange, and requires the helper to exit and remove its socket. On a failed exchange it terminates/reaps only the helper child it created and removes only a still-matching caller-owned private socket. Activation UUIDs are validated before deriving the socket filename. The complete diagnostic collection window is bounded to ten seconds. The controller exposes the returned mark as readiness evidence only when at least one exact-peer process-owned record is present, every record matches the configured mask/value, and all observed records agree on the mark. The common readiness evaluator now has a Linux entry point that consumes this validated broker response directly, requires its peer endpoint and transport to match the readiness target, fills the observed-mark field itself, and then evaluates the remaining independently supplied evidence. This prevents that entry point from trusting a caller-invented mark value, but route/interface, physical-egress, proxied-traffic, DNS, and firewall evidence collection is still not implemented as one live probe.

Build it with `cargo build --release --locked --bin proxyctl-tun-helper`, then explicitly install it with `sudo sh packaging/install-tun-helper.sh` (optionally pass the ordinary Proxyctl executable path as the second argument for the no-file-capabilities check); remove it with `sudo sh packaging/remove-tun-helper.sh`. The installer places it at `/usr/libexec/proxyctl-tun-helper` with only `cap_net_admin=ep`; the remover clears the file capability before deleting the binary. The scripts refuse a setuid fallback and do not create sudoers rules, polkit policy, or service units. Installation is an explicit administrator action and has not been run as part of this repository change. This is a diagnostic-only privilege boundary, not the privileged TUN mutator: it does not create interfaces, add routes/rules, or clean kernel resources. A reviewed distribution package, capability bounding policy, helper/controller lifecycle integration, and independent recovery remain outstanding.

## Remaining implementation gates (not yet complete)

The broker request/response path now has isolated server-side and client-side transport/execution primitives, but this does not close the TUN implementation. The following production gates remain intentionally open:

- [x] Add a separate diagnostic-only helper binary with a fixed one-request protocol, exact CAP_NET_ADMIN capability-set checks, no_new_privs, no setuid path, and explicit install/remove scripts; add a controller launcher pinned to the root-owned installed path.
- [ ] Produce and review distribution-native packages and a narrowly scoped installation/update policy; independently audit that the ordinary Proxyctl process never receives CAP_NET_ADMIN and that the helper cannot be used as a privilege trampoline.
- [ ] Implement the concrete Linux kernel mutator against rtnetlink/TUN ioctls, with exact live fingerprints, durable intent-before-mutation journaling, atomic compare-and-delete, and rollback. The current kernel backend remains a planner/trait, not a mutator.
- [ ] Implement detached recovery supervisors and service-manager backends. Init-system detection and lifecycle state transitions are not a recovery service; all backend kinds currently report unimplemented.
- [x] Implement controller-side launch of the diagnostic helper and strict conversion of matching process-owned exact-peer socket records into a validated observed-mark value.
- [ ] Connect runtime mark allocation, supported core-specific outbound marking, broker-observed socket marks, physical-egress route verification, route-policy/interface evidence, and end-to-end proxied-traffic checks into one live readiness decision. The current mark probe is not yet wired into activation, and a matching diagnostic socket alone is not end-to-end readiness.
- [ ] Integrate the kernel transaction, broker, supervisor, core lifecycle, and readiness gate into the CLI while preserving the existing unconditional TUN activation block until every prerequisite is present.
- [x] Extend fake-backend transaction coverage across each of the four route/rule apply failure boundaries, asserting reverse rollback, interface removal, and journal finalization without host kernel access.
- [x] Add filesystem-only restart-boundary journal tests that reopen the store after intent, confirmed absence, and applied-fingerprint persistence; verify unresolved intents never authorize deletion, exact fingerprints produce compare-and-delete decisions, and changed fingerprints preserve recovery state.
- [ ] Add end-to-end offline fault-injection coverage for process crashes at every durable journal boundary, controller/core termination, broker failure, partial kernel apply, rollback conflicts, and recovery restart.
- [ ] Complete local formatting, Clippy, tests, release build, and native adapter validation. These checks have not been run for this change set.
- [ ] Only after all offline gates pass, perform separately approved controlled real-network validation. No real TUN activation is authorized by this implementation task.

Do not mark TUN complete or enable activation while any item above remains unchecked.


### Supervisor identity path validation

Supervisor identities now reject relative manifest paths, parent-directory traversal, interior dot segments, repeated separators, backslashes, embedded NUL/control bytes, and paths longer than the platform-independent 4096-byte bound. Lexical checks run before `Path` component parsing so normalization cannot hide a dot segment. This validation is intentionally syntactic; the manifest store still performs the authoritative owner, directory, symlink, and file-mode checks when opening the path. This does not make a recovery backend operational.


### Manifest interface-name validation

Owned interface names are now restricted to Linux-safe ASCII alphanumeric, underscore, hyphen, and dot characters within the 15-byte IFNAMSIZ payload limit. This prevents whitespace, control bytes, separators, and shell-like punctuation from entering persisted ownership identities. It remains input validation only; interface creation/deletion still requires the missing concrete kernel backend and atomic identity checks.


### Diagnostic helper path trust checks

The controller-side socket-mark probe now requires the supplied private runtime directory to resolve to itself (rejecting symlink aliases) and verifies that `/usr/libexec` is a real root-owned directory not writable by group or other users before trusting the fixed helper executable. The helper file itself remains root-owned, executable, non-writable by group/other, and non-setuid. These checks reduce path substitution risk but do not eliminate the filesystem-to-exec race or replace package integrity verification and an independent security audit. The probe remains diagnostic-only.


### Helper installation rollback

The manual helper installer now removes the copied helper if applying `cap_net_admin=ep` fails or if `getcap` reports any capability set other than the exact expected value. It attempts to clear file capabilities before removal and never leaves a knowingly incomplete helper installation behind. This does not install the helper or authorize its use; package integration and security review remain open.


### Consistent socket-mark response records

The broker response validator now requires every returned peer-matched socket record to carry the same full observed mark, not merely a value that matches the requested mask. This prevents a single response from mixing different mark values that happen to select the same policy rule. The readiness bridge still validates the response against the exact requested peer, transport, mark, and mask. Socket diagnostics remain supporting evidence rather than proof of proxied end-to-end traffic.


### Journal dependency ordering

A transaction journal now rejects route or policy-rule operations unless the TUN interface creation intent is already the first operation. This mirrors the only supported apply order and prevents a malformed or edited journal from authorizing cleanup decisions for policy resources without the owning interface operation being represented. It remains validation/planning only; no kernel mutation is performed.


### Journal state progression

Journal validation now enforces the transaction's monotonic state progression: an unresolved intent can exist only as the final operation, applied resources cannot appear after cleanup has started, and removed/confirmed-absent operations form a reverse-cleanup suffix. This rejects impossible or reordered persisted states before recovery planning. Ambiguous final intents still require fresh kernel inspection and never authorize deletion by themselves.


### Route journal-key validation

Route resource keys now validate their address family, IP address syntax, and prefix-length range instead of accepting any non-whitespace destination string. IPv4 keys require IPv4 addresses and prefixes no greater than 32; IPv6 keys require IPv6 addresses and prefixes no greater than 128. This prevents malformed persisted route identities from reaching a future kernel recovery adapter.


### Recovery observation ownership validation

The pure recovery planner now rejects observations for resource keys not present in the transaction journal and rejects empty, oversized, or control-character fingerprints. Missing observations remain conservative conflicts rather than being treated as absence. This narrows the accepted evidence to the exact journal-owned resource set and still performs no mutation.


### Reverse-order recovery planner regression coverage

Added a focused recovery-planner test proving that decisions are emitted in reverse resource-creation order and that a changed route fingerprint is isolated as a conflict without changing the decisions for independently matching resources. This tests planning only; it does not imply that an atomic kernel compare-and-delete backend exists.


### Kernel transaction fingerprint bounds

The transaction executor now validates every route/rule fingerprint immediately when returned by a backend: values must be non-empty, no larger than 16 KiB, and free of control characters. Invalid evidence retains the recovery journal and prevents further mutation or manifest promotion. The concrete backend remains unimplemented.


### Ambiguous interface-creation failure

If interface creation reports an error, the executor now explicitly asks the backend to retain the write-ahead journal before returning. A backend can fail after the kernel mutation but before returning the interface identity; that boundary is ambiguous and must not be treated as a clean no-op. Fake-backend coverage exercises a post-intent creation failure while preserving the created interface and recovery journal.


### Ambiguous route/rule mutation failures

A route or policy-rule backend error can occur after the kernel accepted the mutation but before its exact fingerprint was durably returned. The executor now retains the journal and stops immediately for this boundary instead of rolling back known resources and deleting the journal while the failed operation may remain in the kernel. Recovery must inspect the unresolved intent against fresh exact kernel inventory. Fake-backend fault injection covers post-mutation route and rule errors.


The fake transaction backend now injects failures after each of the four route/rule mutations have been applied in memory. Each case asserts that the ambiguous resource remains untouched, the journal is retained, and transaction finalization is not attempted. These tests do not open netlink sockets or mutate host networking.


### Recovery-journal retention failure coverage

Additional fault-injection cases cover the case where both a kernel mutation and the attempt to retain its recovery journal fail. The executor returns an explicit error and does not claim finalization or success. Such a condition is unrecoverable automatically without external inspection and remains a hard stop; no fallback deletion is attempted.


The post-mutation fault-injection assertion accounts for all successful earlier mutations plus the one ambiguous failing mutation at each boundary, rather than assuming only one resource exists at every step.


### Journal and ambiguous-mutation regression corrections

Journal fixtures now represent valid transaction histories: interface creation precedes routes and rules, completed earlier operations carry their applied fingerprints, and only the final operation may remain an unresolved intent. The route-key validator accepts the canonical `default` destination used by the existing manifest store while continuing to validate explicit CIDR destinations against their declared address family.

Kernel transaction tests now reflect the fail-closed mutation contract: an add error is ambiguous even when a fake backend fails before inserting a resource, so the executor retains the journal and does not attempt rollback or finalization. Recovery fixtures use separate transactions when an interface creation intent is conclusively absent; they do not append routes to an absent interface transaction. The managed activation lifecycle fixture uses a bounded `sleep` process instead of `tail -f`.

These are offline regression and fixture corrections only. They do not implement a production kernel mutator or recovery supervisor, and TUN activation remains disabled.


### Follow-up journal, transaction-test, and Clippy fixes

The journal route-key parser now splits only the fixed route-family and table components, then treats the remaining destination as an opaque string for IP parsing. This preserves IPv6 destinations containing colons. The journal state test now clears the fingerprint when marking an operation Absent, matching the persisted-state invariant.

Transaction tests again assert that invalid preflight input causes zero backend calls. The ambiguous-add test checks the actual contextual error emitted by the executor. Broker test child processes are explicitly killed and waited on after failed identity acquisition attempts, and broker response tests use borrowed one-element slices to satisfy Clippy without cloning records.

All changes are offline test/validation corrections. No privileged operation, host-network mutation, or TUN activation was performed.


### Compressed IPv6 journal-key regression

The route journal key uses a colon separator before the destination, so an IPv6 destination beginning with compression syntax (for example `::/0`) places adjacent colons at that boundary. Validation restores the consumed leading compression colon for IPv6 before parsing and canonical-address checks. The family, table, address, and prefix checks remain strict; malformed and cross-family destinations are still rejected. This is parser validation only and does not change kernel route construction or TUN activation.


### IPv6 canonicalization follow-up

The compressed-IPv6 route-key validator now compares the parsed address against the restored, normalized destination text. This is important because the key separator consumes one colon before parsing: comparing against the unnormalized suffix incorrectly rejects valid leading-compression forms such as `::/0` and `::1/128`. The family and prefix bounds remain enforced, and the parser still rejects non-canonical or cross-family addresses. This is a pure journal-validation correction; it adds no kernel mutation or activation capability.


### Kernel inventory record-shape validation

The read-only route/rule inventory parser now requires every JSON array entry to be an object before interpreting or retaining it. Scalars, nulls, and nested arrays are rejected rather than being accepted as incomplete route records with an implicit main-table identity. This prevents malformed command output from becoming apparently valid inventory evidence. No command behavior or kernel state is changed.


### Manifest routing-allocation validation

Persisted ownership manifests now enforce the same private allocation floor as the routing-policy planner: table IDs must be at least `10_000` and cannot name Linux's reserved default, main, or local tables; policy-rule priorities must also be in the Proxyctl private range. This rejects edited, stale, or malformed manifests that could otherwise describe cleanup targets in shared system routing namespaces. Existing valid private allocations remain unchanged.


### Live fingerprint evidence bounds

Manifest cleanup now validates fingerprints returned by the backend before comparing any resource or beginning deletion. A live fingerprint must be non-empty, at most 16 KiB, and contain no control characters; malformed evidence aborts the complete preflight, so no resource is removed. This supplements the existing manifest-side bounds and atomic compare-and-delete contract. It does not implement a production backend.


### Kernel interface-name identity decoding

The sysfs interface inventory now rejects names that are not valid UTF-8 instead of converting them lossily. Lossy conversion can make distinct kernel names collapse to the same replacement-character string, which is unsuitable for exact name/ifindex ownership comparisons. The inspector remains read-only and now fails closed when an interface identity cannot be represented exactly by the current string model.


### Interface inventory preflight consistency

Kernel-command planning now validates the complete supplied interface snapshot before accepting a free-name preflight or a created-interface identity. Every record must have a valid bounded Linux interface name and non-zero ifindex, and names and indices must both be unique. This also protects callers that construct snapshots outside the live sysfs collector; malformed or ambiguous snapshots cannot be used as ownership evidence.



### Bounded NETLINK_ROUTE transport foundation

A Linux-only raw NETLINK_ROUTE transport now provides a bounded, sequence-checked request/response primitive for the forthcoming typed kernel backend. It uses a close-on-exec kernel netlink socket, caps datagrams at 1 MiB, applies a short response deadline, validates message framing and sequence identity, and treats negative kernel acknowledgements as errors. Its module is private to the TUN subsystem; it does not expose a CLI operation or accept untrusted request bytes across the privilege boundary.

This is transport groundwork only: typed TUN/interface, route, and policy-rule encoders; inventory decoding; write-ahead integration; exact ownership fingerprints; atomic compare-and-delete; and the privileged broker execution path remain outstanding. No network mutation is wired to this transport, and activation remains disabled.


### NETLINK_ROUTE transport hardening

The bounded transport now verifies that every response datagram is sent by kernel port ID zero, retries interrupted polling/receives within the existing deadline, and validates final-message alignment without indexing beyond an unpadded datagram. These checks strengthen the read-only transport boundary; they do not enable kernel mutation or TUN activation.


### Read-only NETLINK_ROUTE link probe

The transport now has a narrow typed public diagnostic, `tun::rtnetlink::inspect_link_count()`. It issues only `RTM_GETLINK` with dump flags, validates returned message kinds and minimum link-record framing, and reports a count. It does not expose raw netlink requests to callers, acquire capabilities, or mutate links. The existing iproute2/sysfs snapshot remains the richer source of interface metadata until a fully decoded netlink inventory is implemented.


The transport tests now cover a final unpadded `NLMSG_DONE`, reject malformed alignment padding, and pin the diagnostic request to `RTM_GETLINK` dump semantics. The request length is computed before mutably writing its header.


### Aggregate netlink response bounds

NETLINK_ROUTE transactions now enforce both per-datagram and aggregate response budgets (4 MiB and 16,384 records). This prevents a multipart kernel dump from growing memory without bound even when every individual datagram is within the 1 MiB transport limit. The operation remains read-only at this stage.


The aggregate response limits are isolated in a deterministic validation helper and covered for byte overflow, record-count overflow, and a valid bounded response. No live kernel state is required by these tests.


### NETLINK_ROUTE inventory integration

The Linux kernel snapshot now records an independent interface-record count from the bounded `RTM_GETLINK` dump. The probe is part of the read-only snapshot path, so the transport, request validator, message parser, and response bounds are exercised by production inventory collection rather than remaining unused scaffolding. The richer interface identities still come from sysfs; no kernel mutation or privileged helper is involved. If the netlink snapshot cannot be obtained, the combined snapshot fails closed rather than silently omitting this evidence.


### Linux snapshot fixture compatibility

The independent NETLINK_ROUTE interface count is a Linux-only field on the kernel snapshot. Offline test fixtures now initialize it explicitly to zero; this keeps synthetic snapshots deterministic without opening a netlink socket. Production Linux snapshots still obtain the count from the live read-only RTM_GETLINK dump. No network mutation or TUN activation is introduced.


### Final unpadded netlink message handling

The NETLINK_ROUTE parser now distinguishes a valid final message whose declared payload ends exactly at the datagram boundary from a message whose required alignment bytes are truncated. It uses checked alignment arithmetic and never advances beyond the received buffer. A regression test covers a non-four-byte-aligned final message without padding. Multipart messages still require their inter-message alignment bytes. This is parser hardening only.


### Cross-checking Linux interface inventory sources

A live Linux snapshot now requires the sysfs interface count and the independent RTM_GETLINK record count to agree. If interfaces are created or removed between the two read-only observations, the snapshot fails closed and asks the caller to retry rather than presenting a mixed-time inventory as authoritative. This is a consistency check, not a lock on kernel state; every future destructive operation still needs an immediate exact identity/fingerprint comparison.


### Terminal netlink response framing

The netlink datagram parser now rejects any record following NLMSG_DONE or a successful NLMSG_ERROR acknowledgement. A terminal response cannot be followed by additional payload records in the same datagram; accepting such a sequence would make completion ambiguous. A regression test pins this fail-closed behavior. No kernel mutation is involved.


### Netlink alignment-padding validation

Alignment validation is isolated in a dedicated checked helper and invoked for every parsed message. It verifies each present padding byte is zero before the parser advances, while permitting a final message to end exactly at its declared length without optional trailing padding. Missing required inter-message padding and non-zero padding are rejected. Regression coverage exercises both malformed forms and the valid unpadded-final-message case. This is framing validation only; the transport remains read-only.

### Netlink acknowledgement error-code validation

Successful NLMSG_ERROR acknowledgements remain terminal. Non-zero error payloads are now required to be valid negative errno values and are converted with checked arithmetic; positive values and i32::MIN are rejected without risking integer-negation overflow. This hardens malformed-response handling in the read-only transport and does not change kernel state.

### Exact NETLINK_ROUTE link identity inventory

The read-only RTM_GETLINK path now decodes each RTM_NEWLINK record into its exact interface name, positive ifindex, and optional IFLA_INFO_KIND. Attribute framing, NUL termination, UTF-8, name bounds, duplicate identity attributes, alignment, and duplicate names/indices are validated. The production snapshot cross-checks every decoded name/index against sysfs and verifies TUN kind against the sysfs tun_flags marker. A disagreement fails the snapshot closed. This replaces a count-only cross-check with per-interface identity evidence; it remains read-only and does not create or delete links.

### NETLINK_ROUTE link-record validation follow-up

The link decoder additionally binds each decoded record to an RTM_NEWLINK header whose declared length exactly matches the received message. It rejects duplicate outer link-info attributes and requires interface-name and link-kind strings to contain exactly one terminal NUL, rather than accepting embedded terminators followed by extra payload. These checks keep malformed kernel records from being promoted to interface ownership evidence. The snapshot remains read-only.

### Interrupted NETLINK_ROUTE dump handling

Multipart NETLINK_ROUTE parsing now rejects the kernel's NLM_F_DUMP_INTR indication and checks the optional integer status carried by NLMSG_DONE. Non-zero valid negative errno statuses, positive or overflowing status values, and truncated status payloads fail the snapshot rather than being mistaken for a complete inventory. This prevents a partial route/link dump from being used as authoritative ownership evidence. No mutation is performed.

### Link inventory consistency test boundary

The sysfs/NETLINK_ROUTE reconciliation is now an isolated validation function. It requires equal inventory sizes, unique netlink names, matching name-to-ifindex identities, and matching TUN kind evidence. Focused tests cover the matching case and name, index, kind, and missing-record disagreements without requiring a live network namespace. Production collection still performs both read-only observations and fails closed on any mismatch.

### NETLINK_ROUTE link attribute flag validation

The exact link decoder now rejects unsupported netlink attribute flags on interface-name and link-kind identity attributes. IFLA_LINKINFO accepts only its ordinary or nested form; identity strings cannot carry network-byte-order or other unexpected flags. This prevents an otherwise well-framed but semantically altered attribute from being accepted as ownership evidence. Tests exercise flagged interface-name and nested link-kind attributes.


### Service-manager identity precedence

Service-manager detection now treats a recognized PID 1 executable as authoritative. Runtime marker directories are consulted only when PID 1 is the generic `init` process, preventing stale or bind-mounted markers from selecting the wrong recovery integration. A regression test covers conflicting OpenRC PID 1 identity and a stale systemd marker. Detection remains read-only; no init service is installed, started, or modified.


### Activation-bound recovery service identity

The recovery supervisor identity now requires its deterministic service name to include the first eight characters of the exact activation UUID. This prevents a valid but unrelated service name from being paired with another activation's manifest and generation. The validation is pure and covered by a mismatch regression test; no service files or services are created.


### Privileged helper installation path checks

The helper installer now rejects a symlinked source or destination, requires the system `/usr/libexec` directory to be a real root-owned directory, and refuses group- or world-writable installation directories. These checks protect the set-capability executable from path redirection and unprivileged replacement. The installer still grants only `cap_net_admin=ep` to the separate diagnostic helper and does not install a service or enable TUN activation.


### Privileged helper removal checks

The helper remover now refuses symlinks, non-regular paths, and files not owned by root before clearing capabilities or unlinking the helper. This avoids following or deleting an unexpected replacement path during package removal. It does not stop services or alter any other Proxyctl or system executable.


### Helper socket cleanup on every exit path

The diagnostic helper now owns its bound Unix socket through an inode-checked guard. The guard removes the socket on normal return and error unwinding, but only when the path still identifies the same socket device/inode and owner captured immediately after binding. If the path is replaced, cleanup leaves the replacement untouched. This closes the stale-socket failure path without broadening the helper's diagnostic-only privilege contract.

### Kernel plan validation boundary

The fixed-argument kernel operation plan now has an explicit validation pass before any future privileged handoff. It requires the guarded TUN creation to be the first operation, rejects empty/control-character arguments, validates the interface deletion guard, rejects duplicate cleanup identities, and ensures every planned route cleanup targets the guarded interface. This remains a plan-integrity check only: it does not execute operations, establish ownership, or replace live fingerprint comparison and durable write-ahead journaling.

The plan-validation contract is covered by offline tests for a valid generated plan, foreign-interface route cleanup, and duplicate cleanup identities. These tests validate the plan boundary only; live kernel ownership still requires a concrete backend and exact compare-before-delete.

### Recovery identity path validation

A supervisor identity now accepts only a normalized absolute manifest file path: the path must begin at the root, contain only normal path components, have a filename, and contain no duplicate separators, trailing separator, NUL, or control characters. This prevents ambiguous path spellings from crossing the future service-manager boundary. It does not grant the supervisor authority to open or modify the path; owner, mode, no-follow, and activation-lock checks remain mandatory at the storage layer.

### Re-entrant recovery cleanup

A supervisor that observes core exit while already in CleanupPending now emits the cleanup action again instead of treating the repeated event as a no-op. This supports supervisor restart and event replay: cleanup must tolerate already-removed resources, while any ownership mismatch remains a conflict that preserves the manifest. The transition function remains pure and does not itself perform cleanup.

### Atomic helper installation

The helper installer now stages the new executable inside the root-owned libexec directory, applies and verifies the exact CAP_NET_ADMIN file capability on that staged file, and only then atomically renames it over the installed helper. Failures before the rename preserve the previous helper instead of deleting or leaving it partially replaced. Signal handling removes only the staging file. The installer still creates no service, sudoers rule, setuid fallback, or automatic startup.

The manifest-path validator also checks the original path spelling before `Path::components()` normalization, explicitly rejecting interior `.` and `..` segments. This matters because standard path component iteration may normalize away interior `.` components rather than expose them to the caller.

Kernel command-plan validation now binds every planned route cleanup to both the guarded TUN interface name and its kernel-assigned ifindex. A matching name with a stale or reused ifindex is rejected before a plan can cross a future privileged boundary; tests cover both mismatches. This remains plan validation only and does not perform cleanup.

Before a kernel plan can be handed to a future privileged executor, validation now requires exactly two guarded interface setup operations followed by one operation per typed route/rule resource. Every generated apply argument vector must equal the canonical command reconstructed from the reverse-ordered cleanup identities; extra commands, altered arguments, and mismatched resource counts fail closed. The plan remains non-executable until a concrete backend supplies atomic ownership checks and journal integration.

Recovery supervisor activation identifiers must use the canonical lowercase hexadecimal UUID spelling before they are incorporated into service names. This avoids multiple textual identities for the same UUID and keeps service-name binding deterministic; uppercase lookalikes are rejected. The check remains syntactic and does not replace persisted generation checks.

The helper remover now applies the same `/usr/libexec` trust checks as installation: the directory must be a real root-owned directory and must not be group- or world-writable. It refuses to follow a symlinked or substituted parent before inspecting or removing the helper. This narrows the privileged filesystem boundary for uninstall as well as install.

The NETLINK_ROUTE receive path now accepts responses only from the exact kernel unicast endpoint: sockaddr length must match exactly, family must be AF_NETLINK, sender port ID must be zero, and multicast groups must be zero. This prevents a userspace netlink peer or multicast sender from being mistaken for the kernel's reply. The sender predicate has focused negative tests; the transport remains read-only.

Kernel command-plan validation parses the TUN owner UID and GID as bounded `u32` values and requires their canonical decimal spelling. Empty values, overflow, and alternate spellings such as leading-zero numbers are rejected before any future privileged executor can consume the plan.

The post-creation interface check now has a single binding helper: it validates a fresh link inventory, confirms the named device is a TUN interface with a unique non-zero ifindex, and returns a cloned routing policy whose interface and every planned route use that kernel-assigned index. Route planning must use this bound policy, not the constructor's placeholder index.

Transaction-journal route table IDs and rule priorities now require canonical positive `u32` decimal strings. Zero, overflow, and leading-zero aliases are rejected, ensuring one textual resource key maps to one numeric kernel identity during recovery and compare-delete.

Transaction journals and privilege-broker requests now require canonical lowercase hexadecimal activation UUIDs. Uppercase aliases are rejected consistently at both boundaries, and focused tests cover journal and broker validation so a single activation has one textual identity across persisted state and helper requests.

Privilege-broker requests now apply lexical manifest-path validation before `Path` component normalization. They reject interior `.`/`..` segments, repeated or trailing separators, backslashes, non-UTF-8 paths, and control bytes, in addition to requiring the exact manifest filename. This keeps the helper's path identity consistent with the recovery-supervisor contract.


### Canonical activation identity across manifests and transactions

Ownership manifests and kernel transaction requests now enforce the same canonical lowercase hexadecimal UUID spelling already required by journals, broker requests, and recovery identities. This prevents case-variant aliases for one activation from crossing storage and execution boundaries. Focused tests reject uppercase UUID aliases; this validation does not enable kernel mutation.


### Fallible kernel-assigned interface binding

The helper that binds a routing policy to the kernel-assigned TUN ifindex no longer relies on an internal panic after validation. It now reports an ordinary error if the interface cannot be found in the supplied inventory, preserving fail-closed behavior even if the inventory changes or a future refactor weakens the preceding invariant. No interface or route operation is performed by this helper.


### Canonical recovery manifest filename

The recovery-supervisor identity now requires the exact `tun-manifest.json` filename used by `ManifestStore`, not merely any final path component. This aligns service-manager identity validation with the broker and durable-store contract, preventing a syntactically valid supervisor request from naming a different file. Parent-directory ownership and no-follow checks remain the storage layer's responsibility.


### Pidfd target identity input validation

Persisted process identities now reject PIDs outside Linux's signed `pid_t` range before the value can be cast into a pidfd syscall argument. Executable paths are also checked lexically before `Path` normalization, rejecting dot segments, parent traversal, control bytes, and non-UTF-8 representations. This prevents malformed recovery state from aliasing another PID or executable path; live pidfd and start-time verification remain required.


### Pidfd signal argument validation

The pinned-process signaling API now rejects signal zero and values outside Linux's supported signal-number range before invoking `pidfd_send_signal`. Signal zero is a permission/liveness probe rather than a termination request, so accepting it through the supervisor's signaling API would blur the distinction between verification and process control. The check is covered with a live fake child and does not signal or terminate that child.


Readiness validation now independently validates the expected TUN interface name and non-zero ifindex before evaluating evidence. This prevents malformed expectation values from bypassing the same identity shape enforced by route planning and manifests. Offline tests cover malformed names and zero indices; readiness remains a pure evaluator and TUN activation remains disabled.


Socket-peer candidate classification now rejects zero-inode records at its own boundary, even when a caller supplies synthetic or otherwise untrusted records instead of the strict parser's output. This avoids treating inode zero as an ownership key. The classifier remains offline and read-only.


The socket-diagnostic record parser now rejects IPv4 address fields whose unused 12-byte tail is non-zero, keeping the address-family representation canonical. This is parser validation only; the diagnostic transport remains read-only and no socket-marking operation is enabled.


Read-only ownership snapshot key parsing now requires route table IDs and rule priorities to be canonical positive decimal `u32` values. Zero, overflow, leading-zero aliases, and malformed numerics are classified as unsupported identities rather than interpreted loosely. This is comparison/parser hardening only and does not authorize cleanup.


Route ownership snapshot comparison now treats malformed canonical route JSON within the target family/table as ambiguous, rather than silently skipping it and reporting the resource absent. An inconclusive snapshot must never be interpreted as deletion evidence. A regression test covers the malformed-record case; comparison remains advisory and read-only.


The canonical resource-key numeric parser uses an owned error-context string when wrapping parse errors, satisfying `anyhow`'s context lifetime requirement without changing validation behavior.


## Concrete kernel backend implementation milestone

This milestone moves the Linux TUN work from offline planning toward a real kernel executor. Implement concrete typed TUN interface creation, link-up, IPv4/IPv6 route and policy-rule operations using NETLINK_ROUTE (not shell commands), exact resource identity verification, and rollback/cleanup driven by durable write-ahead journal records. Execution is routed through the restricted privilege-broker protocol; callers cannot submit arbitrary netlink bytes or command strings. The backend must re-inventory and fingerprint resources before cleanup, persist intent before mutation and applied evidence after mutation, and preserve ambiguous resources for recovery. The milestone includes offline fake-kernel/fault-injection tests for partial apply, ack failure, inventory mismatch, cleanup conflict, and replay. The activation CLI remains gated until the executor, broker, supervisor, core socket-marking and readiness paths are all integrated.


### Concrete Linux TUN descriptor allocation

A first real mutation primitive now allocates an exclusive, non-persistent TUN device via `/dev/net/tun` and `TUNSETIFF` with `IFF_TUN`, `IFF_NO_PI`, and `IFF_TUN_EXCL`. Owner/group are assigned using typed `TUNSETOWNER` and `TUNSETGROUP` ioctl calls. The descriptor owns the attachment; closing it removes the non-persistent interface. Interface names are validated and the kernel-returned name is checked. This primitive does not bring the interface up, configure addresses, install routes or rules, or alter DNS/firewall state. It is not yet wired into the journaled transaction or broker.


### TUN link state mutation

The TUN descriptor allocator now performs a typed link-up operation after successful exclusive allocation and owner/group assignment. It reads current interface flags using `SIOCGIFFLAGS` and sets only `IFF_UP` via `SIOCSIFFLAGS`, preserving other flags. If link-up fails, descriptor ownership unwinds and the non-persistent interface is released. The link-up operation is now reached through the journal-backed `PersistentTunOwner` allocation path.


### Typed route and policy-rule installation primitives

Added Linux-only typed NETLINK_ROUTE mutation functions for installing the validated default unicast route into its dedicated table and installing RPDB lookup rules with optional fwmark selectors. They encode `RTM_NEWROUTE`/`RTM_NEWRULE` and structured attributes, use create-exclusive plus ACK, and reject unsupported route types or malformed identity values. The typed add/delete primitives are now invoked by the journal-backed Linux executor, which persists intent, captures live fingerprints, and verifies absence after deletion.


The route/rule primitive also has typed delete requests keyed by the explicit route family, table, interface index, rule priority, and mark selector. These are narrowly scoped selectors but are not yet conditional on a live canonical fingerprint comparison; the transaction/recovery layer must enforce that precondition before these deletes are used for owned-resource cleanup.


### Linux `ifreq` ABI correction

The TUN allocation/link-up primitive uses the Linux `ifreq` ABI with a 16-byte interface-name field and an 8-byte union (24 bytes total). Its flags view is a 16-bit field with six bytes of union padding. This keeps `TUNSETIFF`, `SIOCGIFFLAGS`, and `SIOCSIFFLAGS` ioctl payload layouts consistent with the kernel ABI; this correction is implementation-only and does not enable activation.


### TUN transaction integration review — ABI and execution-boundary correction

The flags union in the link-up ioctl's `ifreq` now uses six bytes of padding, matching the 24-byte Linux ABI representation (16-byte interface name plus an 8-byte union). This corrects the source implementation, not merely its description.

This review captured the integration boundary before the concrete backend existed. The subsequent implementation now supplies the broker-held interface lifecycle, durable operation transitions, fresh canonical observations, and immediate fingerprint comparison before typed cleanup. The diagnostic socket-mark broker remains separate and unchanged. Route/rule deletes are still selector-based rather than kernel-atomic compare-and-delete; the executor documents and handles that limitation with immediate pre-delete comparison and post-delete verification.

### Generation-bound persistent TUN descriptor owner

A Linux-only `PersistentTunOwner` now retains each non-persistent `TunDevice` descriptor in a long-lived owner map keyed by the canonical activation UUID and non-zero generation. Allocation is exclusive, rejects duplicate activation ownership and interface-name collisions, and obtains the returned ifindex from a fresh cross-checked kernel snapshot rather than from the routing plan. The exact name/ifindex pair is retained alongside the descriptor. Lookup and release require the same activation generation; release additionally requires the exact interface name and ifindex, so stale cleanup cannot close a later activation's device. Closing the retained entry releases the non-persistent TUN interface.

The persistent mutation helper now owns this registry through a long-lived typed request loop, and journal intent/applied transitions surround TUN allocation and route/rule mutations. The registry still exposes no raw descriptor transfer, arbitrary ioctl operations, or arbitrary command execution. Broker restart closes descriptors by kernel design; the durable journal remains the recovery source.

### Canonical journal observations from fresh kernel inventory

The read-only resource snapshot layer now exposes a journal observation builder. Given a validated transaction journal and one fresh `KernelSnapshot`, it returns an exact observation for every journal key: interface fingerprints are derived from the live TUN name/ifindex/kind record, while route and rule fingerprints are copied from the full canonical JSON records returned by kernel inventory. It does not synthesize fingerprints from the planned operation. Duplicate identities, malformed live records, missing selectors, and unsupported journal keys fail closed; exact absence is represented explicitly as `None`. The result feeds the existing pure reverse-order journal recovery planner.

These observations are evidence for recovery planning, not an atomic delete authorization. The kernel may change after the snapshot; the privileged mutation backend must re-inspect and compare the complete identity immediately before each delete, then durably mark that operation removed. This batch supplies canonical live observation, not the still-missing broker-side atomic compare-and-delete executor.

### Detached journal recovery executor

A reusable recovery executor now drives the existing durable journal and pure recovery planner. It processes operations in reverse creation order, obtains a new full kernel snapshot for each pending operation, derives canonical observations from that snapshot, and then selects only the planner's exact state transition. An unresolved intent is marked absent only when the exact key is absent. An applied operation is durably marked removed only after absence is confirmed or the backend reports successful compare-and-delete. Changed, duplicate, malformed, or otherwise ambiguous resources stop recovery and leave the journal intact. Once every operation is durably Removed/Absent, the executor removes only the matching activation/generation journal.

The executor delegates the actual typed compare-and-delete syscall to `JournalRecoveryBackend`; its contract requires an immediate live fingerprint recheck and forbids using the earlier inventory as deletion authorization. The production Linux implementation and separate long-lived typed mutation service are now implemented in the later milestones below. This executor does not widen the existing diagnostic socket-mark broker.


### Concrete Linux journal-backed apply and recovery backend

A Linux implementation of both transaction and detached-recovery backend contracts is now present. It creates the generation-scoped journal before any kernel mutation, writes an operation intent before TUN allocation or each route/rule NETLINK_ROUTE request, and records the full canonical live fingerprint from a fresh inventory after the acknowledged mutation. The TUN descriptor is held by the backend's `PersistentTunOwner`; callers must therefore keep the backend alive for the activation lifetime. Manifest promotion is refused unless every journal operation is durably Applied.

The recovery implementation re-reads the journal and fresh inventory immediately before cleanup, compares the complete live canonical fingerprint, and issues only the typed route/rule delete operation or exact retained-descriptor release. It obtains another inventory after route/rule deletion and reports success only when the exact journal identity is absent. The detached recovery executor then persists the Removed transition. If the broker process has already exited, the non-persistent TUN descriptor closes with it; recovery treats an absent interface as already gone and retains conflicts for any reused or changed identity.

The NETLINK_ROUTE API does not provide an atomic compare-and-delete primitive for these selectors. This implementation therefore performs immediate pre-delete comparison and post-delete verification, but cannot eliminate a kernel-state race between comparison and the delete request. It never represents that check as atomic. The concrete backend is a library component; the long-lived helper IPC service and caller wiring are a separate remaining integration task. The existing diagnostic broker protocol remains read-only and unchanged.


### Persistent typed mutation-broker service

The helper now has a separate `--mutation-socket PATH` mode. Unlike the existing one-request diagnostic `--socket PATH` mode, this service remains alive across client connections and retains a map of active `LinuxJournalBackend` instances, which in turn retain the TUN descriptors. Its versioned JSON envelope is a closed typed enum with only `Activate` and `Recover`; unknown fields are rejected, frames are bounded, activation UUIDs and generations are validated, and requests are authenticated with kernel `SO_PEERCRED` against the helper's owning UID. Invalid clients are closed without terminating the service.

Activation requests contain only the interface name, owner IDs, dedicated table, rule priorities, and mark policy. The helper constructs the validated routing plan itself; clients cannot provide netlink bytes, command strings, executable paths, ioctl numbers, or arbitrary resource selectors. Recovery requests identify only an activation UUID and generation, and the backend loads the matching durable journal before acting. A small typed client call API is available for the same protocol. The diagnostic socket-mark request/response format and executor remain unchanged.

The service is now wired into the helper binary, but packaging and the application-side process supervisor still need to launch this mode as a persistent helper and manage its lifecycle. The helper's existing capability check continues to require exactly CAP_NET_ADMIN. This service is not automatically started or installed by the current packaging scripts.


The mutation IPC frame now uses one monotonic deadline for the complete header and payload, rather than resetting a timeout for every partial read. Activation owner UID/GID must equal the kernel-authenticated peer UID/GID; the caller cannot ask the helper to create a device owned by another account. Rollback through the concrete transaction backend also fsyncs each Removed transition before final journal deletion, matching the detached recovery progress contract. The helper installer output documents the explicit persistent mode without enabling or installing a service automatically.


Before creating a transaction journal, the mutation service now takes a fresh kernel inventory and validates that the requested dedicated routing table and both families' rule priorities are unoccupied. The subsequent route/rule additions still use create-exclusive NETLINK_ROUTE flags and ACKs, so the preflight is not treated as a lock or race-free reservation. If another actor claims an identity after preflight, the kernel rejects the exclusive add and the durable journal retains the exact partial-transaction state.


### Remaining integration boundary after the journal/broker implementation

The five requested implementation layers now have concrete Linux code: journal-backed apply, persistent TUN descriptor retention, live canonical fingerprints, detached compare-before-delete recovery with durable progress, and a separate typed persistent mutation broker. The helper exposes the persistent mode and the library exposes a typed client call. The diagnostic broker remains unchanged.

This does not yet activate TUN mode from the main Proxyctl CLI. The main-process lifecycle coordinator still needs to spawn/monitor the persistent helper, issue typed activation/recovery requests, connect the active manifest to the core process lifecycle, and gate core launch on socket-mark and end-to-end readiness evidence. Service-manager packaging/automatic startup remains intentionally separate. Route/rule removal is preflight compare + typed delete + post-delete verification, not an atomic kernel compare-and-delete operation.


### Canonical cleanup-key parsing and pidfd restart regression

The concrete Linux journal backend now rejects non-canonical decimal spellings for route table IDs, rule priorities, and numeric rule table selectors. Parsing a string into an integer is not sufficient: its decimal round-trip must match the original key, so leading-zero aliases cannot identify the same kernel resource under a second journal key. The route-key parser also keeps the parsed destination validation explicit while the deletion selector remains constrained to the supported default route.

The restart-recovery regression test now keeps its terminated child unreaped until the supervisor has opened the pidfd and classified the persisted process identity. This prevents the kernel from reusing the numeric PID in the test window. A reused PID is a different process instance and must continue to be rejected; recovery is only allowed after the recorded process is established as gone. The mutation protocol's maximum-frame bound is now asserted at compile time rather than through a runtime test assertion.


The cleanup-key parser refactor keeps exactly one shared rule-table value parser at module scope, before the test module. This avoids duplicate symbol definitions while retaining canonical decimal validation for numeric table selectors.


## Persistent mutation-helper launch milestone

The Linux code now includes a caller-runtime helper launcher (`mutation_helper_launcher`). It targets the installed `/usr/libexec/proxyctl-tun-helper`, starts it in typed mutation-socket mode, and polls for socket readiness. The runtime directory is checked for caller ownership and restrictive permissions; an existing socket that cannot be reached is not unlinked or replaced. The launcher is an orchestration primitive only: it does not yet make TUN activation available, establish the activation transaction, start a core, or manage stop/recovery as one lifecycle. TUN remains disabled in the activation command until those handoffs are integrated and verified.


## Launcher-to-broker client boundary

The Linux mutation-helper launcher now exposes a typed call method over the helper's existing bounded request/response protocol. Activation and recovery requests are passed as closed `MutationRequest` variants; callers do not gain access to raw netlink payloads or arbitrary privileged commands through this client surface. This is a transport integration primitive only: the activation entry point remains gated, and process/core readiness and stop/recovery orchestration are not yet connected to this broker client.


The launcher client additionally provides explicit activation and generation-bound recovery methods that construct the protocol envelopes internally. These methods are available for lifecycle integration; they do not independently make TUN activation available or imply a successful activation without the complete process/readiness lifecycle.


## Launcher API and runtime-directory hardening

The helper launcher exposes the typed `activate`, `recover`, and generic `call` client methods. Runtime-directory validation rejects symlink directories and checks ownership and private permissions before using the broker socket. The launcher does not remove stale socket paths. These primitives are not yet wired into the public activation lifecycle; the legacy activation path remains gated pending generation persistence, native core readiness, and coordinated rollback/recovery.


The mutation launcher now includes a recovery-generation convenience entry point that routes a caller-supplied activation ID and generation through the existing typed recovery request. The broker remains responsible for matching that pair against durable journal identity; callers cannot request recovery by arbitrary resource key. Public lifecycle wiring and state persistence are still outstanding.


## Persistent mutation broker activation exclusivity

The persistent mutation broker owns the TUN descriptor and journal backend for the lifetime of an activation generation. It accepts at most one live activation backend at a time. A replacement activation is rejected while that backend remains retained; the caller must first recover the exact prior activation ID and generation. This prevents two Proxyctl generations from installing overlapping default routes, policy rules, or TUN interfaces through the same privileged helper.

A helper restart clears in-memory descriptor ownership but does not authorize a new activation: the durable transaction journal and ownership manifest still block a fresh transaction until generation-matched recovery has completed. Recovery never selects a generation by guessing or by scanning numeric resource ranges.

This exclusivity is a broker invariant, not a claim that the complete public activation lifecycle is integrated. TUN activation remains disabled until core/device ownership handoff, process supervision, readiness verification, and stop/replacement orchestration are connected.


## Recovery finalizes the matching ownership manifest

A successful broker recovery now retires both durable layers for the same activation ID and generation. Before journal cleanup begins, the broker verifies that any active ownership manifest has the requested identity. The recovery executor then re-inspects and resolves every journal operation. Only after that succeeds is the matching manifest persisted in the `Cleaned` phase and removed.

This prevents a successfully recovered activation from leaving a stale manifest that would block the next transaction. A mismatched recovery request is rejected before the journal is mutated. Failed journal recovery retains the live backend and journal for another exact-identity attempt. This finalization does not start or stop a core and does not enable the public TUN activation path.


## Restartable recovery finalization

Broker recovery validates the requested activation ID and generation against both the ownership manifest and transaction journal before invoking kernel cleanup. This closes the gap where a matching manifest could otherwise be paired with a different journal.

Recovery finalization is also restartable across the boundary between journal deletion and manifest deletion. If the journal is already absent but the matching manifest remains, a repeated recovery request completes the manifest's `Cleaned` transition and removes it without attempting to reopen a nonexistent journal. A request with neither matching durable record is rejected. This makes the post-kernel-cleanup bookkeeping idempotent after helper or caller interruption.


## Broker handling of completed activation rollback

The persistent mutation broker now distinguishes a fully rolled-back activation failure from an activation that still owns recoverable state. When the transaction executor reports an error, the broker checks both durable records. It releases the in-memory backend (and its retained TUN descriptor) only when the transaction journal and ownership manifest are both absent. If either record remains, the backend stays retained for generation-matched recovery.

This prevents a cleanly rolled-back failed activation from leaving an empty backend entry that would incorrectly block every later activation, while preserving the recovery path for ambiguous or incomplete rollback outcomes. If either storage inspection fails, the broker conservatively retains the backend.


## Retain broker exclusivity through recovery finalization errors

After journal-backed kernel recovery succeeds, ownership-manifest retirement is a separate durable step and can itself fail (for example, due to a filesystem error). The broker now retains the generation's backend in that case instead of dropping it while leaving a manifest behind. This preserves the single-generation activation lockout and allows the same generation's recovery request to retry the idempotent manifest-only finalization path. The helper reports that kernel recovery completed but finalization remains pending; it does not report overall recovery success until both durable records are retired.


## Installed helper executable validation

Before spawning the privileged persistent mutation helper, the unprivileged launcher now inspects the executable with `symlink_metadata`. It requires a real regular file (not a symlink), root ownership, at least one execute bit, and no group/world write permission. A missing or unsafe installation fails closed with an installation-oriented error instead of following an unexpected executable path.


## Concurrent persistent-helper startup

The unprivileged launcher now serializes helper discovery and startup with a private runtime lock file and nonblocking `flock`. Concurrent Proxyctl processes wait for the startup owner, then probe the same socket instead of racing to spawn duplicate helpers. The lock descriptor is close-on-exec and remains held through readiness polling; the lock file itself is intentionally persistent, while kernel lock ownership is released automatically when the launcher exits. Lock acquisition is bounded to five seconds and validates file type, owner, restrictive permissions, and link count. This does not change the helper's request protocol or enable TUN activation.


## Mutation socket discovery validation

The launcher no longer treats any connectable filesystem path as a ready helper. Before probing, it uses non-following metadata inspection and requires the endpoint to be a Unix socket owned by the current effective user, mode `0600`, with a single link. Symlinks, regular files, foreign-owned sockets, and sockets with broader permissions are not accepted as an existing helper endpoint. This complements the private runtime directory and startup lock checks.


## Authenticated mutation-helper readiness

The persistent mutation protocol now includes a versioned, side-effect-free `Ping` request. Launcher readiness checks first validate the socket's filesystem identity and permissions, then exchange a bounded protocol frame and require a successful version-matched response. A listening socket alone is no longer considered proof that the expected mutation broker is ready. The broker authenticates the peer with `SO_PEERCRED` before accepting the ping, and the request does not inspect or mutate kernel networking state or alter retained activation ownership.


## Broker-to-managed-core activation handoff

A Linux-only managed activation coordinator now connects the typed mutation helper to the durable lifecycle coordinator. The privileged broker remains the sole creator of the kernel transaction and its Prepared ownership manifest. The unprivileged side adopts that exact activation ID and generation rather than creating a competing manifest, pins the already-launched core using its captured process identity and pidfd validation, and persists the Running transition only after binding succeeds.

If manifest adoption or process binding/start commitment fails after broker activation, the coordinator requests recovery for that exact activation ID and generation. Recovery errors are surfaced rather than reported as successful cleanup. The returned activation token is the one required by the existing supervisor monitor/restart APIs.

The caller remains responsible for launching the core with a compatible native TUN configuration and socket mark before handing its captured process identity to this coordinator. This batch does not yet provide a production core launcher, independent dataplane readiness probes, a service-manager-owned supervisor, or supported Mihomo integration. Public TUN activation therefore remains gated.


A broker activation response that reports failure is surfaced directly; the coordinator does not issue a blind recovery request because a fully rolled-back activation legitimately has no remaining journal or manifest. When the broker reports successful activation but later manifest adoption or process binding fails, the coordinator does issue exact-generation recovery. If that recovery cannot be confirmed, the error includes the recovery failure and the durable record remains available for explicit retry.


## Managed-core supervision through the persistent broker

The managed activation API now has a broker-backed monitor entry point. It verifies that the supplied pidfd belongs to the same process identity persisted in the Running manifest, waits for that exact process instance to exit, and durably records CoreExited before requesting cleanup.

Kernel cleanup is delegated to the persistent mutation broker using the activation token's exact UUID and generation. This is important because the broker retains the privileged Linux journal backend and TUN descriptor across client connections; the unprivileged supervisor does not construct a second backend or attempt direct privileged cleanup. A failed broker response leaves the durable recovery record available and advances it to a conflicted cleanup state where possible. A successful response means the broker completed journal cleanup and manifest retirement.

This is a reusable lifecycle primitive, not yet an installed service-manager supervisor: no systemd/OpenRC/runit/s6/dinit/SysVinit unit is generated or enabled by this change, and automatic restart after supervisor-process loss is still outstanding. Public TUN activation remains gated until service-manager ownership and independent dataplane readiness are integrated.


The broker-backed supervisor also exposes a restart-resume operation. It retries CleanupPending generations directly through the broker. For Running generations it reopens a pidfd from the persisted process identity; if the exact process has exited or its PID no longer identifies that process instance, it records CoreExited and requests generation-matched cleanup. If process identity inspection is inconclusive, resume fails without treating uncertainty as proof of exit. If the process is still live, monitoring resumes against that pinned pidfd.

## Durable-state-aware mutation broker readiness

The persistent mutation helper's versioned Ping now performs a read-only consistency check of the durable ownership manifest and transaction journal before reporting readiness. If both records exist, their activation UUID and generation must agree. If the broker retains an in-memory privileged backend, that backend must correspond to the same durable generation; multiple retained backends or an orphaned in-memory backend make readiness fail closed.

A helper restarted after a crash may have durable records but no in-memory backend or TUN descriptor. That is an expected recoverable state: readiness reports the pending generation, and the broker can reopen its journal backend for exact-generation recovery. A manifest-only or journal-only record is also accepted because recovery finalization and partial transaction rollback can legitimately leave one durable layer temporarily. No kernel inventory or mutation is performed by Ping.

This check makes socket readiness stronger without claiming that a healthy broker implies a healthy dataplane. It does not establish core liveness, TUN interface ownership, route correctness, end-to-end proxy traffic, or service-manager supervision, and it does not enable public TUN activation.

## Composed managed activation preflight

A Linux-only preflight orchestration entry point composes the independent read-only checks: process-pinned local listener and socket ownership, manifest-bound TUN interface identity, exact routing-policy comparison, marked physical-egress lookup, process-bound outbound socket-mark observation, and baseline/current DNS and firewall comparison. It returns a structured `ReadinessEvidence` record with end-to-end traffic explicitly false. It does not infer successful proxied application traffic from route lookup or a listener connection; that final evidence must be supplied separately before the aggregate readiness gate can pass. The orchestration is diagnostic only and does not enable activation or mutate network state.

## Host DNS and firewall preservation check

The readiness layer can compare pre-activation and current read-only `NetworkStatus` snapshots. It requires successful DNS inspection in both snapshots and usable firewall inspection evidence, then compares resolver addresses, resolv.conf symlink target, NetworkManager/systemd-resolved runtime markers, and the complete firewall summary. Unavailable or incomplete inspection fails closed; the iptables fallback is accepted only when both IPv4 and IPv6 listing commands succeeded. Route and interface inventories are deliberately excluded because those are resources the TUN activation is expected to add. The caller must capture the baseline before any activation mutation and refresh the current snapshot immediately before readiness evaluation. This comparison is evidence of observed configuration stability, not a guarantee against changes after the snapshot.

## Live managed-core outbound socket-mark probe

A Linux readiness entry point now launches the fixed, validated diagnostic helper and requests read-only INET_DIAG mark records for the persisted managed-core process, an exact expected peer, and a selected transport. The process identity is checked before and after the helper round trip. The response must echo the requested peer and transport, carry the requested mark/mask policy, and contain consistent matching records attributed to sockets owned by that process. Missing diagnostics, mismatched policy, absent marked sockets, or process replacement fails closed. This observes existing sockets only; it does not set marks, create traffic, or mutate kernel networking state. It is still only one signal and does not prove successful end-to-end proxy traffic.

## Active managed-core listener probe

The readiness layer now provides a bounded Linux loopback TCP probe tied to the persisted managed-core process identity. It rejects wildcard/non-loopback endpoints and zero ports, limits the connection timeout to five seconds, verifies the exact process identity before connecting, checks the connected peer address, and verifies the process identity again before accepting the observation.

This is one independent readiness signal only. A successful connection does not cryptographically prove that the listening socket belongs to the managed core, so the caller must supply the dedicated listener endpoint from the selected core configuration and retain the manifest-bound process identity. The probe does not send application credentials or modify routes, interfaces, DNS, firewall state, or socket marks.

The probe does not establish TUN interface ownership, policy-route correctness, marked physical egress, socket-mark behavior, or end-to-end proxied traffic. The aggregate readiness gate still requires all of those independent evidence fields; this addition does not enable TUN activation.

## End-to-end proxied-traffic readiness contract

The composed preflight deliberately leaves `proxied_traffic_verified` false. The final dataplane signal must be produced by an explicit, bounded traffic-verification stage; callers must not promote this field merely because a listener accepts connections, a route lookup selects physical egress, or a socket carries the expected mark.

A future traffic verifier must use a caller-selected destination and protocol that are documented as safe for diagnostic traffic, enforce a strict timeout and response-size ceiling, and avoid credentials or user data. It must distinguish a direct request from a request through the selected core's proxy path, and must bind the observation to the activation generation and the exact managed process identity. DNS resolution must be controlled or separately evidenced so the check cannot silently rely on host DNS changes. The probe must not change routes, marks, firewall rules, DNS, or interface state.

A result is valid only when the probe confirms the expected response and its process/activation binding remains valid at the end of the observation. Timeout, unsupported proxy transport, ambiguous routing, response mismatch, or process replacement is a failed readiness signal. A diagnostic traffic probe is not a general-purpose benchmark and must not run automatically during ordinary loopback activation.

Until such an implementation is connected to the lifecycle gate, the readiness evidence remains incomplete and public TUN activation stays disabled.

## Bounded proxy-traffic evidence validation

The readiness module now provides a Linux-only validator for externally collected end-to-end traffic observations. It binds evidence to activation UUID, generation, and the exact managed process identity, rechecks process liveness before and after validation, and enforces caller-specified elapsed-time and response-size bounds (with hard ceilings of thirty seconds and one MiB). The observation must indicate that an expected response was independently verified; metadata, listener acceptance, and routing evidence alone are not sufficient. This validator does not execute network requests and is not a traffic probe implementation. The lifecycle gate remains disabled until an actual safe probe implementation and service-manager integration provide this evidence.

The readiness API also exposes a promotion function that accepts only a validated traffic observation and then evaluates the full existing readiness gate. This does not make the observation self-authenticating: the traffic executor is responsible for proving proxy-path semantics and setting the response-verification result accurately. The function only validates identity/bounds and composes readiness evidence; it cannot independently establish that a remote service response traversed the proxy.

The traffic-observation API includes conservative reusable bounds: five seconds and 64 KiB by default, with validation allowing explicit bounds up to thirty seconds and one MiB. These are policy limits for a future executor, not a promise that any traffic probe is currently available or run automatically.


## Bounded SOCKS5 CONNECT diagnostic

A Linux-only SOCKS5 CONNECT probe is available as a diagnostic API. It uses an explicit IP-address destination (IPv4 or IPv6), avoiding DNS resolution, sends no application payload, and accepts only the SOCKS5 no-authentication negotiation and a successful CONNECT reply. It uses bounded read/write timeouts and rechecks the exact managed process and listener socket ownership around the probe. This demonstrates a successful proxy tunnel establishment to the requested endpoint, not application-level content validation or general Internet reachability.


## Diagnostic probe constraints

The SOCKS5 diagnostic is opt-in at the API caller level and does not run during activation automatically. Callers must select a concrete destination address and port; the probe does not resolve names, use credentials, or mutate host routes, resolver settings, firewall rules, or system proxy settings. A refusal or timeout is diagnostic failure only and must not trigger network repair or resource deletion.


## SOCKS5 readiness evidence limits

A successful CONNECT response indicates that the core accepted the SOCKS request and reported establishment of a tunnel to the explicit endpoint. It does not independently verify response content, TLS, HTTP, DNS, or a complete application transaction. This diagnostic therefore cannot alone promote readiness to fully verified proxied traffic, and the public TUN activation gate remains disabled.


## Probe ownership and lifecycle

The diagnostic must be run only against a listener endpoint recorded for the managed activation. Process identity and listener socket ownership are revalidated during the exchange to reduce PID reuse and listener substitution risks. The probe creates a short-lived loopback TCP connection and leaves tunnel cleanup to ordinary connection teardown; it is not a supervisor, recovery executor, or traffic-routing activation path.


## Detailed SOCKS5 probe result and address guardrails

The diagnostic can return structured metadata including its listener, requested destination, measured duration, and request-side protocol byte count. Byte accounting is limited to the request exchange and is not represented as application payload or received-content verification. The diagnostic rejects unspecified, loopback, multicast, link-local, and zero-port destinations; it does not attempt to classify every special-purpose or globally routable range. Operators remain responsible for selecting a suitable explicit endpoint.

The probe also enforces an aggregate duration ceiling in addition to socket operation timeouts. The aggregate bound is conservative and is not a readiness SLA. Failures are reported without automatic retries, activation, or repair.


## First-draft implementation priority

The implementation roadmap is now explicitly focused on a connected first functional draft: (1) device ownership and core handoff, (2) real managed-core launch/configuration, and (3) routing transaction and activation orchestration. Broad edge-case hardening and comprehensive fault-injection tests are deferred until this draft is connected. Essential exact ownership, rollback and safety constraints remain mandatory. See `docs/TUN_FIRST_DRAFT_PLAN.md`. Public TUN activation remains disabled during development.


## First-draft integration status (2026-11-19)

The implementation review confirms that broker transaction code, native TUN config adapters, and an isolated systemd launcher are separate pieces; the public activation function does not orchestrate them. Do not treat this as completed TUN mode.

The intended handoff is broker-created and broker-retained interface ownership, with the core attaching to the named existing device under the activation user's credentials. Interface-name matching is necessary but not sufficient evidence of successful attachment. The integrated start path must capture the actual interface identity, ensure the core is launched only after the interface exists, and tie both to the same activation generation. If core attachment cannot be established, exact-generation rollback must run.

Sing-box and Xray adapters already produce a TUN inbound using `tun-proxyctl`, disable automatic route/DNS ownership, and apply a mark to the proxy outbound. Mihomo's TUN adapter remains intentionally unsupported. These adapters are configuration groundwork, not a verified handoff. Phase 1–3 integration remains unfinished, and public activation stays gated.
## Integration checkpoint (2026-11-20)

The typed mutation broker/helper, journal backend, manifest adoption, process identity binding, generation-scoped lifecycle events, and broker-backed supervision/recovery APIs exist as separate components. They are not yet connected to the public activation/stop workflow. The existing isolated systemd launcher remains a separate path.

A critical device handoff gap remains: native Sing-box and Xray TUN config generation emits an inbound for `tun-proxyctl`, while the mutation broker independently creates an exclusive TUN descriptor. The code does not establish a verified attach-existing-device contract between that descriptor and either core. Name-based interface presence is not attachment evidence. Activation must remain disabled until this ownership/handoff issue, end-to-end readiness/traffic verification, and CLI-independent recovery supervision are connected and reviewed.


## Draft orchestrator checkpoint (2026-11-20)

A draft unified orchestrator façade is now present in `src/tun/activation_orchestrator.rs` and exported from `src/tun/mod.rs`. It composes the existing broker activation, lifecycle adoption/process binding, generation-specific recovery, and supervision-resume APIs. The façade accepts an already-launched process identity and does not itself launch or configure the core.

Routing policy transaction integration is composed through the existing `MutationHelper::activate` request, whose broker path creates the interface, binds routes to the kernel-assigned ifindex, installs route/rule policy, and commits its ownership manifest. The façade provides recover/resume entry points for generation-bound cleanup and supervision.

This remains a draft integration layer, not a complete end-to-end activation pipeline: core launch/configuration ordering and native TUN attachment behavior are not reconciled here, nor are traffic-flow readiness checks connected. No tests or local builds were run.




## Integration continuation checkpoint (2026-11-20)

Repository access was re-established and the current main branch was inspected. The draft `ActivationOrchestrator` composes the typed broker transaction, Prepared-manifest adoption, core-process identity binding, Running transition, exact-generation recovery, and supervision-resume entry points. Its routing activation delegates to the mutation broker, which retains the TUN descriptor and applies the journal-backed route/rule transaction against kernel-assigned interface identity.

The orchestrator is not yet wired into `services::activation::activate`; that public path still rejects TUN mode before config generation. The device handoff is still a blocking integration issue: adapter-native TUN config requests a named interface while the broker separately creates an exclusive TUN attachment. There is no established descriptor transfer or attachment proof between those implementations. Simply enabling the public path or calling the orchestrator after launching the core would risk duplicate/conflicting interfaces and incorrect activation ordering. Therefore the next concrete integration must define and implement one attachment contract (or use a core-supported externally supplied TUN descriptor), then connect launch/stop/readiness around it. No local tests/builds or host networking actions were run.


## Orchestrator validation and recovery draft batch

The unified activation façade now validates request-local invariants (activation ID/generation, Linux interface-name length, positive and distinct policy priorities, table ID, and mark/mask constraints) before invoking broker mutations. It rejects an existing manifest before a new activation and offers explicit-current-generation recovery. Added compact unit checks for request validation. This remains a draft: the public activation service is still gated, and native core TUN attachment to the broker-retained descriptor is not established. No host networking changes, build, or tests were run by the authoring workflow.


## Unified orchestrator monitor and request validation update (2026-11-20)

The draft activation façade now includes a monitor-current entrypoint for persisted Running activations: it validates phase, obtains the recorded process identity, opens a process handle, and delegates monitoring to the managed lifecycle path. Request/recovery identity checks are canonical lowercase UUID checks, interface names are constrained to Linux-safe characters and IFNAMSIZ, and table/priority values must be in the Proxyctl allocation ranges. These changes remain façade-level integration and do not remove the public activation gate. Core descriptor attachment and live dataplane readiness are still unproven and must not be bypassed.


## Attachment evidence contract (continuation)

The draft Linux attachment-contract module rejects incomplete or mismatched evidence fields, non-passed-descriptor mechanisms, and evidence that does not bind to activation identity/generation/interface and a verified process identity. An orchestrator convenience method requires this contract before delegating. These checks are not proof of descriptor transfer and do not alter the activation gate. Native-core integration must produce independently verifiable evidence before this API can be used to enable activation.


### SCM_RIGHTS transport implementation boundary (2026-11-20)

The Linux-only descriptor_transfer module sends and receives one descriptor over an existing Unix stream. Receive uses MSG_CMSG_CLOEXEC and validates the marker and ancillary header shape. This does not authenticate the peer, launch the core, or establish core adoption. A successful sendmsg is not an attachment receipt. Do not populate AttachmentEvidence from send success; require a child-side acknowledgement tied to the pinned process and activation generation, plus a core-specific supported descriptor consumer. Public activation remains disabled until end-to-end integration exists.


### Generation-bound descriptor handoff protocol (2026-11-20)

`src/tun/attachment_protocol.rs` defines a bounded versioned offer and acknowledgement carrying activation UUID, generation, interface name, and a 256-bit nonce. It provides SO_PEERCRED verification against the exact captured process identity and a receiver helper that sends a positive receipt only after a caller-supplied core-adoption callback succeeds. The callback must be implemented by a verified core-specific adapter; it must not simply retain or discard the descriptor and report success. The protocol is not yet connected to any supported native core. Keep activation disabled until a real adapter consumes the descriptor and the parent verifies the acknowledgement and interface identity.


The composed send_attachment and receive_and_adopt APIs enforce this ordering: verify socket peer, validate offer, transfer descriptor, perform core-specific adoption, and only then acknowledge. They remain unused until a supported adapter exists. Never provide a no-op adoption callback.


The composed attachment exchange applies a fixed five-second socket read/write timeout. This bounds stalled peers but does not replace a supervisor deadline or a core-specific readiness probe.


## Native-core attachment capability inventory

Do not infer descriptor adoption from a native TUN configuration. The adapter trait reports one of three acquisition modes: externally supplied descriptor via a documented environment key, native device creation, or unsupported. Xray's Linux `XRAY_TUN_FD` path is documented upstream; the current Proxyctl launch path does not yet pass the broker-retained descriptor into Xray. The current sing-box adapter requests native named-device creation and therefore does not match the broker's exclusive descriptor owner. Mihomo remains unsupported in this marked TUN design. These declarations are used to make the integration gap explicit, not to authorize activation.


## Broker-owned descriptor export (2026-11-20)

The mutation broker now has a typed, generation-scoped descriptor-export request. It only exports a descriptor while the exact activation backend remains live in the broker, validates the authenticated same-UID client, and transfers one descriptor using the existing close-on-exec SCM_RIGHTS primitive. The client API returns an owned descriptor; stale generations, absent backends, and broker-restart cases fail closed. This is a transport/export capability, not a native-core launch integration: callers must still use a verified core adapter and must not claim attachment until core readiness is independently established.


## Xray descriptor inheritance primitive (2026-11-20)

Added a Linux Xray launch helper for the documented `XRAY_TUN_FD` contract. It duplicates the broker-exported descriptor above stdin/stdout/stderr with close-on-exec retained in the parent, sets the environment variable on the child command, and clears close-on-exec only in the forked child immediately before exec. The owner must remain alive through `Command::spawn`. This is a launch primitive, not yet wired into the unified activation orchestrator; it does not itself prove that Xray initialized the interface or that traffic flows. Keep public activation gated until process identity, interface identity, listener readiness, and bounded proxied traffic checks are composed.


## Xray broker-to-process launch composition (2026-11-20)

Added a Linux Xray launcher that requests the exact activation generation's descriptor from the mutation broker, duplicates it through the Xray FD helper, and spawns the managed Xray executable with `XRAY_TUN_FD`. It captures the child ProcessIdentity immediately and kills/reaps the child if identity capture fails. The helper requires an existing absolute executable and config path. It does not apply broker activation itself, commit lifecycle state, wait for the listener/interface, or verify proxied traffic; those remain mandatory orchestration steps before activation can be considered Running.


## Xray kernel attachment verification (2026-11-20)

Added a Linux verifier that pins the exact Xray process identity, checks the expected interface's kernel TUN marker and ifindex, then scans that process's `/proc/PID/fdinfo` records for an exact `iff:` interface-name match. It verifies the process identity and pidfd state again after inspection. This is stronger than checking that the interface merely exists: it establishes that Xray holds a descriptor attached to the expected TUN interface. It still does not prove that packets traverse the proxy dataplane; bounded proxied-traffic verification remains required.


## Xray composed readiness gate (2026-11-20)

Added `verify_xray_readiness` to compose Xray's exact process/fdinfo attachment check with fresh core-listener ownership, kernel TUN interface identity, live route-policy inspection, generation/process-bound bounded traffic observation, and the shared socket-mark/readiness validator. Host DNS/firewall and physical-egress evidence remain explicit caller inputs and must come from their independent probes. A SOCKS5 CONNECT alone is not promoted to successful proxied traffic. The function does not yet launch or mutate the host network; it is the fail-closed post-launch readiness gate.


Xray startup now also has a bounded attachment wait helper. It pins the launched process, checks for early exit, and polls the exact kernel TUN fdinfo attachment for at most five seconds. This wait is only descriptor-adoption confirmation; the composed readiness gate remains responsible for listener, routes, socket mark, host invariants, physical egress, and proxied traffic.


A composed Xray startup primitive now combines broker descriptor export, child launch, and the bounded kernel attachment wait. It returns the child only after the exact interface attachment is observed. If attachment fails or times out, it kills and reaps the child it spawned; the caller must still request exact-generation broker rollback. It does not mark the activation Running or assert dataplane readiness.


## Staged lifecycle commit (2026-11-20)

Split managed activation into two explicit stages: `prepare_managed_activation` commits the broker-owned kernel transaction and adopts the exact Prepared manifest; `commit_managed_process` binds a process and transitions to Running. This permits a core-specific launcher and attachment/readiness verifier to run between Prepared adoption and Running commit. The compatibility wrapper remains for existing callers, but new TUN integration must use the staged path and invoke exact-generation broker recovery if launch or readiness fails.


## Staged Xray activation entrypoint (2026-11-20)

Added `ActivationOrchestrator::activate_xray_with_readiness`. It applies the broker transaction and adopts Prepared first, launches Xray through the broker descriptor path, waits for kernel-confirmed attachment, then invokes a mandatory caller-provided readiness callback while the manifest is still Prepared. Only after that callback succeeds does it bind the pinned process and commit Running. Launch/attachment failures and readiness failures request exact-generation broker recovery; readiness failure also kills and reaps the child. Commit failure terminates the child. There is no default readiness callback, and the public CLI TUN gate remains unchanged.


The staged Xray orchestrator now obtains the expected interface index from the broker-committed Prepared manifest itself, and verifies that manifest token, phase, interface name, table, and positive kernel-assigned index match the request. Callers no longer provide or guess an interface index before kernel creation.


Xray rollback now uses the pinned process identity and a two-second pidfd-based termination bound before reaping the child. It does not rely on an unbounded `Child::wait` after a failed `kill` call. If termination cannot be confirmed, the error is surfaced alongside broker recovery status.


Xray launch now rejects symlinked/non-regular executable and config paths, requires an executable bit on the core binary, and requires the config to be owned by the current user with mode 0600-equivalent private permissions before canonicalizing both paths. This prevents the descriptor launcher from silently following a replaced config symlink or executing a non-executable file.


## Interrupted Prepared activation recovery (2026-11-20)

Restarted supervision now treats a persisted Prepared manifest as an interrupted start and requests exact-generation broker cleanup immediately. This covers crashes after kernel resources were committed but before the core process identity was bound and Running was committed. The operation remains journal-backed and generation-scoped; no broad interface or route sweep is performed.
