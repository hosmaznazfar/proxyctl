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

A serialized operation coordinator uses activation generations to prevent concurrent start/stop/switch races. The recovery supervisor is independent of the CLI and monitors the exact core process instance (PID plus start time/pidfd and canonical executable). Opening a pidfd is race-aware: if the pinned pidfd is already readable, the process has exited and recovery may proceed; otherwise the PID start-time and executable must still match. A PID reused by a live replacement is never accepted. Core exit triggers cleanup.

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
`/sys/class/net`, retaining its exact name, numeric ifindex, and whether the
kernel exposes TUN flags. Missing or malformed ifindex data and duplicate
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

The private TUN runtime store now has a separate bounded transaction journal (256 KiB, at most 256 operations). It records generation-scoped operation intents before a future backend attempts interface/route/rule mutation, then records the observed fingerprint and cleanup completion as separate atomic, fsynced updates. Journal files use the same private directory, owner, no-symlink, no-hard-link, and 0600 protections as the active manifest. Cleanup cannot remove a journal until every recorded operation is marked removed. Invalid transitions, duplicate resource keys, wrong generations, malformed fingerprints, and oversized records fail closed. This is durable filesystem groundwork, not yet wired to a concrete rtnetlink backend. An Intent without an observed fingerprint is deliberately ambiguous after a crash; recovery must inspect and establish exact ownership or preserve the journal, never delete by a guessed name.


The journal recovery classifier now distinguishes unresolved intent, applied resource, removed resource, and an intent explicitly confirmed absent by exact kernel inspection. An unresolved intent never authorizes deletion. It can be closed only through the explicit absent-evidence transition; an applied resource requires fingerprint-based compare-and-delete before it can be marked removed. Journal deletion accepts only removed or confirmed-absent operations.


- **Offline journal recovery planner:** recovery now evaluates a fresh exact kernel-inventory map against the durable write-ahead journal in reverse creation order. An unresolved intent is marked absent only when the inventory explicitly contains that exact key as absent; an unobserved key or any present resource without a recorded fingerprint remains a conflict. Applied resources already absent can be marked removed; matching resources produce only a compare-and-delete decision carrying the recorded fingerprint; changed resources are preserved. The planner performs no mutation and is not yet wired to a concrete rtnetlink backend.

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

A separate `proxyctl-tun-helper` binary now exposes only one operation: accept one bounded Unix-socket request and return same-UID, pidfd-bound socket-mark diagnostics. It accepts only `--socket PATH`; it has no shell, executable, route, link, DNS, firewall, or generic command interface. It requires its effective/permitted capability sets to equal exactly `CAP_NET_ADMIN`, requires an inheritable set of zero, enables `no_new_privs`, disables dumpability, verifies a caller-owned private runtime directory, serves one request, and exits. The helper is a separate Cargo binary. A Linux-only controller probe now launches only the fixed `/usr/libexec/proxyctl-tun-helper` path, verifies that it is a root-owned non-writable non-setuid executable, clears its environment, supplies only the private socket path, checks the helper-created socket identity/permissions, authenticates the helper UID, performs one bounded request/response exchange, and requires the helper to exit and remove its socket. Activation UUIDs are validated before deriving the socket filename. The complete diagnostic collection window is bounded to ten seconds. The controller exposes the returned mark as readiness evidence only when at least one exact-peer process-owned record is present, every record matches the configured mask/value, and all observed records agree on the mark. The common readiness evaluator now has a Linux entry point that consumes this validated broker response directly, fills the observed-mark field itself, and then evaluates the remaining independently supplied evidence. This prevents that entry point from trusting a caller-invented mark value, but route/interface, physical-egress, proxied-traffic, DNS, and firewall evidence collection is still not implemented as one live probe.

`packaging/install-tun-helper.sh` installs it at `/usr/libexec/proxyctl-tun-helper` with only `cap_net_admin=ep`; `packaging/remove-tun-helper.sh` removes the file and capability. The scripts refuse a setuid fallback and do not create sudoers rules, polkit policy, or service units. Installation is an explicit administrator action and has not been run as part of this repository change. This is a diagnostic-only privilege boundary, not the privileged TUN mutator: it does not create interfaces, add routes/rules, or clean kernel resources. A reviewed distribution package, capability bounding policy, helper/controller lifecycle integration, and independent recovery remain outstanding.

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
