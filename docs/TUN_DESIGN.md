# Linux TUN design

> Status: **activation disabled**. Only read-only inspection is available.
> Scope: Linux
> Goal: eventually use the selected managed core's native TUN implementation without adding a second packet-processing daemon.

## Safety incident and current decision

A live sing-box TUN run was associated with loss of internet connectivity. Review of the implementation found a critical recovery gap: shutdown compared the current interface/route/rule/DNS state with a saved baseline, but it did not restore Proxyctl-created routes or rules. If the core was force-killed or the application exited unexpectedly, a baseline mismatch could be detected, but the network was not repaired.

That is not an acceptable recovery guarantee for a feature that changes the host routing table. Therefore:

- `proxyctl use NODE --core CORE --tun` is rejected before starting a process, requesting sudo, or changing networking.
- `proxyctl tun status` remains available and read-only.
- Ordinary `proxyctl use NODE --core CORE` remains loopback-only.
- Benchmarks, setup, updates, and normal activation do not create TUN devices or modify routes, DNS, resolver configuration, or firewall rules.
- No live TUN test should be run while this restriction is in place.

## Non-negotiable isolation requirements

1. Proxyctl may only create, inspect, and remove network resources it can positively identify as Proxyctl-owned.
2. It must never flush routing tables, reset DNS, replace the resolver configuration, or remove interfaces/rules belonging to another application.
3. It must coexist with V2rayN, NetworkManager, Docker, and other VPN clients. A foreign TUN interface or unrelated route change must not be treated as Proxyctl-owned.
4. A single selected managed core remains the only Proxyctl core process active at a time.
5. A core crash, forced termination, Proxyctl crash, startup failure, normal stop, and machine restart must all have a defined, tested recovery path.
6. If ownership cannot be proven, recovery must stop and preserve diagnostics rather than modifying ambiguous host state.

## References and transferable design lessons

- v2rayN uses the selected core's native TUN functionality and has a dedicated core lifecycle manager. Its Linux privilege approach is a reference, not a reason to run all of Proxyctl as root.
- Ninety's lifecycle design reinforces serialized operations, explicit process ownership, cleanup completion before starting a replacement, and the distinction between process liveness and dataplane health. Its Windows-specific WFP implementation is not portable to Linux.
- Neither project removes the need for Proxyctl to prove Linux route ownership and crash recovery on its own supported host environments.

## Planned architecture before re-enabling TUN

The following are design requirements, not claims about current implementation:

- A serialized activation coordinator with operation identity/generation, preventing concurrent start/stop/switch operations.
- A durable ownership manifest written before the first network mutation. It must record exact resource identifiers and the original state necessary for safe restoration.
- A recovery helper whose lifecycle survives the managed core and Proxyctl process. Its cleanup must be invoked for normal stop, core failure, forced process termination, and service teardown.
- Explicit route/rule ownership markers or a Proxyctl-managed routing table/priority range. Do not rely on comparing the entire machine snapshot and then broadly restoring it.
- Idempotent recovery that removes only exact resources still matching the manifest. It must not overwrite legitimate changes made by NetworkManager, Docker, V2rayN, or the user while TUN was active.
- A startup gate that verifies process identity, systemd unit identity, interface ownership, local SOCKS/HTTP listener readiness, physical egress selection, and an end-to-end proxied health check before declaring TUN usable.
- DNS integration and firewall auto-redirect remain out of scope until their ownership and rollback models are separately designed. No automatic DNS, nftables, or iptables changes are allowed by default.
- If the selected core's native route manager cannot meet the ownership and recovery contract, Proxyctl must manage a narrowly scoped route table itself or keep that core's TUN mode unsupported.

## Process identity

Normal activation presents the process as `proxyctl-core` in argv[0] and Linux's short `comm` name. This is a display identity only. `/proc/PID/exe` remains the canonical path to the actual Proxyctl-managed upstream binary and is the authoritative executable identity for ownership checks, updates, and shutdown. Proxyctl must never fake the executable path or signal processes based only on their display name.

## Verification gates

### Gate 1 — offline automated tests

Use fake child processes, fake systemd/ip command runners, and synthetic route/rule snapshots. Tests must cover:

- Exact ownership matching and refusal to touch foreign resources.
- Cleanup after startup failure, normal stop, core crash, SIGKILL, Proxyctl crash, and simulated reboot recovery.
- Idempotent recovery and partially completed cleanup.
- Preservation of third-party routes/rules/interfaces and DNS state.
- Concurrent start/stop/switch serialization.
- Process identity consistency while retaining canonical executable verification.
- No real TUN device, route, rule, DNS, or firewall mutation in tests.

### Gate 2 — native configuration validation

Validate generated configurations using the installed managed core binaries, but do not start a core in TUN mode and do not create host network resources.

### Gate 3 — controlled live test

Only after Gates 1 and 2 pass and the recovery design is reviewed should a live test be considered. It must start from a recorded read-only network snapshot, have an independently available recovery path, use one selected node/core, verify end-to-end traffic, and prove exact cleanup. Do not use the user's normal V2rayN profile or alter another application's resources.

Until all gates are complete, TUN activation remains unavailable.
