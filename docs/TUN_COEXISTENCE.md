# TUN coexistence architecture

> Decision status: accepted design; implementation is not enabled.
> Scope: explicitly selected external VPN applications that must keep their own upstream sockets outside Proxyctl's TUN policy.

## Problem

Proxyctl's current native TUN policy routes unmarked local traffic through its dedicated TUN table. The existing core-bypass rule protects the selected Proxyctl core by its socket mark. It does not protect a second VPN client's upstream sockets.

This matters even when the other VPN is in ordinary proxy mode and has no TUN device. Its core still creates outbound sockets to its remote proxy endpoint. If those sockets are captured by Proxyctl's default route policy, the second VPN can loop into Proxyctl.

The requirement is coexistence with other VPN clients, including clients using the same executable/core family. Executable-name matching, core-type matching, and UID-wide bypasses do not satisfy this requirement.

## Reference comparison

### v2rayN

The reviewed v2rayN implementation elevates only supported TUN core launches. Its ordinary proxy mode remains unprivileged. That is the accepted privilege-model reference for Proxyctl.

It does not provide a general cgroup-scoped exemption for unrelated VPN applications. Its privilege model must not be mistaken for a multi-VPN routing-isolation mechanism.

### Throne

Throne's Linux documentation describes core privilege options and TUN auto-redirect behavior. Its documentation warns that multiple VPNs compete for routes and DNS and recommends disabling other VPN applications while TUN mode is active.

Throne is therefore not a coexistence implementation to copy. Proxyctl must explicitly solve the second application's upstream-routing problem.

## Accepted direction

Add an explicitly managed, opt-in external-application bypass, based on a cgroup v2 socket identity rather than process names or UIDs.

The intended packet path is:

1. The user explicitly selects a running external VPN process (initial CLI shape is not yet frozen).
2. The unprivileged front end captures a stable process identity: PID, process start time, executable identity, UID, and its cgroup v2 path.
3. The privileged supervisor independently validates the process identity and resolves the cgroup path beneath the cgroup v2 mount. It does not trust a caller-supplied cgroup path as authority.
4. A narrowly scoped nftables `inet` output route chain matches sockets belonging to that exact cgroup v2 scope and sets the current activation's existing packet bypass mark.
5. Proxyctl's existing marked-traffic RPDB rule sends those packets to the main routing table. Unmatched traffic continues through Proxyctl's TUN table.
6. The cgroup exemption and its identity are recorded as generation-owned state. Stop and recovery remove only the exact Proxyctl-owned nftables objects.

This is an exemption for the selected application scope, not for all processes owned by the invoking UID. Descendant processes in the selected scope should inherit the same cgroup ancestry and therefore the same routing treatment. A second application using Xray, sing-box, or Mihomo remains distinguishable by its cgroup, not by its core binary.

## nftables mechanism and prerequisites

The candidate mechanism is the nftables socket expression:

```nft
socket cgroupv2 level <scope-level> "<exact-cgroup-path>"
```

in a dedicated Proxyctl-owned `inet` table and an output base chain of type `route`. The matching rule sets only the packet mark bits used by the active Proxyctl bypass RPDB selector. A route-type output chain is required because changing the packet mark must cause the kernel to reconsider the route.

Important constraints:

- The socket expression is a socket lookup. It is intended for packets associated with an existing full TCP/UDP socket; it is not a general PID matcher for arbitrary packets.
- Kernel support depends on `CONFIG_SOCK_CGROUP_DATA`; nftables userspace version alone is not proof that the running kernel supports the expression.
- The cgroup v2 level is relative to the cgroup v2 hierarchy. The selected scope must be matched at its exact hierarchy level, not at a shared ancestor such as `user.slice`, `user@UID.service`, or `app.slice`.
- The exact cgroup path is dynamic. Systemd scope names can contain transient suffixes. Never hardcode a scope name or assume a fixed depth.
- The cgroup path must be canonicalized beneath the mounted cgroup v2 root, and its identity must be rechecked before rule installation.
- A selected cgroup disappearing, changing identity, or becoming ambiguous must not broaden the match. The feature must fail closed and preserve enough state for safe cleanup.
- Existing established connections may need to reconnect before their routing behavior is fully representative. Readiness tests must establish fresh connections after the bypass is installed.
- IPv4 and IPv6 must both be covered by the same `inet` policy, and tests must verify that neither family leaks into the Proxyctl TUN.

The user's current environment reports Linux `7.3.6-1-cachyos`, nftables `1.1.7`, and a unified cgroup v2 hierarchy. Those facts are encouraging but do not establish `CONFIG_SOCK_CGROUP_DATA` or prove that the installed kernel accepts the cgroup socket expression. That capability must be probed without changing live networking before implementation is enabled.

## Ownership and coexistence rules

- Use a uniquely named Proxyctl nftables table, chain, and rule comments/handles with an activation identity. Do not modify or flush existing `ip`, `ip6`, `inet`, `bridge`, or `netdev` tables owned by other software.
- Never use `nft flush ruleset`, replace another application's base chain, or assume Proxyctl owns the global output hook.
- Inspect existing tables and base-chain priorities before installation. If an ordering conflict or ambiguous ownership is found, abort before mutation.
- Install the nftables objects and any required RPDB state transactionally. Journal the exact pre-state and post-state fingerprints before mutation.
- Recovery deletes only objects whose table/chain/rule identity still matches the Proxyctl journal. If an administrator or another application changed the object, preserve it and report incomplete recovery.
- Do not add a UID-wide bypass. Proxyctl and other VPN clients commonly run under the same user.
- Do not automatically exempt every process named `xray`, `sing-box`, or `mihomo`.
- Do not move arbitrary third-party processes between cgroups as a side effect. Selection must work with an already isolated systemd scope, or a separately reviewed explicit launcher integration.
- Do not install a daemon, helper package, setuid bit, or permanent file capabilities. Use the existing single Proxyctl executable and the existing TUN-only sudo supervisor.
- Normal Proxyctl proxy sessions remain unprivileged. This feature is relevant only while Proxyctl's TUN policy is active.

## Process and cgroup identity

A PID alone is insufficient because it can be reused. The selected target identity must include at least:

- PID and `/proc/<pid>/stat` start time;
- executable identity obtained from the live process, with a clearly defined policy for deleted/replaced executables;
- effective UID;
- canonical cgroup v2 path and cgroup directory identity;
- the exact hierarchy level used by nftables.

The privileged supervisor must re-read these values immediately before installation and compare them with the prepared request. It must reject a process that exited, changed cgroup, changed executable identity, or no longer belongs to the expected invoking user. The cgroup path is a selector, not an authorization token.

The first supported workflow should target an existing dedicated application scope, such as the observed v2rayN scope. A generic application running in the user's shared session cgroup must not be selected because matching that ancestor would exempt unrelated applications.

## Lifecycle and failure behavior

The external bypass belongs to the same TUN activation generation as the interface, routes, RPDB rules, core process, manifest, and session receipt.

- Add bypass state to the typed transaction/journal model; do not create an unjournaled side channel.
- Install it before the core readiness probes that depend on external VPN connectivity.
- Revalidate the target cgroup while the session is active. If the scope exits, the bypass naturally stops matching; cleanup must still remove the exact nftables rule.
- On normal stop, remove the external bypass as part of generation-scoped recovery.
- On partial installation, rollback only the objects proven to belong to that generation.
- On supervisor crash, retain journal evidence; explicit `proxyctl tun stop` must recover it.
- If nftables is unavailable, the kernel expression is unsupported, or existing rules make safe hook ordering impossible, refuse to start a TUN session when an external bypass was requested. Do not silently fall back to a broader exemption or continue with a known routing loop.
- Existing TUN sessions without an external bypass retain their current behavior until the feature is explicitly requested.

## CLI direction (not yet frozen)

The interface should make selection explicit and inspectable. A likely shape is:

```text
proxyctl tun bypass add --pid <pid>
proxyctl tun bypass list
proxyctl tun bypass remove <id>
```

The final command design must account for the fact that a TUN activation is generation-owned and privileged. Adding or removing a bypass while a session is active must go through the same supervisor and journal, not mutate nftables directly from the unprivileged CLI.

Do not implement these commands until the capability probe, nftables ownership contract, and transaction integration are complete.

## Required validation before enabling

1. Read-only capability probe confirms cgroup v2 socket matching is supported by the running kernel and nftables userspace.
2. A disposable, non-production cgroup scope can be matched exactly without matching its parent or sibling scopes.
3. A disposable test verifies that TCP and UDP sockets in the selected cgroup receive the bypass mark, while sockets in the same UID but another cgroup do not.
4. Both IPv4 and IPv6 route lookups use the main table for the selected scope and Proxyctl's TUN table for ordinary applications.
5. Fresh outbound connections from a second VPN core succeed while Proxyctl TUN is active; ordinary application traffic still traverses Proxyctl.
6. Same-core coexistence is tested with two distinct cgroups running the same core executable.
7. Existing nftables tables and chains remain byte-for-byte/semantically unchanged.
8. Failure injection covers target exit, PID reuse, cgroup deletion, nftables rejection, partial transaction, supervisor termination, and recovery.
9. The existing dual-stack readiness, process attachment, journal, and cleanup guarantees remain mandatory.

No live host networking mutation is part of the design/documentation phase.
