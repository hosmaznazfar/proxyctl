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

The selected mechanism uses a named nftables set of type `cgroupsv2`:

```nft
table inet proxyctl {
    set external_vpn_cgroups {
        type cgroupsv2
        elements = { <kernel-cgroup-id> }
    }

    chain output {
        type route hook output priority mangle; policy accept;
        socket cgroupv2 level <scope-level> @external_vpn_cgroups meta mark set 0x1
    }
}
```

The socket expression extracts a 64-bit kernel cgroup ID at the requested hierarchy level and looks it up in the typed set. This avoids nftables' inline path-to-ID parser, which fails for the literal escaped systemd scope name on the current host.

The ID must be the kernel cgroup ID (`cgroup_id()` / kernfs node ID), not the directory's `st_ino`. Linux kernel selftests obtain it from the cgroupfs file handle returned by `name_to_handle_at()`; the cgroup v2 file handle is eight bytes. Proxyctl resolves this handle from an opened/pinned cgroup directory using `AT_EMPTY_PATH`, then rechecks process membership, directory device/inode, and kernel cgroup ID before trusting the target.

The numeric ID is dynamic and can change when a cgroup is destroyed and recreated. Proxyctl therefore records the exact ID and pinned directory identity for the selected process instance, revalidates them before installation, and journals the corresponding set element for generation-scoped cleanup. The nftables set is private to Proxyctl; it does not depend on systemd's `NFTSet=` integration, which systemd documents as unsupported for per-user service managers.

The expression belongs in a dedicated Proxyctl-owned `inet` table and an output base chain of type `route`. The matching rule sets only the packet mark bits used by the active Proxyctl bypass RPDB selector. A route-type output chain is required because changing the packet mark must cause the kernel to reconsider the route. See the nftables socket-expression and route-chain semantics in the upstream manual.

Because nftables resolves the path to a kernel cgroup identity at rule installation, deleting and recreating a cgroup at the same textual path must not silently transfer the exemption. Proxyctl must compare the current cgroup directory identity and process membership before installation and during lifecycle checks; stale rules must be removed only through the exact journaled ownership record.

Important constraints:

- The socket expression is a socket lookup. It is intended for packets associated with an existing full TCP/UDP socket; it is not a general PID matcher for arbitrary packets.
- Kernel support depends on `CONFIG_SOCK_CGROUP_DATA`; nftables userspace version alone is not proof that the running kernel supports the expression.
- The cgroup v2 level is relative to the cgroup v2 hierarchy. The selected scope must be matched at its exact hierarchy level, not at a shared ancestor such as `user.slice`, `user@UID.service`, or `app.slice`.
- The exact cgroup path is dynamic. Systemd scope names can contain transient suffixes. Never hardcode a scope name or assume a fixed depth.
- The cgroup path must be canonicalized beneath the mounted cgroup v2 root, and its identity must be rechecked before rule installation.
- A selected cgroup disappearing, changing identity, or becoming ambiguous must not broaden the match. The feature must fail closed and preserve enough state for safe cleanup.
- Existing established connections may need to reconnect before their routing behavior is fully representative. Readiness tests must establish fresh connections after the bypass is installed.
- IPv4 and IPv6 must both be covered by the same `inet` policy, and tests must verify that neither family leaks into the Proxyctl TUN.

The first implementation target is the user's current CachyOS system: Linux `7.3.6-1-cachyos`, nftables `1.1.7`, unified cgroup v2, and a systemd-created per-application scope. The kernel configuration reports `CONFIG_SOCK_CGROUP_DATA=y`, `CONFIG_NF_TABLES=m`, and `CONFIG_NFT_SOCKET=m`. This confirms the relevant features were configured, but the latter two are modules and configuration alone does not prove they are currently loadable, loaded, or usable. Runtime capability detection must verify the nftables socket expression without changing live networking before the feature is enabled.

The initial provider will discover process membership through procfs and resolve the cgroup2 mount from mountinfo. It will not call systemd APIs or assume a fixed scope name. This is sufficient for the current systemd application scope while keeping the discovery interface independent so other Linux cgroup layouts can be added later.

## Linux distribution portability

This feature is Linux-only but must not be CachyOS-specific. The implementation must use stable kernel interfaces and discover runtime capabilities instead of relying on distribution identity, package manager, release naming, or hardcoded filesystem locations.

Supported environments are determined by capabilities, not a distro allowlist:

- A unified cgroup v2 hierarchy mounted and readable by the privileged supervisor.
- Kernel support for cgroup socket metadata and nftables socket matching (including `CONFIG_SOCK_CGROUP_DATA`, `CONFIG_NF_TABLES`, and `CONFIG_NFT_SOCKET`, built in or available as loadable modules).
- A compatible nftables userspace tool and kernel netlink API.
- Permission to create and own a dedicated nftables table and output route chain without taking ownership of another firewall manager's rules.
- The existing Proxyctl Linux TUN, routing, and privilege prerequisites.

The first usable target is an already isolated systemd application scope on the current CachyOS installation. The implementation resolves cgroup v2 membership from `/proc/<pid>/cgroup` and the cgroup2 mount from `/proc/self/mountinfo`; it does not call systemd APIs, depend on systemd's transient scope naming convention, or move arbitrary processes. The discovery contract is kept separate from the nftables backend so non-systemd cgroup v2 providers can be added later.

The feature must detect unsupported environments and report a precise reason. It must not silently fall back to UID-wide matching, executable-name matching, iptables rules, broad route exclusions, or a different mechanism with weaker isolation. In particular, cgroup v1-only systems do not satisfy this feature's initial requirements; they should continue to run ordinary Proxyctl features, while this optional coexistence feature reports that unified cgroup v2 is required.

Runtime discovery must account for distro differences in nftables binary location, module loading policy, cgroup mount location, and firewall ownership. Do not assume `/usr/sbin/nft`, `/sys/fs/cgroup` without mount discovery, or permission to load kernel modules. Proxyctl should not automatically load modules or install packages. If a required module is unavailable, explain the missing capability and leave the host unchanged.

A capability probe must be non-mutating with respect to the active ruleset. Prefer an isolated network namespace for syntax/kernel-expression validation when available; otherwise use an offline parser check plus a safe kernel capability query. Do not create a temporary rule in the host's active output hook merely to test support.

The initial inline path selector was rejected for the selected v2rayN scope's literal `\\x2d` sequence. A follow-up check accepted the named-set form (`type cgroupsv2` with `socket cgroupv2 level N @set`) in an isolated network namespace. This proves parser/kernel acceptance of the set expression, but does **not** yet prove correct kernel-ID resolution, live socket matching, TCP/UDP behavior, dual-stack routing, or coexistence under a live Proxyctl TUN session.

Proxyctl now exposes the same non-mutating check through:

```text
proxyctl tun bypass probe --pid <PID>
```

The command re-inspects the live process and cgroup, resolves its kernel cgroup ID from the pinned cgroupfs file handle, locates trusted root-owned `sudo`, `unshare`, and `nft` executables, and invokes them directly without a shell. It checks a numeric `cgroupsv2` set element and socket expression inside a temporary network namespace, then revalidates process, directory, and kernel cgroup identities. A successful probe changes no host firewall, route, cgroup, or process state.

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
- canonical cgroup v2 path and cgroup directory device/inode;
- kernel cgroup ID obtained from the cgroupfs file handle (never substitute `st_ino`);
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

## First implementation milestone

The first user-facing inspection command is:

```text
proxyctl tun bypass inspect --pid <PID>
```

It is read-only. It accepts only a live process owned by the invoking UID, pins and verifies the process instance, resolves its unified cgroup v2 membership and mount, and reports the exact hierarchy path, nftables level, and cgroup directory identity. It does not invoke nftables, move the process, install a bypass, or change routes/firewall state.

This command validates the process/cgroup discovery layer on the current CachyOS system before the nftables capability probe and transactional rule integration are introduced.

## Required validation before enabling

1. Read-only capability probe confirms cgroup v2 socket matching is supported by the running kernel and nftables userspace. Use nftables check mode (`nft --check --file -`) with a candidate typed set and numeric cgroup ID; check mode validates commands without applying them.
2. A disposable, non-production cgroup scope can be matched exactly without matching its parent or sibling scopes.
3. A disposable test verifies that TCP and UDP sockets in the selected cgroup receive the bypass mark, while sockets in the same UID but another cgroup do not.
4. Both IPv4 and IPv6 route lookups use the main table for the selected scope and Proxyctl's TUN table for ordinary applications.
5. Fresh outbound connections from a second VPN core succeed while Proxyctl TUN is active; ordinary application traffic still traverses Proxyctl.
6. Same-core coexistence is tested with two distinct cgroups running the same core executable.
7. Existing nftables tables and chains remain byte-for-byte/semantically unchanged.
8. Failure injection covers target exit, PID reuse, cgroup deletion, nftables rejection, partial transaction, supervisor termination, and recovery.
9. The existing dual-stack readiness, process attachment, journal, and cleanup guarantees remain mandatory.

The current milestone adds read-only process/cgroup inspection and a non-mutating check of the numeric set-based selector. It does not install an nftables rule or change host networking.
