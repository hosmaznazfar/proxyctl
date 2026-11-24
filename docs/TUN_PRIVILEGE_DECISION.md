# TUN privilege architecture decision

> Decision status: accepted design direction; implementation remains fail-closed.
> Reference revision: v2rayN commit `91c61b1fe595994c7bcf09739ddb5dc32fde4f04`.
> Scope: Linux TUN privilege handoff and the single-executable Proxyctl session owner. This document records the architecture decision before implementation; it does not authorize TUN activation.

## Decision

Proxyctl will follow v2rayN's **TUN-only elevation model** rather than the former narrow file-capability/helper model:

- Ordinary Proxyctl commands and ordinary loopback core sessions remain unprivileged.
- Only a TUN session requests root authorization.
- The selected TUN-capable core runs in the root-authorized session and creates/opens its native TUN device using its own native configuration.
- Proxyctl remains one application package with one installed `proxyctl` executable. The hidden `__tun-supervisor` role is another invocation of that executable, not a separately installed helper, launcher, daemon binary, or systemd service.
- No setuid bit or permanent file capabilities are installed.
- TUN remains fail-closed until the launch, process-identity, resource-ownership, cleanup, and recovery gates are implemented and validated.

This deliberately matches v2rayN's operational privilege boundary. It does not copy v2rayN's shell-script construction or assume its process tracking is sufficient for Proxyctl's stronger journal/recovery requirements.

## What was verified in v2rayN

The inspected source is pinned to the revision above:

- [CoreManager.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib/Manager/CoreManager.cs) makes the sudo decision from the launch context's TUN snapshot. Linux/non-Windows TUN launches for sing-box, Mihomo, and Xray are elevated; ordinary launches and unsupported core types are not.
- [CoreAdminManager.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib/Manager/CoreAdminManager.cs) launches the selected core through `sudo` and retains a process identifier for its stop path.
- [CoreConfigContextBuilder.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib/Handler/Builder/CoreConfigContextBuilder.cs) resolves the selected profile and builds the launch context in the application before core launch.
- [CoreConfigHandler.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib/Handler/CoreConfigHandler.cs) generates the native configuration before the process launch path.
- [CoreManagerTests.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib.Tests/Manager/CoreManagerTests.cs) tests that supported non-Windows TUN launches require elevation, ordinary launches do not, and unsupported core types do not trigger elevation.

The inspected implementation therefore supports these conclusions: the application itself is not elevated for normal use; TUN is the reason for elevation; profile/configuration work occurs before core launch; and the selected core is the elevated process. The inspected tests establish the elevation decision, not a complete fault-injection proof of every launch, stop, crash, and reboot path.

## Proxyctl launch sequence

The intended sequence is:

1. The ordinary, unprivileged CLI acquires Proxyctl's activation lock and resolves the active node from the user's database.
2. It checks adapter compatibility, generates the native TUN configuration, and performs the ordinary preflight validation before asking for elevation.
3. It constructs a bounded, versioned request containing only typed launch metadata and the generated configuration payload. It must not ask the privileged process to open the user's redb database or resolve a node ID against user-owned state.
4. The CLI invokes `sudo` directly (no shell script) for the installed Proxyctl executable's hidden `__tun-supervisor` role. The request is sent over standard input; the privileged process rejects a terminal as request input and applies strict size/schema validation.
5. The supervisor derives the core selection from the closed `CoreKind` enum. It does not accept an executable path, config path, working directory, arbitrary environment map, or shell command from the request.
6. The supervisor creates private root-owned runtime/configuration state under a per-invoking-UID directory below `/run/proxyctl`, validates the staged configuration, and launches the selected managed core with the core-specific native arguments.
7. The supervisor records the exact core PID, process start identity, and executable identity, owns the TUN transaction/manifest lifecycle, monitors the core, and performs exact idempotent cleanup when the core exits.
8. `tun stop` and top-level `stop` request a privileged stop through the same executable and verify the exact recorded process/session identity before signaling or cleaning anything.

The request is a one-way launch handoff, not a remote command language. The supervisor must not accept arbitrary paths, arbitrary arguments, arbitrary environment variables, or caller-selected network operations.

## Core binary trust boundary

Proxyctl's managed core binaries currently live under the invoking user's private data directory and are installed by the unprivileged core installer after verifying the upstream release archive's SHA-256 digest. The directory and binary remain user-owned.

That fact must be explicit in the privilege design: launching a user-owned core as root means the invoking user is authorizing that selected managed core to execute with root privileges for the TUN session. A path supplied in the request must never be trusted. The supervisor must derive the expected binary location from the invoking UID and the fixed core catalog, canonicalize it, enforce the managed-directory boundary, reject symlinks/non-regular files and unsafe ownership/permission states, and avoid shell interpretation. It must not claim that these checks make a user-owned executable immutable against that same user. The user already has to authorize the root launch through sudo; the confirmation is the security boundary for running that selected core as root.

If a future threat model requires protection against a same-UID process tampering with the managed core after authorization, that requires a separately designed integrity mechanism (for example, trusted release-digest revalidation plus race-free staging, or root-owned core installation). Do not silently claim that canonical-path checks alone solve that problem.

The privileged process must not read the user's database, write root-owned files into the user's data directory, or accept a user-provided config pathname. The generated config is transferred as bounded data and staged in root-owned runtime storage with restrictive permissions.

## Core-specific behavior

The root-authorized core owns native TUN device creation/opening:

- sing-box: retain its native TUN creation contract.
- Mihomo: retain its native TUN creation contract.
- Xray: retain its native TUN inbound contract. Its external descriptor environment capability may remain a future alternative, but it is not required by this sudo-core architecture.

Do not force all cores through Xray's descriptor-passing mechanism. Keep core-specific configuration and validation in the existing adapters. Core-managed automatic route/DNS mutation remains disabled where Proxyctl's own route/journal lifecycle owns those resources.

## Process and runtime rules

- Invoke `sudo` with an argument vector; never construct a shell command or shell script from node/config values.
- The supervisor executable is the installed Proxyctl executable selected by the front-end, not a caller-supplied path. The internal role remains hidden from normal help.
- Determine the invoking UID from trusted sudo/process credentials, cross-check it, and never trust a UID supplied only in JSON.
- Use root-owned, non-user-writable runtime directories and files below `/run/proxyctl/<uid>`; verify ownership and modes on every open.
- Keep the supervisor alive independently of the invoking terminal. Background detachment must include a startup handshake so the CLI can distinguish a successfully established supervisor from an early failure.
- Track the core with PID plus process start identity and canonical executable identity (and pidfd where supported). Never use a PID alone.
- The supervisor owns the TUN manifest and write-ahead transaction journal. Cleanup removes only exact resources still matching those records.
- A supervisor/core crash or reboot must not leave a stale policy rule capable of blackholing ordinary traffic. If this cannot be proven for a platform/backend, TUN remains unsupported there.
- Foreground mode uses the same supervisor and privilege boundary but keeps the lifecycle attached for diagnostics; it does not introduce a second activation implementation.

## Differences from v2rayN

Proxyctl intentionally improves the handoff and lifecycle boundaries:

1. It sends a bounded typed request over a pipe rather than interpolating launch values into a generated shell script.
2. The privileged side derives executable selection from an enum and fixed core catalog; it accepts no executable/config paths or arbitrary command arguments.
3. It stages configuration and runtime state under a root-owned per-UID runtime directory rather than using user-owned configuration paths as privileged instructions.
4. It retains Proxyctl's exact generation manifest, write-ahead journal, process identity checks, readiness verifier, and conservative recovery behavior.
5. It refuses to claim support until supervisor crash, core crash, CLI termination, and reboot cases have an explicit safe recovery path.

## Current implementation boundary

The repository currently has:

- a hidden `__tun-supervisor` command that checks effective UID, rejects terminal stdin, reads a bounded version-1 launch specification, and then deliberately exits as not implemented;
- a version-1 request containing node ID, core enum, and listener port, but not yet the generated configuration payload;
- user-owned managed core binaries under the private data directory;
- TUN adapters with different native device-attachment contracts;
- offline manifest/journal, route/rule mutation, cleanup, and readiness groundwork;
- a closed TUN activation gate.

The existing launch specification is therefore only a bootstrap transport test. It is not yet the accepted final request contract. The next implementation slice must revise the request to carry the already-generated configuration (with a separately justified byte limit), remove the privileged need to resolve the node ID from redb, and add tests for the exact request/credential boundary. No core launch, root runtime creation, or host network mutation is part of this documentation decision.

## Non-goals

- Do not restore the separate file-capability mutation helper, Xray launcher, or transient systemd service.
- Do not elevate normal Proxyctl commands or ordinary loopback core sessions.
- Do not install setuid bits or permanent file capabilities.
- Do not let the core install Proxyctl-owned host routes, policy rules, DNS settings, or firewall rules independently.
- Do not use the user's database, user-owned config files, or caller-supplied filesystem paths from the privileged process.
- Do not enable TUN merely because the request parser or a core's native config validator succeeds.
