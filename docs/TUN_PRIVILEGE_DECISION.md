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

- a hidden `__tun-supervisor` command that checks effective UID, rejects terminal stdin, reads a bounded version-3 launch specification, verifies the invoking UID and root-owned runtime, stages the generated config as a root-owned mode-0600 file, and then deliberately exits as not implemented;
- a version-3 request containing node ID, core enum, listener port, and the generated native configuration as bounded JSON data;
- user-owned managed core binaries under the private data directory;
- TUN adapters with different native device-attachment contracts;
- offline manifest/journal, route/rule mutation, cleanup, and readiness groundwork;
- a closed TUN activation gate.

The current version-3 launch specification carries the generated configuration as JSON data plus an untrusted managed-core-root hint. The hint is not an executable path: the supervisor validates the complete directory tree against the invoking UID, enforces the fixed `proxyctl/cores/<core>/<core>` layout, and derives the executable from the closed CoreKind enum. The request still rejects unknown fields and non-object/invalid JSON, caps the config at 1 MiB, and bounds the complete wire envelope. The privileged process does not open redb or reconstruct the node from its ID. The hidden supervisor verifies caller provenance and the root-owned runtime, validates the managed core, stages the config, and exits as not implemented. It does not launch a core or change host networking.

## Non-goals

- Do not restore the separate file-capability mutation helper, Xray launcher, or transient systemd service.
- Do not elevate normal Proxyctl commands or ordinary loopback core sessions.
- Do not install setuid bits or permanent file capabilities.
- Do not let the core install Proxyctl-owned host routes, policy rules, DNS settings, or firewall rules independently.
- Do not use the user's database, user-owned config files, or caller-supplied filesystem paths from the privileged process.
- Do not enable TUN merely because the request parser or a core's native config validator succeeds.


## Implemented preparation boundary (next slice)

The launch-spec module now exposes a pure `from_generated_config` constructor. It accepts
node/core/port metadata and the already-generated configuration bytes, requires UTF-8,
constructs the version-3 request, and validates it before returning. It does not resolve
database state, validate through a core executable, spawn processes, create runtime
files, or change host networking. The constructor is a narrow building block for the
unprivileged front-end preparation path; it does not connect that path to sudo or open
the supervisor gate.


## Unprivileged preparation service

`services::tun_preparation::prepare_launch_spec` now provides a preparation path that
resolves the requested node from the user database, rejects deleted/incompatible nodes,
checks the selected managed-core path, derives a fresh outbound mark, generates the
adapter-specific native TUN configuration, validates it using the selected core's native
config-check command, and returns a validated version-3 launch request.

This service performs only the unprivileged preparation and temporary config validation
steps. It does not launch sudo/supervisor/core, allocate or persist a TUN generation,
create privileged runtime files, or mutate host networking. The activation gate remains
closed. This API is not yet wired to `tun start`; port-availability checks and supervisor
handoff/startup acknowledgement belong to subsequent slices.


## Shell-free privilege handoff transport

A new `services::tun_handoff` transport serializes a validated LaunchSpec using the
bounded protocol encoder and invokes `sudo -- <current-proxyctl-executable>
__tun-supervisor` using direct argv (no shell or shell script). The generated request
is written to the child stdin and stdin is closed to delimit the message. stdout and
stderr are inherited; sudo's password prompt remains terminal-driven, not stdin-driven.

The transport resolves sudo from PATH and canonicalizes its executable, and resolves the
current Proxyctl executable from the process environment. It does not pass arbitrary core
paths or arguments. This transport is deliberately not connected to the TUN CLI yet:
the supervisor remains validation-only and networking stays fail-closed until the
root-runtime ownership, lifecycle handshake, process identity, journaled mutation,
readiness and recovery path are completed and locally verified.



## Invoking-user identity and root runtime boundary

The Linux supervisor now derives the session owner from sudo's `SUDO_UID` and requires
it to match the inherited kernel audit login UID in `/proc/self/loginuid`. It also
requires both real and effective process UIDs to be root. Missing, malformed, root,
or mismatched identity data fails closed; the launch JSON cannot nominate a UID.

After request validation, the supervisor creates or verifies `/run/proxyctl`
(root-owned, mode 0755) and `/run/proxyctl/<uid>` (root-owned, mode 0700). Existing
symlinks, non-directories, unexpected owners, or unexpected permission modes are
rejected. This runtime bootstrap is the only privileged filesystem side effect in
the current supervisor path. It does not stage the config, launch a core, create a
TUN device, alter routes/rules/DNS/firewall state, or enable the CLI activation path.

The audit-login-UID cross-check intentionally fails closed in environments where
Linux does not provide a valid login UID. Supporting such environments requires a
separate, explicit identity-provenance design rather than trusting a caller-supplied
UID or silently falling back to `SUDO_UID` alone.


## Root-owned generated-config staging

The Linux supervisor now stages the request's already-validated JSON configuration
inside the verified per-UID runtime directory. It uses a kernel-generated unique
identifier and exclusive file creation, writes the payload without shell or path input
from the request, syncs it, and verifies that the resulting file is regular, root-owned,
and mode 0600. The runtime directory is rechecked as a real root-owned mode-0700
directory before staging.

The staged-file guard removes the temporary config on normal scope exit and explicit
close. If writing or metadata verification fails, the partial file is removed. This
stage is intentionally ephemeral in the current validation-only supervisor: no core
consumes it, no process/session manifest is created, and no host networking is changed.
Durable config retention and cleanup will be tied to the supervisor-owned session
manifest only when process lifecycle and crash recovery are implemented.

## Core process launch contract (design gate)

The first supervisor process-launch implementation must reuse the established core argv contract from ordinary activation, while keeping the executable selection entirely supervisor-derived:

| Core | Executable selected from the fixed catalog | Fixed native argv after argv[0] |
|---|---|---|
| sing-box | `sing-box` | `run -c <root-staged-config>` |
| Xray | `xray` | `run -c <root-staged-config>` |
| Mihomo | `mihomo` | `-f <root-staged-config>` |

Only the staged config pathname is dynamic, and it is generated inside the verified root-owned runtime. The request cannot supply argv, environment variables, a working directory, or any filesystem path. The child receives null stdin; supervisor diagnostics remain separate from the generated-config transport. No shell is involved.

### Managed-core path resolution is a prerequisite

The unprivileged installer currently honors `XDG_DATA_HOME` (or `$HOME/.local/share`) and places cores below `proxyctl/cores/<core>/<executable>`. The root supervisor cannot safely reuse its own environment, trust an arbitrary path from the request, or read the user's redb database to discover that path. Before core spawning is implemented, the project must settle a trusted way to resolve the invoking user's effective data root while preserving XDG behavior. The path resolver must:

- derive the home directory from the invoking UID's system account record, not from root's `HOME`;
- define and validate how a non-default `XDG_DATA_HOME` is obtained without accepting an unchecked request path;
- walk each path component without following symlinks, verify ownership and non-group/world-writable permissions, and enforce the fixed `proxyctl/cores/<core>` suffix;
- require a regular executable owned by the invoking UID and reject unexpected mode/ownership states;
- canonicalize and re-check the final executable immediately before spawn.

If a secure, compatible XDG resolution cannot be established, the supervisor must fail closed with a clear diagnostic; it must not silently launch a different core from the default data directory. These checks document the trust boundary, not immutability: the invoking user owns the managed binary and explicitly authorizes its execution as root through sudo.

### Process identity and startup handshake

The supervisor must persist a session record before reporting success. At minimum it binds the invoking UID, session nonce, core kind, PID, `/proc/<pid>/stat` start-time ticks, and canonical executable identity. PID reuse must be rejected; signaling must use a pidfd when available or repeat full identity verification immediately before the signal. The supervisor, not the front-end CLI, owns the child and its lifecycle.

A background start must use a private, root-owned control/handshake channel under `/run/proxyctl/<uid>`. The front end may report success only after the supervisor has spawned the core, verified its executable/start identity, completed the core-specific readiness check, and durably committed the session record. An early child exit, timeout, failed write, or failed handshake must cause bounded rollback and a failure response. The front end must not treat successful sudo process creation as successful TUN activation.

Foreground mode must execute this same supervisor lifecycle synchronously with inherited diagnostics. It must not create a second launch path or weaken the same validation and cleanup gates.

### Deliberately excluded from this slice

Core spawning alone does not enable TUN. Do not connect `tun start`, `use --tun`, or the legacy TUN orchestrator to this process-launch code until process ownership, supervisor survival, stop protocol, manifest/WAL transaction ownership, readiness, exact cleanup, crash recovery, and reboot recovery are complete. In particular, do not create a TUN device or mutate routes, policy rules, DNS, firewall, or forwarding state in the process-launch slice.


## Invoking user's managed-core path verification

The version-3 request carries the effective `managed_cores_path()` value from the unprivileged preparation process. This preserves the user's configured `XDG_DATA_HOME` rather than assuming root's home or silently selecting a default installation. The field is only a directory hint; it is not an executable path and cannot select the core or its arguments.

The privileged supervisor validates the hint after deriving the invoking UID:

- The path must be absolute and end exactly in `proxyctl/cores`.
- Every path component is inspected with `symlink_metadata`; symlinked and non-directory components are rejected.
- Shared ancestors must be root-owned or invoking-user-owned and not group/world writable. A root-owned sticky ancestor (for example, `/tmp`) is permitted for traversal.
- The `proxyctl`, `cores`, and selected core directory must be invoking-user-owned and mode 0700.
- The fixed executable name comes from the closed core catalog. It must be a regular, invoking-user-owned executable and not group/world writable.
- The resolved executable must remain below the canonical managed-core root.

This intentionally accepts a validated user-selected XDG data root while refusing unchecked paths. It does not make the user-owned binary immutable against the same user; sudo authorization remains the explicit trust boundary. The supervisor currently performs validation only: it does not execute the returned path.
