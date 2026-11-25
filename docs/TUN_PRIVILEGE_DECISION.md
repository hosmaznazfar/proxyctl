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
- TUN start remains fail-closed until the launch, process-identity, resource-ownership, readiness, monitoring, and recovery gates are implemented and validated. Explicit `tun stop` is available to recover an existing durable activation.

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
3. It constructs a bounded, versioned request containing typed launch metadata, the managed-core directory hint, and the generated configuration payload. It must not ask the privileged process to open the user's redb database or resolve a node ID against user-owned state.
4. The CLI invokes `sudo` directly (no shell script) for the installed Proxyctl executable's hidden `__tun-supervisor` role. The request is sent over standard input; the privileged process rejects a terminal as request input and applies strict size/schema validation.
5. The supervisor derives the core selection from the closed `CoreKind` enum. It does not accept an executable path, config path, working directory, arbitrary environment map, or shell command from the request.
6. The supervisor creates private root-owned runtime/configuration state under a per-invoking-UID directory below `/run/proxyctl`, validates the staged configuration, and launches the selected managed core with the core-specific native arguments.
7. The supervisor records the exact core PID, process start identity, and executable identity, owns the TUN transaction/manifest lifecycle, monitors the core, and performs exact idempotent cleanup when the core exits.
8. `tun stop` requests privileged recovery through the same executable; the supervisor verifies the exact recorded process/session identity before signaling and removes only journal-owned resources whose fresh fingerprints still match. Top-level `stop` remains on the existing loopback activation path until the TUN stop contract is integrated there.

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
- a hidden `__tun-recover` command used by `tun stop`, which opens only the invoking user's root-owned runtime, reconciles the durable session records, stops the exact recorded core process, performs journaled compare-before-delete cleanup, and finalizes records only after cleanup is durable;
- a version-3 request containing node ID, core enum, listener port, a validated-later managed-core directory hint, and the generated native configuration as bounded JSON data;
- user-owned managed core binaries under the private data directory;
- TUN adapters with different native device-attachment contracts;
- offline manifest/journal, route/rule mutation, cleanup, and readiness groundwork;
- a closed TUN activation gate.

The current version-3 launch specification carries the generated configuration as JSON data plus an untrusted managed-core-root hint. The hint is not an executable path: the supervisor validates the complete directory tree against the invoking UID, enforces the fixed `proxyctl/cores/<core>/<core>` layout, and derives the executable from the closed CoreKind enum. The request still rejects unknown fields and non-object/invalid JSON, caps the config at 1 MiB, and bounds the complete wire envelope. The privileged process does not open redb or reconstruct the node from its ID. The hidden start supervisor verifies caller provenance and the root-owned runtime, validates the managed core, stages the config, and exits as not implemented. The separate hidden recovery role is invoked only by `tun stop`; it uses the durable root-owned manifest/journal/session receipt and the typed Linux recovery backend. It does not read the user database or launch a core.

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

The transport checks only the conventional `/usr/bin/sudo` and `/bin/sudo` system
locations; it never searches the caller-controlled PATH. It canonicalizes the selected
executable and requires a root-owned regular file with execute permission and no group/world
write permission. The current Proxyctl executable is resolved from the running process. If
request delivery fails, the transport closes stdin, best-effort kills the sudo child, and
waits to reap it rather than leaving a potentially blocked validation process behind. It
does not pass arbitrary core paths or arguments. The transport is connected to both `proxyctl use --tun` and `proxyctl tun start`.
For the native persistent-device path, the supervisor stages the generated config,
applies the journaled interface/routes/rules transaction, launches the selected
sing-box or Mihomo core directly, verifies full dual-stack readiness, commits the
root-owned session receipt and Running manifest, then remains alive to monitor the
child and recover its generation on exit. Xray remains excluded from this native
path until its descriptor-backed lifecycle is integrated.



## Invoking-user identity and root runtime boundary

The Linux supervisor now derives the session owner from sudo's `SUDO_UID` and requires
it to match the inherited kernel audit login UID in `/proc/self/loginuid`. It also
requires both real and effective process UIDs to be root. Missing, malformed, root,
or mismatched identity data fails closed; the launch JSON cannot nominate a UID.

After request validation, the supervisor creates or verifies `/run/proxyctl`
(root-owned, mode 0755) and `/run/proxyctl/<uid>` (root-owned, mode 0700). Existing
symlinks, non-directories, unexpected owners, or unexpected permission modes are
rejected. The same runtime contains the staged 0600 config, root-owned manifest,
write-ahead journal, and session receipt. All privileged state is generation-bound
and confined to this per-UID directory.

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

The staged-file guard remains alive for the entire supervised core lifetime and removes
the config after the core exits and generation cleanup completes. If writing or metadata
verification fails, the partial file is removed. Startup failures terminate the direct
child where possible and immediately attempt journal-based recovery; unresolved or
ambiguous resources retain their durable evidence for explicit `proxyctl tun stop`
recovery.

## Core process launch contract (native persistent-device path)

The first supervisor process-launch implementation must reuse the established core argv contract from ordinary activation, while keeping the executable selection entirely supervisor-derived:

| Core | Executable selected from the fixed catalog | Fixed native argv after argv[0] |
|---|---|---|
| sing-box | `sing-box` | `run -c <root-staged-config>` |
| Mihomo | `mihomo` | `-f <root-staged-config>` |
| Xray | Not enabled in this native-device path | Requires its separate generation-bound descriptor lifecycle |

Only the staged config pathname is dynamic, and it is generated inside the verified root-owned runtime. The request cannot supply argv, environment variables, a working directory, or an executable path. The child receives null stdin, a minimal fixed environment, and fixed core-specific argv; no shell is involved. A parent-death signal ties the root core's lifetime to its supervisor. Foreground core stdout is redirected to stderr so it cannot corrupt the supervisor's one-shot stdout acknowledgement.

### Managed-core path resolution

This prerequisite is implemented by the version-3 launch request and Linux `tun::core_paths` validator. The unprivileged preparation service sends the effective `managed_cores_path()` as a directory hint, preserving custom `XDG_DATA_HOME` without asking the privileged process to trust root's environment or guess a home-directory default.

The hint is not an executable path. The supervisor validates the absolute `proxyctl/cores` suffix, rejects lexical traversal and symlinked components, checks ownership and write permissions through the full path, requires the Proxyctl and core directories to be invoking-user-owned mode 0700, and derives the executable name from the closed CoreKind enum. The executable must be a regular file owned by the invoking UID, executable, not group/world writable, and resolve beneath the canonical managed root.

The validator is deliberately not described as race-free or as making a user-owned binary immutable. The invoking user owns the binary and explicitly authorizes its root execution through sudo. The privileged supervisor repeats validation immediately before spawning and retains the canonical executable identity in the root-owned session receipt. The same-UID trust boundary remains explicit; path validation does not make the user-owned binary immutable.

### Process identity and startup handshake

The supervisor must persist a session record before reporting success. At minimum it binds the invoking UID, session nonce, core kind, PID, `/proc/<pid>/stat` start-time ticks, and canonical executable identity. PID reuse must be rejected; signaling must use a pidfd when available or repeat full identity verification immediately before the signal. The supervisor, not the front-end CLI, owns the child and its lifecycle.

A background start uses the per-invocation stdout pipe as its one-shot acknowledgement channel; no filesystem control socket or extra helper is installed. The front end reports success only after the supervisor has spawned the core, verified its executable and process identity, completed the dual-stack end-to-end readiness gate, and durably committed the session receipt plus Running manifest. An early child exit, timeout, failed write, or failed handshake causes bounded termination and journal recovery. Successful sudo process creation alone is never treated as successful TUN activation.

Foreground mode executes this same supervisor lifecycle synchronously. Core diagnostics are attached to the terminal's stderr while stdout remains reserved for the acknowledgement; it does not create a second launch path or weaken validation and cleanup gates.

### Deliberately excluded from this slice

The native persistent-device path is now connected to `proxyctl use --tun` and `proxyctl tun start` for sing-box and Mihomo. It creates the owned TUN device and journaled routes/rules, verifies the complete readiness evidence, and supports explicit stop/recovery. Xray's descriptor-backed path and automatic reboot-time recovery remain separate unfinished work; no systemd service or additional helper executable is introduced for new sessions.


## Invoking user's managed-core path verification

The version-3 request carries the effective `managed_cores_path()` value from the unprivileged preparation process. This preserves the user's configured `XDG_DATA_HOME` rather than assuming root's home or silently selecting a default installation. The field is only a directory hint; it is not an executable path and cannot select the core or its arguments.

The privileged supervisor validates the hint after deriving the invoking UID:

- The path must be absolute and end exactly in `proxyctl/cores`.
- Every path component is inspected with `symlink_metadata`; symlinked and non-directory components are rejected.
- Shared ancestors must be root-owned or invoking-user-owned and not group/world writable. A root-owned sticky ancestor (for example, `/tmp`) is permitted for traversal.
- The `proxyctl`, `cores`, and selected core directory must be invoking-user-owned and mode 0700.
- The fixed executable name comes from the closed core catalog. It must be a regular, invoking-user-owned executable and not group/world writable.
- The resolved executable must remain below the canonical managed-core root.

This intentionally accepts a validated user-selected XDG data root while refusing unchecked paths. It does not make the user-owned binary immutable against the same user; sudo authorization remains the explicit trust boundary. The native supervisor executes only the validated sing-box or Mihomo path selected by the closed core enum. Xray remains excluded from this path.


## Privilege handoff hardening

The unprivileged handoff no longer searches `PATH` for sudo. It considers only
`/usr/bin/sudo` and `/bin/sudo`, canonicalizes the selected candidate, and checks that
the resulting executable is a root-owned regular file with at least one execute bit
and no group/world write permission. This prevents a user-controlled PATH entry from
being selected as the privilege broker.

If writing the bounded launch request to sudo's stdin fails, the handoff closes the
pipe, sends a termination request to the sudo child, and waits for the child to be
reaped. The request pipe remains separate from sudo's terminal-driven password prompt;
`sudo -S` is not used. These checks harden the shell-free handoff. New native TUN sessions use the same
Proxyctl executable as the privileged supervisor; socket-mark readiness now uses
in-process NETLINK_SOCK_DIAG collection and does not launch
`/usr/libexec/proxyctl-tun-helper` or any separate diagnostic binary.


## Root-owned privileged session record

A separate Linux session record now models the privileged supervisor's durable process
ownership without treating the user-owned lifecycle manifest as privileged input. Its
versioned, strict schema binds:

- the invoking non-root UID;
- a fresh canonical session nonce;
- the activation UUID and non-zero generation;
- the closed core-kind enum; and
- the exact process identity (PID, procfs start-time ticks, canonical executable path).

The record store is rooted only in the root-owned per-UID runtime directory. It requires
a real mode-0700 directory, writes a mode-0600 root-owned regular file through an
exclusive temporary-file plus no-clobber atomic persistence, syncs the file and directory,
and rejects symlinks, hard links, unexpected ownership/modes, oversized or changing
records, unknown schema fields, and malformed identities. The store also requires the runtime directory name and the
record's invoking UID to match, preventing a valid record from being replayed under a
different user's runtime. Removal requires a full record equality match, so a stale
cleanup request cannot delete a newer session record.

This is storage groundwork only. The current hidden supervisor does not create or consume
the record, no core is spawned, and the TUN CLI remains fail-closed. The next integration
must commit the record only after capturing and pinning the launched core identity, and
must coordinate it with the activation manifest so partial commits have deterministic
rollback/recovery behavior.


## Supervisor acknowledgement and coordinated session commit

The implementation has a bounded, versioned JSON acknowledgement on the dedicated stdout pipe. Human-readable diagnostics remain on stderr. The supervisor emits `started` only after the native core passes readiness and the root-owned session receipt and Running manifest are committed; the front end also verifies that the supervisor remains alive to own the session. The pipe is a per-invocation kernel channel rather than a filesystem socket below the root-only runtime directory.

The Linux lifecycle coordinator also has a root-side `bind_core_session` operation. Under the lifecycle lock it verifies the pinned process and its credentials against the privileged supervisor's effective UID (root in production), writes the root-owned session receipt first, then persists the matching `Running` lifecycle manifest with the same process identity. The receipt separately binds the invoking non-root UID. If the manifest write fails, the receipt is deliberately retained as recovery evidence.

The exact crash-state matrix and remaining gates are documented in [TUN_SUPERVISOR_PROTOCOL.md](TUN_SUPERVISOR_PROTOCOL.md). This is still groundwork only: the acknowledgement transport and durable commit method are not connected to core spawning, readiness, supervisor detachment, stop, or recovery. The TUN activation gate remains closed, and no host networking changes are made.


## Pidfd-safe stop and durable cleanup finalization

The lifecycle coordinator can now move a matching activation to `CleanupPending` before sending SIGTERM to the exact pidfd-pinned core. It waits for a bounded grace period and escalates to SIGKILL only against that same process instance. A vanished or reused PID is never signaled. The stop primitive retains the manifest and root-owned receipt as recovery evidence.

Final record cleanup is separate and fail-closed. It requires the recorded core to be gone, a matching transaction journal with all operations durably `Removed` or `Absent`, and an exact removed fingerprint for every owned manifest resource. It then persists `Cleaned`, removes the completed journal and matching session receipt, and finally removes the manifest. The operation is restartable across crashes at each durable boundary.

The coordinator now has a generic recovery orchestration method that can invoke the existing compare-before-delete journal recovery executor through a caller-supplied privileged backend, then finalize the root-owned receipt and manifest. It retains the completed journal until the `Cleaned` phase is durable. This method is not wired to CLI stop or the hidden supervisor, and no recovery backend has been invoked by this implementation. The hidden supervisor still does not launch a core, and TUN remains disabled.


Launch protocol version 5 carries the kernel-generated activation UUID, non-zero generation, foreground preference, resolved proxy peer candidates, and exactly one IPv4 plus one IPv6 numeric HTTP readiness target. The supervisor validates those bounded inputs and reuses the exact activation UUID/generation for the manifest, transaction journal, and session receipt; it does not generate replacement identities. The pre-activation DNS/firewall baseline is captured independently by the privileged supervisor and is never accepted from the request.
