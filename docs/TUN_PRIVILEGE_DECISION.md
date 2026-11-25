# TUN privilege architecture decision

> Decision status: accepted and implemented for sing-box and Mihomo on Linux.
> Reference revision: v2rayN commit `91c61b1fe595994c7bcf09739ddb5dc32fde4f04`.
> Scope: TUN-only privilege handoff, native persistent-device activation, and the single-executable Proxyctl session owner.

## Decision

Proxyctl follows v2rayN's **TUN-only elevation model**:

- Ordinary Proxyctl commands and ordinary loopback core sessions remain unprivileged.
- Only an explicitly requested TUN session invokes `sudo`.
- The selected TUN core runs with root credentials for the TUN session and opens its native TUN device.
- Proxyctl remains one application package with one installed `proxyctl` executable. The hidden `__tun-supervisor` and `__tun-recover` roles are invocations of that executable, not separately installed helpers, launchers, daemons, or systemd services.
- No setuid bit or permanent file capabilities are installed.
- Native persistent-device activation is enabled for sing-box and Mihomo. Xray remains disabled until its descriptor-backed adapter is replaced or reconciled with the native-inbound design below.

The privileged process does not elevate the whole application, read the user's node database, or accept arbitrary commands, executable paths, config paths, working directories, or environment maps.

## What was verified in v2rayN

The inspected source is pinned to the revision above:

- [CoreManager.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib/Manager/CoreManager.cs) makes the sudo decision from the launch context's TUN snapshot. Linux TUN launches for sing-box, Mihomo, and Xray are elevated; ordinary launches and unsupported core types are not.
- [CoreAdminManager.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib/Manager/CoreAdminManager.cs) launches the selected core through `sudo` and retains process information for its stop path.
- [CoreConfigContextBuilder.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib/Handler/Builder/CoreConfigContextBuilder.cs) and [CoreConfigHandler.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib/Handler/CoreConfigHandler.cs) resolve the profile and generate core configuration in the application before launch.
- [CoreManagerTests.cs](https://github.com/2dust/v2rayN/blob/91c61b1fe595994c7bcf09739ddb5dc32fde4f04/v2rayN/ServiceLib.Tests/Manager/CoreManagerTests.cs) tests that supported TUN launches require elevation, ordinary launches do not, and unsupported core types do not trigger elevation.

This confirms the operational model, not a complete proof of every failure or crash path. Proxyctl retains stronger typed handoff, process identity, journal, readiness, and recovery checks rather than copying v2rayN's shell-script construction.

## Privilege and launch sequence

1. The unprivileged CLI acquires the activation lock, resolves the selected node from the user's database, checks adapter compatibility, generates the native config, resolves readiness endpoints, and validates the config before elevation.
2. It builds a bounded, versioned request and invokes `sudo -- <current-proxyctl-executable> __tun-supervisor` with direct argv. The generated config is sent as data on stdin; no shell or generated script is involved.
3. The supervisor authenticates the invoking UID from sudo credentials and cross-checks Linux's audit login UID. It resolves the primary GID from the system account database; neither UID nor GID is trusted from the request.
4. It verifies and creates the root-owned `/run/proxyctl/<uid>` runtime, captures its own host-network baseline, stages the generated config as a root-owned 0600 file, and validates the selected managed core path.
5. It captures a fresh kernel snapshot, creates a generation-bound write-ahead journal, and applies the native TUN interface, routes, and policy rules through the typed Linux backend.
6. It launches the selected core directly with fixed core-specific arguments, verifies the exact process identity and TUN attachment, and runs the complete dual-stack end-to-end readiness gate.
7. It commits the root-owned session receipt and Running manifest, then sends the one-shot Started acknowledgement. The same supervisor remains alive, retains the staged config, monitors the core, and performs generation-scoped journal recovery when the core exits.
8. `proxyctl tun stop` performs privileged recovery and restores a saved loopback session. `proxyctl stop` performs privileged recovery only when a TUN handoff/session marker is present, discards saved restoration state, and otherwise stops an ordinary loopback session without elevation.

The front end holds its activation lock through the supervisor's Started acknowledgement. This makes the marker check, startup handoff, and stop path serialize with ordinary activation and restoration.

## Core binary trust boundary

Managed core binaries live under the invoking user's private data directory and remain user-owned. The installer verifies the upstream release archive's SHA-256 digest, but the installed binary is not immutable against that same user.

Running a user-owned core as root means the invoking user explicitly authorizes that selected binary to execute with root privileges for the TUN session. The supervisor derives the executable from a closed `CoreKind` enum and the fixed managed-core layout; it does not trust an executable path in the request. It canonicalizes and revalidates the directory tree, ownership, permissions, file type, link count, and executable bit immediately before launch.

These checks reduce path confusion and accidental privilege expansion. They do not make a user-owned executable immutable or eliminate every same-UID replacement race. The sudo authorization is the trust boundary for executing that user's selected managed core as root. Do not claim otherwise.

The privileged process never reads the user's redb database, writes root-owned files into the user's data directory, or accepts a caller-provided config pathname. Generated configuration is transferred as bounded data and staged under the root-owned runtime.

## Core-specific behavior

- **sing-box:** native persistent TUN device creation; launched directly by the privileged supervisor.
- **Mihomo:** native persistent TUN device creation; launched directly by the privileged supervisor.
- **Xray:** the intended v2rayN-compatible target is Xray's native TUN inbound. The current Proxyctl adapter/launcher still describes a generation-bound descriptor contract, so Xray is deliberately rejected by the native persistent-device supervisor. Do not combine the descriptor-backed contract with a separately created persistent device or claim Xray support until the configuration, ownership, and readiness path are reconciled.

Proxyctl owns route and policy-rule creation through its journal. Core-managed automatic route and DNS mutation must remain disabled where it would compete with that ownership. The new native supervisor does not modify host DNS or firewall state; readiness verifies that both remain unchanged.

## Runtime, process, and recovery rules

- The only privileged entry for a new session is the same `proxyctl` executable invoked through sudo. No helper package, separate launcher, systemd unit, setuid bit, or permanent file capability is installed for new native sessions.
- The supervisor accepts a strict bounded protocol, a closed core enum, generated JSON data, and bounded readiness endpoints. It accepts no arbitrary argv, shell text, executable path, config path, or environment map.
- Runtime files are root-owned below `/run/proxyctl/<uid>`; directories and files are checked for exact ownership and restrictive modes.
- The exact core is tracked by PID, process start identity, executable identity, and pidfd-safe operations. A parent-death signal terminates the core if its supervisor dies.
- The write-ahead journal is committed before kernel mutation. Recovery compares fresh resource fingerprints and removes only resources still matching the journal. Ambiguous or inconsistent evidence is preserved; cleanup never guesses.
- The supervisor keeps the staged config alive for the core's lifetime. It acknowledges startup only after attachment, readiness, durable receipt/manifest commit, and establishment of the monitor.
- An abrupt supervisor death can leave journaled kernel state after the core receives its parent-death signal. Run `proxyctl tun stop` or `proxyctl stop` to perform explicit recovery. Reboot recovery is not implemented; the runtime is under volatile `/run`, and Linux removes the session's TUN link, routes, and policy rules during reboot.
- Foreground mode uses the same supervisor and privilege boundary. It keeps the lifecycle attached for diagnostics rather than introducing a second activation path.

## Current implementation boundary

Implemented on Linux for sing-box and Mihomo:

- `proxyctl use <number> --core <core> --tun` starts a new TUN session.
- `proxyctl tun start` transitions a verified active loopback session to TUN mode and saves enough metadata to restore that loopback session later.
- `proxyctl tun stop` stops/reconciles the exact privileged session, recovers journal-owned resources, and restores the saved loopback session when one exists.
- `proxyctl stop` performs the same privileged recovery only when a TUN marker is pending; it discards the saved loopback marker because this command means a full stop. Without a TUN marker, it stops the ordinary loopback session under the activation lock and does not request sudo.
- `proxyctl tun status` and `proxyctl status` provide read-only network/session inspection.

Xray TUN activation, automatic reboot-time recovery, and any migration of pre-existing legacy helper/systemd-managed sessions remain separate work. Legacy compatibility code must not be used for new sing-box or Mihomo TUN sessions.

## Non-goals

- Do not elevate normal Proxyctl commands or ordinary loopback core sessions.
- Do not install setuid bits or permanent file capabilities.
- Do not add a separate helper package, launcher binary, daemon, or systemd service for new native sessions.
- Do not let the core independently install Proxyctl-owned routes, policy rules, DNS settings, or firewall rules.
- Do not let the privileged process access the user's database or trust user-owned configuration files or manifests.
- Do not enable a core path until its process ownership, attachment, end-to-end readiness, monitoring, and journaled recovery contract are complete.
