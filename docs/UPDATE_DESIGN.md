# Update and Installation Design

> Status: approved design baseline
> Last updated: 2026-11-08

## 1. Goals

Proxyctl uses one consistent, verifiable artifact acquisition and installation pipeline for the proxyctl CLI executable and the managed sing-box, Xray, and Mihomo binaries. The CLI and core targets share safety rules and reusable implementation, while each upstream project has its own release resolver because asset names, archive formats, and checksum conventions differ.

## 2. Official release sources

| Component | Official release source |
|---|---|
| proxyctl | https://github.com/hosmaznazfar/proxyctl/releases |
| sing-box | https://github.com/SagerNet/sing-box/releases |
| Xray | https://github.com/XTLS/Xray-core/releases |
| Mihomo | https://github.com/MetaCubeX/mihomo/releases |

Only stable releases are selected by default. Prereleases, drafts, arbitrary branch snapshots, unofficial mirrors, and third-party repackaging are not silently accepted. A future explicit opt-in may support prereleases.

The updater queries each project's official GitHub Releases metadata and selects an asset using a component-specific release resolver. It must not assume all projects share a tag format, asset naming scheme, archive format, or checksum convention.

## 3. Platform and architecture

The initial validated target is Linux x86_64 (GNU/Linux, including CachyOS/Arch Linux). The artifact model must allow additional targets, especially Linux aarch64, without changing update orchestration.

Proxyctl detects the operating system and architecture before downloading and resolves an exact compatible asset. If no compatible artifact exists, it fails with a clear unsupported-platform message; it never guesses or installs a binary for a different architecture.

## 4. Shared artifact pipeline

Setup and update use the same underlying component installer:

1. Resolve official release metadata.
2. Select the latest stable release and a compatible asset.
3. Resolve the checksum/signature artifact and its trusted verification procedure.
4. Download into a private staging directory beneath proxyctl's data directory.
5. Verify downloaded bytes before extraction or execution.
6. Safely inspect and extract only expected files; reject path traversal and unexpected layouts.
7. Set executable permissions and verify the binary's reported version.
8. Install using a staged replacement strategy, retaining the previous working binary until the replacement is ready.
9. Record installed version, release identifier, source, asset identity, and verification result.
10. Remove temporary artifacts on success and failure.

If an upstream release does not provide verification material that proxyctl can validate against a trusted source, installation fails closed. It must not silently skip verification. Exact checksum/signature formats are implemented and tested separately for each upstream project.

Downloaded files and temporary configuration are stored with restrictive permissions. Never log credential-bearing URLs or sensitive local paths unnecessarily.

## 5. CLI self-update

Proxyctl releases are published in this repository with versioned tags and platform-specific release assets. The release workflow builds clearly identified artifacts for supported targets and publishes a SHA-256 manifest (and stronger signatures/provenance when configured).

The self-updater compares the installed CLI version with the latest stable proxyctl release, chooses the exact asset for the detected platform/architecture, verifies it against the release's published SHA-256 manifest from the official repository, and stages and validates the new executable before replacement.

It uses atomic replacement where supported and safe. It never truncates or overwrites the currently running executable before the replacement is verified and ready.

If the OS or installation layout prevents safe self-replacement, proxyctl leaves the current executable untouched and prints the official release URL plus a precise manual update instruction. It must not claim success when no update occurred.

## 6. Command behavior

~~~sh
# Initial installation of managed cores
proxyctl setup
proxyctl setup --core sing-box

# Inventory and versions
proxyctl cores

# Check all update targets without modifying anything
proxyctl update --check

# Update CLI and all installed managed cores
proxyctl update

# Update only selected targets
proxyctl update --app
proxyctl update --cores
proxyctl update --core mihomo
~~~

With no target selector, update targets the CLI and every already-installed managed core. It does not install cores that are not installed; setup is responsible for initial installation. Check is read-only. App, cores, and core are mutually exclusive target selectors unless a later explicit CLI design supports another combination.

The command reports each target independently: installed version, latest stable version, status, verification result, and action/error. One component's failure must not corrupt another component or hide its result.

## 7. Operational safety

- Update and setup never start a proxy core.
- They do not alter active proxy processes, system proxy settings, DNS, routes, firewall rules, or TUN state.
- Only binaries in proxyctl's managed directory are installed or updated. System-installed cores and other proxy applications are not modified.
- A failed request, checksum/signature check, extraction, version check, or replacement leaves the last working binary intact.
- Staging and replacement are serialized per component to avoid concurrent update races.
- The updater handles interrupted operations and stale staging files safely.
- Release metadata and asset URLs are constrained to the expected official GitHub repository/release origin; redirects and downloaded content are validated rather than blindly trusted.

## 8. Release workflow and testing

The proxyctl repository should publish release assets from a version tag (for example, v0.1.0) through GitHub Actions. The workflow should validate the tag/version relationship, build each supported target, package binaries with unambiguous OS/architecture names, generate a SHA-256 manifest after packaging, attach assets and manifest to the GitHub Release, and avoid publishing when required build or test jobs fail.

Tests cover platform/asset selection, stable-versus-prerelease selection, checksum parsing and mismatch, missing verification material, archive path traversal, interrupted downloads, failed version checks, staging cleanup, atomic replacement behavior, self-update fallback, and independent per-component failures. Network-dependent integration tests are opt-in; ordinary CI uses fixtures and fake download/process interfaces.

## 9. Implementation boundaries

The Rust implementation keeps policy and mechanisms separate:

| Module | Single responsibility |
|---|---|
| `updates/application.rs` | Proxyctl-specific release policy and self-update use case |
| `updates/release.rs` | GitHub Releases metadata model and retrieval |
| `updates/platform.rs` | Platform/architecture detection and application asset naming |
| `updates/artifact.rs` | Bounded downloads, trusted-host validation, checksum parsing and verification |
| `updates/installer.rs` | Staging, executable validation, permissions, and replacement |
| `updates/mod.rs` | Module boundary and public update entry point |

Core-specific release resolution and archive extraction must be implemented as separate adapters. They may use the shared artifact and installer services, but must not duplicate HTTP, checksum, staging, or replacement code. The CLI only dispatches use cases; it does not implement update policy. Keep individual modules narrowly scoped and split them when a new responsibility is introduced.
