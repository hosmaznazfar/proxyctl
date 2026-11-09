# Update and Installation Design

> Status: implementation baseline
> Last updated: 2026-11-08

## 1. Goals

Proxyctl uses one verified artifact pipeline for its CLI and managed sing-box, Xray, and Mihomo binaries. Shared mechanisms (release metadata, bounded download, SHA-256 verification, archive extraction boundary, staging, and executable validation) are separate from upstream asset policy.

## 2. Official sources and verification

| Component | Official source |
|---|---|
| proxyctl | https://github.com/hosmaznazfar/proxyctl/releases |
| sing-box | https://github.com/SagerNet/sing-box/releases |
| Xray | https://github.com/XTLS/Xray-core/releases |
| Mihomo | https://github.com/MetaCubeX/mihomo/releases |

If the Proxyctl repository has no published release eligible for the selected channel (including a repository with no releases yet), self-update reports that no app update is available and skips that target without failing core updates. Stable releases are the default channel for Proxyctl itself and every managed core. Prereleases (alpha, beta, release candidates, and other GitHub releases marked `prerelease`) are eligible only when the user explicitly passes `--prerelease`. The option applies only to the update target selected by the command: `--app`, `--cores`, or `--core <id>`; with no target selector it applies to the CLI and all installed managed cores. A prerelease for one component must never change the channel for another component unless both are in the selected target set. Draft releases are never eligible. Release selection must enumerate official release metadata and filter by the requested channel; do not assume the GitHub `/releases/latest` endpoint can return prereleases. The installer uses GitHub's release asset digest field and requires a sha256 digest. If release metadata does not provide a digest, installation fails closed. No checksum bypass or unofficial mirror is provided.

## 3. Initial platform and asset policy

The first implementation supports Linux x86_64 only.

| Core | Asset policy | Archive | Extracted executable |
|---|---|---|---|
| sing-box | sing-box-{version}-linux-amd64.tar.gz | tar.gz | sing-box |
| Xray | Xray-linux-64.zip | ZIP | xray |
| Mihomo | mihomo-linux-amd64-v1-{version}.gz | gzip | mihomo |

Mihomo's GOAMD64 v1 build is selected for broad x86_64 compatibility rather than assuming newer CPU instruction support. Each asset selector lives in its own core-specific module.

## 4. Shared installation pipeline

1. Query the fixed official GitHub Releases API endpoint.
2. Reject drafts and, unless explicitly opted in, prereleases.
3. Select the exact platform-specific asset by name.
4. Require the release API's SHA-256 digest.
5. Download and verify the complete archive before parsing it.
6. Extract only the expected regular executable into memory. Archive paths are never written to disk; directories and symlinks are ignored.
7. Stage the executable beside its final managed path, set executable permissions, and execute its version command.
8. Replace the destination only after the version matches the selected release.
9. Remove staging files on failure.

The download reader is capped at 256 MiB and extracted executables at 128 MiB. Installation directories are private (0700 on Unix); installed binaries are executable (0755).

## 5. CLI behavior

~~~sh
proxyctl setup
proxyctl setup --core sing-box
proxyctl cores
proxyctl update --check
proxyctl update
proxyctl update --app
proxyctl update --cores
proxyctl update --core mihomo
proxyctl update --prerelease
proxyctl update --app --prerelease
proxyctl update --core sing-box --prerelease
~~~

Setup installs all three cores by default; --core installs one. Cores displays each managed installation and its reported version. Update without a selector targets the CLI and every installed managed core. Check performs metadata and asset checks without downloading or changing files, using the same release channel requested for installation. Stable is the default. `--prerelease` opts the selected target(s) into prerelease selection; it can be combined with `--app`, `--cores`, or `--core <id>`. App, cores, and core are exclusive selectors. Prerelease selection is independent per component and never silently changes the channel of unselected components.

## 6. Safety boundaries

- Only binaries inside proxyctl's private managed directory are installed or updated.
- No package manager, sudo, PATH lookup, external core process, or system proxy setting is used.
- Setup and update do not start a core or alter active proxy processes, DNS, routes, firewall, or TUN.
- Existing working binaries are preserved until the staged replacement passes its version check.
- A failed core update does not stop other selected core updates.
- Archive paths are never extracted to the filesystem.

## 7. Module responsibilities

| Module | Responsibility |
|---|---|
| cores/catalog.rs | Core identity, official endpoint, executable and version command |
| cores/paths.rs | Private managed filesystem layout |
| cores/releases/*.rs | One upstream's asset naming and archive format |
| cores/archive.rs | Safe extraction of one expected executable |
| cores/installer.rs | Shared core installation orchestration |
| updates/release.rs | GitHub release metadata and asset digest |
| updates/artifact.rs | Bounded download and SHA-256 verification |
| updates/installer.rs | Staging, version validation, replacement |
| services/cores.rs | Setup, update, and inventory use cases |
| cli/mod.rs | Argument parsing and presentation only |

Each module has one narrow responsibility. Core-specific policy is not duplicated in the shared installer.

## 8. Tests

Unit tests cover core-name parsing, archive rejection, checksum mismatch, URL host validation, and staged installation. Network-dependent release tests are not part of ordinary CI. An empty release list or a list with no eligible SemVer release is a normal 'no update published for this channel' state for the self-updater, not a fatal error. Local checks:

~~~sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
~~~
