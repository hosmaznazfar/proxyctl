# proxyctl

A lightweight Rust command-line tool for managing proxy URLs, testing them through multiple proxy cores, comparing performance, and optionally activating a selected proxy.

> **Project status:** the first usable node-management commands are implemented. Core installation, benchmarking, reports, sorting, pruning, activation, and TUN are planned next.

## Goals

- Manage proxy URLs from VLESS, VMess, Trojan, Shadowsocks, and Hysteria2 sources.
- Work with three external proxy cores: [sing-box](https://sing-box.sagernet.org/), [Xray](https://github.com/XTLS/Xray-core), and [Mihomo](https://github.com/MetaCubeX/mihomo).
- Install and update core binaries in a proxyctl-managed directory.
- Update the proxyctl CLI itself from this repository's official GitHub Releases.
- Benchmark latency, download, and upload performance through each compatible core.
- Sort nodes by their best result across compatible cores or by a selected core.
- Keep benchmark history and safely prune unavailable nodes.
- Remain a CLI application with no GUI, tray, or required background daemon.

## Design principles

- Rust application logic with external core binaries.
- Embedded [redb](https://github.com/cberner/redb) storage; no database server.
- Open the database only while a command needs it, then close it.
- Preserve imported source files; never edit them.
- Mask credentials by default and protect local data files.
- Run benchmarks sequentially by default.
- Do not silently discard unsupported URL options.
- Make TUN and system-wide networking changes explicit and reversible.
- Download only platform-compatible stable release assets from official project release sources.
- Verify artifacts and stage replacements before installing; never discard a working binary on failure.

## Available commands

Build and run the application:

~~~sh
cargo run -- --help
cargo run -- --version
~~~

Add one URL:

~~~sh
proxyctl add "vless://..."
~~~

Import a text file. Blank lines and lines beginning with # are ignored; the source file is never modified.

~~~sh
proxyctl import ~/Documents/servers.txt
~~~

List, inspect, soft-delete, and restore records:

~~~sh
proxyctl list
proxyctl list --include-deleted
proxyctl show 12
proxyctl remove 12
proxyctl restore 12
~~~

The default database is stored under XDG_DATA_HOME when set, otherwise under ~/.local/share/proxyctl/proxyctl.redb. On Unix, the application secures its data directory with mode 0700 and the database file with mode 0600.

Normal output masks credentials. The show command displays option names but not option values or the original URL.

## Updating proxyctl

The initial self-update command is implemented for Linux x86_64. It checks the official GitHub Releases endpoint, verifies the matching asset against the release SHA-256 manifest, validates the staged executable, and replaces the current binary only after validation.

~~~sh
proxyctl update --check
proxyctl update
proxyctl update --app
~~~

The first published proxyctl release is required before an update can be downloaded. Core installation and core update targets are still under development; the unified command will include installed managed cores when that stage is complete.

## Planned commands

The following command groups are planned and are not available yet.

~~~sh
# Managed-core installation and updates (not implemented yet)
proxyctl setup
proxyctl setup --core sing-box
proxyctl cores
proxyctl update --cores
proxyctl update --core sing-box
proxyctl update --core xray
proxyctl update --core mihomo

# Test nodes
proxyctl test --all-cores
proxyctl test --node 12 --core sing-box

# View benchmark reports
proxyctl report
proxyctl report --history
proxyctl report --compare
proxyctl report --core mihomo
proxyctl report --node 12

# Sort by the best result across compatible cores
proxyctl list --sort ping
proxyctl list --sort download
proxyctl list --sort upload

# Restrict sorting to one core
proxyctl list --sort ping --core xray
proxyctl list --sort download --core sing-box
proxyctl list --sort upload --core mihomo

# Preview cleanup before applying it
proxyctl prune --unavailable-all --dry-run
proxyctl prune --unavailable-all --apply
proxyctl prune --core xray --unavailable --dry-run
proxyctl prune --core xray --unavailable --apply

# Activate one node or stop a proxyctl-managed process
proxyctl use 12 --core sing-box
proxyctl stop

# Optional TUN mode
proxyctl tun on
proxyctl tun off
~~~

### Unified update and installation behavior

The update command is the single entry point for keeping the CLI and its managed cores current. With no target selector, it updates the CLI and every core already installed by proxyctl. It does not install missing cores; setup handles initial core installation. Use --check for a read-only check, --app for the CLI only, --cores for all installed cores, or --core <name> for one core.

The CLI updater uses official releases from [hosmaznazfar/proxyctl](https://github.com/hosmaznazfar/proxyctl/releases). Core installers use the official releases of [sing-box](https://github.com/SagerNet/sing-box/releases), [Xray](https://github.com/XTLS/Xray-core/releases), and [Mihomo](https://github.com/MetaCubeX/mihomo/releases). Stable releases are selected by default, and asset selection must match the detected OS and architecture.

Setup and update share the same artifact download, verification, staging, validation, and installation pipeline. Checksums/signatures are verified before extraction or execution. If trusted verification material is unavailable or verification fails, proxyctl refuses to install the artifact. The previous working binary is preserved if an update fails. If safe self-replacement is not possible, the CLI prints a manual update path and leaves the current executable intact.

Updates never start a core or modify active proxy processes, system proxy settings, DNS, routes, firewall, or TUN state. Only proxyctl-managed binaries are touched; system installations and other proxy applications are left alone.

See [Update and Installation Design](docs/UPDATE_DESIGN.md) for the detailed release, verification, platform, and failure-handling contract.

### Sorting behavior

Without a core filter, proxyctl will calculate each node's median successful result per compatible core, select that node's best result, and show which core produced it. With the core filter, only results from that core are considered. Lower latency is better; higher download and upload throughput are better.

### Cleanup behavior

A node is considered unavailable across cores only if all cores capable of representing that node have completed connectivity evaluations and none has a successful connection. Unsupported cores do not count as connection failures. Cleanup previews candidates first and uses soft deletion so records can be restored.

## Documentation

- [Plan and architecture decisions](docs/PLAN.md)
- [Software requirements](docs/REQUIREMENTS.md)
- [Update and installation design](docs/UPDATE_DESIGN.md)

The plan documents the design, architecture, command semantics, and delivery stages. The requirements document defines functional behavior and acceptance criteria. The update design specifies the shared secure installation/update pipeline.

## Development

- Rust edition: 2024.
- Toolchain: Rust 1.99.1, pinned in rust-toolchain.toml.
- Minimum supported Rust version: 1.90.
- Core dependencies: clap, redb, serde, serde_json, thiserror, anyhow, and tracing.

Build and test locally with:

~~~sh
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
~~~

CI runs formatting, Clippy, and tests on pushes and pull requests. The next stages add core adapters and management, benchmarking, reporting, sorting, and cleanup. See [PLAN.md](docs/PLAN.md) for the staged roadmap.

## Security

Proxy URLs may contain credentials and other sensitive values. Do not share database files, debug logs, or command output containing unmasked URLs. Proxyctl masks secrets in normal output and uses restrictive permissions for local data.

Core binaries and the CLI updater are designed to download official release assets and verify them before installation. TUN support will be opt-in and will require explicit network-state checks and rollback handling.

## License

License: not selected yet.
