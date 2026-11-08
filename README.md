# proxyctl

A lightweight Rust command-line tool for managing proxy URLs, testing them through multiple proxy cores, comparing performance, and optionally activating a selected proxy.

> **Project status:** initial Rust project foundation is in place. Protocol parsing, storage, core management, and benchmarking are the next implementation stages.

## Goals

- Manage proxy URLs from VLESS, VMess, Trojan, Shadowsocks, and Hysteria2 sources.
- Work with three external proxy cores: [sing-box](https://sing-box.sagernet.org/), [Xray](https://github.com/XTLS/Xray-core), and [Mihomo](https://github.com/MetaCubeX/mihomo).
- Install and update core binaries in a proxyctl-managed directory.
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

## Current development status

The initial Rust package and module boundaries are committed. The current executable supports Cargo's generated help and version output; application commands are being added incrementally.

~~~sh
cargo run -- --help
cargo run -- --version
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
~~~

The repository CI runs formatting, Clippy, and tests on pushes and pull requests.

## Planned commands

The following is the target command interface. Commands remain planned until their implementation is merged.

~~~sh
proxyctl setup
proxyctl cores
proxyctl update

proxyctl import ~/Documents/servers.txt
proxyctl add "vless://..."
proxyctl list
proxyctl show 12
proxyctl remove 12
proxyctl restore 12

proxyctl test --all-cores
proxyctl test --node 12 --core sing-box

proxyctl report
proxyctl report --history
proxyctl report --compare
proxyctl report --core mihomo
proxyctl report --node 12

proxyctl list --sort ping
proxyctl list --sort download
proxyctl list --sort upload
proxyctl list --sort ping --core xray

proxyctl prune --unavailable-all --dry-run
proxyctl prune --unavailable-all --apply
proxyctl prune --core xray --unavailable --dry-run
proxyctl prune --core xray --unavailable --apply

proxyctl use 12 --core sing-box
proxyctl stop

proxyctl tun on
proxyctl tun off
~~~

### Sorting behavior

Without a core filter, proxyctl will calculate each node's median successful result per compatible core, select that node's best result, and show which core produced it. With the core filter, only results from that core are considered. Lower latency is better; higher download and upload throughput are better.

### Cleanup behavior

A node is considered unavailable across cores only if all cores capable of representing that node have completed connectivity evaluations and none has a successful connection. Unsupported cores do not count as connection failures. Cleanup previews candidates first and uses soft deletion so records can be restored.

## Documentation

- [Plan and architecture decisions](docs/PLAN.md)
- [Software requirements](docs/REQUIREMENTS.md)

The plan documents the design, architecture, command semantics, and delivery stages. The requirements document defines functional behavior and acceptance criteria.

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

The next stages add the domain model and URL parsers, followed by database repositories and node-management commands. See [PLAN.md](docs/PLAN.md) for the staged roadmap.

## Security

Proxy URLs may contain credentials and other sensitive values. Do not share database files, debug logs, or command output containing unmasked URLs. Proxyctl is designed to mask secrets in normal output and use restrictive permissions for local data.

Core binaries are planned to be downloaded from official release sources and verified before execution. TUN support will be opt-in and will require explicit network-state checks and rollback handling.

## License

License: not selected yet.
