# proxyctl

A lightweight Rust CLI for managing proxy URLs, testing them through multiple proxy cores, comparing performance, and optionally activating a selected proxy.

> Project status: node management, managed-core inventory, initial core installation, and the shared verified artifact pipeline are implemented. Benchmarking, reports, sorting, pruning, activation, and TUN are being developed in stages.

## Goals

- Manage VLESS, VMess, Trojan, Shadowsocks, and Hysteria2 proxy URLs.
- Use sing-box, Xray, and Mihomo as external proxy cores.
- Install managed core binaries privately without touching system installations or other proxy applications.
- Benchmark latency, download, and upload performance through compatible cores.
- Keep benchmark history and safely prune unavailable nodes.
- Remain a CLI application with no GUI, tray, or required background daemon.

## Node management

~~~sh
proxyctl add "vless://..."
proxyctl import ~/Documents/servers.txt
proxyctl list
proxyctl list --include-deleted
proxyctl show 12
proxyctl remove 12
proxyctl restore 12
~~~

Imported source files are read-only. Credentials are masked in normal output. Proxyctl's data directory is private (0700 on Unix), and the database is protected (0600).

## Managed cores

Install all supported cores, or one selected core:

~~~sh
proxyctl setup
proxyctl setup --core sing-box
proxyctl setup --core xray
proxyctl setup --core mihomo
~~~

Show managed core versions and installation state:

~~~sh
proxyctl cores
~~~

The initial installer supports Linux x86_64. It selects stable assets from each core's official GitHub Releases API, verifies the GitHub-published SHA-256 asset digest before extraction, extracts only the expected regular executable without writing archive paths to disk, validates its reported version, then installs into the proxyctl data directory under cores/. It does not use PATH, package managers, sudo, or system directories. It does not start a core or change proxy, network, DNS, route, firewall, or TUN settings.

## Updating

~~~sh
proxyctl update --check
proxyctl update --check --prerelease
proxyctl update
proxyctl update --app
proxyctl update --cores
proxyctl update --core sing-box
proxyctl update --prerelease
proxyctl update --core sing-box --prerelease
~~~

With no selector, update targets the CLI and every installed managed core. Check is read-only. App updates only proxyctl; cores updates all installed managed cores; core selects one. Stable releases are always the default. `--prerelease` explicitly opts the selected update target(s) into prereleases; combine it with `--app`, `--cores`, or `--core` to scope that choice. Without it, a newer alpha, beta, or release candidate is ignored. Setup handles initial installation; update does not install missing cores. A component failure is reported independently.

The self-updater requires a published proxyctl GitHub Release. Core updates use the same official-release, digest-verification, staged installation pipeline as setup.

## Planned commands

~~~sh
proxyctl test --all-cores
proxyctl test --node 12 --core sing-box
proxyctl test --node 12 --core xray --download-bytes 2097152 --upload-bytes 1048576
proxyctl report
proxyctl list --sort ping
proxyctl list --sort download
proxyctl list --sort upload
proxyctl prune --unavailable-all --dry-run
proxyctl use 12 --core sing-box
proxyctl stop
proxyctl tun on
proxyctl tun off
~~~

Benchmark design and external measurement-service disclosure: see [docs/BENCHMARK_DESIGN.md](docs/BENCHMARK_DESIGN.md). `proxyctl test --all-cores` tests active nodes against installed compatible managed cores; `--node ID --core CORE` selects one pair. The initial defaults use Cloudflare Speed Test endpoints. Cloudflare states that completed measurements are collected for aggregated Internet-connection insights. Endpoint URLs, payload sizes, and timeouts are configurable. Benchmarking is explicit and sequential, uses a loopback-only local HTTP proxy listener, and does not change system proxy or network settings.

See docs/PLAN.md, docs/REQUIREMENTS.md, and docs/UPDATE_DESIGN.md.

## Development

Rust edition 2024; Rust 1.99.1 toolchain pinned. Run:

~~~sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
# Requires all three proxyctl-managed cores to be installed
cargo test --test native_adapter_validation -- --ignored --nocapture
cargo build --release
~~~

## Security

Proxy URLs can contain credentials. Do not share database files or logs containing unmasked URLs. Proxyctl only modifies its own private data directory. Core artifacts are verified before extraction or execution; archive paths are not extracted to disk. Setup and update never start cores or change system networking.
