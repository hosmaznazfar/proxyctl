# proxyctl

A lightweight Rust CLI for managing proxy URLs, testing them through multiple proxy cores, comparing performance, and optionally activating a selected proxy.

> Project status: node management, managed-core inventory and updates, adapters, sequential benchmarking, metric-specific sorting, benchmark reports/history, compatibility-aware pruning, Linux single-core activation, and opt-in native TUN activation are implemented.

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

## Single-core activation

Activate one stored node with one explicitly selected Proxyctl-managed core:

~~~sh
proxyctl use 12 --core sing-box
proxyctl use 12 --core xray
proxyctl use 12 --core mihomo

# Explicitly opt in to core-native TUN routing (Linux only)
proxyctl use 12 --core sing-box --tun
proxyctl stop
~~~

Only one Proxyctl-managed core may be active at a time. Switching validates the replacement config first, then stops the previously tracked Proxyctl process before starting the selected core. The shared SOCKS5 + HTTP listener binds exclusively to 127.0.0.1; both protocols use the same printed port for manual application configuration. sing-box uses its native `mixed` inbound, Xray uses its native `mixed` inbound (the SOCKS handler also accepts HTTP proxy requests), and Mihomo uses `mixed-port`. No extra listener or proxy process is created. Default activation does not enable a system proxy or modify DNS, routes, firewall, or TUN settings. Stop verifies the recorded Linux process start identity and canonical executable path, then uses a pidfd-backed signal; stale or mismatched records never cause another process to be signalled. Activation currently requires Linux.

Setup and non-check update operations targeting the currently active core stop that exact tracked process before invoking the installer; update check-only remains read-only. Activation state and credentials-bearing runtime configuration are stored under the private Proxyctl runtime directory (0700 directory, 0600 files). State contains process identity and node/core identifiers only, not node credentials. Proxyctl uses only its own managed core binary path, never PATH fallback, and never manages another application's processes or core installations. The other managed core binaries remain idle and consume disk space only.

## TUN status inspection and opt-in activation

Read-only inspection remains available independently of activation:

~~~sh
proxyctl tun status
~~~

It reports Linux network interfaces, detected TUN/TAP devices, IPv4/IPv6 default routes, resolver nameservers and `resolv.conf` target, NetworkManager/systemd-resolved runtime presence, and a summary of the current nftables or iptables ruleset when a supported listing utility is available. Firewall rule contents are never printed. If the firewall cannot be inspected, the output says so rather than treating missing evidence as an empty ruleset.

The status command never creates or deletes interfaces, changes routes, alters DNS, modifies firewall rules, starts a proxy core, or requests elevated privileges.

TUN activation is a separate explicit opt-in through `proxyctl use NODE --core CORE --tun`. It uses the selected core's native TUN mode and route manager; it requires systemd, sudo authorization, iproute2, and readable/writable `/dev/net/tun`. It refuses to start while a foreign TUN/TAP interface is present, to avoid taking over another VPN's routing. A transient systemd service runs the core as the invoking user with only `CAP_NET_ADMIN` in its capability bounding and ambient sets, plus `NoNewPrivileges=yes`; Proxyctl does not run the core as root, change file capabilities, store passwords, or install a permanent privileged daemon. TUN configs disable system DNS integration and firewall auto-redirect. Before stopping an existing core, Proxyctl checks the current network baseline and preflights the transient systemd capability policy with a one-shot `true` service that changes no networking. After stopping the previous Proxyctl activation, it captures the final baseline of interfaces, IPv4/IPv6 routes and policy rules, DNS nameservers, and the `resolv.conf` target. Stop asks systemd to stop only the recorded unit and clears state only after the full baseline is restored. If cleanup differs, the manifest/config are retained for manual inspection and Proxyctl never broadly deletes routes or interfaces. See [docs/TUN_DESIGN.md](docs/TUN_DESIGN.md).

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

## Benchmarking

Run the initial sequential benchmark against all active nodes and installed compatible cores, or select one node/core pair:

~~~sh
# Test every active node against all installed compatible cores
proxyctl test --all-cores

# Test one node against one selected core
proxyctl test --node 12 --core sing-box

# Test one node against every installed compatible core
proxyctl test --node 12 --all-cores
~~~

Each selected node receives three direct TCP-ping samples. Each compatible node/core pair receives three real-ping, download, and upload samples through that core. The revised defaults follow v2rayN where applicable: Google `generate_204` for real ping and CacheFly's 10 MB test file for download, sampling only the first 2 MiB per sample to keep data use modest. Upload remains separately configurable and initially uses Cloudflare's upload endpoint, with a 256 KiB synthetic payload per sample to keep the default usable on slower upstream links. Cloudflare documents aggregated measurement collection; Proxyctl sends only a generated synthetic body, not user files or proxy credentials. All endpoint URLs, payload limits, and timeouts are configurable.

Benchmarking is explicit and sequential. The CLI reports live node/core/metric/sample progress, and Ctrl-C stops the active core so an in-flight request can be interrupted and cleaned up. The temporary HTTP proxy listener binds only to 127.0.0.1. Benchmarking does not change system proxy, DNS, routes, firewall, or TUN settings. See [docs/BENCHMARK_DESIGN.md](docs/BENCHMARK_DESIGN.md) for the measurement definitions, endpoint contract, and privacy notes.

Sort nodes independently by each benchmark metric:

~~~sh
# Cross-core comparison: median of the latest completed per-core medians
proxyctl list --sort ping
proxyctl list --sort download
proxyctl list --sort upload

# Restrict comparison to one managed core
proxyctl list --sort ping --core sing-box
proxyctl list --sort download --core xray
proxyctl list --sort upload --core mihomo

# Direct TCP ping is a separate metric and does not use a proxy core
proxyctl list --sort tcp-ping
~~~

Real ping and direct TCP ping are separate measurements. Cross-core sorting gives each core with a successful latest completed result equal weight by taking the median of those per-core medians. Core-specific sorting uses only that core. Interrupted and cancelled runs are ignored; a newer completed run supersedes an older result even if its samples failed. Missing measurements remain unranked at the bottom, never as zero.

## Benchmark reports and history

Show the latest run for every active node, or inspect one node:

~~~sh
proxyctl report
proxyctl report --node 18
~~~

Show the full run history (newest first), including cancelled and interrupted runs:

~~~sh
proxyctl report --history
proxyctl report --node 18 --history
~~~

Compare each core independently using its latest completed run:

~~~sh
proxyctl report --compare
proxyctl report --compare --node 18
proxyctl report --compare --core xray
proxyctl report --compare --node 18 --core mihomo

# Full version/build metadata
proxyctl report --verbose
proxyctl report --history --verbose
proxyctl report --compare --verbose
~~~

Reports retain the distinction between direct TCP ping and measurements through a proxy core. Each metric displays its median of successful samples, the successful count out of three, and failure or not-run counts. A partial median is explicitly marked partial. A newer completed run supersedes older results even if all of its samples failed; cancelled and interrupted runs appear in history but do not replace a core's latest completed comparison. Reports are read-only and never start proxy cores or change system networking. Core versions are concise by default (for example, `sing-box (1.14.4)`); `--verbose` preserves the full version/build metadata recorded with the run.

## Compatibility-aware pruning

Preview candidates across all installed cores that currently support each node:

~~~sh
proxyctl prune --unavailable-all
proxyctl prune --unavailable-all --dry-run
~~~

Or evaluate one installed managed core:

~~~sh
proxyctl prune --core xray --unavailable
proxyctl prune --core xray --unavailable --apply
~~~

Preview is the default; only `--apply` soft-deletes eligible nodes. In all-core mode, unsupported core/node combinations are excluded rather than counted as failures. A node is eligible only when every currently compatible core has a latest completed benchmark run with three distinct real-ping samples, all marked unreachable. One successful sample keeps the node. Missing runs, partial samples, invalid compatibility, startup/preflight errors, timeouts, cancellations, and other ambiguous HTTP/runtime failures prevent pruning. A newer completed run supersedes older evidence; cancelled/interrupted runs do not. Use `proxyctl restore ID` to restore a soft-deleted node.

## Additional planned commands

~~~sh
proxyctl test --all-cores
proxyctl test --node 12 --all-cores
proxyctl test --node 12 --core sing-box
proxyctl test --node 12 --core xray --download-bytes 2097152 --upload-bytes 1048576
proxyctl report
proxyctl report --node 18 --history
proxyctl report --compare
proxyctl list --sort ping
proxyctl list --sort download
proxyctl list --sort upload
proxyctl prune --unavailable-all --dry-run
proxyctl use 12 --core sing-box --tun
proxyctl stop
~~~

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

Proxy URLs can contain credentials. Do not share database files or logs containing unmasked URLs. Proxyctl only modifies its own private data directory. Core artifacts are verified before extraction or execution; archive paths are not extracted to disk. Setup and update never start cores or change system networking. Only explicit benchmark and activation commands start a managed core, always with a loopback-only listener. Normal activation is limited to one Proxyctl-owned core process. Stop uses process-identity verification and cannot target another application's process. TUN is opt-in and changes system routes only when explicitly requested; it does not alter system DNS or firewall rules. The TUN core runs with CAP_NET_ADMIN only inside a transient systemd service, and stop verifies restoration of the captured route/rule/interface/DNS baseline.
