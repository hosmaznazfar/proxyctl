# proxyctl

A lightweight Rust CLI for managing proxy URLs, testing them through multiple proxy cores, comparing performance, and optionally activating a selected proxy.

> Project status: node management, managed-core inventory and updates, adapters, sequential benchmarking, metric-specific sorting, benchmark reports/history, compatibility-aware pruning, and Linux single-core loopback activation are implemented. TUN inspection is read-only; TUN activation is temporarily disabled pending safe route ownership and crash recovery.

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
proxyctl show 1 2 3
proxyctl show 1..5
proxyctl remove 12
proxyctl remove 1 2 3
proxyctl remove 1..5
proxyctl remove all
proxyctl remove all --yes
proxyctl restore 1 2 3
proxyctl restore 1..5
proxyctl restore all
proxyctl check 1 2 3
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
proxyctl stop
~~~

Only one Proxyctl-managed core may be active at a time. Switching validates the replacement config first, then stops the previously tracked Proxyctl process before starting the selected core. The shared SOCKS5 + HTTP listener binds exclusively to 127.0.0.1; both protocols use the same printed port for manual application configuration. sing-box uses its native `mixed` inbound, Xray uses its native `mixed` inbound (the SOCKS handler also accepts HTTP proxy requests), and Mihomo uses `mixed-port`. No extra listener or proxy process is created. Managed core processes are displayed as `proxyctl-core` (argv[0] and Linux `comm`) regardless of the selected engine; `/proc/PID/exe` remains the real managed sing-box/Xray/Mihomo binary and is still checked for ownership. Default activation does not enable a system proxy or modify DNS, routes, firewall, or TUN settings. Stop verifies the recorded Linux process start identity and canonical executable path, then uses a pidfd-backed signal; stale or mismatched records never cause another process to be signalled. Activation currently requires Linux.

Setup and non-check update operations targeting the currently active core stop that exact tracked process before invoking the installer; update check-only remains read-only. Activation state and credentials-bearing runtime configuration are stored under the private Proxyctl runtime directory (0700 directory, 0600 files). State contains process identity and node/core identifiers only, not node credentials. Proxyctl uses only its own managed core binary path, never PATH fallback, and never manages another application's processes or core installations. The other managed core binaries remain idle and consume disk space only.

## TUN status inspection (read-only; activation disabled)

Read-only inspection remains available independently of activation:

~~~sh
proxyctl tun status
~~~

It reports Linux network interfaces, detected TUN/TAP devices, IPv4/IPv6 default routes, resolver nameservers and `resolv.conf` target, NetworkManager/systemd-resolved runtime presence, and a summary of the current nftables or iptables ruleset when a supported listing utility is available. Firewall rule contents are never printed. If the firewall cannot be inspected, the output says so rather than treating missing evidence as an empty ruleset.

The status command never creates or deletes interfaces, changes routes, alters DNS, modifies firewall rules, starts a proxy core, or requests elevated privileges.

TUN inspection is available through `proxyctl tun status` and is read-only. **TUN activation is temporarily disabled**, including `proxyctl use NODE --core CORE --tun`. The previous implementation could compare the post-stop network state with a baseline, but it did not implement safe restoration of routes/rules left behind when a core was force-killed or the application crashed. Detection without recovery is not sufficient for a system-wide routing feature. The CLI rejects TUN activation before starting a core, requesting elevated privileges, or changing network state. This restriction remains until Proxyctl has explicit ownership of every route/rule/interface it creates, crash-safe cleanup, idempotent recovery, and fault-injection tests proving that foreign VPNs and other applications are untouched. See [docs/TUN_DESIGN.md](docs/TUN_DESIGN.md).

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
proxyctl test --node 12 13 14 --core sing-box
proxyctl test --node 12..18 --core sing-box
proxyctl test --node 12 13 14 --all-cores
proxyctl test --node 12..18 --all-cores
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
proxyctl report --node 18 19 20
proxyctl report --node 18..25
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

## Shared node selection

Commands accepting node selectors share one syntax: a positive ID (`12`), list (`1 2 3`), inclusive range (`1..5`), combined IDs/ranges (`1 3 5..8`), or standalone `all`. The word `all` cannot be mixed with IDs. Duplicate IDs are removed; malformed, zero, reversed, and oversized ranges are rejected before work begins.

`remove` and `restore` are soft lifecycle operations that preserve benchmark history. `remove all` requires interactive confirmation; `--yes` explicitly confirms non-interactive removal. `restore all` selects deleted nodes only. Batch operations report missing and unchanged IDs separately.

~~~sh
proxyctl show 1 2 3
proxyctl check 1..5 --core xray
proxyctl test --node 1 2 3 --all-cores
proxyctl report --node 1..5 --history
proxyctl remove all
proxyctl restore all
~~~

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

Proxy URLs can contain credentials. Do not share database files or logs containing unmasked URLs. Proxyctl only modifies its own private data directory. Core artifacts are verified before extraction or execution; archive paths are not extracted to disk. Setup and update never start cores or change system networking. Only explicit benchmark and activation commands start a managed core, always with a loopback-only listener. Normal activation is limited to one Proxyctl-owned core process. Stop uses process-identity verification and cannot target another application's process. TUN activation is currently disabled at the service boundary. No command can start a TUN core or change routes, DNS, firewall rules, or interfaces through TUN mode until ownership and crash-safe recovery are implemented and fault-tested.
