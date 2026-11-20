# proxyctl

A lightweight Rust CLI for managing proxy URLs, testing them through multiple proxy cores, comparing performance, and optionally activating a selected proxy.

> Project status: node management, managed-core inventory and updates, adapters, core-batched benchmarking with bounded probes (Stages 1–5 user-verified; Stage 6 full offline verification batch passed and coverage audit completed), metric-specific sorting, benchmark reports/history, compatibility-aware pruning, Linux single-core loopback activation, and Bash/Fish/Zsh shell completion are implemented. TUN inspection is read-only; TUN activation remains disabled pending verified broker-owned TUN descriptor attachment, core launch/readiness integration, and independent recovery supervision. Draft broker, lifecycle, orchestration, request-validation, and attachment-evidence contract components exist but are not a usable end-to-end activation path.

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
proxyctl list --protocol vless
proxyctl list --search example.com
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

Imported source files are read-only. Credentials are masked in normal output.

### Configurable benchmark result tables

`proxyctl show` and `proxyctl report` use the same persistent table profile and column selection. `show` displays the latest results; `report` supports latest, history, and comparison views in the same table layout. The default profile is **normal** and shows node, server, protocol, core, latency, download, upload, and status. Compact shows node, core, latency, download, and upload. `show --details` switches to a separate connection-metadata table with protocol, server, port, name, active/deleted status, whether identity/secret values exist (masked), and option keys (values hidden).

~~~sh
proxyctl show 1..10
proxyctl show 1 --details

# Reports use the same configured table columns
proxyctl report
proxyctl report --history
proxyctl report --compare --core xray
proxyctl report --history --verbose

# Inspect and select a persistent profile
proxyctl config display
proxyctl config display profile compact
proxyctl config display profile normal
proxyctl config display profile full

# Customize each profile independently
proxyctl config display add-field compact server
proxyctl config display remove-field normal protocol
proxyctl config display add-field full tcp-ping
proxyctl config display remove-field full failures
~~~

Built-in profiles:
- **compact**: node, core, latency, download, upload.
- **normal** (default): node, server, protocol, core, latency, download, upload, status.
- **full**: expanded connection, core-version, direct TCP ping, sample, failure, run, and test-time context.

Available fields: `node`, `name`, `server`, `port`, `protocol`, `core`, `version`, `latency`, `tcp-ping`, `download`, `upload`, `status`, `attempts`, `failures`, `run`, and `tested`. The configuration is stored privately and persists across sessions. It applies consistently to `show`, `report`, `report --history`, and `report --compare`. In history mode each row represents one node/core/run; in comparison mode each row represents the latest completed node/core result. `--verbose` expands core version metadata without changing the selected columns. `not-run` means a metric was not attempted; `unavailable` means a preflight or runtime availability check explicitly failed; `skipped` means a metric was deliberately not attempted (for example, throughput blocked by the latency gate). These states are never merged.
 Proxyctl's data directory is private (0700 on Unix), and the database is protected (0600).

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

## Shell completion

During the first successful `proxyctl setup` in an interactive Bash, Fish, or Zsh session, Proxyctl offers to install completion for the detected shell. The offer is remembered independently per shell; declining does not affect core installation.

Install or refresh completion later (the shell is detected automatically):

~~~sh
proxyctl completions install
~~~

Or explicitly select a shell:

~~~sh
proxyctl completions install --shell fish
proxyctl completions install --shell bash
proxyctl completions install --shell zsh
~~~

Fish loads its completion file automatically. Bash installs into the standard per-user `bash-completion` directory and requires the `bash-completion` package to be installed and enabled. Zsh installs a `_proxyctl` function and adds its per-user completion directory plus `compinit` to `~/.zshrc`; restart Zsh (or source that file) afterward. No root privileges are used.

#### Shell-specific setup and verification

- **Fish:** install with `proxyctl completions install --shell fish`, then start a fresh Fish session. Use `complete -C 'proxyctl test --core '` to inspect suggestions without pressing Tab.
- **Bash:** install `bash-completion` with your distribution package manager, then ensure interactive Bash sources `/usr/share/bash-completion/bash_completion`. On systems where `~/.bashrc` does not already initialize it, add:

  ```bash
  if [[ $- == *i* ]] && [[ -r /usr/share/bash-completion/bash_completion ]]; then
      source /usr/share/bash-completion/bash_completion
  fi
  ```

  Install with `proxyctl completions install --shell bash`, start a new Bash session, and verify registration with `complete -p proxyctl`.
- **Zsh:** install with `proxyctl completions install --shell zsh`, then enter Zsh before sourcing its startup file: `zsh` followed by `source ~/.zshrc`. Do not source `~/.zshrc` from Fish or Bash. Verify with `whence -v _proxyctl` and `print -r -- ${+functions[_proxyctl]}` (expected: `1`).

In each shell, test command, option, and value completion by typing these prefixes and pressing Tab (or use the Fish `complete -C` form):

```sh
proxyctl 
proxyctl test 
proxyctl test --core 
proxyctl use 1 --core 
proxyctl update --core 
proxyctl config set 
proxyctl config reset 
proxyctl config display profile 
proxyctl config display add-field 
```

Core values offered by `--core` are `sing-box`, `xray`, and `mihomo`. Finite config values include `listen-port`, display profiles (`compact`, `normal`, `full`), and supported display fields. Arbitrary node IDs, URLs, search text, and numeric port values remain user-entered.

Inspect command help:

~~~sh
proxyctl --help
proxyctl test --help
proxyctl config display --help
proxyctl completions --help
proxyctl completions install --help
~~~

Completion scripts can also be printed for manual installation:

~~~sh
proxyctl completions generate fish
proxyctl completions generate bash
proxyctl completions generate zsh
~~~

The generated scripts include current command options and declared finite-value arguments. For example, `config set` completes `listen-port`, and display-profile commands complete the supported profiles and fields. Values such as node IDs, arbitrary search text, URLs, and port numbers remain user-entered.

To inspect and test the generated completions in each shell:

~~~sh
proxyctl completions generate bash
proxyctl completions generate fish
proxyctl completions generate zsh
~~~

After installing, start a fresh shell. In Zsh, verify that the completion directory is in `$fpath` and that `_proxyctl` is registered:

~~~zsh
source ~/.zshrc
print -rl -- $fpath
whence -v _proxyctl
compdef | grep -E '(^|[ =])proxyctl([ =]|$)'
~~~

Then try completion interactively by typing `proxyctl test `, `proxyctl config set `, and `proxyctl config display profile ` followed by Tab. For a non-interactive Zsh registration check:

~~~sh
zsh -ic 'autoload -Uz compinit; compinit; source ~/.zshrc; whence -v _proxyctl; print -r -- ${+functions[_proxyctl]}'
~~~

In Bash, check registration with `complete -p proxyctl` and try the same commands followed by Tab.

## Single-core activation

Activate one stored node with one explicitly selected Proxyctl-managed core:

~~~sh
proxyctl use 12 --core sing-box
proxyctl use 12 --core xray
proxyctl use 12 --core mihomo
proxyctl use 12 --core sing-box --port 10910
proxyctl config
proxyctl config set listen-port 10909
proxyctl config reset listen-port
proxyctl stop
~~~

Only one Proxyctl-managed core may be active at a time. Switching validates the replacement config first, then stops the previously tracked Proxyctl process before starting the selected core. The shared SOCKS5 + HTTP listener binds exclusively to 127.0.0.1; both protocols use the same port for manual application configuration. The persistent default is 10909 and is stored in the private Proxyctl data directory, so it survives terminal closure and reboot. `proxyctl config` displays it; `proxyctl config set listen-port PORT` changes it after checking that the loopback port is available; `proxyctl config reset listen-port` restores 10909. `proxyctl use NODE --core CORE --port PORT` overrides the saved value for one activation without changing the setting. Ports must be in the unprivileged range 1024–65535. If a requested port is occupied while changing the setting, Proxyctl reports the conflict and falls back to the built-in 10909 default; activation checks availability again and reports a startup-time conflict rather than silently choosing another port. sing-box uses its native `mixed` inbound, Xray uses its native `mixed` inbound (the SOCKS handler also accepts HTTP proxy requests), and Mihomo uses `mixed-port`. No extra listener or proxy process is created. Managed core processes use `proxyctl-core` as argv[0]; Linux `comm` is also set when the kernel permits it. `/proc/PID/exe` remains the real managed sing-box/Xray/Mihomo binary and is still checked for ownership. Default activation does not enable a system proxy or modify DNS, routes, firewall, or TUN settings. Stop verifies the recorded Linux process start identity and canonical executable path, then uses a pidfd-backed signal; stale or mismatched records never cause another process to be signalled. Activation currently requires Linux.

Setup and non-check update operations targeting the currently active core stop that exact tracked process before invoking the installer; update check-only remains read-only. Activation state and credentials-bearing runtime configuration are stored under the private Proxyctl runtime directory (0700 directory, 0600 files). State contains process identity and node/core identifiers only, not node credentials. Proxyctl uses only its own managed core binary path, never PATH fallback, and never manages another application's processes or core installations. The other managed core binaries remain idle and consume disk space only.

## TUN status inspection (read-only; activation disabled)

Read-only inspection remains available independently of activation:

~~~sh
proxyctl tun status
~~~

It reports Linux network interfaces, detected TUN/TAP devices, IPv4/IPv6 default routes, resolver nameservers and `resolv.conf` target, NetworkManager/systemd-resolved runtime presence, and a summary of the current nftables or iptables ruleset when a supported listing utility is available. Firewall rule contents are never printed. If the firewall cannot be inspected, the output says so rather than treating missing evidence as an empty ruleset.

The status command never creates or deletes interfaces, changes routes, alters DNS, modifies firewall rules, starts a proxy core, or requests elevated privileges.

TUN inspection is available through `proxyctl tun status` and is read-only. **TUN activation is temporarily disabled**, including `proxyctl use NODE --core CORE --tun`. The previous implementation could compare the post-stop network state with a baseline, but it did not implement safe restoration of routes/rules left behind when a core was force-killed or the application crashed. Detection without recovery is not sufficient for a system-wide routing feature. The CLI rejects TUN activation before starting a core, requesting elevated privileges, or changing network state. This restriction remains until Proxyctl has explicit ownership of every route/rule/interface it creates, crash-safe cleanup, idempotent recovery, and fault-injection tests proving that foreign VPNs and other applications are untouched. The target design is Linux-distribution-independent: it detects the active init/service manager at runtime rather than assuming systemd or branching on distro names. Offline groundwork now includes a private, atomic, generation-scoped ownership-manifest store with persisted lifecycle-event transitions, stale-generation rejection, cleanup-conflict retention, and cleanup-before-removal ordering. Linux process monitoring now has a pidfd-backed exact process identity primitive (PID, start time, and canonical executable) with fake-child tests, but a backend-injected monitor now watches a pinned core process; its PID, start ticks, and executable identity are persisted so restart recovery can safely resume monitoring or clean up after a confirmed process exit. It is not yet launched as a detached/init-managed supervisor and has no production kernel route manager. Each service-manager backend must pass the same recovery tests; unsupported managers fail closed instead of falling back to unsafe route handling. See [docs/TUN_DESIGN.md](docs/TUN_DESIGN.md).

### Stale legacy runtime recovery

If an older TUN experiment left a PID-zero runtime record, ordinary activation can retire that record only after confirming its systemd unit is absent, no TUN interface exists, and no new route or policy-rule entries appeared relative to the saved baseline. This compatibility recovery removes only Proxyctl's private stale state/config files; it never deletes or changes host network resources. Ambiguous state remains preserved and blocks activation.

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

Run the benchmark against all active nodes and installed compatible cores, or select one node/core pair. Proxyctl now prepares one process per selected core batch, rather than restarting the core for every node:

~~~sh
# Test every active node against all installed compatible cores
proxyctl test --all-cores

# Test one node against one selected core
proxyctl test --node 12 --core sing-box
proxyctl test --node 12 13 14 --core sing-box
proxyctl test --node 12..18 --core sing-box
proxyctl test --node 12 13 14 --all-cores
proxyctl test --node 12..18 --all-cores

# Quick is the default; Accurate uses three bounded parallel streams and a warm-up
proxyctl test --all-cores --profile quick
proxyctl test --node 12 --core xray --profile accurate

# Override a profile's download budget when needed
proxyctl test --node 12 --core xray --profile accurate --download-max-bytes 12582912

# Tune bounded latency workers and independent request deadlines
proxyctl test --all-cores --concurrency 3 --latency-timeout-secs 5 --request-timeout-secs 30
~~~

Each selected node receives up to three direct TCP-ping attempts, stopping at the first successful connection. Multiple IDs or ranges supplied to one `--node` option are executed under one shared benchmark run ID. For each compatible node/core pair, Proxyctl performs up to three real-latency attempts, stopping at the first successful response. Download and upload are attempted only if at least one latency attempt succeeds; otherwise both throughput metrics are recorded as skipped (`latency_gate`) and no transfer request is sent. Unsupported/invalid compatibility or core preflight failures skip all metrics for that node/core pair. Google `generate_204` is used for real ping and CacheFly's 10 MB test file for download. The **Quick** profile is the default: one download stream, a 1 MiB cap, a 5-second total download budget, and no warm-up bytes. **Accurate** uses three concurrent streams, an 8 MiB aggregate download cap, a 20-second total budget, and a 64 KiB best-effort warm-up request that is excluded from the timed result. The stream count, byte cap, and duration are persisted with every run. Downloads are capped at 32 MiB; upload payloads remain capped at 1 MiB. Upload uses Cloudflare's endpoint and a generated synthetic payload, never user files or proxy credentials. Each stream makes one request per benchmark attempt. Quick accepts a useful partial result without retrying solely for the missing bytes. Accurate retries incomplete aggregate downloads up to three total attempts, each with its full configured duration; bytes from different attempts are never combined. Quick retains a partial result only when at least 16 KiB was received; Accurate retries partial results and records them as incomplete attempts. Probe concurrency is configurable from 1 to 3 (default 3). Upload timing includes sending the complete synthetic body and receiving the server response.

Core batches run one at a time in deterministic core order; Proxyctl never runs multiple managed cores concurrently. Each compatible node has its own uniquely routed loopback listener and outbound inside the batch. Node compatibility and native single-node config validation happen independently before batching, so an unsupported or invalid node is excluded without preventing its peers from running. Real-latency and direct TCP probes use the configured concurrency (default 3, hard maximum 3); each node receives up to three latency attempts, stopping at the first success, with a configurable latency request deadline (default five seconds). Download and upload remain sequential per node and retain the full-mode latency gate. Ctrl-C stops and reaps the active managed core and waits for in-flight probe workers to finish. Benchmark optimization Stages 1–6 have been implemented and locally verified by the user. Stage 7 (real-world comparison against the reference clients) remains a separate, user-run validation step. No public endpoint or real core is used by automated tests. The temporary HTTP proxy listener binds only to 127.0.0.1. Benchmarking does not change system proxy, DNS, routes, firewall, or TUN settings. See [docs/BENCHMARK_DESIGN.md](docs/BENCHMARK_DESIGN.md) for the measurement definitions, endpoint contract, and privacy notes.

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

Real ping and direct TCP ping are separate measurements. Cross-core sorting gives each core with a successful latest completed result equal weight by taking the median of those per-core medians. Core-specific sorting uses only that core. Interrupted and cancelled runs are ignored; a newer completed run supersedes an older result even if its attempts failed. Missing measurements remain unranked at the bottom, never as zero.

## Benchmark reports and history

Show the latest run for every active node, or inspect one node:

~~~sh
proxyctl report
proxyctl report --node 18
proxyctl report --node 18 19 20
proxyctl report --node 18..25
~~~

Show the retained run history (newest first), including cancelled and interrupted runs. Proxyctl automatically keeps at most the three newest runs per node/core target and removes older target attempts:

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

Reports retain the distinction between direct TCP ping and measurements through a proxy core. Each metric displays its successful measurement (when available), the number of attempts made, and failure or not-run counts. A Quick partial download is explicitly marked partial. A newer completed run supersedes older results even if all of its attempts failed; cancelled and interrupted runs appear in history but do not replace a core's latest completed comparison. Reports are read-only and never start proxy cores or change system networking. Core versions are concise by default (for example, `sing-box (1.14.4)`); `--verbose` preserves the full version/build metadata recorded with the run.

## Compatibility-aware pruning

Preview whether a node has any usable real-ping path through sing-box, Xray, or Mihomo:

~~~sh
proxyctl prune --unavailable-all
proxyctl prune --unavailable-all --dry-run
proxyctl prune --unavailable-all --apply
~~~

Or evaluate one managed core:

~~~sh
proxyctl prune --core xray --unavailable
proxyctl prune --core xray --unavailable --apply
~~~

Preview is the default; only `--apply` soft-deletes eligible nodes. In all-core mode, Proxyctl evaluates sing-box, Xray, and Mihomo, regardless of whether a node is currently supported by each adapter. A core counts as unusable when the current adapter marks the node unsupported/invalid, or when its latest completed benchmark evidence shows no successful real-ping sample (including timeout, unreachable, or unavailable outcomes). A node is eligible only when all three cores are proven unusable. One successful real-ping sample through any core keeps the node. Missing runs, incomplete attempts, and cancelled runs remain inconclusive and prevent pruning. Pruning is based only on stored evidence; it never starts cores or contacts the Internet. A newer completed run supersedes older evidence; cancelled/interrupted runs do not. Use `list --include-deleted` to see deleted positions (`D1`, `D2`, ...), then run `proxyctl restore 1` to restore the first deleted row.

## Shared node selection

Commands accepting node selectors use **current one-based display numbers**, not persistent database IDs: a number (`12`), list (`1 2 3`), inclusive range (`1..5`), combined numbers/ranges (`1 3 5..8`), or standalone `all`. Active-node commands (`show`, `remove`, `check`, `test`, `report`, and `use`) resolve against the current active list. After a removal, later active nodes immediately shift up in display numbering. `list --include-deleted` labels deleted rows `D1`, `D2`, and so on; `restore 1` selects the first deleted row, and ranges/lists use those deleted-row positions. `all` selects the relevant active or deleted set. Duplicate selectors are removed; malformed, zero, reversed, oversized, and out-of-range selections are rejected before work begins.

Persistent database IDs are never renumbered. Benchmark runs and attempts continue referencing the same records, so adding, removing, or restoring a node cannot reassign another node's history. New nodes and restored nodes are appended to active display order. Filtered lists keep the numbers from the full active list; sorted lists show the original node number alongside the separate rank.

`remove` and `restore` are soft lifecycle operations that preserve benchmark history. `remove all` requires interactive confirmation; `--yes` explicitly confirms non-interactive removal. `restore all` selects deleted rows only. Batch operations report missing and unchanged selections separately. For a deleted row, use its `D#` position from `list --include-deleted` with `restore`.

~~~sh
proxyctl show 1 2 3
proxyctl check 1..5 --core xray
proxyctl test --node 1 2 3 --all-cores
proxyctl test --all-cores --latency-only
proxyctl test --all-cores --download-only
proxyctl test --all-cores --upload-only
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


### Accurate download retry policy

Quick accepts a useful partial download after one attempt. Accurate retries an incomplete download up to three total attempts, stopping only when the configured byte cap is reached. Each Accurate attempt receives the full configured download duration; attempts are not divided into one shared duration. Latency, TCP-connect, and upload checks retry failures up to three total attempts and stop at the first success. Attempt history records only the attempts actually made.


**TUN integration status:** Linux SCM_RIGHTS descriptor-transfer primitives now exist, but they are not connected to a managed-core launch or a core-supported TUN descriptor consumer. A successful descriptor send is not proof of attachment. TUN activation remains gated; see docs/TUN_FIRST_DRAFT_PLAN.md.


**TUN handoff status:** A generation-bound, nonce-bearing descriptor offer/acknowledgement protocol is available as an integration seam. It verifies Unix-socket peer credentials against a process identity and acknowledges only after a core-adoption callback succeeds. No native-core adapter currently consumes the descriptor; TUN activation remains gated.


The native-core attachment inventory is explicit: Xray documents Linux external TUN FD input through `XRAY_TUN_FD`, while the current sing-box adapter requests native named-device creation and Mihomo remains unsupported for the marked TUN contract. Proxyctl has not yet connected broker descriptor export and process launch to Xray's environment-variable path, so this does not change the TUN activation gate.


The TUN mutation broker can now export its retained descriptor to an authenticated same-user client for an exact live activation generation using SCM_RIGHTS. This is only the broker-to-client transport leg; core launch/adoption and independent readiness are still not integrated, so TUN activation remains disabled.


Xray now has a Linux-only descriptor-inheritance helper for its documented `XRAY_TUN_FD` input. It preserves close-on-exec in the parent and exposes the descriptor only to the spawned Xray child. The helper is not yet connected to public activation or readiness checks; TUN remains disabled.
