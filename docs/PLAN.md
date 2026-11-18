# Proxyctl — Plan and Architecture Decisions

> Status: approved baseline; benchmark optimization Stages 1–6 and architecture refactor Phases 1–3 are user-verified; benchmark persistence has been extracted into its own database module and locally verified; architecture review findings are in `docs/ARCHITECTURE_REVIEW.md`; real-world runbook is in `docs/BENCHMARK_REAL_WORLD_VALIDATION.md`
> Repository: https://github.com/hosmaznazfar/proxyctl  
> Last updated: 2026-11-18

## 1. Purpose

Proxyctl is a lightweight, command-line-only Rust application for importing proxy URLs, checking compatibility with supported proxy cores, benchmarking them, comparing results, selecting a node, and with TUN activation deferred until crash-safe network recovery is implemented.

Initial cores: sing-box, Xray, and Mihomo. Proxyctl orchestrates official core binaries; it does not reimplement proxy protocols or embed the cores as Rust libraries.

## 2. Product principles

1. CLI only: no GUI, tray, background manager daemon, or always-running database service.
2. Low overhead: keep dependencies and runtime footprint small; run one benchmark core at a time by default.
3. Explicit behavior: never silently ignore unsupported URL options, silently change system networking, or delete a node based on incomplete tests.
4. Separation of concerns: CLI parsing, domain logic, storage, protocol parsing, core adapters, benchmarking, and system networking remain independent.
5. Extensibility: new cores, protocols, benchmark metrics, sort keys, and cleanup policies should be addable without rewriting command handlers.
6. Safe defaults: mask credentials, protect local files, verify downloaded binaries, and make destructive or system-wide operations explicit.
7. Preserve the source: importing a text file must never modify that file.

## 3. Core decisions

| Area | Decision |
|---|---|
| Language | Rust |
| Interface | CLI only |
| Core engines | sing-box, Xray, Mihomo |
| Core installation | Proxyctl-managed binaries in its private data directory |
| Core execution | External processes; one selected core at a time for normal use |
| URL input | Import a user-provided text file or add one URL |
| Source file | Read-only input; proxyctl never edits it |
| Persistent storage | Embedded redb database |
| Database lifecycle | Open only for a command's read/write phase, then close; no database daemon |
| Benchmark history | Keep multiple runs and individual attempts |
| Default URL display | Mask credentials and sensitive URL fields |
| Benchmark probe concurrency | Bounded to three concurrent latency/TCP probes; throughput transfers sequential |
| TUN | Disabled until exact route ownership, crash-safe recovery, and isolation are proven |

### 3.1 Managed core binaries

**Implementation status:** the first managed-core installer and inventory are implemented for Linux x86_64.

- `proxyctl setup` installs all three supported cores sequentially; `--core` selects one.
- `proxyctl cores` reports whether each proxyctl-managed executable is installed and displays its reported version.
- Core binaries are stored only below the proxyctl data directory. The installer never searches PATH, invokes a package manager, uses sudo, or modifies system core installations.
- Each upstream has a separate asset resolver. sing-box uses its Linux amd64 tar.gz archive, Xray uses its Linux 64-bit ZIP, and Mihomo uses its baseline GOAMD64 v1 gzip binary.
- The installer requires the SHA-256 digest published in the official GitHub release asset metadata, verifies the complete archive before extraction, extracts only the expected regular executable, validates its version command, and replaces the destination only after validation.
- Archive paths are never extracted to disk. Download and extracted executable sizes are bounded. Missing digest metadata or an unsupported platform fails closed.
- Setup does not start a core or change proxy, DNS, routes, firewall, or TUN state. Other proxy applications, including V2rayN, remain outside Proxyctl's managed paths.

### 3.1.1 Unified application and core updater

There is one update entry point for the proxyctl executable and all managed core binaries:

~~~sh
# Check and apply updates for proxyctl and every installed managed core
proxyctl update

# Check only; do not download or replace anything
proxyctl update --check

# Limit the update operation
proxyctl update --app
proxyctl update --cores
proxyctl update --core sing-box
proxyctl update --core xray
proxyctl update --core mihomo
~~~

With no target selector, `proxyctl update` checks and updates both the CLI application and all installed managed cores. `--check` makes the operation read-only and reports current/latest versions and availability. The target selectors are mutually exclusive; `--core` may be repeated only if the CLI design explicitly supports multiple values, otherwise it selects one core.

Application releases are published by the proxyctl GitHub repository. The initial implementation supports Linux x86_64 assets produced by the release workflow. The updater requests a bounded page of 10 GitHub releases per component to avoid oversized metadata responses, selects the newest eligible semantic version from that page, verifies the published SHA-256 manifest, stages the compatible asset beside the installed executable, validates its --version output, and replaces the executable atomically where the platform permits. Core version banners are parsed down to their semantic version before display, so update status output stays concise; check-only mode prints only the up-to-date or update-available status for each core. Other OS/architectures remain unsupported until matching release jobs are added. It must never overwrite the running binary before the verified replacement is ready. If a safe self-replacement is unavailable, it reports the manual update command instead of risking a broken installation.

Core updates use the same download/verification/staging policy and preserve the last working binary on any failure. The updater reports each component independently: current version, available version, action taken, and error. A failure updating one core must not corrupt or silently roll back another component. Updates never start a core or change active proxy/network settings.

`proxyctl setup` remains the initial installation/bootstrap command; it installs the selected managed cores and does not update the CLI itself. `proxyctl cores` reports installed core versions and status.

#### Shell completion

- Bash, Fish, and Zsh are supported by the same Clap-derived command/argument completion definitions.
- On the first successful `proxyctl setup` in an interactive supported shell, offer to install completion for that detected shell. The prompt is remembered independently per shell; declining does not affect core setup.
- `proxyctl completions install` detects the current shell; `--shell fish|bash|zsh` explicitly selects or refreshes one.
- Fish uses its native per-user autoload directory. Bash uses the standard per-user bash-completion directory and requires the system `bash-completion` integration to be installed/enabled. Zsh installs a per-user `_proxyctl` function and adds its completion directory plus `compinit` to `~/.zshrc`.
- `proxyctl completions generate SHELL` remains available for printing scripts for manual installation.
- Completion files are written atomically and per-user; no sudo or system-wide file changes are used. Zsh's user startup file is updated idempotently to activate its per-user completion directory.
- Interactive verification completed by the user in Fish, Zsh, and Bash: root/subcommand suggestions, command options, `--core` values (`sing-box`, `xray`, `mihomo`), and positional config values were checked. Bash required the distribution's `bash-completion` package and interactive initialization in `~/.bashrc`; Zsh's `~/.zshrc` must be sourced from Zsh itself, not from Fish or Bash.
- Automated local verification completed after the final completion changes: `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test`, and `cargo build --release` all passed (user-reported).

### 3.2 URL records and source-file handling

The user's text file is an import source, not a live database or output file. Proxyctl reads it without changing it. Imported URL records are stored in redb, including the original URL needed to recreate core configurations.

A stable fingerprint prevents duplicate records. Re-importing an existing URL updates import metadata rather than creating a duplicate. Different credentials or connection settings remain distinct records. Duplicate lines within one import are also deduplicated.

Default list output shows an ID, protocol, server, port, and optional display name. Credentials and other secrets are masked. Any future reveal operation must be explicit and must not write secrets to logs or ordinary error output.

### 3.3 Storage model

Use versioned logical tables, initially:

- nodes: original URL, parsed fields, fingerprint, display metadata, lifecycle state, timestamps.
- node_fingerprints: unique fingerprint-to-node lookup.
- benchmark_runs: run metadata, selected cores, test settings, start/end state.
- benchmark_attempts: individual metric attempts, status, value/unit, error category, and timestamp.

The schema must include a migration/version strategy from the first implementation. Database access is behind repository interfaces so the storage engine can be replaced without changing domain services.

Recommended local permissions: data/config directories 0700; database and secret-bearing files 0600, subject to platform support. Never print full credentials in diagnostics.



### 3.3.1 Node retention and permanent cleanup

`remove` remains a reversible soft-delete operation. `proxyctl nodes purge --deleted` previews permanent removal; `--apply` performs the atomic purge, optionally limited by `--older-than 30d`. Purging removes the node, fingerprint index, node-specific benchmark samples, and node IDs from shared run metadata while preserving data for other nodes in multi-node runs. Nodes referenced by running benchmarks are protected. A daily systemd user timer with a 30-day restore window is documented in [`docs/NODE_RETENTION.md`](NODE_RETENTION.md). Active nodes are not automatically age-purged because the current schema has no reliable last-used timestamp.

### 3.4 Protocol and core compatibility

Initial URL schemes:

- VLESS
- VMess
- Trojan
- Shadowsocks
- Hysteria2

Compatibility is not just a scheme lookup. Each core adapter reports whether it can represent the complete parsed node configuration. The domain model retains ordered option entries, repeated URI query keys, and structured VMess JSON values. The legacy string map remains as a compatibility index for existing database records; new adapter code reads the complete option entries.

**Adapter implementation status:** the shared `CoreAdapter` contract, sing-box/Xray/Mihomo serializers, and validation-only execution through `proxyctl check <NODE_ID> [--core CORE]` are implemented on `main`. The check command writes generated configuration to a private temporary file, invokes the selected installed core's config parser, and removes the file without starting a proxy process. The implemented subset now includes basic protocol outbounds; TLS/SNI, ALPN, uTLS fingerprints, VLESS REALITY (all three cores), Xray VMess REALITY, WebSocket/early data, gRPC, HTTP/2, HTTPUpgrade, XHTTP, a validated XHTTP extra-settings subset, Shadowsocks SIP003 `obfs-local` and `v2ray-plugin` for sing-box/Mihomo, and Hysteria2 Salamander/Gecko obfuscation including Gecko packet-size controls. Core-specific unsupported combinations are rejected rather than partially serialized. The shared adapter layer remains split by responsibility (`options`, `protocol`, `tls`, `transport`, and `capabilities`), with fixtures grouped into adapter, TLS, and transport suites. Current differences include: Xray rejects legacy HTTP/2; sing-box rejects XHTTP; Xray alone maps gRPC authority/multi mode and VMess XHTTP; Mihomo requires an explicit gRPC service name; Xray alone accepts REALITY SpiderX/ML-DSA optional fields in this subset; Xray rejects SIP003 Shadowsocks plugins. TLS source fields distinguish uTLS `fp`, full-certificate SHA-256 pins (`pcs` / Hysteria2 `pinSHA256`), certificate-name verification (`vcn`), insecure verification flags, and VLESS Vision flow. Empty optional VMess JSON values are normalized as absent, and VMess `security` is treated as the cipher alias for `scy`, not TLS security. Full mappings and remaining limitations are documented in `docs/CORE_COMPATIBILITY.md`. The adapter unit suite and opt-in native conformance matrix passed. The expanded native test also checks benchmark-config generation; those additional benchmark-config checks are pending a fresh run against the installed managed binaries.

The adapter implementation gate is complete. Validation remains available with `proxyctl check <NODE_ID>` (all installed compatible cores) or `proxyctl check <NODE_ID> --core sing-box|xray|mihomo`; it validates configuration only and never starts a core or alters networking. The opt-in native adapter matrix passed with 51 supported fixture/core combinations across 23 sanitized fixtures against the installed managed versions: sing-box 1.14.4, Xray 26.11.9, and Mihomo 1.19.33. The expanded integration test now additionally checks the benchmark configuration for each supported pair; this added check has not yet been run against the managed binaries. The matrix covers WebSocket/early data, standard and extended gRPC, HTTP/2, HTTPUpgrade, XHTTP and supported extra settings, REALITY, Shadowsocks plugins, and Hysteria2 obfuscation. TLS verification/pinning edge cases not represented by native fixtures remain covered by unit tests and must not be described as native-validated. The adapter stage is closed. Benchmark implementation has been approved and is now in progress under section 3.5 and docs/BENCHMARK_DESIGN.md.

If an option cannot be represented faithfully, the node/core combination is unsupported; proxyctl must not silently drop that option. Invalid input, unsupported configuration, connection failure, timeout, and missing measurement are distinct outcomes.

### 3.4.1 Extensible import, normalization, and adapter architecture

**Decision: approved.** Proxyctl will use a shared semantic model between source parsers and core adapters. The design takes architectural inspiration from L×Box's registry/conformance-fixture approach, microsubsproxy's separation of protocol parsers, common node model, and renderers, and the real-world format coverage documented by v2rayN, Hiddify, and subconverter. These projects are references, not runtime dependencies; Proxyctl will implement its own Rust model and mappings.

The pipeline is:

1. **Source acquisition:** accept individual URLs and local text imports now; keep subscription retrieval and additional source formats independently addable.
2. **Format detection:** dispatch URI schemes and structured formats (including VMess JSON, Clash YAML, and sing-box/Xray JSON when those importers are implemented) to independent parsers.
3. **Loss-aware parsing:** retain the exact original source, source format, ordered/repeated URI query entries, structured JSON values, and unknown fields. Never discard an unrecognized field merely because the current adapters do not understand it.
4. **Shared semantic normalization:** interpret protocol, transport, TLS, REALITY, authentication, and protocol-specific extensions once. Keep distinct concepts distinct: for example, a WebSocket HTTP Host header is not TLS SNI, and VMess JSON `type` may carry transport-specific mode information while `net` selects the transport.
5. **Core capability evaluation:** evaluate the normalized node against an explicit per-core/per-version capability definition. A core may support a node while another rejects it.
6. **Native serialization:** each adapter maps the same semantic model into its own native schema. Adapters must not independently reinterpret source URI keys.
7. **Native validation:** validate generated configurations with the actual managed core binary/version before claiming compatibility.

#### Domain and preservation rules

- Preserve original input exactly and keep all parsed source fields, including fields not yet understood by Proxyctl. Source data is immutable; normalization must not rewrite it.
- Keep ordered/repeated URI query parameters. Repetition is valid only where the format defines multi-value semantics (for example, ALPN); otherwise report ambiguity instead of silently selecting a value.
- Preserve structured VMess JSON values as JSON values (arrays, objects, booleans, numbers, and strings); do not flatten objects into lossy strings.
- Store normalized semantics separately from source representation. The normalized model is the adapter input; raw fields remain available for future parsers/adapters and diagnostics.
- Never expose credentials or sensitive option values in Debug output, errors, logs, or ordinary CLI output.
- Unknown fields are retained and surfaced as unsupported/unmapped when evaluating a core. They must never be silently ignored during config generation.
- Parser failures, invalid semantics, unsupported-by-this-core features, missing core binaries, and native config validation failures remain distinct outcomes.

#### Transport and security model

Transport is a shared domain concept, not a core-specific string. Initial transport vocabulary: TCP, WebSocket, gRPC, HTTP/2, HTTPUpgrade, and XHTTP; extend only when upstream specifications and native schemas are verified. A normalized transport carries semantically distinct fields (path, WebSocket HTTP Host headers, HTTP/2 host lists, HTTPUpgrade/XHTTP host, gRPC authority, service name, and transport mode). Do not infer a transport from a field name alone.

TLS is independent from transport. Keep SNI, ALPN, uTLS client fingerprint (`fp`), full-certificate SHA-256 pin (`pcs` / `pinSHA256`), certificate-name verification (`vcn`), insecure verification policy, and REALITY parameters separate. Empty optional fields in structured VMess JSON are treated as absent, and VMess `security` is a cipher alias for `scy` while `tls` controls TLS. In particular, transport Host and TLS SNI must never overwrite one another. VMess JSON field aliases and VLESS/Trojan URI query names are normalized by source parsers, not by core adapters.

#### Capability registry

Maintain declarative, testable capability definitions per core and feature. Capability checks must explain whether a feature is supported, invalid, or unsupported for a specific core/version. Do not assume all cores support the same subset or force the common model to the lowest common denominator. The current registry is core-scoped and records the researched managed-schema baseline; version predicates are not yet wired because the adapter compatibility API does not yet receive the detected installed core version. Add that input before supporting multiple schema generations of the same core. Version-specific differences must be recorded in the compatibility documentation and covered by fixtures.

A registry may initially be ordinary typed Rust data rather than an external configuration dependency. Avoid building a generic plugin framework prematurely. Adding a new protocol, transport, or core should require a focused parser/model definition, capability mapping, serializer, and fixtures—not edits scattered across command handlers.

#### Conformance and regression tests

- Keep sanitized, source-attributed fixtures for real-world URI variants and structured subscription formats. Fixtures must not contain live credentials or endpoints.
- Test parse → normalized model, repeated/unknown field retention, and fingerprint stability.
- Test semantic equivalence across different source encodings (for example URI and VMess JSON where both represent the same settings).
- Test adapter output independently for sing-box, Xray, and Mihomo.
- Run generated configurations through the exact supported core binaries in integration tests where available; unit tests alone do not establish upstream schema validity.
- Test unsupported features per core and assert that no partial config is emitted.
- Add round-trip tests only for formats whose serializer can preserve their semantics; do not claim round-trip fidelity where the source format cannot represent the full model.

#### Implementation sequence

1. **Implemented:** preserve source representation and structured VMess values; add typed normalized transport semantics.
2. **Implemented:** extract shared transport normalization and TLS interpretation into focused modules.
3. **Implemented and native-validated:** WebSocket/early data, standard gRPC, HTTP/2, HTTPUpgrade, and XHTTP mappings represented by the 23-fixture matrix.
4. **Implemented and native-validated for the fixture matrix:** per-core capability definitions and explicit `Invalid` versus `Unsupported` compatibility outcomes. Version-aware capability predicates remain a documented follow-up because the adapter API currently receives a core identity but not its detected version.
5. **Implemented; native-validated where represented by fixtures:** VMess aliases/defaults, VLESS REALITY across all three cores, Xray VMess REALITY, Shadowsocks SIP003 plugin subset, Hysteria2 Salamander/Gecko obfuscation, and XHTTP extra settings shared by Xray/Mihomo. TLS verification/pinning edge cases outside the fixture matrix remain unit-tested, not native-validated.
6. **Complete:** the opt-in native fixture matrix passed with 51 supported fixture/core combinations across 23 fixtures against sing-box 1.14.4, Xray 26.11.9, and Mihomo 1.19.33. `docs/CORE_COMPATIBILITY.md` records the validated subset and remaining unit-only cases. Benchmark core batching, persistence, and profile implementation are now committed; see the verification status below.

This work does not start cores, activate proxies, or modify system networking. All config checks remain validation-only.

### 3.5 Benchmark execution and persistence

**Revised methodology:** see [BENCHMARK_DESIGN.md](BENCHMARK_DESIGN.md). Proxyctl will follow the useful separation used by v2rayN:

- Direct TCP ping to the node server/port (does not start a core).
- Real HTTP ping through the selected core (configurable small-response URL).
- Download throughput through the selected core (configurable bounded file URL).
- Upload throughput through the selected core (configurable upload endpoint; separate from v2rayN's current download-only speed test).

The default endpoints remain Google `generate_204` for real ping, CacheFly's 10 MB test file for download, and Cloudflare's upload endpoint for a synthetic upload body. Proxyctl never sends user files or proxy credentials to the upload endpoint. Public LibreSpeed endpoints may be configured, but Proxyctl does not silently select a public server with operator-dependent telemetry/privacy behavior.

TCP ping runs once per node and is stored under the reserved `direct` target. HTTP tests run for each compatible node/core pair. The CLI prints node/core/metric/sample progress. Ctrl-C stops the active managed core to interrupt loopback proxy requests, waits for measurement workers and the child to exit, persists completed/cancelled attempts, and finalizes the run as cancelled.

**Implementation status: core-batched benchmark and profile implementation committed; latest profile verification pending user report.** Typed run/sample records, schema version 3, incremental persistence, median/throughput helpers, stale-run recovery, loopback-only per-core configs, native config validation, bounded child lifecycle, HTTP measurements, progress, and cooperative cancellation are implemented. Failure diagnostics are allowlisted and do not expose raw core logs or transport details. Accurate-profile incomplete download attempts retain their measured byte count and elapsed duration while remaining failed samples; failed upload attempts retain elapsed duration, but sent-byte counts remain unknown unless the HTTP client can prove them. Report output lists attempt indexes and measured transfer facts rather than treating failures as zero throughput. Metric rows include a sanitized endpoint host/path; query strings, fragments, and credentials are never displayed. Quick defaults to a 1 MiB one-stream download with a 5-second budget; Accurate defaults to three concurrent streams, an 8 MiB aggregate cap, a 20-second budget, and a best-effort 64 KiB warm-up excluded from timing. The download hard cap is 32 MiB; upload remains sequential and capped at 1 MiB. up to three attempts per metric; stop at the first success. Accurate retries incomplete downloads with the full configured duration on each attempt; Quick accepts useful partial downloads without retrying solely for the missing bytes. In full-suite mode, throughput remains gated on at least one successful real-latency sample for that node/core pair. The core-first scheduler starts only one managed core process at a time and batches compatible nodes. No system networking is changed.

The remaining work is broader metric coverage and hardening, not a blocker for read-only reporting. Report and sorting views consume persisted attempts only and never start cores.
  
### 3.6 Sorting and comparison semantics

Metric-specific sorting is implemented for real ping, direct TCP ping, download, and upload:

~~~sh
proxyctl list --sort ping
proxyctl list --sort download
proxyctl list --sort upload
proxyctl list --sort tcp-ping

proxyctl list --sort ping --core xray
proxyctl list --sort download --core sing-box
proxyctl list --sort upload --core mihomo
~~~

For each node/core pair, use its latest completed run and use the successful measurement from the latest completed run. A newer completed run supersedes an older one even if it contains no successful attempts; do not fall back to stale measurements. Ignore interrupted, cancelled, and running runs.

Cross-core sorting takes the median of available per-core medians, giving each successful core equal weight rather than selecting only the fastest core. Core-specific sorting restricts the calculation to the selected core. Direct TCP ping uses the reserved `direct` target and is never combined with real ping.

Ping sorts ascending; download and upload sort descending. Nodes without successful comparable measurements remain at the bottom as unmeasured, not zero. Unsupported results do not contribute values. Sorting is read-only and never starts a core or changes network settings.

### 3.7 Benchmark reporting and history

**Implementation status: implemented.** Reporting is read-only and uses the persisted benchmark run/sample records.

~~~sh
# Latest run per active node
proxyctl report
proxyctl report --node 18

# Full history, including cancelled and interrupted runs
proxyctl report --history
proxyctl report --node 18 --history

# Compare each core independently
proxyctl report --compare
proxyctl report --compare --node 18
proxyctl report --compare --core xray
~~~

Latest mode displays the newest run containing each node, regardless of lifecycle status. History mode displays all matching runs newest first. Compare mode independently selects the latest completed run for each node/core pair; newer completed runs supersede older ones even when all attempts failed. Cancelled, interrupted, and running runs do not replace comparison results. Direct TCP ping is shown under the separate `direct` target.

Every metric reports the successful measurement when available, the number of attempts made, failure counts, and attempts not run. Failed transfer attempts with measured body bytes and elapsed time show those facts by attempt index; they remain excluded from successful medians. Run IDs remain visible in report rows. One successful attempt completes the metric; retries stop immediately after success. Preflight outcomes (unsupported, invalid, unavailable) remain distinct from attempted network failures. Missing or failed measurements are never rendered as zero.

Reports do not start proxy cores, contact measurement endpoints, or modify system networking. `show` and all report modes share the configurable compact/normal/full table profiles. Normal is the default; compact and full can be selected persistently with `proxyctl config display profile`. `show --details` displays connection/configuration fields with secrets masked. `report --details` selects the full benchmark table profile for that invocation, while `--verbose` expands core version metadata without changing table columns. Latest output has one row per node/core, history has one row per node/core/run, and compare has one row per node/core from the latest completed run.

### 3.7 Pruning and recovery

Core-independent pruning:

~~~sh
proxyctl prune --unavailable-all --dry-run
proxyctl prune --unavailable-all --apply
~~~

Core-specific pruning:

~~~sh
proxyctl prune --core xray --unavailable --dry-run
proxyctl prune --core xray --unavailable --apply
~~~

**Implementation status: updated.** `proxyctl prune --unavailable-all` evaluates every active node against all three managed cores: sing-box, Xray, and Mihomo. Unsupported and invalid adapter outcomes count as a core that cannot use the node. For supported combinations, the latest completed run must contain three distinct real-ping attempts with no successful sample; timeout, unreachable, and unavailable outcomes count as failed connectivity. Any successful real-ping sample through any core keeps the node. Missing runs, incomplete attempts, and cancelled evidence remain inconclusive. `proxyctl prune --core xray --unavailable` remains available for a single-core evaluation. Preview is the default; `--apply` is the only mode that soft-deletes nodes.

Benchmark history is automatically retained to at most three newest runs per node/target pair. attempts for older target histories are removed; shared run metadata is retained only while another target in that run still has retained attempts. Running runs are never pruned.

Pruning is a soft-delete/lifecycle-state change, not immediate permanent erasure. Use `list --include-deleted` to see deleted positions (`D1`, `D2`, ...), then `proxyctl restore 1` to restore the first deleted row. Pruning reads persisted benchmark evidence only: it does not start cores, contact measurement endpoints, or change system networking.

### 3.8 Managed activation and TUN safety

**Linux single-core loopback activation: implemented. TUN activation: disabled pending recovery redesign.** The command surface is:

~~~sh
proxyctl use 12 --core sing-box
proxyctl stop
~~~

Activation is restricted to one node and one explicitly selected Proxyctl-managed core. The generated config is checked with the selected core's native validator before the current Proxyctl process is stopped. Ordinary activation launches the selected core directly as the user with a loopback-only mixed listener. Its process record includes PID, Linux process start ticks, canonical managed executable path, node/core IDs, loopback port, and private config path; it contains no node credentials. Stop verifies process identity and uses a pidfd-backed signal. Setup and non-check update operations targeting the active core stop the matching Proxyctl process before invoking the installer; update check-only does not stop anything.

The shared SOCKS5/HTTP inbound binds only to 127.0.0.1. Normal activation does not enable a system proxy or change DNS, routes, firewall, or TUN. Only binaries at Proxyctl's private managed-core paths are eligible; there is no PATH fallback and no discovery, update, reuse, or shutdown of cores owned by V2rayN or other applications. Other installed core binaries remain idle during normal activation. Runtime config and state live in a 0700 directory with 0600 files. Both activation modes currently require Linux.

Automated Linux lifecycle tests exercise the same managed-process launch/switch/stop helper used by activation. They use a copied fake `sleep` executable inside temporary managed directories plus a separately held loopback readiness listener; they verify one-process-at-a-time switching, PID/start-time/executable identity, pidfd shutdown, prior config cleanup, final state/config cleanup, refusal to launch outside the managed root, and cleanup after spawn and readiness failures. These tests never invoke sing-box, Xray, or Mihomo and never alter system networking. They reuse the existing `tempfile` dependency; no test-only runtime dependency is added. Actual activation remains an explicit user command.

TUN status inspection remains read-only. TUN activation via `--tun` is temporarily rejected before any process start, privilege request, or network mutation. The previous implementation detected baseline differences but did not restore Proxyctl-owned routes/rules after forced termination or a crash. Re-enabling TUN is blocked until exact resource ownership, an independently surviving recovery path, idempotent cleanup, and fault-injection tests prove that third-party network state is preserved. See [docs/TUN_DESIGN.md](TUN_DESIGN.md) for the recovery requirements and verification gates.

## 3.4.2 Shared local proxy listener

**Decision: approved and implemented for interactive activation.** The selected core exposes SOCKS5 and HTTP proxy protocols on one loopback TCP port, matching the v2rayN mixed-listener behavior. Proxyctl does not create a second listener or add a proxy translation process.

| Core | Native configuration |
|---|---|
| sing-box | One `mixed` inbound |
| Xray | One `mixed` inbound (Xray's native alias for the SOCKS handler, which accepts HTTP proxy requests) |
| Mihomo | One `mixed-port` |

The listener binds only to `127.0.0.1`; LAN access remains disabled. The benchmark path intentionally remains a separate HTTP-only listener because its measurement client uses HTTP CONNECT and does not need SOCKS support. The mixed listener is used by `proxyctl use` only.

## 3.4.3 TUN research and lightweight implementation direction

**Research complete; live activation remains disabled.** The approved direction is distribution-independent Linux kernel networking with a dedicated Proxyctl policy-routing table and exact owned rules/routes. sing-box, Xray, and Mihomo must disable their own automatic route/rule installation; Proxyctl owns the host routing policy. DNS, resolver, firewall, and system-proxy mutation remain out of scope.

The architecture is split into a kernel/network backend, a narrowly privileged helper, a recovery supervisor, per-core config adapters, and a readiness verifier. Service-manager integration is selected at runtime, not by distro name. The target backend matrix is systemd, OpenRC, runit, s6, dinit, and SysVinit, with a portable supervisor path where its recovery guarantees are proven. No systemd-only assumptions, distro-specific package paths, or package-manager operations are allowed. A manager/backend is supported only after passing the same fault-injection contract; otherwise TUN is refused safely while loopback activation continues to work.

The previous transient-systemd implementation is not the target architecture. It required systemd, sudo, and core-managed automatic routes and did not restore owned routes/rules after failure. Its baseline comparison is diagnostic only and must not be used as a cleanup mechanism. See [TUN_DESIGN.md](TUN_DESIGN.md) for ownership, privilege, cross-distribution compatibility, recovery, and verification requirements.

No TUN activation, route mutation, privileged service start, or live core launch is part of this design/documentation stage.

## 4. Implemented command surface

Node selectors share one parser and use one-based display positions, not persistent database IDs. Active commands resolve positions against the active list; `restore` resolves positions against deleted rows (`D1`, `D2`, ...) shown by `list --include-deleted`. `all` selects the relevant active/deleted set. Persistent IDs and benchmark references are never renumbered. New and restored nodes append to active display order; deleting a node compacts the active numbering immediately. Filtered lists retain canonical active positions, and sorted lists show both rank and original active number.

~~~sh
proxyctl setup
proxyctl cores
proxyctl update
proxyctl update --check
proxyctl update --app
proxyctl update --cores
proxyctl update --core sing-box
proxyctl use 12 --core sing-box
proxyctl stop
proxyctl tun status

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
proxyctl check 1..5 --core xray

proxyctl test --all-cores
proxyctl test --node 12 --core sing-box
proxyctl test --node 12 13 14 --all-cores
proxyctl test --node 12..18 --core xray

proxyctl report
proxyctl report --history
proxyctl report --compare
proxyctl report --node 12 13 14 --history
proxyctl report --node 12..18 --compare

proxyctl list --sort ping
proxyctl list --sort download --core sing-box
proxyctl list --sort tcp-ping

proxyctl prune --unavailable-all --dry-run
proxyctl prune --unavailable-all --apply
proxyctl prune --core xray --unavailable --dry-run
proxyctl prune --core xray --unavailable --apply
~~~

`remove` and `restore` remain soft lifecycle operations. `remove all` requires interactive confirmation unless `--yes` is supplied; `restore all` selects deleted records only. For individual restore operations, use the deleted-row position shown as `D#` by `list --include-deleted`. Batch operations report missing and unchanged selections separately. Benchmark/report selectors accept lists and ranges; selected nodes are recorded together in one benchmark run, with individual attempts persisted for each node/core target.

## 5. Architecture

Keep the binary thin. Command handlers translate CLI arguments into application-service calls; domain logic must not depend on clap, redb, or a particular core's JSON/YAML format.

~~~text
src/
├── main.rs
├── cli/
│   ├── mod.rs
│   ├── setup.rs
│   ├── nodes.rs
│   ├── benchmark.rs
│   ├── report.rs
│   ├── prune.rs
│   ├── proxy.rs
│   └── tun.rs
├── domain/
│   ├── mod.rs
│   ├── node.rs
│   ├── protocol.rs
│   ├── core.rs
│   ├── benchmark.rs
│   └── errors.rs
├── parser/
│   ├── mod.rs
│   └── schemes/
├── cores/
│   ├── mod.rs
│   ├── sing_box.rs
│   ├── xray.rs
│   └── mihomo.rs
├── database/
│   ├── mod.rs
│   ├── schema.rs
│   ├── migrations/
│   └── repositories/
├── services/
│   ├── mod.rs
│   ├── import.rs
│   ├── setup.rs
│   ├── benchmark.rs
│   ├── sorting.rs
│   ├── reporting.rs
│   ├── pruning.rs
│   └── activation.rs
└── tun/
    ├── mod.rs
    └── platform/

tests/
├── parser/
├── database/
├── cores/
├── services/
└── cli/
~~~

Core adapters implement a shared interface for capability inspection, config generation/validation, process startup, and shutdown. Protocol parsers are independent of core adapters. Benchmark metrics are independent strategies so future metrics do not require changes to every command.

## 6. Initial dependency direction

Prefer small, focused crates. Candidate dependencies:

- clap for CLI parsing
- redb for embedded storage
- serde and serde_json for structured data
- url for URL parsing support where appropriate
- thiserror for domain errors
- anyhow at application boundaries
- tracing for structured, secret-safe diagnostics

Avoid introducing an async runtime, ORM, or large application framework unless implementation evidence demonstrates a need. Exact crate versions and core release versions are selected and verified during implementation.

## 7. Delivery plan

1. Project foundation: Cargo package, module boundaries, formatting/lint configuration, CLI skeleton, CI, and conventions.
2. Domain and parser: typed node/protocol models, URL parsing, normalization, validation, fingerprints, and compatibility representation.
3. Persistence: redb schema, migrations/versioning, repository layer, permissions, and database tests.
4. Node management: import, add, list, show, remove, restore, and duplicate handling.
5. Core management and unified updater: official-source metadata, pinned versions, checksum verification, setup, detection, and a single update workflow for the proxyctl CLI plus managed cores.
6. Core adapters: **complete for the documented initial subset**; the adapter unit suite, formatting, Clippy, release build, and the 23-fixture native matrix (51 supported fixture/core combinations) passed. Version-aware capability predicates and additional protocol/option coverage remain future enhancements. The expanded native test also checks benchmark configs, and the expanded native matrix has passed.
7. Benchmark engine: **complete for the current contract**. Typed records, schema migration, short sample transactions, aggregation primitives, stale-run recovery, per-core loopback HTTP config, process lifecycle, bounded HTTP measurements, cooperative cancellation, progress, native validation, and real single-node smoke tests are implemented.
8. Reports and sorting: **implemented**. Metric-specific sorting, latest-run reports, full per-node history, and per-core comparison views are implemented with partial/failure/missing-sample accounting. Concise core versions are the default; `--verbose` displays complete stored build metadata.
9. **Complete:** all-three-core usability pruning with default dry-run, explicit soft-delete apply, invalid/unsupported outcomes counted as unusable, and inconclusive evidence protected from deletion. Benchmark history is automatically capped at three latest runs per node/target pair.
10. **Implemented on Linux:** single-core activation, private runtime state/config, loopback-only inbound, process identity verification, serialized switching, and safe stop. Other platforms remain disabled pending equivalent process-handle support.
11. **TUN activation deferred:** read-only status inspection remains available. Offline groundwork includes versioned exact-resource manifests, compare-and-delete cleanup contracts with fake-backend fault tests, runtime-selected service-manager kinds, native core configs with automatic route installation disabled, a generation-scoped lifecycle state machine, and a pure dual-stack routing-policy planner. The planner validates exact default-route/interface identity, mark-based core bypass ordering, unmarked proxy routing, table/rule collisions against synthetic inventories, and non-terminal fallthrough semantics. These remain non-mutating groundwork: a new read-only iproute2 JSON inventory inspects IPv4/IPv6 route tables and policy-rule priorities. Each query is bounded to two seconds, output is capped at 4 MiB, and timeout or process-status errors trigger child termination and reaping. Oversized or incomplete inventory fails closed. A detailed read-only snapshot retains canonical full route/rule attributes alongside family, table, and priority metadata for future exact ownership comparisons; it does not authorize mutation. The planner and cleanup contracts remain offline. No kernel mutation, socket marking, route installation, or live fallthrough proof exists. Production rtnetlink mutation, the supervisor executable, concrete service-manager implementations, privilege broker, dataplane readiness, and full crash/reboot fault injection remain outstanding. A private durable manifest store now provides atomic 0600 persistence, 0700 directory enforcement, generation checks, symlink rejection, and bounded validated reads. Write-ahead journal persistence has been extracted into `tun/journal_store.rs`; it shares the hardened private filesystem primitives but has a separate API and responsibility. `ManifestStore` retains compatibility delegates while existing transaction orchestration is migrated. Its filesystem-only lifecycle API persists generation-checked Prepared/Running/CleanupPending/Cleaned transitions, retains manifests on cleanup conflict, and marks cleanup complete before attempting manifest removal. A filesystem-only lifecycle coordinator now serializes cross-process manifest operations with a bounded advisory lock and checks both activation UUID and generation on every event. The OS releases the lock automatically if a process exits; the lock file is retained to avoid inode races. This is offline groundwork only: a reusable Linux pidfd process-identity primitive now captures PID, start ticks, and canonical executable, verifies the identity after pidfd acquisition, and supports exact-process exit monitoring/signaling. It is tested with fake child processes but is not yet wired to a surviving supervisor. Privilege brokering, a backend-injected supervisor runtime now pins and monitors the exact core process, persists CoreExited before cleanup, retains CleanupPending on conflicts, and can retry only pending cleanup after restart. Fake-child and fake-resource tests cover these paths; fake-process setup uses bounded retries when pinning procfs identity and pidfds to avoid timing-sensitive test failures. A detached/init-managed supervisor, process identity persistence for reboot recovery, privilege broker, concrete kernel backend, and concrete service-manager integration remain outstanding. Do not enable TUN until all are implemented and tested; unsupported managers must fail closed.
12. **Implemented:** shared node selector parser, multi-node show/check/test/report command syntax, bulk soft-delete/restore, remove-all confirmation, and synchronized command documentation.
13. Hardening: integration tests, documentation, packaging, security review, and performance checks.

Each stage should leave the default branch buildable and tested. Apply related CLI, service, tests, and documentation together when they share a command contract. The SOLID/extensibility refactor status and its verification commands are tracked in [ARCHITECTURE_REFACTOR.md](ARCHITECTURE_REFACTOR.md). Update this plan when a material design decision changes.

## Benchmark optimization implementation status

Stages 1–5 are now committed on `main`: adapters can generate independently routed multi-node configs; the process manager starts one core for a batch and waits for every loopback listener; the scheduler is core-first; real HTTP latency and direct TCP probes use persisted bounded concurrency; latency and throughput have separate persisted timeouts. Downloads are capped at the configured byte count and expose throttled byte/rate progress; early-close/read-failed outcomes retry up to three total attempts on fresh connections. If no attempt completes, the fastest partial transfer of at least 16 KiB is retained, using ureq's streaming response reader so received bytes survive later transport/framing errors. Upload timing includes request transmission and response completion. Selected multi-node runs share one run ID, handled cancellation records unattempted scheduled attempts, and each run stores a sample-count summary. Throughput remains sequential and the full-mode latency gate is preserved. Stages 1–5 have been user-verified. The Stage 6 offline verification batch (formatting, focused benchmark HTTP tests, full tests, Clippy with warnings denied, and release build) was confirmed passing by the user on 2026-11-15. The subsequent coverage audit reviewed config generation/routing, native validation, process lifecycle/readiness, HTTP metrics, persistence/recovery/retention, and cancellation. The fake-executable test verifies native validation command arguments and temporary-config permissions/cleanup for all three cores; the user confirmed the focused test and full verification batch passed. Stage 6 is complete; Stage 7 real-world comparison remains user-run under the separate validation runbook. Stage 7 real-world comparison is user-run under the separate validation runbook.

## 8. Open implementation details

These are implementation choices, not blockers to the architecture:

- Exact minimum supported Rust version and edition.
- Exact pinned versions and official release/checksum metadata for each core.
- Proxyctl release asset naming, signing/checksum publication, and safe self-update behavior for each supported platform.
- Benchmark endpoint selection, payload sizes, and timeout defaults.
- Precise configuration support matrix for each core version and URL option.
- Linux TUN service-manager backend matrix and privilege-broker support; Linux kernel networking is the common backend, while init-manager integration is runtime-selected. DNS and firewall mutation remain deliberately out of scope.
- Whether an explicit credential-reveal command is needed.

Resolve these choices with evidence and document them before the affected feature is considered complete.


- **TUN privilege-broker groundwork:** Linux now has read-only candidate discovery for executable sudo/doas/pkexec binaries and a versioned, generation-scoped request contract limited to applying or cleaning one private TUN manifest. This does not test authorization or execute a helper. A real broker must independently validate manifest ownership and exact kernel resource fingerprints; TUN remains disabled until that implementation and its fault-injection tests are complete.


- **TUN dataplane readiness contract:** a new offline evaluator rejects readiness unless the exact manifest interface identity, core identity, local listener, route policy, physical-egress bypass, end-to-end proxied traffic, and unchanged DNS/firewall evidence are all present. Live evidence collection is not implemented; this remains a testable gate, not an activation feature.

- Fake-process identity tests use bounded retries for transient procfs/pidfd startup races and a stable argv-preserving executable fixture. Production identity verification remains strict.

- **Fixed kernel operation planner:** deterministic dual-stack iproute2 argument plans now cover TUN creation, link-up, dedicated-table routes, marked-core bypass rules, proxy rules, and reverse-order cleanup. This is an offline planner only; no command is executed. Real kernel inspection, interface-index binding, resource fingerprinting, privileged execution, and compare-and-delete remain blockers; TUN stays disabled.

- **TUN reference review:** v2rayN and Throne were reviewed as implementation references. Reuse the unprivileged controller / elevated-core separation pattern, and v2rayN's SOCKS5 greeting readiness probe; improve on it by aborting startup if the probe times out (the current v2rayN path logs the timeout but proceeds to start its pre-service). Do not copy Throne's SUID-root core or broad five-capability bundle, nftables auto-redirect defaults, or implicit DNS behavior. Proxyctl retains a narrow privilege broker, no initial firewall/DNS mutation, exact ownership manifests, independent crash recovery, and end-to-end readiness evidence. See [TUN_DESIGN.md](TUN_DESIGN.md).


- **Manifest/snapshot comparison:** an offline comparator now maps stable manifest route/rule keys (constrained to its dedicated default-route table) to dual-stack kernel snapshot records and checks full canonical fingerprints, including route device and rule selectors. Missing resources are idempotently absent; changed, duplicated, or unsupported identities fail closed. This snapshot is advisory only and never authorizes deletion; production still requires atomic compare-and-delete, exact interface-index verification, and durable per-resource cleanup progress.


- **Exact interface identity snapshot:** the read-only kernel inventory now includes sysfs interface name, ifindex, and TUN-kind evidence. The manifest comparator requires both the recorded name and index to match and rejects index/name reuse or a non-TUN replacement. Missing interfaces are idempotently absent. This is advisory read-only evidence only; atomic privileged verification and mutation remain unimplemented.


- Stabilized the activation pidfd signal test with a persistent fake child and bounded identity readiness before testing that a mismatched identity cannot be signalled. No live process or networking behavior is exercised.


- **Two-phase TUN interface identity gate:** offline preflight now rejects occupied interface names/indices and routing-policy collisions. A post-creation verifier requires the exact kernel-assigned interface name, ifindex, and TUN kind before route installation. No kernel operation is executed; the activation gate remains closed.


- **Identity-bound interface teardown:** the offline kernel planner no longer emits a name-only TUN link deletion. It carries a separate interface cleanup guard with the manifest name and non-zero ifindex; production teardown must atomically re-check exact identity and ownership before deleting. Route/rule command previews likewise require full fingerprint comparison at mutation time. No kernel mutation is implemented and TUN remains disabled.


- **Typed cleanup planning:** route and policy-rule teardown is now represented as typed exact identities in reverse creation order, not raw destructive iproute2 command strings. A future backend must perform full fingerprint comparison and atomic compare-and-delete for each resource; interface deletion separately requires exact name+ifindex verification. Offline only; TUN remains disabled.


- **Recovery backend capability gate:** detecting systemd/OpenRC/runit/s6/dinit/SysVinit is now explicitly separate from having an implemented supervisor backend. Every current backend reports not implemented; TUN activation must refuse all of them until concrete lifecycle integration and fault-injection validation are complete.


- **Loopback readiness enforcement:** dataplane readiness now accepts only IPv4/IPv6 loopback listener addresses and rejects wildcard or LAN exposure. This is an offline evidence check; live listener probing is still outstanding.


- **Socket-diagnostic record parser:** added a pure parser for Linux `inet_diag_msg` payloads and aligned netlink attributes. It validates family, inode, attribute framing/padding, requires exactly one four-byte `INET_DIAG_MARK`, rejects malformed/missing/duplicate marks, and skips valid unknown attributes. Synthetic IPv4/IPv6 and malformed-record fixtures cover the parser. It performs no netlink I/O; the privileged bounded collector and broker executor remain outstanding.

- **Process-owned socket inode attribution:** Linux now has an unprivileged, read-only helper that enumerates socket descriptor inodes for the exact pidfd-pinned managed core process, verifies process identity around the procfs walk, detects exit races, deduplicates repeated descriptors, and fails closed on incomplete descriptor inspection. It is only the attribution half of the future collector; it does not observe SO_MARK. The privileged INET_DIAG_MARK query and broker executor remain outstanding.

- **Outbound socket-mark observation design:** Linux `/proc/net/{tcp,tcp6,udp,udp6}` does not expose `SO_MARK`, so parsing procfs socket tables or trusting generated config is not sufficient. The kernel's INET socket-diagnostic interface exposes `INET_DIAG_MARK` only to callers with `CAP_NET_ADMIN`; the request's legacy `idiag_ext` byte cannot request that newer attribute directly. A correct collector therefore needs a narrowly scoped privileged read-only operation, not a broad root Proxyctl process. It must enumerate IPv4/IPv6 TCP and UDP sockets through `NETLINK_SOCK_DIAG`, read the mark attribute, map socket inodes to file descriptors owned by the exact pidfd-pinned core process, and revalidate process start-time/executable identity before accepting evidence. Missing permission, unsupported kernel/protocol coverage, absent mark attributes, inaccessible process descriptors, or ambiguous inode ownership must fail closed. This is now the selected implementation direction; no live collector or privilege-broker executor is claimed yet.

- **Core mark validation and readiness:** routing-policy planning rejects zero marks; the adapter API now requires a non-zero mark/mask for TUN config, with outbound-scoped generation for sing-box and Xray only. The readiness evaluator also requires an observed proxy-outbound socket mark matching the policy mask. Runtime mark collection, Mihomo support, native validation against pinned binaries, live marked-egress verification, and the production kernel/recovery backends remain outstanding.


- Cleanup completion is now gated on an empty conflict list from every exact-resource deletion. If a resource changes after preflight, the supervisor retains the CleanupPending manifest for a later recovery attempt; it does not discard ownership evidence or treat a partial cleanup as success.


- Seven offline hardening increments were added: readiness rejects port zero; manifest resource counts/strings are bounded; broker requests must match the exact manifest generation and valid lifecycle phase; policy-rule priorities use a private range; process executable paths must be normalized; lifecycle lock and manifest files reject external hard links. Synthetic tests cover each guard. No privileged or live network behavior was added; TUN activation remains disabled.


- Core-process manifest binding now retains a pidfd across the durable write and checks the pinned process for exit immediately before persistence. The lifecycle fixture uses a persistent fake child with bounded procfs readiness retries, avoiding parallel-test startup races without weakening production identity checks. This remains offline groundwork; TUN activation is disabled.

- **Offline TUN transaction orchestration:** added a typed transaction sequence for interface creation, dual-stack route installation, and policy-rule installation. The backend contract requires durable per-operation ownership journaling, atomic fingerprint-checked deletion, and active-manifest commit before core startup, exact interface name+ifindex agreement, and non-empty fingerprints. Invalid identity/fingerprint responses retain the journal rather than attempting ambiguous cleanup. Failure rolls back recorded resources in reverse order; incomplete rollback retains the recovery journal. Fake-backend tests cover ordering, invalid requests, successful manifest construction, partial-apply rollback, rollback failure, and unexpected interface identity. This is orchestration only: no production kernel mutator or privilege broker is connected, and TUN activation remains disabled.


- **Kernel-assigned TUN ifindex:** corrected the planning model so Linux's dynamically allocated ifindex is captured after interface creation and bound into both dual-stack routes and the durable manifest. Preflight no longer treats a placeholder ifindex as a reservation. Post-create checks require the exact name, a unique non-zero assigned index, and TUN-kind evidence. This remains offline orchestration; no kernel interface is created.


- **Transaction journal failure-path hardening:** the offline kernel transaction now retains the recovery journal on policy-binding and generated-manifest validation failures. It no longer claims rollback evidence was retained when the backend's retention call failed, and it handles journal-finalization failure after rollback explicitly. Fake-backend tests and the concrete write-ahead journal remain required before live mutation.


- **Durable TUN write-ahead journal foundation:** the private manifest store now persists bounded, generation-scoped interface/route/rule operation intents, observed fingerprints, and cleanup progress as atomic fsynced records. It rejects unsafe file identities, invalid state transitions, duplicate keys, stale generations, and incomplete journal removal. This is not yet connected to a concrete rtnetlink mutator. A crash after an intent but before its fingerprint remains ambiguous and must fail closed pending exact kernel inspection.


- Journal recovery now distinguishes unresolved intent, applied, removed, and explicitly confirmed-absent operations. An intent cannot authorize deletion; exact inspection must establish absence or ownership first. Applied resources require fingerprint compare-and-delete before cleanup progress is committed.


- **Journal recovery planning:** added a pure reverse-order planner for durable transaction journals and fresh exact inventory observations. It distinguishes proven absence, exact fingerprint compare-and-delete, already-absent applied resources, and conflicts; unresolved intents never authorize deletion. This is planning only, not a live recovery backend.

- **Journal identity validation:** operation kinds are now checked against strict interface, route, and rule key formats; malformed or mismatched resource identities are rejected before recovery.

- Journal ordering validation requires interface creation first, then routes, then rules; duplicate or misplaced interface operations and routes after rules are rejected.


## Persistent shared proxy listener port

Ordinary (non-TUN) activation now uses a persistent loopback HTTP/SOCKS5 listener setting. The built-in default is **10909**. The setting is stored as a small private JSON file under the Proxyctl XDG data directory, independently of benchmark state, and therefore survives terminal closure and reboot. `proxyctl config` displays the effective value; `config set listen-port PORT` validates the unprivileged port range and checks the actual 127.0.0.1 bind before saving; `config reset listen-port` returns to 10909. An occupied requested port is rejected and the effective setting falls back to the built-in default. `use --port PORT` is a one-run override and does not modify the persistent setting. Activation repeats the port preflight before it stops/replaces a managed core. The OS can still allocate the port to another process after preflight and before the core binds; that race is reported as a startup failure, never handled by silently selecting a different port. Benchmark listeners remain independently ephemeral.


- **Metric-specific benchmark execution:** `test` now supports mutually exclusive `--latency-only`, `--download-only`, and `--upload-only` selectors. The default remains all HTTP metrics plus direct TCP ping. Each metric-only mode runs only its named HTTP metric and skips direct TCP ping. Preflight failures are persisted only for the selected metric, so a single-metric run does not create misleading outcomes for skipped metrics. Each selected HTTP metric retains up to three attempts, stopping at the first success per supported node/core pair. In the default full-suite mode, download and upload run only after at least one successful latency sample; if all three latency attempts fail, throughput is skipped with a `latency_gate` preflight outcome.


## Configurable result presentation

**Approved and implemented on main:** `proxyctl show` and `proxyctl report` use persistent compact/normal/full table profiles, with normal as the default. Compact contains node, core, latency, download, and upload. Full exposes additional diagnostic columns. `show --details` displays connection/configuration details; `report --details` selects the full benchmark table for one invocation. Each profile can be customized independently using `proxyctl config display add-field` and `remove-field`; users can switch the active profile with `proxyctl config display profile`. The table renderer uses the Rust `tabled` crate. Ordinary output never includes fingerprints or credentials. `not-run`, `unavailable`, `unsupported`, and `invalid` remain distinct.


## Benchmark performance optimization

**Core batching and the Quick/Accurate profile implementation are committed; profile verification is pending user-run checks.** Proxyctl uses one managed core process per core batch, bounded-concurrent latency/TCP probes (maximum three workers), up to three attempts per metric, stopping at the first success, independent latency/throughput timeouts, explicit cancellation records, and persisted run summaries.

Throughput profiles:
- **Quick (default):** one download stream, 1 MiB aggregate cap, 5-second budget, no warm-up.
- **Accurate:** three concurrent download streams, 8 MiB aggregate cap, 20-second budget, and a best-effort 64 KiB warm-up excluded from timing.
- Download cap hard limit: 32 MiB. Upload remains sequential and capped at 1 MiB.
- Quick accepts a useful partial download after one attempt. Accurate retries incomplete downloads up to three times, with the full configured duration for each attempt; partial transfers are not combined across attempts.
- Effective profile and settings are persisted; legacy settings deserialize to Quick defaults.

CLI examples: `proxyctl test --all-cores --profile quick` and `proxyctl test --node 12 --core xray --profile accurate`. The implementation and acceptance criteria are tracked in [BENCHMARK_OPTIMIZATION_PLAN.md](BENCHMARK_OPTIMIZATION_PLAN.md) and [BENCHMARK_DESIGN.md](BENCHMARK_DESIGN.md).

Do not claim profile verification until the user reports formatting, Clippy, tests, and release build. No automated test contacts public endpoints, runs multiple managed cores, changes system networking, or activates TUN.


- **Xray WebSocket Host schema correction:** Xray Trojan/VLESS/VMess WebSocket outbounds now serialize the imported WebSocket Host to the native `wsSettings.host` field, matching v2rayN's Xray configuration model. SNI remains independently mapped to `tlsSettings.serverName`, and certificate verification remains enabled by default. Regression coverage includes a Trojan + WS + TLS fixture with distinct Host and SNI values. Local Rust checks are pending user verification.


### Benchmark local proxy protocol

- [x] Make SOCKS5 the default local inbound for benchmark HTTP measurements.
- [x] Add `proxyctl test --proxy-type socks5|http` and persist the selected protocol in run settings.
- [x] Route latency, download, and upload through the selected local protocol.
- [x] Generate protocol-matched sing-box and Xray benchmark inbounds; retain Mihomo mixed listener.
- [ ] Verify SOCKS5 and HTTP modes with local fake-proxy tests and user-run native-core benchmarks.


- **Read-only marked physical-egress probe:** Linux preflight now resolves fixed IPv4 and IPv6 destinations using the planned core socket mark, requires the main table and a hardware-backed non-TUN interface with exact current ifindex evidence, and fails closed on ambiguity or missing address-family routes. Synthetic JSON and temporary-sysfs tests do not touch host networking. This does not prove the core applies `SO_MARK`; outbound-scoped config generation now exists for sing-box and Xray, while Mihomo remains unsupported. Runtime socket-mark observation, privileged kernel operations, independent recovery, and live dataplane readiness remain outstanding. TUN activation remains disabled.


- **Core-scoped TUN outbound mark generation:** the TUN adapter API requires a validated non-zero mark/mask; it no longer exposes an unmarked TUN configuration path and fails closed unless an adapter has an explicitly implemented outbound-scoped native setting. sing-box writes `routing_mark` only to the tagged proxy outbound; Xray writes `streamSettings.sockopt.mark` only to that outbound. Mihomo remains unsupported until its pinned-version mark scope is verified. Synthetic tests assert no mark is applied to inbound listeners or ordinary activation configs. The ordinary activation service rejects TUN mode before config generation rather than supplying an arbitrary placeholder mark. Opt-in native validation of marked sing-box/Xray TUN configs is now covered by `tests/native_adapter_validation.rs` (Mihomo is asserted fail-closed); run it with installed managed binaries. Runtime mark allocation/observation, live marked-egress verification, and the production kernel/recovery backends remain outstanding. TUN activation remains disabled.


- **Socket-diagnostic netlink framing and bounded accumulation:** added a pure builder/decoder plus a multipart accumulator for IPv4/IPv6 TCP/UDP `SOCK_DIAG_BY_FAMILY` dumps. The accumulator enforces 4 MiB total bytes, 1,024 datagrams, and 65,536 total records; it rejects empty or post-completion datagrams and only releases records after an uninterrupted `NLMSG_DONE`. The decoder rejects `NLM_F_DUMP_INTR` on data and completion messages. Synthetic fixtures cover request fields, multipart accumulation, incomplete/interrupted dumps, sequence mismatches, truncation, aggregate byte limits, kernel errors, and invalid message ordering. No netlink socket is opened and no privilege is requested. The actual collector must still detect `recvmsg` truncation, enforce elapsed-time limits, validate kernel sender identity, and perform exact process-inode attribution; TUN remains disabled.


- **Netlink response-origin and datagram bounds:** the pure socket-diagnostic decoder rejects response headers whose sender port ID is non-zero, and the multipart accumulator has a regression test for its 1,024-datagram ceiling. This is only an additional parser check. The future broker must still validate the kernel sender address from `recvmsg`, detect `MSG_TRUNC`, enforce a monotonic deadline, and discard incomplete collections. No netlink socket I/O or privileged execution is implemented.


- The dump accumulator now offers a production-facing receive method that requires `recvmsg` sender-port metadata and the `MSG_TRUNC` result, rejecting non-kernel senders and truncated datagrams before parsing. The byte-only method is retained for pure decoder tests; a real collector must use the metadata-aware method.


- **Race-checked socket attribution:** a pure reconciliation function now compares pre/post process socket snapshots, rejects identity/inode-set changes and duplicate diagnostic inodes, and selects matching-mark records only when their inode belongs to the stable process snapshot. Synthetic tests cover unrelated inodes, races, duplicates, and invalid/missing marks. This is candidate attribution only: it does not distinguish inbound sockets from proxy-outbound sockets and must not populate readiness evidence until protocol/peer-direction classification and live pidfd-bound collection are implemented.


- **Proxy-peer socket classification:** INET_DIAG records now preserve local/remote addresses and ports, and a pure classifier narrows marked process-owned sockets to the exact configured proxy endpoint. TCP candidates require ESTABLISHED state; UDP requires a concrete connected peer. The classifier rejects duplicate inodes and invalid mark/peer policies. It is deliberately conservative and does not resolve hostnames, collect live diagnostics, or claim end-to-end traffic readiness. The broker collector and pidfd-bound before/after snapshots remain outstanding; TUN stays disabled.

### Bounded socket-diagnostic collection orchestration

A new Linux-only collector orchestration layer now connects the pure request builder, receive-metadata validation, and multipart accumulator through a narrow injectable I/O contract. Each dump has a monotonic deadline capped at five seconds; receive calls are given the remaining budget, and a response arriving after the deadline is rejected. The collector requires kernel sender metadata and rejects MSG_TRUNC, transport errors, malformed/interrupted dumps, and missing NLMSG_DONE. The multi-family coordinator requests IPv4 TCP, IPv4 UDP, IPv6 TCP, and IPv6 UDP with distinct non-zero sequence identifiers and rejects sequence-space exhaustion before sending any request.

This is deliberately not yet the production netlink transport: no socket is opened, no CAP_NET_ADMIN is requested, and no privilege broker is executed. A future transport must implement the narrow send/recv contract with AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG, kernel sockaddr_nl destination/sender validation, recvmsg MSG_TRUNC handling, and bounded receive buffers. The broker must own that transport in a narrowly scoped process; the main Proxyctl process remains unprivileged. Synthetic transport tests cover complete/incomplete dumps, sender identity, truncation, timeout bounds, transport exhaustion, all four family/protocol combinations, and sequence exhaustion. No readiness evidence is populated and TUN activation remains disabled.

### Linux NETLINK_SOCK_DIAG transport boundary

Added a Linux-only, read-only NETLINK_SOCK_DIAG socket transport implementing the bounded collector I/O contract. It opens an AF_NETLINK/SOCK_RAW/SOCK_CLOEXEC socket, binds a local netlink address, sends requests only to kernel port ID 0, and receives with poll plus recvmsg. It validates the sender address family, rejects multicast-origin responses, returns the sender port ID and MSG_TRUNC metadata from the same receive operation, and bounds each receive buffer to 64 KiB. The collector's monotonic deadline and multipart accumulator remain responsible for total per-dump time, bytes, datagrams, records, sequence, and completion checks.

This transport does not request or acquire capabilities, perform privilege escalation, or alter host networking. Linux only includes INET_DIAG_MARK in diagnostic records for callers with CAP_NET_ADMIN; without it the strict parser rejects the missing mark. Therefore this transport must be instantiated only inside a narrowly scoped diagnostic broker with the minimum required capability. Do not run Proxyctl as root or grant the main process broad CAP_NET_ADMIN. The broker protocol/executor, pidfd-bound before/after process socket snapshots, live peer correlation, and readiness integration are still outstanding. The only transport test opens and closes the read-only netlink socket; it sends no diagnostic request and performs no network mutation. TUN activation remains disabled.

#### Socket-mark broker request boundary

A versioned, bounded request contract now exists for the future read-only socket-mark broker. It carries only a pid/start-time/canonical-executable process identity, the configured upstream peer endpoint, TCP/UDP transport, and expected mark/mask. Validation rejects malformed identities, invalid peer endpoints, invalid mark policies, unknown JSON fields, truncated/oversized frames, and trailing bytes. The wire frame is length-prefixed and capped at 16 KiB.

This does not launch a privilege helper or perform IPC. The executor must authenticate the connecting user's peer credentials, enforce same-user process ownership, pin the target process with pidfd, recheck identity around collection, and return only peer/mark-matched records. It must never expose a generic command interface or accept arbitrary kernel operations. No ambient capability is granted to Proxyctl; no TUN activation is enabled. Response protocol, IPC transport, helper packaging/policy, and integration with readiness remain future work.

#### Broker peer authentication primitive

A Linux SO_PEERCRED reader now extracts PID, UID, and GID from an accepted Unix stream socket using kernel-provided credentials. The authorization policy requires a valid peer PID and exact same-UID ownership of the requested target process. The future helper must obtain the target UID from procfs only after pidfd-pinning and verifying the requested process identity; the request cannot assert its own owner UID.

This remains a tested primitive rather than an active IPC service. A private listener, socket filesystem permissions, target-owner inspection, pidfd-bound request handling, response framing, helper lifecycle, and end-to-end isolation tests are still outstanding. No TUN activation is enabled.


- **Pidfd-bound broker target ownership:** added a Linux procfs reader that obtains all four target UID values only after opening a pidfd and validating the exact process identity. It rejects UID divergence, rechecks identity/liveness around the read, and never trusts an owner UID from the IPC request. This is an offline authorization primitive only; no helper is launched and TUN remains disabled.


- **Bounded broker request stream:** added a one-request Unix-stream reader with pre-allocation length validation, a 16 KiB payload ceiling, and a two-second monotonic deadline covering the complete frame. Truncated, oversized, malformed, and slow-trickle requests fail closed. Listener lifecycle, response framing, helper packaging, and readiness integration remain outstanding; TUN is disabled.


- **Private broker listener boundary:** added Linux Unix-socket binding restricted to an existing caller-owned private directory and a newly created mode-0600 socket. Symlink parents, shared directories, pre-existing paths, and unsafe socket metadata are rejected. No stale path is unlinked, no helper/service is launched, and TUN remains disabled.


- **Socket-mark broker protocol groundwork:** added pidfd-bound same-user request authorization, strict bounded response serialization (1,024 records / 256 KiB), stable process-inode plus exact proxy-peer response assembly, and bounded Unix-listener acceptance with SO_PEERCRED authentication and one-frame reads. These are isolated primitives with synthetic tests; there is still no privileged helper, capability grant, production request executor, or readiness integration. TUN activation remains disabled.


- **TUN broker execution groundwork:** added a single-request Linux broker server path that authenticates the Unix peer, pins and authorizes the exact same-user target, snapshots process socket ownership around four bounded dual-stack diagnostic dumps, and returns only exact upstream peer/mark candidates through a bounded response frame. This remains a helper-side API only: no helper binary, privilege policy, service-manager supervisor, kernel mutation backend, or CLI activation path is installed. TUN activation stays disabled pending the remaining recovery/kernel/readiness integration and local verification.
- **Broker transport and recovery status hardening:** the controller now requires EOF immediately after the single bounded broker response frame, rejecting trailing bytes and peers that leave the response stream open. `proxyctl tun status` also reports the detected init manager and whether its concrete recovery backend exists; all current managers remain explicitly unimplemented. Offline transaction tests now inject failure at each route/rule apply boundary and assert reverse cleanup. These changes improve diagnostics and offline coverage only; they do not install a helper, mutate the kernel, or enable TUN.
- **Durable restart-boundary fault tests:** the journal-store suite now drops/reopens the filesystem store after unresolved intent, confirmed absence, and applied fingerprint writes. It proves unresolved intents cannot authorize deletion, exact observations produce compare-and-delete decisions, changed fingerprints preserve the recovery manifest, and completed journal removal requires all operations to be resolved. These are filesystem/fake-inventory tests only.
- **Separate diagnostic helper boundary:** added a dedicated `proxyctl-tun-helper` binary with a single `--socket PATH` operation, exact `CAP_NET_ADMIN` capability-set checks, `no_new_privs`, dumpability disabled, caller-owned private runtime directory checks, and one-request exit behavior. Explicit install/remove scripts apply/remove only `cap_net_admin=ep`; they never set the setuid bit or create sudoers/service policy. The helper only collects same-UID socket-mark diagnostics. A controller-side probe now launches only the fixed root-owned helper path with a cleared environment, validates the private socket, performs one bounded exchange, and verifies helper exit/socket removal. This path is a callable diagnostic primitive, not yet wired into TUN activation/readiness. The helper is not a kernel mutator; no TUN activation or host networking change is enabled. The readiness evaluator now accepts the validated broker response directly and derives its observed-mark field internally; all other readiness evidence remains independently supplied and the live full-readiness collector is not yet connected.


- **Broker client exchange:** added the controller-side one-request Unix-stream exchange. It checks the connected helper's kernel-reported UID against an explicit expected UID, writes one validated bounded request, shuts down the request write side, and reads one bounded validated response. The socket path remains caller-supplied and must already be anchored in the private runtime directory; no helper discovery or execution is inferred from sudo/doas presence. This is transport groundwork only and is not wired into activation.


## Remaining implementation gates (not yet complete)

The broker request/response path now has isolated server-side and client-side transport/execution primitives, but this does not close the TUN implementation. The following production gates remain intentionally open:

- [ ] Package and install a dedicated helper with a reviewed, narrowly scoped privilege policy; prove that the ordinary Proxyctl process never receives CAP_NET_ADMIN.
- [ ] Implement the concrete Linux kernel mutator against rtnetlink/TUN ioctls, with exact live fingerprints, durable intent-before-mutation journaling, atomic compare-and-delete, and rollback. The current kernel backend remains a planner/trait, not a mutator.
- [ ] Implement detached recovery supervisors and service-manager backends. Init-system detection and lifecycle state transitions are not a recovery service; all backend kinds currently report unimplemented.
- [ ] Connect runtime mark allocation, supported core-specific outbound marking, broker-observed socket marks, and physical-egress route verification into a single readiness decision. A matching diagnostic socket alone is not end-to-end readiness.
- [ ] Integrate the kernel transaction, broker, supervisor, core lifecycle, and readiness gate into the CLI while preserving the existing unconditional TUN activation block until every prerequisite is present.
- [ ] Add end-to-end offline fault-injection coverage for crashes at every journal boundary, controller/core termination, broker failure, partial kernel apply, rollback conflicts, and recovery restart.
- [ ] Complete local formatting, Clippy, tests, release build, and native adapter validation. These checks have not been run for this change set.
- [ ] Only after all offline gates pass, perform separately approved controlled real-network validation. No real TUN activation is authorized by this implementation task.

Do not mark TUN complete or enable activation while any item above remains unchecked.


- [x] Harden supervisor identity validation against relative paths, parent traversal, embedded NUL, and oversized manifest paths; retain filesystem ownership and no-follow checks as the authoritative boundary.

- [x] Restrict persisted TUN interface names to bounded Linux-safe ASCII characters and cover separators, whitespace, and control-character rejection.

- [x] Strengthen diagnostic helper trust checks with canonical private-runtime path validation and root-owned, non-writable helper-directory validation; retain packaging audit as an open gate.

- [x] Make manual helper installation fail closed by clearing capabilities and removing the copied helper when capability setup or exact verification fails.
