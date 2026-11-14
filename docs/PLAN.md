# Proxyctl — Plan and Architecture Decisions

> Status: approved baseline; benchmark batching and bounded probes are implemented pending local verification in `docs/BENCHMARK_OPTIMIZATION_PLAN.md`  
> Repository: https://github.com/hosmaznazfar/proxyctl  
> Last updated: 2026-11-10

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
| Benchmark history | Keep multiple runs and individual samples |
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

Application releases are published by the proxyctl GitHub repository. The initial implementation supports Linux x86_64 assets produced by the release workflow. The updater selects the compatible release asset, verifies its published SHA-256 manifest, stages it beside the installed executable, validates its --version output, and replaces the executable atomically where the platform permits. Other OS/architectures remain unsupported until matching release jobs are added. It must never overwrite the running binary before the verified replacement is ready. If a safe self-replacement is unavailable, it reports the manual update command instead of risking a broken installation.

Core updates use the same download/verification/staging policy and preserve the last working binary on any failure. The updater reports each component independently: current version, available version, action taken, and error. A failure updating one core must not corrupt or silently roll back another component. Updates never start a core or change active proxy/network settings.

`proxyctl setup` remains the initial installation/bootstrap command; it installs the selected managed cores and does not update the CLI itself. `proxyctl cores` reports installed core versions and status.

### 3.2 URL records and source-file handling

The user's text file is an import source, not a live database or output file. Proxyctl reads it without changing it. Imported URL records are stored in redb, including the original URL needed to recreate core configurations.

A stable fingerprint prevents duplicate records. Re-importing an existing URL updates import metadata rather than creating a duplicate. Different credentials or connection settings remain distinct records. Duplicate lines within one import are also deduplicated.

Default list output shows an ID, protocol, server, port, and optional display name. Credentials and other secrets are masked. Any future reveal operation must be explicit and must not write secrets to logs or ordinary error output.

### 3.3 Storage model

Use versioned logical tables, initially:

- nodes: original URL, parsed fields, fingerprint, display metadata, lifecycle state, timestamps.
- node_fingerprints: unique fingerprint-to-node lookup.
- benchmark_runs: run metadata, selected cores, test settings, start/end state.
- benchmark_samples: individual metric samples, status, value/unit, error category, and timestamp.

The schema must include a migration/version strategy from the first implementation. Database access is behind repository interfaces so the storage engine can be replaced without changing domain services.

Recommended local permissions: data/config directories 0700; database and secret-bearing files 0600, subject to platform support. Never print full credentials in diagnostics.

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
6. **Complete:** the opt-in native fixture matrix passed with 51 supported fixture/core combinations across 23 fixtures against sing-box 1.14.4, Xray 26.11.9, and Mihomo 1.19.33. `docs/CORE_COMPATIBILITY.md` records the validated subset and remaining unit-only cases. Benchmark implementation is now in progress as the next delivery stage.

This work does not start cores, activate proxies, or modify system networking. All config checks remain validation-only.

### 3.5 Benchmark execution and persistence

**Revised methodology:** see [BENCHMARK_DESIGN.md](BENCHMARK_DESIGN.md). Proxyctl will follow the useful separation used by v2rayN:

- Direct TCP ping to the node server/port (does not start a core).
- Real HTTP ping through the selected core (configurable small-response URL).
- Download throughput through the selected core (configurable bounded file URL).
- Upload throughput through the selected core (configurable upload endpoint; separate from v2rayN's current download-only speed test).

The initial HTTP defaults follow v2rayN's current defaults where applicable: Google `generate_204` for real ping and CacheFly's 10 MB test file for download, but Proxyctl measures only the first 2 MiB per sample and closes the response instead of fetching the full object. Upload remains separately configurable and initially uses Cloudflare's upload endpoint because v2rayN does not provide an equivalent upload metric. Its default synthetic payload is 256 KiB per sample, reduced from 1 MiB after real runs repeatedly exceeded the 15-second request timeout. Cloudflare is therefore not the universal latency/download provider. Public LibreSpeed endpoints may be configured, but Proxyctl must not silently choose a public server with operator-dependent telemetry/privacy behavior.

TCP ping runs once per node and is stored under the reserved `direct` target. HTTP tests run for each compatible node/core pair. The CLI prints node/core/metric/sample progress; downloads report bounded, throttled byte progress. Ctrl-C must be observed during a running request: stop the active managed core to break the loopback proxy connection, wait for the measurement worker and child to exit, persist completed/cancelled samples, and finalize the run as cancelled. A global HTTP timeout alone is not an acceptable cancellation strategy.

**Implementation status: complete for the current benchmark contract.** Typed run/sample records, schema version 2, incremental persistence, median/throughput helpers, stale-run recovery, loopback-only per-core configs, native config validation, bounded child lifecycle, HTTP measurements, live progress, and cooperative cancellation are implemented. Failure diagnostics are allowlisted and do not expose raw core logs or transport details. The default sample sizes are 2 MiB download and 256 KiB upload, with three samples per metric. In full-suite mode, download and upload are gated on at least one successful real-latency sample for that node/core pair; otherwise they are marked unavailable with the `latency_gate` reason and no transfer request is sent. Unsupported/invalid compatibility and core preflight failures skip all metrics for that pair. The expanded native config matrix and real single-node smoke tests have passed. Benchmark execution remains sequential and does not alter system networking; one core process is started per node/core pair, so grouping by core would not reduce process starts, while parallel execution would increase RAM usage.

The remaining work is broader metric coverage and hardening, not a blocker for read-only reporting. Report and sorting views consume persisted samples only and never start cores.
  
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

For each node/core pair, use its latest completed run and calculate the median of successful samples. A newer completed run supersedes an older one even if it contains no successful samples; do not fall back to stale measurements. Ignore interrupted, cancelled, and running runs.

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

Latest mode displays the newest run containing each node, regardless of lifecycle status. History mode displays all matching runs newest first. Compare mode independently selects the latest completed run for each node/core pair; newer completed runs supersede older ones even when all samples failed. Cancelled, interrupted, and running runs do not replace comparison results. Direct TCP ping is shown under the separate `direct` target.

Every metric reports the successful count out of three, the median of successful samples, failure counts, and samples not run. One or two successful samples produce an explicitly partial median; three successful samples are complete. Preflight outcomes (unsupported, invalid, unavailable) remain distinct from attempted network failures. Missing or failed measurements are never rendered as zero.

Reports do not start proxy cores, contact measurement endpoints, or modify system networking. `show` and all report modes share the configurable compact/normal/full table profiles. Latest output has one row per node/core, history has one row per node/core/run, and compare has one row per node/core from the latest completed run. The `--verbose` flag expands core version metadata without changing table columns.

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

**Implementation status: updated.** `proxyctl prune --unavailable-all` evaluates every active node against all three managed cores: sing-box, Xray, and Mihomo. Unsupported and invalid adapter outcomes count as a core that cannot use the node. For supported combinations, the latest completed run must contain three distinct real-ping attempts with no successful sample; timeout, unreachable, and unavailable outcomes count as failed connectivity. Any successful real-ping sample through any core keeps the node. Missing runs, incomplete samples, and cancelled evidence remain inconclusive. `proxyctl prune --core xray --unavailable` remains available for a single-core evaluation. Preview is the default; `--apply` is the only mode that soft-deletes nodes.

Benchmark history is automatically retained to at most three newest runs per node/target pair. Samples for older target histories are removed; shared run metadata is retained only while another target in that run still has retained samples. Running runs are never pruned.

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

`remove` and `restore` remain soft lifecycle operations. `remove all` requires interactive confirmation unless `--yes` is supplied; `restore all` selects deleted records only. For individual restore operations, use the deleted-row position shown as `D#` by `list --include-deleted`. Batch operations report missing and unchanged selections separately. Benchmark/report selectors accept lists and ranges; selected nodes are recorded together in one benchmark run, with individual samples persisted for each node/core target.

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
11. **TUN activation deferred:** read-only status inspection remains available. Offline groundwork includes versioned exact-resource manifests, compare-and-delete cleanup contracts with fake-backend fault tests, runtime-selected service-manager kinds, native core configs with automatic route installation disabled, a generation-scoped lifecycle state machine, and a pure dual-stack routing-policy planner. The planner validates exact default-route/interface identity, mark-based core bypass ordering, unmarked proxy routing, table/rule collisions against synthetic inventories, and non-terminal fallthrough semantics. These remain non-mutating groundwork: a new read-only iproute2 JSON inventory inspects IPv4/IPv6 route tables and policy-rule priorities. Each query is bounded to two seconds, output is capped at 4 MiB, and timeout or process-status errors trigger child termination and reaping. Oversized or incomplete inventory fails closed. A detailed read-only snapshot retains canonical full route/rule attributes alongside family, table, and priority metadata for future exact ownership comparisons; it does not authorize mutation. The planner and cleanup contracts remain offline. No kernel mutation, socket marking, route installation, or live fallthrough proof exists. Production rtnetlink mutation, the supervisor executable, concrete service-manager implementations, privilege broker, dataplane readiness, and full crash/reboot fault injection remain outstanding. A private durable manifest store now provides atomic 0600 persistence, 0700 directory enforcement, generation checks, symlink rejection, and bounded validated reads. Its filesystem-only lifecycle API persists generation-checked Prepared/Running/CleanupPending/Cleaned transitions, retains manifests on cleanup conflict, and marks cleanup complete before attempting manifest removal. A filesystem-only lifecycle coordinator now serializes cross-process manifest operations with a bounded advisory lock and checks both activation UUID and generation on every event. The OS releases the lock automatically if a process exits; the lock file is retained to avoid inode races. This is offline groundwork only: a reusable Linux pidfd process-identity primitive now captures PID, start ticks, and canonical executable, verifies the identity after pidfd acquisition, and supports exact-process exit monitoring/signaling. It is tested with fake child processes but is not yet wired to a surviving supervisor. Privilege brokering, a backend-injected supervisor runtime now pins and monitors the exact core process, persists CoreExited before cleanup, retains CleanupPending on conflicts, and can retry only pending cleanup after restart. Fake-child and fake-resource tests cover these paths; fake-process setup uses bounded retries when pinning procfs identity and pidfds to avoid timing-sensitive test failures. A detached/init-managed supervisor, process identity persistence for reboot recovery, privilege broker, concrete kernel backend, and concrete service-manager integration remain outstanding. Do not enable TUN until all are implemented and tested; unsupported managers must fail closed.
12. **Implemented:** shared node selector parser, multi-node show/check/test/report command syntax, bulk soft-delete/restore, remove-all confirmation, and synchronized command documentation.
13. Hardening: integration tests, documentation, packaging, security review, and performance checks.

Each stage should leave the default branch buildable and tested. Apply related CLI, service, tests, and documentation together when they share a command contract. Update this plan when a material design decision changes.

## Benchmark optimization implementation status

Stages 1–3 are now committed on `main`: adapters can generate independently routed multi-node configs; the process manager starts one core for a batch and waits for every loopback listener; the scheduler is core-first; real HTTP latency and direct TCP probes use at most three workers; latency has a five-second request deadline. Download/upload remain sequential and the existing full-mode latency gate is preserved. These changes await local formatting, Clippy, and test verification. The later throughput-accuracy, persistence/run-scope, offline performance, and separately approved real-world comparison stages remain outstanding.

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


- **Core mark validation:** routing-policy planning rejects a zero socket mark because it could match unmarked traffic and bypass the TUN table. This is pure validation; per-core socket-mark configuration and live route-loop verification remain outstanding.


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


- **Metric-specific benchmark execution:** `test` now supports mutually exclusive `--latency-only`, `--download-only`, and `--upload-only` selectors. The default remains all HTTP metrics plus direct TCP ping. Each metric-only mode runs only its named HTTP metric and skips direct TCP ping. Preflight failures are persisted only for the selected metric, so a single-metric run does not create misleading outcomes for skipped metrics. Each selected HTTP metric retains three samples per supported node/core pair. In the default full-suite mode, download and upload run only after at least one successful latency sample; if all three latency samples fail, throughput is skipped with a `latency_gate` preflight outcome.


## Configurable result presentation

**Approved and implemented on main:** `proxyctl show` uses a persistent table profile, with compact as the default. Compact contains node, core, latency, download, and upload. Normal and Full expose progressively more context. Each profile can be customized independently using `proxyctl config display add-field` and `remove-field`; users can switch the active profile with `proxyctl config display profile`. The table renderer uses the Rust `tabled` crate. Ordinary output never includes fingerprints or credentials. `not-run`, `unavailable`, `unsupported`, and `invalid` remain distinct.


## Benchmark performance optimization

**Approved for staged implementation; not yet implemented.** The current benchmark starts one core process per node/core pair and performs samples sequentially. The optimization target is to batch compatible nodes per core while still running only one managed core process at a time. Latency probes will use bounded concurrency (initial target 3), preserve three samples and median aggregation, and follow the Throne latency reference. Download/upload will use v2rayN as the user's throughput-quality reference, but transfers remain sequential by default to avoid competing transfers distorting rates.

The full plan defines adapter batch configuration, per-listener readiness, failure isolation, independent latency/throughput timeouts, cancellation, progress, run metadata, offline tests, and separately approved real-world comparison. See [Benchmark Optimization Plan](BENCHMARK_OPTIMIZATION_PLAN.md).

Until implementation stages pass local verification, the existing scheduler remains authoritative. No stage may start multiple managed cores concurrently, alter system networking, enable TUN, or contact public test endpoints during automated tests.
