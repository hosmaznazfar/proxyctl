# Proxyctl — Plan and Architecture Decisions

> Status: approved baseline for implementation  
> Repository: https://github.com/hosmaznazfar/proxyctl  
> Last updated: 2026-11-09

## 1. Purpose

Proxyctl is a lightweight, command-line-only Rust application for importing proxy URLs, checking compatibility with supported proxy cores, benchmarking them, comparing results, selecting a node, and optionally managing TUN mode.

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
| Default benchmark concurrency | Sequential |
| TUN | Optional, separate, explicit feature; never enabled by setup or benchmarking |

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

**Design baseline:** see [BENCHMARK_DESIGN.md](BENCHMARK_DESIGN.md). The first benchmark command is explicit and sequential:

```sh
proxyctl test --all-cores
proxyctl test --node 12 --core sing-box
```

For each compatible installed node/core pair, Proxyctl validates a generated config, starts one managed core with a loopback-only HTTP inbound, probes readiness, measures latency/download/upload, then stops and waits for the child and removes the private config. The selected core is the only process started. No TUN, system proxy, DNS, route, or firewall changes are involved.

The database is never held open while a core process or HTTP request is active. Read node data and close redb before execution; persist the run before starting; keep the database closed for each core-process lifetime; after stopping a core, persist that node/core's samples in short transactions; and reopen for finalization. A run interrupted by cancellation retains completed samples and is marked incomplete. Stale running records are recovered on the next benchmark invocation. Typed run/sample records, median/throughput calculations, schema version 2, short sample transactions, finalization, stale-run recovery, loopback-only per-core configs, bounded child-process lifecycle, HTTPS measurement client, and the sequential `proxyctl test` service/CLI are implemented. The fake-core startup/cleanup and local fake HTTP-proxy measurement tests are implemented; service orchestration tests remain pending.

Collect three independent samples per metric per compatible node/core pair: three latency, three download, and three upload samples. A failed sample has a status and no numeric value. A failure in one metric does not erase successful samples from another. Unsupported/invalid/missing-core preflight outcomes are recorded without starting a process and are not fabricated as attempted network samples.

Latency is application-level HTTP response-header latency through the proxy, not ICMP ping. Throughput is measured from bounded HTTP download/upload transfers and stored in bits per second. The initial default endpoint is Cloudflare Speed Test (`/__down` and `/__up`); endpoints, payload sizes, and timeouts are configurable and recorded with the run. Cloudflare's published speed-test documentation states that completed measurement results are collected for aggregated insights; the CLI and README must disclose this before benchmark execution. Results describe the end-to-end route and test conditions, not isolated core CPU performance.

Initial sample statuses: `success`, `unreachable`, `unsupported`, `invalid`, `timeout`, `unavailable`, and `cancelled`.

### 3.6 Sorting and comparison semantics

Core-independent commands compare each node's best available compatible-core result:

~~~sh
proxyctl list --sort ping
proxyctl list --sort download
proxyctl list --sort upload
~~~

For each node, calculate the median of successful samples for a metric on each core, then choose the best compatible-core median. Display the core responsible for that result. Lower latency is better; higher download/upload throughput is better.

Core-specific comparisons use the same aggregation but restrict results to the selected core:

~~~sh
proxyctl list --sort ping --core xray
proxyctl list --sort download --core sing-box
proxyctl list --sort upload --core mihomo
~~~

Only comparable successful results are ranked. Missing results are shown as unavailable/unmeasured rather than assigned fabricated values. Reports identify the benchmark run and methodology used.

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

A node is unavailable across all cores only when every compatible core has a completed connectivity evaluation and none has a successful connection result. A core that cannot support the node is unsupported, not a failed connection. Thus, a Hysteria2 node is evaluated against sing-box and Mihomo; Xray's unsupported status does not count as a connection failure.

A node must not be pruned if required tests are missing, incomplete, or ambiguous. One successful sample is enough to prevent classifying the node as unavailable, even if other samples failed. Core-specific pruning likewise requires a completed evaluation for that core.

Pruning is a soft-delete/lifecycle-state change, not immediate permanent erasure. Preview is the default; applying changes requires an explicit flag. A restore command is part of the planned interface.

### 3.8 Activation and TUN safety

Normal activation selects one node and one core. The stop command stops only processes started and tracked by proxyctl.

TUN is a separate opt-in feature. It must detect existing interfaces, routes, DNS configuration, NetworkManager/systemd-resolved state, and firewall configuration before making changes. It must not assume it owns the machine's network stack. Enabling TUN requires explicit user intent, privilege escalation where needed, and a rollback/cleanup path. Benchmarking must not depend on TUN and must use isolated local listeners.

## 4. Proposed command surface

~~~sh
# Managed binaries
proxyctl setup
proxyctl cores
proxyctl update
proxyctl update --check
proxyctl update --app
proxyctl update --cores
proxyctl update --core sing-box

# URL records
proxyctl import ~/Documents/servers.txt
proxyctl add "vless://..."
proxyctl list
proxyctl show 12
proxyctl remove 12
proxyctl restore 12

# Benchmarks
proxyctl test --all-cores
proxyctl test --node 12 --core sing-box

# Reports
proxyctl report
proxyctl report --history
proxyctl report --compare
proxyctl report --core mihomo
proxyctl report --node 12

# Sorting
proxyctl list --sort ping
proxyctl list --sort download --core sing-box

# Cleanup
proxyctl prune --unavailable-all --dry-run
proxyctl prune --unavailable-all --apply
proxyctl prune --core xray --unavailable --dry-run
proxyctl prune --core xray --unavailable --apply

# Activation
proxyctl use 12 --core sing-box
proxyctl stop

# Optional TUN
proxyctl tun on
proxyctl tun off
~~~

This is the initial command contract. Help text and flags may be refined while preserving documented behavior.

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
6. Core adapters: **complete for the documented initial subset**; the adapter unit suite, formatting, Clippy, release build, and the 23-fixture native matrix (51 supported fixture/core combinations) passed. Version-aware capability predicates and additional protocol/option coverage remain future enhancements. The expanded native test now also checks benchmark configs; that extension is pending execution.
7. Benchmark engine: **in progress**. Typed records, schema migration, incremental persistence, aggregation primitives, stale-run recovery, per-core loopback HTTP config, process lifecycle, bounded HTTP measurements, cooperative cancellation, and CLI orchestration are implemented. Remaining work: deterministic service tests and local fake-core/fake-endpoint integration tests.
8. Reports and sorting: latest/history/compare views and core-independent/core-specific sorting.
9. Pruning: dry-run previews, compatible-core evaluation rules, soft deletion, and restore.
10. Activation: managed process lifecycle and safe stop behavior.
11. TUN: implement only after network-state detection and rollback design are tested.
12. Hardening: integration tests, documentation, packaging, security review, and performance checks.

Each stage should leave the default branch buildable and tested. Do not implement all features in one large change. Update this plan when a material design decision changes.

## 8. Open implementation details

These are implementation choices, not blockers to the architecture:

- Exact minimum supported Rust version and edition.
- Exact pinned versions and official release/checksum metadata for each core.
- Proxyctl release asset naming, signing/checksum publication, and safe self-update behavior for each supported platform.
- Benchmark endpoint selection, payload sizes, and timeout defaults.
- Precise configuration support matrix for each core version and URL option.
- Platform-specific TUN backend and DNS/firewall rollback strategy.
- Whether an explicit credential-reveal command is needed.

Resolve these choices with evidence and document them before the affected feature is considered complete.
