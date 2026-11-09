# Proxyctl — Software Requirements

> Status: baseline requirements for implementation  
> Source of truth for behavior: this document and [PLAN.md](PLAN.md)  
> Last updated: 2026-11-09

## 1. Scope

Proxyctl is a local Rust CLI for managing proxy URL records and orchestrating three external proxy cores: sing-box, Xray, and Mihomo.

The application must support URL import and management, core setup, configuration compatibility checks, network benchmarking, reports, sorting, safe pruning, local proxy activation, and optional TUN operation.

### 1.1 In scope

- Linux-first implementation, initially targeting CachyOS/Arch Linux.
- Rust CLI executable named `proxyctl`.
- Managed installation and updates of external core binaries.
- VLESS, VMess, Trojan, Shadowsocks, and Hysteria2 URL parsing.
- Embedded local database using redb.
- Per-core compatibility validation and config generation.
- Latency, download, and upload measurements through a proxy.
- Benchmark history and reports.
- Best-result sorting across compatible cores and sorting within one core.
- Dry-run and soft-delete cleanup.
- Explicit activation/stop lifecycle.
- Optional TUN support, implemented after core CLI and benchmark functionality.

### 1.2 Out of scope for the initial product

- GUI, tray icon, web UI, or background management daemon.
- Replacing or modifying another proxy manager.
- Editing the user's imported source text file.
- Implementing proxy protocols in Rust instead of using the supported core binaries.
- Running multiple benchmark cores concurrently by default.
- Automatically changing DNS, routes, firewall, or TUN state during setup or benchmarking.
- Cloud synchronization or remote database service.

## 2. Functional requirements

Priority levels: **P0** required for the first usable release; **P1** required for the complete planned feature set; **P2** optional future enhancement.

### FR-001 — CLI interface (P0)

The application shall expose a command-line interface named `proxyctl`.

Acceptance criteria:

- `proxyctl --help` displays top-level commands and usage.
- `proxyctl --version` displays the application version.
- Invalid arguments return a non-zero exit code and useful, secret-safe error text.
- Command handlers contain minimal orchestration and delegate behavior to services.
- Commands do not require a permanently running proxyctl process.

### FR-002 — Managed core installation (P1)

The application shall manage private installations of sing-box, Xray, and Mihomo.

Acceptance criteria:

- `proxyctl setup` installs the selected supported core binaries into a proxyctl-owned directory.
- `proxyctl cores` reports installed core names and versions.
- `proxyctl update` checks for and updates both the proxyctl CLI and all installed managed cores by default.
- `proxyctl update --check` checks versions without downloading or changing files.
- `proxyctl update --app` updates only the CLI; `--cores` updates all installed cores; `--core <CORE>` updates one selected core.
- `--check` is mutually exclusive with apply behavior and is supported with target selectors.
- Downloads use official project release sources.
- The selected version and platform artifact are explicit and recorded.
- Published checksums/signatures are verified before installation; unverifiable artifacts are not silently trusted.
- Installation uses temporary files and an atomic replacement strategy where practical.
- A failed download or verification does not replace a working installed binary.
- Setup does not stop, replace, or reconfigure other proxy applications.
- Core version metadata is separate from application logic so supported versions can be updated without rewriting command handlers.
- CLI releases are published with platform-specific assets and verifiable checksums/signatures.
- Self-update stages and verifies a replacement before atomic replacement; if safe replacement is not supported, the command provides a manual update path.
- A failure updating one component does not damage other installed components or replace a working binary.
- Update output reports current version, available version, and result separately for the CLI and each selected core.
- Updates do not start cores or alter active proxy, DNS, routes, firewall, or TUN state.

### FR-003 — URL import (P0)

The application shall import proxy URLs from a user-supplied text file.

Acceptance criteria:

- One non-empty URL per line is accepted; blank lines and documented comment lines are ignored.
- Supported schemes are VLESS, VMess, Trojan, Shadowsocks, and Hysteria2.
- Malformed or unsupported lines are reported with line numbers and safe error descriptions.
- A partial import reports successful, duplicate, invalid, and unsupported line counts.
- The source file is never modified, renamed, moved, or deleted.
- Re-importing the same file does not create duplicate node records.
- Duplicate lines within one import are deduplicated.
- The original URL is retained in local storage so the node can be reconstructed.
- Import does not print credentials or full secret-bearing URLs.

### FR-004 — Add and deduplicate nodes (P0)

The application shall allow one URL to be added directly.

Acceptance criteria:

- `proxyctl add <URL>` parses and validates the supplied URL.
- A stable fingerprint is calculated from normalized connection identity.
- Re-adding the same URL returns or updates the existing record rather than duplicating it.
- Different credentials or connection-affecting settings produce distinct records.
- Fingerprint uniqueness is enforced by storage, not only by an in-memory pre-check.
- The command does not echo the supplied secret URL.

### FR-005 — List, inspect, remove, and restore nodes (P0)

The application shall provide node lifecycle commands.

Acceptance criteria:

- `proxyctl list` shows ID, protocol, server, port, and available display name.
- Credentials and sensitive query values are masked by default.
- `proxyctl show <ID>` displays detailed non-secret metadata and benchmark state.
- `proxyctl remove <ID>` changes the record's lifecycle state without immediately erasing its history.
- `proxyctl restore <ID>` restores a soft-deleted record.
- Unknown IDs produce a clear error.
- List and show work without any core binary running.

### FR-006 — Protocol parsing and normalized domain model (P0)

The application shall parse supported proxy URL schemes into a core-independent domain representation.

Acceptance criteria:

- Each supported scheme has dedicated parsing tests and representative fixtures.
- URL decoding, percent encoding, IPv6 hosts, optional names, fragments, and scheme-specific fields are handled correctly.
- Parsing preserves meaningful options rather than discarding unrecognized connection settings.
- Invalid values are rejected with typed errors.
- Parser code does not depend on a specific core's config format.
- Credentials are not included in Debug output, logs, or ordinary error messages.
- A stable normalized representation is used for deduplication without collapsing distinct credentials or settings.

### FR-007 — Core compatibility and configuration generation (P1)

Each core adapter shall determine whether it can faithfully represent a parsed node and generate a valid temporary core configuration.

Acceptance criteria:

- Initial adapters exist for sing-box, Xray, and Mihomo.
- Compatibility is evaluated at the option/feature level, not only by URL scheme.
- Each adapter reports supported, unsupported, or invalid with a reason that does not expose secrets.
- Unsupported options are never silently dropped.
- Generated configurations are validated using the selected core's own validation mechanism where available.
- Core-specific serialization is isolated within the adapter.
- Adapter fixtures cover supported and unsupported transports/security options.
- Compatibility metadata is tied to the installed core version.

### FR-008 — Benchmark execution (P1)

The application shall benchmark nodes through each compatible core.

Acceptance criteria:

- `proxyctl test --all-cores` tests all active nodes against every compatible installed core.
- `proxyctl test --node <ID> --core <CORE>` tests one node with one selected core.
- A requested core that is missing or incompatible produces an explicit result; it is not silently skipped.
- The benchmark creates a private temporary config and an HTTP proxy listener bound only to `127.0.0.1`; it never binds to a LAN or wildcard address.
- Each core's native config is validated before startup; the benchmark process uses only the selected Proxyctl-managed binary.
- The core is launched as a managed child process and stopped after its test.
- Benchmarking does not require TUN.
- The database is closed while the core and network tests are running.
- Tests are sequential; at most one managed core child process exists at a time.
- The HTTP measurement client uses an explicit proxy pointing to the local inbound and ignores shell proxy environment variables.
- Temporary configurations and listeners are cleaned up after success, failure, timeout, or cancellation.
- A failed node does not prevent the remaining nodes from being tested unless the user explicitly requests fail-fast behavior.
- The run records its start/end state, methodology version, core versions, endpoints, payload sizes, and timeouts.
- Completed samples are committed in short transactions after each node/core child process has stopped; the database is closed during process execution and network requests.
- Cancellation stops and waits for the child process, cleans temporary files, and retains completed samples.

### FR-009 — Benchmark metrics and sample persistence (P1)

The application shall measure latency, download throughput, and upload throughput.

Acceptance criteria:

- Latency is measured using an application-level HTTP request through the proxy; ICMP-only ping is insufficient.
- Three samples are collected for each metric for each node/core combination.
- Download and upload tests use bounded, deterministic payloads and documented HTTPS endpoints.
- The default endpoint is Cloudflare Speed Test (`speed.cloudflare.com/__down` and `/__up`); the CLI and README disclose that Cloudflare collects completed measurement results for aggregated insights. Endpoints and payload sizes are configurable.
- Test endpoints, payload sizes, timeouts, and relevant settings are recorded with the run.
- Each sample stores node ID, run ID, core, metric, sample index, status, optional numeric value, unit, error category, and timestamp.
- Successful samples require a finite non-negative value and the metric's canonical unit; failed samples must have no numeric value.
- A reserved sample index of 0 represents a preflight outcome (unsupported, invalid, or missing core), not a network measurement.
- A failed sample has no numeric value; it is never stored as zero or a magic negative number.
- Successful samples for one metric remain stored even if another metric fails.
- A run interrupted partway retains completed samples and is marked incomplete.
- Status values distinguish success, unreachable, unsupported, invalid, timeout, unavailable, and cancelled.
- Results are not described as isolated core performance; they represent the end-to-end proxy route and test conditions.

### FR-010 — Sorting across cores (P1)

The application shall rank nodes using the best successful compatible-core result for a selected metric.

Acceptance criteria:

- `proxyctl list --sort ping` sorts by lowest median successful latency.
- `proxyctl list --sort download` sorts by highest median successful download throughput.
- `proxyctl list --sort upload` sorts by highest median successful upload throughput.
- For each node, the median is calculated from its successful samples per core.
- The best compatible-core median is selected for each node.
- The output identifies which core produced the displayed best result.
- Nodes without successful measurements are shown separately as unmeasured/unavailable, not assigned a fabricated value.
- The output identifies the benchmark run or timestamp used.

### FR-011 — Sorting within a core (P1)

The application shall rank nodes using results from one selected core only.

Acceptance criteria:

- `--core sing-box`, `--core xray`, and `--core mihomo` are supported filters.
- Sorting direction and median aggregation match FR-010.
- Results from other cores are not included in the ranking.
- Unsupported or missing results are clearly distinguished from failed connection tests.

### FR-012 — Reports and benchmark history (P1)

The application shall provide current and historical benchmark reports.

Acceptance criteria:

- `proxyctl report` shows the latest available results.
- `proxyctl report --history` shows previous runs.
- `proxyctl report --compare` compares runs without mixing incompatible test methodologies.
- `proxyctl report --core <CORE>` filters by core.
- `proxyctl report --node <ID>` filters by node.
- Reports include metric values, units, core, timestamp/run ID, sample success information, and failure reasons where useful.
- Historical samples are retained when a new benchmark is run.
- Reports mask secrets.

### FR-013 — Prune unavailable nodes safely (P1)

The application shall identify and soft-delete nodes that have no successful connectivity result across all compatible cores or within a selected core.

Acceptance criteria:

- `proxyctl prune --unavailable-all --dry-run` previews candidates without changing the database.
- `proxyctl prune --unavailable-all --apply` applies soft deletion after displaying or confirming the candidate set.
- `proxyctl prune --core <CORE> --unavailable --dry-run` previews core-specific candidates.
- The corresponding `--apply` operation applies the soft deletion.
- A node is eligible for all-core pruning only after completed connectivity evaluations exist for every compatible core.
- Unsupported cores do not count as failed connectivity tests.
- A node with any successful connectivity sample is not considered unavailable.
- Missing, incomplete, or ambiguous evaluations never qualify a node for automatic pruning.
- The operation records why and when a node was pruned.
- Soft-deleted nodes can be restored.

### FR-014 — Local proxy activation and stop (P1)

The application shall activate one node using one selected core.

Acceptance criteria:

- `proxyctl use <ID> --core <CORE>` validates the node/core combination before startup.
- Only one proxyctl-managed core is active for the normal activation workflow.
- Proxyctl records the child process identity and runtime metadata needed to stop only its own process.
- `proxyctl stop` does not stop unrelated processes.
- Failed startup cleans up temporary files and partially started processes.
- Activation does not silently enable TUN or rewrite system DNS/routes.
- Local listener addresses/ports are configurable or safely selected and checked for conflicts.

### FR-015 — Optional TUN operation (P2)

The application may provide explicit TUN enable/disable commands after the non-TUN workflow is stable.

Acceptance criteria:

- TUN is never enabled by setup, import, testing, or normal activation without explicit user action.
- Before changing networking, proxyctl inspects relevant interfaces, routes, DNS configuration, NetworkManager/systemd-resolved state, and firewall rules.
- Existing proxy applications and TUN interfaces are detected and preserved.
- Privileged changes are explicit and narrowly scoped.
- Proxyctl tracks the changes it makes and can roll them back.
- Disable/cleanup removes only proxyctl-owned resources.
- Errors leave the system in a recoverable state and explain any manual recovery needed.
- TUN behavior is tested on supported Linux configurations before being advertised as stable.


### FR-016 — Unified application and core updates (P1)

The application shall provide one update command for the proxyctl executable and its managed core binaries.

Acceptance criteria:

- `proxyctl update` checks and applies available updates for proxyctl and all installed managed cores by default.
- `proxyctl update --check` checks available versions without downloading or modifying files.
- `proxyctl update --app` targets only the proxyctl executable.
- `proxyctl update --cores` targets all installed managed cores.
- `proxyctl update --core <CORE>` targets one selected core.
- Target selectors are validated; ambiguous or conflicting selectors return a clear usage error.
- The CLI and core versions are reported independently.
- The CLI updater selects a release asset compatible with the current OS and architecture (initial implementation: Linux x86_64).
- Application and core downloads come from official release sources and are verified against published checksums/signatures before execution or installation.
- Updates are staged before replacement. A failed download, verification, or staging operation leaves the currently working binary untouched.
- Self-update uses a safe atomic replacement strategy where supported; otherwise it provides a documented manual update path.
- A failure updating one component does not prevent accurate reporting for other selected components and does not corrupt them.
- Updates do not start a proxy core or modify active proxy, DNS, routes, firewall, or TUN configuration.
- `proxyctl setup` remains the initial managed-core installation command and does not replace the unified update workflow.

## 3. Non-functional requirements

### NFR-001 — Resource usage

- No background daemon is required for ordinary commands.
- The database is opened only for the duration of required database operations.
- Benchmarking is sequential by default.
- Avoid large frameworks and unnecessary runtime dependencies.
- Close database handles and child processes deterministically.

### NFR-002 — Security and privacy

- Secret-bearing local directories use restrictive permissions (target 0700).
- Database and secret-bearing files use restrictive permissions (target 0600).
- Credentials are masked in list/report output and omitted from logs.
- Errors must not include complete URLs or credentials.
- Downloaded core artifacts are verified before execution.
- Temporary configs containing credentials use restrictive permissions and are removed after use.
- Never execute a downloaded artifact before successful verification.

### NFR-003 — Reliability

- Database writes use transactions where supported by the storage design.
- Duplicate prevention is enforced atomically.
- Interrupted benchmarks retain completed samples where possible.
- Core processes are reaped and temporary resources cleaned up on all normal error paths.
- Failed operations must not corrupt previously stored node records or replace working core binaries.

### NFR-004 — Portability

- Initial target is Linux, with CachyOS/Arch Linux as the first validated environment.
- OS-specific paths, process management, permissions, and TUN operations are isolated behind platform modules.
- Core adapters must account for supported OS/architecture artifacts.
- Do not assume a core binary exists in PATH; proxyctl uses its managed installation and may report external installations separately.

### NFR-005 — Maintainability and extensibility

- Keep domain models independent from CLI, database, and core-specific formats.
- Add a core through a shared adapter interface.
- Add a protocol through parser modules and explicit core capability mappings.
- Add benchmark metrics through independent metric implementations and typed result records.
- Add sort criteria and prune policies without embedding business logic in command parsing.
- Use typed errors and structured, secret-safe logging.
- Document non-obvious design decisions and schema changes.

### NFR-006 — Testability

- Unit tests cover parsers, normalization, fingerprints, compatibility, aggregation, and prune eligibility.
- Database tests cover migrations, transactions, uniqueness, lifecycle states, and benchmark history.
- Core adapter tests use checked-in sanitized fixtures and validation tests where practical.
- Service tests use fake core/process and benchmark interfaces; no unit or integration test contacts the default external measurement service.
- CLI tests cover help, argument validation, output masking, and exit codes.
- Network-dependent tests are opt-in and must not be required for ordinary CI.
- CI runs formatting, linting, tests, and dependency/build checks.

## 4. Data and domain requirements

### 4.1 Node record

A node record should include:

- Stable internal ID.
- Original URL, stored privately.
- Normalized protocol and connection fields.
- Stable deduplication fingerprint.
- Optional display name.
- Created/updated/imported timestamps.
- Active/soft-deleted state and deletion metadata.
- Parser/schema version where needed for future migrations.

Do not expose credential fields through default display models.

### 4.2 Benchmark run

A run record should include:

- Run ID and lifecycle status.
- Start and completion timestamps.
- Selected node/core scope.
- Test methodology/version.
- Endpoint and payload settings.
- Relevant timeout/retry configuration.
- Application and core versions where useful.
- Error/interruption summary.

### 4.3 Benchmark sample

A sample record should include:

- Sample ID.
- Run ID.
- Node ID.
- Core identifier and core version.
- Metric identifier.
- Sample index (1–3).
- Status.
- Optional value and unit.
- Optional typed failure category/reason.
- Timestamp and duration where available.

### 4.4 Aggregation

For each node/core/metric/run, calculate the median from successful samples only. Do not turn failed samples into zero values. If no successful samples exist, the aggregate is absent and the failure state remains visible.

## 5. CLI command requirements summary

~~~sh
proxyctl setup
proxyctl cores
proxyctl update
proxyctl update --check
proxyctl update --app
proxyctl update --cores
proxyctl update --core sing-box

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

The exact help wording and minor flag refinements may evolve, but the safety and behavior requirements above must remain intact.

## 6. Release acceptance checklist

A release must not be considered complete until all applicable P0 requirements and the planned P1 requirements are implemented and tested.

- [ ] CLI help/version and stable command structure.
- [ ] Typed protocol parsers with fixture coverage.
- [ ] Import/add deduplication and source-file preservation.
- [ ] Secret masking and restrictive local permissions.
- [ ] Versioned redb schema and repository tests.
- [ ] Core compatibility and config validation.
- [ ] Verified managed core installation/update.
- [ ] Unified, verified proxyctl self-update and managed-core update.
- [ ] Isolated, sequential benchmark process lifecycle.
- [ ] Three samples per metric and per compatible core.
- [ ] Benchmark history and accurate status handling.
- [ ] Core-independent and core-specific sorting.
- [ ] Reports and run comparisons.
- [ ] Dry-run, safe soft-delete, and restore.
- [ ] Activation/stop limited to proxyctl-owned processes.
- [ ] CI, formatting, linting, tests, and user documentation.
- [ ] TUN safety and rollback tests before TUN is marked stable.
