# Benchmark design

> Status: approved implementation baseline
> Last updated: 2026-11-09

## 1. Scope and non-goals

The first benchmark implementation measures the end-to-end route through each compatible managed proxy core. It does not attempt to isolate core CPU performance, test TUN mode, change system proxy settings, or modify DNS, routes, firewall rules, or interfaces.

Initial metrics are:
- Unloaded HTTP request latency, in milliseconds.
- Download throughput, in bits per second.
- Upload throughput, in bits per second.

Each compatible node/core pair receives three samples per metric. Runs are sequential: one core process and one node test at a time. A failure for one node or metric does not stop the remaining work.

## 2. CLI contract

Initial commands:

```sh
# Test all active nodes against all installed compatible managed cores
proxyctl test --all-cores

# Test one node using one explicitly selected core
proxyctl test --node 12 --core sing-box
```

The selectors are mutually exclusive. The all-cores form discovers installed managed cores and checks every active node against each installed core. The explicit form reports a missing or incompatible selected core instead of silently skipping it. Deleted nodes are excluded from all-node runs; an explicitly selected deleted node is rejected.

Initial configurable settings:
- Latency URL, download URL, and upload URL.
- Download and upload payload sizes.
- Per-request timeout and core startup/readiness timeout.

The command records the effective settings and methodology version in the run. Defaults are conservative and bounded; no automatic retries are hidden inside a sample. One request is one sample. The first implementation uses 1 MiB download and 1 MiB upload payloads per sample, three samples per metric, and a 15-second request timeout. These defaults are overridable and can be tuned after real-world test evidence.

## 3. Measurement endpoint and disclosure

The initial default measurement service is Cloudflare Speed Test:
- Latency: `GET https://speed.cloudflare.com/__down?bytes=0`.
- Download: `GET https://speed.cloudflare.com/__down?bytes=<configured-bytes>`.
- Upload: `POST https://speed.cloudflare.com/__up` with a deterministic synthetic body of the configured size.

Cloudflare documents these download/upload endpoints and states that completed speed-test measurements are collected for aggregated Internet-connection insights. Proxyctl must disclose this in `proxyctl test --help`, README, and benchmark documentation. The endpoint URLs are configurable so users can select another compatible measurement service they trust. Custom endpoints must use HTTPS, contain no URL credentials, query parameters, or fragments, and implement the same request contract. Configure base endpoint URLs; Proxyctl adds the `bytes` query parameter to the latency/download requests. Local HTTP endpoints may be used only by tests.

No user files or proxy credentials are sent to measurement endpoints. The upload body is generated in memory and contains no user data. Only the test requests and normal network metadata reach the endpoint.

Sources:
- Cloudflare Speed Test API defaults and measurement behavior: https://github.com/cloudflare/speedtest
- Cloudflare's README notes that completed results are collected for aggregated insights.

## 4. Proxy process isolation

All three cores expose a local HTTP proxy inbound for the benchmark:
- Bind only to `127.0.0.1`.
- Select an ephemeral port for each node/core attempt.
- Never listen on a LAN or wildcard address.
- Do not use SOCKS or rely on system proxy environment variables.

Each adapter will expose a benchmark-config generation path that adds the local HTTP inbound to the already validated outbound config and routes traffic to the node's `proxy` outbound. The generated config is validated with the selected core's native config-check command before startup.

Core startup commands:
- sing-box: `sing-box run -c CONFIG`.
- Xray: `xray run -c CONFIG`.
- Mihomo: `mihomo -f CONFIG`.

The runner writes the generated config to a private temporary file (0600 on Unix), starts one managed child process, suppresses raw child stdout/stderr from normal output, and waits for the local listener to become ready. Readiness is bounded by a timeout. The port is reserved by asking the OS for an ephemeral local port; because the reservation must be released before the core binds, startup/readiness retry is bounded to handle a rare port collision.

The HTTP client uses an explicit proxy URL for the local listener. It must not inherit `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY` settings from the user's shell. This prevents tests from accidentally routing around the selected core or through an unrelated proxy application.

A process guard owns the child and temporary config. Every normal error, timeout, and cancellation path stops and waits for the child and removes the config. The runner never invokes a shell and never changes global networking. Ctrl-C requests cancellation; the active request is bounded by its timeout, then cleanup runs and the run is finalized as cancelled/incomplete.

## 5. Measurement semantics

For each compatible node/core pair, after config validation and readiness:

1. Send three latency requests, sequentially. Measure from immediately before the HTTP request until response headers arrive. The zero-byte endpoint minimizes payload transfer.
2. Send three download requests. Measure until exactly the configured response body bytes have been read; reject short or oversized responses.
3. Send three upload requests with a deterministic in-memory body. Measure until the successful response is received.

Use a monotonic clock for durations. Throughput is calculated as `transferred_bytes * 8 / elapsed_seconds` and stored as bits per second (`bps`). Latency is stored as milliseconds (`ms`). Do not convert failures to zero. HTTP status errors, DNS/connect failures, request timeouts, malformed responses, and cancellation map to typed safe failure categories. Error details must not include full URLs, credentials, response bodies, or generated config content.

These are end-to-end measurements of the proxy route, endpoint, and test conditions—not isolated core performance. Three samples are retained individually; medians are calculated for reporting/sorting from successful samples only.

## 6. Compatibility and outcome handling

Before starting a core:
1. Load the node record and close the database.
2. Evaluate the adapter compatibility result.
3. Confirm the managed core binary exists and capture its version.
4. Generate and native-validate the benchmark config.
5. Start the core and probe readiness.

Unsupported or invalid node/core combinations do not start a core. A selected but missing managed core is reported as unavailable. Incompatible combinations are recorded as unsupported or invalid. Compatible combinations that cannot connect are recorded as unreachable; bounded request failures are recorded as timeout or unavailable as appropriate.

For a compatible, installed core, each metric has three separately recorded sample outcomes. Preflight outcomes (unsupported, invalid, or missing core) are recorded as a single non-measurement outcome per metric with no numeric value; they are not represented as three attempted network samples.

The initial sample status vocabulary is: `success`, `unreachable`, `unsupported`, `invalid`, `timeout`, `unavailable`, and `cancelled`.

## 7. Persistence and crash recovery

Use the existing redb `benchmark_runs` and `benchmark_samples` tables. Add typed domain records and repository methods; keep redb-specific encoding inside the database module.

A run records:
- Monotonic run ID, status, start/end timestamps.
- Selected node/core scope and methodology version.
- Configured endpoint URLs, payload sizes, timeouts, and retry policy.
- Managed core versions observed during the run.
- Safe interruption/error summary.

A sample records:
- Sample ID, run ID, node ID, core ID and core version.
- Metric, sample index (1–3 for attempted measurements).
- Status, optional value, unit, safe failure category/reason.
- Start timestamp and elapsed duration.

Persist the run as running before tests begin. Keep the database closed while a core is active or a network request is running. After stopping a core, persist its completed node/core sample batch in short write transactions. Finalize the run after all work. Never keep a redb handle open while a core process or HTTP request is active.

If Ctrl-C is received, stop the active child, persist the current node/core's completed sample batch and finalize the run as cancelled. If the process is killed without cleanup, the next benchmark invocation detects stale running records and marks them interrupted; only the unflushed active node/core batch may be lost. Never delete prior runs or samples when a new run begins.

Schema migration: advance the current schema version and initialize benchmark ID counters through an explicit migration. Existing node records and fingerprints must remain unchanged.

## 8. Failure isolation and safety

- One node/core failure does not prevent later node/core attempts.
- A metric failure does not erase successful samples from other metrics.
- A core startup, readiness, or shutdown failure is reported without leaking credentials.
- The runner owns exactly one child process at a time and always waits for it after termination.
- Temporary configs are private and removed on every handled exit path.
- Local listeners bind only to loopback and are closed when the core exits.
- No system proxy, DNS, route, firewall, or TUN state is read-modified or changed.
- No core is started by `check`, `setup`, `update`, or other existing commands; only the explicit `test` command starts a core.

## 9. Implementation sequence

1. **Implemented:** typed benchmark run/sample/metric/status models, validation invariants, and pure median/throughput calculations.
2. **Implemented:** schema version 2 migration, independent run/sample ID counters, short sample transactions, run finalization, and stale-running-run recovery.
3. **Implemented:** per-core benchmark config generation with loopback HTTP inbounds and native config validation.
4. **Implemented:** isolated child-process ownership, bounded readiness, termination/wait, and temporary-config cleanup; Unix SIGINT/SIGTERM are converted into cooperative cancellation requests.
5. **Implemented:** explicit local HTTP proxy client, HTTPS endpoint validation, bounded download/upload bodies, and throughput calculation.
6. **Implemented:** sequential service orchestration and the `proxyctl test` CLI command, including preflight outcomes and post-process node/core sample-batch persistence.
7. **Next:** add deterministic service-level tests and local fake-core/fake-endpoint integration tests. Tests must not contact Cloudflare or start real proxy cores.
8. Add reports and sorting only after benchmark persistence is verified.

Keep each step buildable and update this document and `docs/PLAN.md` as implementation decisions are refined.
