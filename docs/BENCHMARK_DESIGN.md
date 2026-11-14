# Benchmark design

> Status: Stages 1–5 user-verified; Stage 6 focused offline tests user-verified, full offline verification pending; real-world runbook prepared for user execution
> Last updated: 2026-11-14

## 1. Goals and scope

Proxyctl reports four distinct measurements for each node:

1. **TCP ping (direct):** connect to the node's advertised server and port without starting a proxy core. This is a reachability/transport measurement, not a measurement through a proxy.
2. **Real ping (through proxy):** send HTTP requests through the selected managed core to a configurable small-response URL. This is application-level response latency, not ICMP.
3. **Download (through proxy):** download a bounded test object through the selected managed core and measure bytes received over elapsed time.
4. **Upload (through proxy):** send a bounded synthetic payload through the selected managed core to a configurable upload endpoint.

Do not combine TCP ping and real ping into one value. Their paths and meanings differ. These results measure the complete route, remote endpoint, and current test conditions; they do not isolate core CPU performance.

The command remains sequential by default: one node/core process at a time. The direct TCP test runs once per node in a run, not once for every core. Each metric keeps three individual samples; summaries use successful samples only.

## 2. v2rayN-inspired endpoint defaults

Use the same practical separation as v2rayN:

- Real-ping default: `https://www.google.com/generate_204`.
- Download default: `https://cachefly.cachefly.net/10mb.test`, sampling only the first 2 MiB per measurement.
- Upload default: `https://speed.cloudflare.com/__up` because v2rayN's current speed-test workflow does not provide an equivalent upload measurement.

These are defaults, not hard dependencies. Provide CLI overrides for all three HTTP endpoints. Keep TCP ping independent of HTTP endpoint selection.

The v2rayN reference implementation uses a direct TCP connect to the node host/port for TCPing, an HTTP response-time request through its local proxy for real ping, and a configurable download URL (including CacheFly and Cloudflare options). Its real-ping defaults include Google, YouTube, and Apple small-response URLs. Proxyctl uses three retained samples and a median rather than silently keeping only the fastest of two requests.

LibreSpeed remains a supported endpoint family when a user supplies a compatible server. Do not silently select a public LibreSpeed server: operators and locations vary, and the public librespeed.org service currently discloses telemetry collection including IP address, ISP/location estimates, and test results. No public speed-test provider is assumed to be privacy-neutral.

## 3. CLI contract

```sh
# Test all active nodes against installed compatible cores
proxyctl test --all-cores

# Test one node against every installed compatible core
proxyctl test --node 12 --all-cores

# Test one node through one selected core
proxyctl test --node 12 --core sing-box

# Run exactly one HTTP metric across every installed core
proxyctl test --all-cores --latency-only
proxyctl test --all-cores --download-only
proxyctl test --all-cores --upload-only

# Run one metric for selected nodes across every installed core
proxyctl test --node 1 2 3 --all-cores --latency-only

# Override the HTTP measurement endpoints
proxyctl test --node 12 --core sing-box \
  --latency-url https://www.google.com/generate_204 \
  --download-url https://cachefly.cachefly.net/10mb.test \
  --upload-url https://speed.cloudflare.com/__up
```

The all-cores scope can cover every active node or be restricted to selected nodes with `--node`. A specific node/core pair uses `--node` with `--core`; `--core` and `--all-cores` are mutually exclusive. By default, all three HTTP metrics run. The mutually exclusive `--latency-only`, `--download-only`, and `--upload-only` selectors run only the named metric; omitting them preserves the full benchmark. Direct TCP ping is included only in the default all-metrics mode, once per selected node. Metric-only modes skip direct TCP ping. HTTP samples run once per supported node/core pair, with three samples for each selected metric.

The run stores effective endpoint URLs, payload limits, separate latency/throughput timeouts, bounded probe concurrency, and methodology version. The default download sample is 2 MiB even though the static CacheFly object is 10 MB; Proxyctl stops reading once the sample target is reached and closes the response rather than downloading the full object. The upload body is a bounded 256 KiB synthetic payload per sample. This smaller default keeps a single POST practical on asymmetric or slow upstream links; users can raise it with `--upload-bytes`. Upload requests still have a finite configurable timeout, and Proxyctl does not retry a failed sample automatically. Keep the request timeout finite and configurable. No automatic retries are hidden inside a sample.

## 4. Measurement semantics

### 4.1 Direct TCP ping

Resolve the node hostname and attempt a TCP connection to its configured port. Time from immediately before connection until the connection succeeds. Use a bounded connect timeout and three independent samples. Do not send proxy credentials or application data. This test does not use the selected core and may use the machine's normal DNS resolver; it must not modify DNS configuration.

### 4.2 Real ping through the selected core

Use the explicit loopback HTTP proxy created for the selected core. Send a GET request to the configured real-ping URL and measure until response headers arrive. Accept successful HTTP responses including 204 No Content; do not require a special query parameter or a zero-length response body. Read/discard only a small bounded response body. Three samples are retained.

### 4.3 Download through the selected core

GET the configured download URL exactly as supplied. Do not append provider-specific query parameters. Stream the response body in bounded chunks, count the actual bytes received, and calculate throughput from the exact configured sample byte count and monotonic elapsed time. Stop reading once the configured sample byte count is reached, even if the remote object is larger; close the response without downloading the remainder. If the server ends the response earlier, record an incomplete response rather than scoring a shorter sample. Emit throttled progress with transferred bytes, target bytes, elapsed time, and current rate.

### 4.4 Upload through the selected core

POST a deterministic in-memory payload containing no user data. Start timing immediately before the request so the complete request-body transmission and response exchange are included. Measure until the endpoint returns a successful HTTP response and its bounded response body is consumed. Bound payload and response sizes. Report the upload stage and its completion/failure; do not imply byte-level progress if the HTTP library cannot expose it.

### 4.5 Units and aggregation

- TCP ping and real ping: milliseconds (`ms`).
- Download and upload: bits per second (`bps`).
- Throughput = `transferred_bytes * 8 / elapsed_seconds`.
- Use a monotonic clock.
- Never turn a failed request into zero.
- Keep all individual samples and calculate medians from successful samples only.

A failure in one metric must not erase successful samples from another metric.

## 5. Offline optimization verification

Stages 1–5 have been locally verified. Stage 6 adds synthetic batch-size coverage (1/10/50 nodes across all three adapter formats), a failed-startup child-reaping assertion, and local fake-proxy HTTP-status failure tests for both download and upload. The focused Stage 6 tests have passed locally; the full formatting/test/Clippy/release verification batch remains pending. Real-world testing is user-run and documented in `docs/BENCHMARK_REAL_WORLD_VALIDATION.md`; ordinary automated tests remain offline.

## 5. Progress and cancellation

The CLI must never remain silent during a long benchmark. Print the run ID, node ID/name, core, current metric, sample index, and stage transitions. For downloads, report received bytes and current/overall progress at a throttled interval (for example, no more often than every 200 ms) to avoid excessive terminal output. Print a final result or safe failure reason for every sample.

Ctrl-C must be cooperative but prompt:
1. The signal handler only sets an atomic cancellation flag.
2. The orchestration loop observes the flag while a request is active, not only between requests.
3. On cancellation, stop the active managed core to break its loopback proxy connection, allow the measurement worker to exit, then wait for and reap the child.
4. Persist completed samples and explicit cancelled outcomes for remaining scheduled samples; finalize the run as cancelled.
5. Never leave a core process or temporary config behind.

The synchronous HTTP client must not make cancellation wait for the full global request timeout. Use a worker/coordination design that lets the orchestration thread stop the core when cancellation is requested. Keep the configured timeout as a final bound for network operations.

## 6. Proxy process isolation

All three cores expose a temporary HTTP inbound bound only to `127.0.0.1` on an ephemeral port. The generated config routes requests to the selected node's proxy outbound and is validated with the exact installed core before startup.

Startup commands:
- sing-box: `sing-box run -c CONFIG`.
- Xray: `xray run -c CONFIG`.
- Mihomo: `mihomo -f CONFIG`.

Write secret-bearing generated configs to private temporary files (0600 on Unix). Start the core directly without a shell; capture both child stdout and stderr in one private temporary log (0600 on Unix), because the three cores do not necessarily emit diagnostics to the same stream. Never print raw log lines; surface only allowlisted diagnostic categories. Native validation output from sing-box, Xray, and Mihomo is reduced to safe categories (for example, an unrecognized field, invalid inbound/outbound, TLS/REALITY rejection, or parse failure). Distinguish adapter/native-config rejection (invalid) from validator execution failure, process spawn failure, and listener-readiness timeout (unavailable/timeout). Remove temporary logs after the attempt. Probe readiness with a bounded timeout. The HTTP client must use an explicit proxy URL for the loopback listener and must not inherit `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY`.

The process guard owns the child and config. Every normal error, timeout, and cancellation path stops and waits for the child and removes the config. Benchmarking never changes system proxy settings, DNS, routes, firewall rules, interfaces, or TUN state.

## 7. Compatibility and outcomes

Before starting a core:
1. Load node data and close the database.
2. Evaluate adapter compatibility.
3. Confirm the managed core exists and capture its version.
4. Generate and native-validate the loopback benchmark config.
5. Start the core and probe readiness.

TCP ping is independent of core compatibility. An unsupported or invalid node/core pair must not start a core; its real-ping/download/upload metrics receive explicit preflight outcomes. Missing selected cores are unavailable, not silently skipped.

Keep distinct outcomes for success, unreachable, unsupported, invalid, timeout, unavailable, and cancelled. Never store a numeric value for a failed sample. Store the direct TCP metric under a reserved `direct` target rather than pretending it belongs to a proxy core; the run scope must explicitly include that target.

For the full benchmark selection, latency is the gate for throughput: run three real-ping samples first. If at least one succeeds, continue with download and upload. If all three fail, record download and upload as unavailable with the `latency_gate` reason and send no transfer requests. Metric-only modes remain independent and run only the selected metric. Unsupported/invalid compatibility and core preflight failures skip all metrics for that node/core pair.

**Current implementation:** scheduling is node-first and starts one temporary core process per supported node/core pair. **Target implementation:** process one core at a time but batch multiple compatible nodes into one core process, then run bounded-concurrent latency probes and conservative sequential throughput transfers. The staged design, Throne latency reference, v2rayN throughput reference, acceptance criteria, and offline-only test policy are specified in `docs/BENCHMARK_OPTIMIZATION_PLAN.md`. The service now uses multi-node adapter configs and one managed process per core batch, with bounded concurrent latency/TCP probes. Stages 4–5 add exact throughput accounting, per-run timeout/concurrency metadata, shared run IDs for selected node sets, and explicit cancellation outcomes; local verification is pending.

## 8. Persistence and crash recovery

Use the existing redb benchmark run/sample tables. A run records:
- Run ID, status, timestamps, selected node IDs, and selected targets (including the reserved `direct` target).
- Methodology version and effective endpoint/payload/timeout settings.
- Installed core versions and a safe final summary.

A sample records node, target, optional core version, metric, sample index, status, optional value/unit, safe failure category/reason, timestamp, and elapsed duration.

Persist the run before testing. Keep redb closed while any core process or measurement request is active. Flush completed samples after the relevant child exits; direct TCP samples can be persisted without starting a core. On handled cancellation, stop the child and flush completed/cancelled samples. On uncatchable termination, the next invocation marks stale running records interrupted; only the active unflushed batch may be lost.

## 9. Failure isolation and safety

- One node/target failure does not stop unrelated tests.
- One metric failure does not erase other metrics.
- One core failure does not prevent later selected cores from being tested.
- Credentials, raw URLs with secrets, response bodies, generated configs, raw core log lines, and raw HTTP-library diagnostics never appear in progress output or errors. HTTP request failures and response-body failures are classified separately: connection failures before response headers are distinguished from timeouts, proxy-tunnel failures, TLS failures, HTTP status responses, protocol failures, truncated response bodies, and other read failures. A reset after response headers is an incomplete exchange, not an unreachable endpoint. HTTP status codes may be shown, but raw transport details are withheld. During a benchmark, Proxyctl may inspect the selected core's private stdout/stderr log and print a recognized runtime category (for example, a rejected WebSocket handshake, TLS verification failure, DNS failure, or remote connection reset). Raw log lines and endpoint details are never printed.
- Local listeners bind only to loopback.
- Temporary configs are private and removed on every handled exit path.
- Only the explicit `test` command starts a managed core.
- Direct TCP ping opens only an outbound TCP connection to the node endpoint; it does not alter networking state.

## 10. Implementation sequence

1. **Complete:** typed run/sample records, redb schema version 2, persistence, median/throughput helpers, and stale-run recovery.
2. **Complete:** per-core loopback benchmark configs, native config validation, and managed process lifecycle.
3. **In progress:** replace provider-specific Cloudflare download/latency assumptions with v2rayN-style real-ping and download URL semantics; keep upload separately configurable.
4. **In progress:** add direct TCP ping as a distinct metric/target.
5. **In progress:** add live metric/sample/download progress and cancellation that stops the active core while a request is in flight.
6. Add service-level orchestration tests for normal completion, per-metric failure, Ctrl-C during each metric, child cleanup, and sample persistence.
7. **Complete:** the expanded native config matrix and real single-node benchmark smoke tests passed. Metric-specific sorting and latest/history/per-core comparison reports are implemented; pruning remains the next feature stage.

## 11. Metric-specific sorting and comparison

Sorting is independent for each metric. Real HTTP ping, direct TCP ping, download, and upload are separate measurements:

~~~sh
proxyctl list --sort ping
proxyctl list --sort download
proxyctl list --sort upload

proxyctl list --sort ping --core xray
proxyctl list --sort download --core sing-box
proxyctl list --sort upload --core mihomo

proxyctl list --sort tcp-ping
~~~

For each node/core pair, use that pair's latest completed benchmark run and calculate the median from successful samples in that run. A newer completed run supersedes an older result even if the newer run has no successful samples; never fall back to stale measurements. Interrupted, cancelled, and running records are ignored.

Cross-core comparisons take the median of the available per-core medians, giving every core with a successful result equal weight. They do not select only the fastest core. Core-specific sorting uses only the selected core's latest completed run. Direct TCP ping uses the reserved `direct` target and is never combined with real ping or proxy-core results.

Ping metrics sort ascending; download and upload sort descending. Nodes without a successful comparable measurement remain at the bottom as unmeasured, never as zero. Unsupported core outcomes do not contribute a value. Sorting is read-only and does not start cores or change network settings.

Sources:
- v2rayN implementation: https://github.com/2dust/v2rayN
- v2rayN's configurable real-ping and download defaults are in `ServiceLib/Global.cs`; TCPing, real ping, and download orchestration are in `ServiceLib/Services/SpeedtestService.cs` and `ServiceLib/Handler/ConnectionHandler.cs`.
- LibreSpeed endpoint and server-list contract: https://github.com/librespeed/speedtest/blob/master/doc.md
- LibreSpeed public service privacy disclosure: https://librespeed.org/

Keep this document and `docs/PLAN.md` synchronized as implementation evidence changes.


## 12. Benchmark reports and history

The report command is a read-only view over the persisted run and sample tables. It never starts a core or performs a network measurement.

~~~sh
# Latest run for each active node
proxyctl report

# Latest run for one node
proxyctl report --node 18

# All runs, newest first; includes completed, cancelled, interrupted, and running records
proxyctl report --history
proxyctl report --node 18 --history

# Per-core comparison using the latest completed run for each node/core pair
proxyctl report --compare
proxyctl report --compare --node 18
proxyctl report --compare --core xray
proxyctl report --compare --node 18 --core mihomo
~~~

Latest mode selects the most recent run containing each selected node, regardless of lifecycle status, so an interrupted or cancelled latest run is visible rather than silently replaced by an older run. History mode shows the retained matching runs newest first. Automatic retention keeps at most the three newest runs independently for each node/target pair; older samples for that pair are removed, and run metadata is removed when no retained target samples remain.

Comparison mode is intentionally different: it selects the latest **completed** run independently for each node/core pair. A newer completed run supersedes an older one even if it has no successful samples; comparison never falls back to stale measurements. Cancelled, interrupted, and running runs remain visible in history but do not replace the latest completed comparison. Direct TCP ping is shown as its own `direct` row and is not attributed to a proxy core.

Each metric summary reports:
- The median of successful samples only, when at least one succeeded.
- The successful count out of the three scheduled samples.
- Failure counts by outcome (for example, timeout or unreachable).
- The number of samples not run when a run ended before all three attempts.
- A preflight outcome such as unsupported, invalid, or unavailable when the core was not tested.

A median based on one or two successful samples is explicitly labelled partial. Three successes are labelled complete. No failed or missing sample is represented as zero. The report does not infer a failure for a sample that was never attempted.


## 13. Configurable CLI result tables

`proxyctl show NODE...` and all `proxyctl report` modes render persisted benchmark results with the same configurable table renderer. The active profile defaults to compact. Compact shows node, core, real HTTP latency, download, and upload. Normal adds server, protocol, and outcome status. Full adds node metadata, core version, direct TCP ping, sample/failure counts, run ID, and test timestamp. The profiles are independently customizable through `proxyctl config display add-field` and `remove-field`; the active profile is selected with `proxyctl config display profile`. Latest reports render one row per node/core, history renders one row per node/core/run (including running, cancelled, and interrupted runs), and comparison renders one row per node/core using the latest completed run. `--verbose` expands core version metadata but does not change the profile's columns. Profile configuration is private, persisted separately from the database, and does not contain node credentials.

Metric outcomes must remain semantically distinct:
- `not-run`: no sample was attempted and there is no preflight outcome.
- `unavailable`: a preflight or runtime availability check explicitly says the selected core/target could not be used.
- `unsupported` and `invalid`: adapter compatibility outcomes, not network failures.
- `timeout`, `unreachable`, and `cancelled`: attempted measurements with their own outcomes.

Use the Rust `tabled` crate for terminal table layout rather than hand-calculated column widths. The table renderer is presentation-only; report aggregation and persisted benchmark records remain in the service/domain layers. Sensitive source URLs, credentials, fingerprints, and internal database IDs are not display fields. `show --details` renders a separate connection-metadata table (protocol, server, port, name, status, masked identity/secret presence, and option keys with values hidden); it does not reuse the benchmark profile columns.


## 14. Automatic history retention

After each benchmark run is finalized, Proxyctl retains at most the three newest runs independently for every node/target pair (including the separate direct target). This includes completed, interrupted, and cancelled runs; a running run is never pruned. For older multi-node or multi-core runs, samples are removed only for the expired node/target pair. Shared run metadata remains while another target still has retained samples, and reports omit target rows whose samples have expired. This keeps per-target history bounded without deleting another node's or core's recent results.


## 15. Benchmark performance optimization roadmap

The per-node/core process bottleneck has been replaced in the current implementation by **core-batch scheduling**: one managed core process at a time, with multiple compatible node outbounds and isolated loopback inbounds in its temporary config. Each node is native-validated independently before it is admitted to the batch; startup readiness requires every batch listener. Real HTTP latency and direct TCP probes run in bounded groups of at most three workers, with three samples per node. Latency timeout and concurrency are stored with each run and exposed as CLI settings. Throughput transfers remain sequential; downloads require the exact target byte count, expose throttled byte/rate progress, and classify early EOF as incomplete. Upload timing includes request-body transmission and successful response consumption. Multiple selected node IDs now share one run record, cancellation fills scheduled-but-unattempted samples, and run summaries persist sample counts. Stages 2–5 are implemented and await local verification.

The user's comparative observations guide optimization priorities: Throne is the latency reference; v2rayN is the download/upload reference. This does not justify copying either project's exact sample policy or assuming their endpoint semantics are interchangeable. Proxyctl retains three samples, medians, explicit outcomes, and the full-mode latency gate.

Implementation is staged: batch adapter config generation; batch process/readiness lifecycle; bounded-concurrent latency and direct TCP; accurate sequential throughput and progress; orchestration/persistence/report integration; offline performance and fault-injection tests; separately approved real-world comparison. See `docs/BENCHMARK_OPTIMIZATION_PLAN.md` for details and acceptance criteria.

No public endpoint benchmarking, real proxy-core startup, system networking mutation, or TUN activation is part of ordinary tests. Real-world comparative validation requires separate explicit approval.
