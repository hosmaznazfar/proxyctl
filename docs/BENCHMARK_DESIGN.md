# Benchmark design

> Status: revised methodology approved; implementation in progress
> Last updated: 2026-11-09

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

# Test one node through one selected core
proxyctl test --node 12 --core sing-box

# Override the HTTP measurement endpoints
proxyctl test --node 12 --core sing-box \
  --latency-url https://www.google.com/generate_204 \
  --download-url https://cachefly.cachefly.net/10mb.test \
  --upload-url https://speed.cloudflare.com/__up
```

The all-cores and explicit node/core selectors remain mutually exclusive. The direct TCP test runs once for each selected node. The HTTP tests run once for each supported node/core pair.

The run stores effective endpoint URLs, payload limits, timeout values, and methodology version. The default download sample is 2 MiB even though the static CacheFly object is 10 MB; Proxyctl stops reading once the sample target is reached and closes the response rather than downloading the full object. The upload body remains a bounded 1 MiB synthetic payload. Keep the request timeout finite and configurable. No automatic retries are hidden inside a sample.

## 4. Measurement semantics

### 4.1 Direct TCP ping

Resolve the node hostname and attempt a TCP connection to its configured port. Time from immediately before connection until the connection succeeds. Use a bounded connect timeout and three independent samples. Do not send proxy credentials or application data. This test does not use the selected core and may use the machine's normal DNS resolver; it must not modify DNS configuration.

### 4.2 Real ping through the selected core

Use the explicit loopback HTTP proxy created for the selected core. Send a GET request to the configured real-ping URL and measure until response headers arrive. Accept successful HTTP responses including 204 No Content; do not require a special query parameter or a zero-length response body. Read/discard only a small bounded response body. Three samples are retained.

### 4.3 Download through the selected core

GET the configured download URL exactly as supplied. Do not append provider-specific query parameters. Stream the response body in bounded chunks, count the actual bytes received, and calculate throughput from bytes received and elapsed time. Stop reading once the configured sample byte count is reached, even if the remote object is larger; close the response without downloading the remainder. If the server ends the response earlier, measure the bytes actually received. Emit progress updates while bytes are arriving. The configured count is the target sample size and hard transfer ceiling, not a requirement that every provider return an identical object size.

### 4.4 Upload through the selected core

POST a deterministic in-memory payload containing no user data. Measure until the endpoint returns a successful response. Bound payload and response sizes. Report the upload stage and its completion/failure; do not imply byte-level progress if the HTTP library cannot expose it.

### 4.5 Units and aggregation

- TCP ping and real ping: milliseconds (`ms`).
- Download and upload: bits per second (`bps`).
- Throughput = `transferred_bytes * 8 / elapsed_seconds`.
- Use a monotonic clock.
- Never turn a failed request into zero.
- Keep all individual samples and calculate medians from successful samples only.

A failure in one metric must not erase successful samples from another metric.

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

Write secret-bearing generated configs to private temporary files (0600 on Unix). Start the core directly without a shell; capture child stderr in a private temporary log (0600 on Unix), never print raw log lines, and surface only allowlisted diagnostic categories on startup failure. Remove the log after the attempt. Probe readiness with a bounded timeout. The HTTP client must use an explicit proxy URL for the loopback listener and must not inherit `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY`.

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
- Credentials, raw URLs with secrets, response bodies, generated configs, and raw core log lines never appear in progress output or errors. Startup diagnostics expose only allowlisted safe categories.
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
7. Run the expanded native config matrix and one real single-node smoke test before implementing reports, sorting, or pruning.

Sources:
- v2rayN implementation: https://github.com/2dust/v2rayN
- v2rayN's configurable real-ping and download defaults are in `ServiceLib/Global.cs`; TCPing, real ping, and download orchestration are in `ServiceLib/Services/SpeedtestService.cs` and `ServiceLib/Handler/ConnectionHandler.cs`.
- LibreSpeed endpoint and server-list contract: https://github.com/librespeed/speedtest/blob/master/doc.md
- LibreSpeed public service privacy disclosure: https://librespeed.org/

Keep this document and `docs/PLAN.md` synchronized as implementation evidence changes.
