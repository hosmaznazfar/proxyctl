# Benchmark performance and measurement optimization plan

> Status: Stages 1–3 implementation committed to main; local verification pending
> Last updated: 2026-11-14
> Scope: benchmark execution, measurement quality, and progress/cancellation only
> Safety: offline implementation and synthetic tests first; no real-network validation without separate approval

## 1. Goals

Proxyctl's original benchmark was too slow for large node sets because it iterated node-first, started a separate managed core for every node/core pair, and performed all probes sequentially. Stages 2 and 3 now change the scheduler to core-first batches, with one process per core batch, isolated loopback listeners, bounded-concurrent latency/TCP probes, and sequential throughput transfers. Local verification of this implementation is still pending.

The optimization must improve elapsed time without sacrificing trustworthy measurements, low memory use, safe process ownership, or the existing persisted history/report semantics.

The user's comparative observations are explicit product requirements:

- **Throne is the latency reference:** prioritize low-overhead HTTP latency probes, prompt tunnel readiness, bounded concurrent probing, and short configurable latency timeouts. Do not copy a fastest-of-two policy; Proxyctl retains three samples and reports their median.
- **v2rayN is the throughput reference:** prioritize representative and repeatable download/upload measurements, accurate transfer accounting, useful progress, and a bounded timeout. Do not trade throughput accuracy for aggressive concurrency.
- These are measurement-quality targets based on the user's own comparisons, not a claim that one project's implementation is universally superior.

## 2. Non-negotiable constraints

1. Run only one Proxyctl-managed core process at a time. Do not run sing-box, Xray, and Mihomo simultaneously.
2. Never use PATH/system/V2rayN-managed binaries. Use only the selected Proxyctl-managed executable.
3. Never change system proxy settings, DNS, routes, firewall, TUN, or other network state.
4. Keep benchmark inbounds loopback-only and ephemeral.
5. Compatibility outcomes remain per node/core. Unsupported or Invalid means skip that node/core entirely; it must not poison a valid peer in a batch.
6. In full mode, run three real-latency samples first. Run download/upload only if at least one latency sample succeeds. If all three fail, mark throughput skipped with `latency_gate`; do not send transfer requests.
7. Metric-only modes remain independent and continue to run only the explicitly selected metric.
8. Keep three samples per metric and use successful-sample medians. Never represent failures as zero.
9. Keep redb closed during process execution and network I/O. Persist completed batch results after the managed child has stopped.
10. Cancellation must stop and reap the exact managed child, preserve completed samples, and record unfinished work as cancelled/interrupted.
11. Do not expose credentials, raw URLs containing secrets, response bodies, generated configs, raw core logs, or raw transport diagnostics.
12. No TUN activation or real-network validation is part of these changes.

## 3. Target execution architecture

### 3.1 Core-first batches, not concurrent cores

Change scheduling from one process per node/core pair to one process per selected core batch:

1. Resolve the selected node set and the installed selected cores.
2. Evaluate compatibility independently for every node/core pair.
3. For each core in deterministic order, create one temporary batch configuration containing only nodes supported by that core.
4. Give every node a unique loopback-only HTTP inbound (or another adapter-supported isolated local endpoint) mapped to its own outbound.
5. Native-validate the complete configuration before starting the core.
6. Start that one core, wait for all required local inbounds to be ready, run its batch, stop and reap it, then move to the next core.
7. Persist the batch's completed samples only after the process is stopped.

A malformed or unsupported node must be excluded before configuration generation; it must not invalidate other supported nodes. If native validation rejects a combined configuration, isolate the failure with a deterministic divide-and-conquer or per-node validation fallback. Never silently mark all nodes invalid because one node broke a batch.

Core-first batching is intended to remove repeated process startup. It is not permission to run cores concurrently. If an adapter cannot safely represent multiple independent outbounds/inbounds, retain a safe per-node fallback for that core and report the fallback explicitly.

### 3.2 Latency: Throne-inspired bounded concurrency

- Probe independent node inbounds concurrently with a configurable, conservative limit. Initial default target: 3 concurrent nodes; expose a CLI setting only after memory and socket behavior are measured.
- Keep three real HTTP latency samples per node.
- Reuse an HTTP client/connection only where doing so does not hide cold-connect behavior or mix traffic between nodes. Define and test connection reuse explicitly.
- Use a small response endpoint, disable redirects for consistent semantics, bound response-body draining, and measure until response headers (or a clearly documented response-completion point) are received.
- Wait for each node's tunnel/inbound readiness before its first probe; do not use arbitrary long fixed sleeps as readiness checks.
- Give latency its own shorter configurable timeout. Proposed initial default: 5 seconds, subject to local offline tests and later user-approved real-world evaluation.
- One node's timeout/failure must not block unrelated nodes.
- Report per-node progress and retain all three samples; do not use a fastest-of-two shortcut.

### 3.3 Throughput: v2rayN-inspired accuracy, conservative execution

Download and upload are accuracy-sensitive and must not compete with one another by default:

- Only nodes that passed the full-mode latency gate are eligible.
- Run one throughput transfer at a time by default, even while the batch core remains running.
- Use explicit endpoint configuration and preserve user overrides.
- Download: stream and count actual bytes; cap bytes; validate response status; distinguish completion, early EOF, timeout, and read failure; calculate rate from transferred bytes and monotonic elapsed time.
- Upload: use a bounded synthetic in-memory payload; measure the completed request/response exchange; require a successful server response; never send user files or credentials; bound response-body consumption.
- Keep upload and download sizes independently configurable.
- Emit throttled progress for active transfers without flooding the terminal.
- Do not add hidden retries. Each of the three samples is an independent recorded attempt.
- Record endpoint, payload size, timeout, methodology version, duration, and transferred bytes needed to interpret the result.
- Evaluate endpoint behavior and server-side semantics before changing defaults. The current Cloudflare upload endpoint is not automatically assumed to be equivalent to v2rayN's throughput path.

### 3.4 Direct TCP ping

- Keep direct TCP ping separate from real HTTP latency.
- Execute direct TCP probes with bounded concurrency across selected nodes.
- Retain three samples, bounded DNS/connect timeouts, and the existing direct target identity.
- Do not require a proxy core or affect the latency gate.

## 4. Async and concurrency decision

The user asked whether benchmarking should run asynchronously. The target behavior is concurrent, cancellable I/O, but adding a heavyweight async runtime is not an end in itself.

Before selecting Tokio/reqwest or a bounded synchronous worker pool, compare:
- dependency and binary-size impact;
- cancellation behavior for in-flight HTTP requests;
- connection-pool reuse and per-node isolation;
- bounded task/worker count;
- interaction with child-process shutdown and redb's closed-during-I/O rule;
- testability with local fake proxies.

Choose one concurrency model and use it consistently. Do not mix unbounded tasks with per-node threads. The implementation must expose a single cancellation path and enforce a hard concurrency limit. If the existing HTTP stack cannot cancel promptly, replace or wrap it rather than claiming that a detached blocking worker is cancelled.

## 5. CLI and configuration direction

Keep existing commands and metric-only semantics. Proposed additions, subject to CLI review:

- `--latency-timeout` independent of throughput timeout.
- `--throughput-timeout` for download/upload.
- `--concurrency N` for latency and direct TCP probes, with a conservative default and upper bound.
- Optional `--sequential` only if the default bounded concurrency proves problematic; avoid unnecessary flags if a persistent config is more appropriate.

Do not change existing download/upload byte defaults without comparative measurements. Any new settings must be persisted in run metadata so historical results remain interpretable.

## 6. Implementation stages and acceptance criteria

Each stage is a separate small implementation batch. Update this plan, `docs/BENCHMARK_DESIGN.md`, and `docs/PLAN.md` as relevant. After each batch, provide local verification commands; do not claim success until the user supplies output.

### Stage 0 — planning and baseline inventory
- Document current scheduling, reference behaviors, target architecture, safety constraints, and staged tests.
- Confirm current CLI dispatch, run-ID scope, adapter config boundaries, and process lifecycle.
- No runtime behavior changes.

Acceptance: planning docs agree; no claim that selected multi-node CLI calls share one run unless code actually does.

### Stage 1 — batch configuration foundation (implemented; user reported all checks passing)
- Added an object-safe adapter batch-config contract and core-specific multi-node generators for sing-box, Xray, and Mihomo. Each target has a unique outbound and loopback inbound; sing-box/Xray routing rules and Mihomo listener-to-proxy mappings keep traffic isolated. Follow-up fixes corrected the inline test-module registration, adapter test imports, unused mutability, and rustfmt layout.
- Added offline structural tests for all three core formats, distinct routing, duplicate IDs/ports, and unsupported-node rejection.
- The benchmark service does not use this generator yet; process batching is a later stage.
- Model each node's compatibility and local inbound/outbound mapping independently.
- Add native-validation fixtures for mixed supported/unsupported nodes and multiple valid nodes.
- Ensure one invalid node can be isolated without rejecting the entire batch.
- Keep a per-node fallback where a core cannot safely batch.

Acceptance: unit and native config tests prove unique loopback ports, correct node-to-outbound routing, no cross-node leakage, and safe failure isolation. No live core startup is required for ordinary tests.

### Stage 2 — core-batch process lifecycle (implementation committed; awaiting local verification)
- Start one selected core for a batch, not one process per node/core pair.
- Validate every node's single-node native config independently before admitting it to the batch.
- Readiness confirms every expected local listener; timeout diagnostics identify missing ports and no measurements start until all are ready.
- Preserve private config/log permissions, exact managed executable checks, bounded startup, and guaranteed stop/reap.
- Process one core batch completely before starting the next core.
- Keep one-node `ManagedCoreProcess::start` as a wrapper over the batch lifecycle.

Acceptance: fake-child/fake-listener integration tests cover startup, partial readiness, cancellation, crash, cleanup, and sequential core batches. Peak active managed-core count is always one. The multi-listener readiness unit test is added; broader batch process lifecycle tests remain to be verified.

### Stage 3 — concurrent latency and direct TCP (implementation committed; awaiting local verification)
- Add bounded concurrency with a hard maximum of 3 workers.
- Preserve three samples and median semantics.
- Use an independent five-second latency request deadline; throughput retains the configured request timeout.
- On cancellation, stop the batch core to interrupt in-flight proxy requests and join workers before continuing cleanup.
- Make direct TCP probes bounded-concurrent and separate.

Acceptance: the hard worker cap has an offline unit test; deterministic fake-proxy tests must still verify all three samples, failure isolation, prompt timeout/cancellation, and the latency gate. Local test verification remains pending.

### Stage 4 — throughput accuracy and progress
- Rework download/upload execution around accurate byte accounting, monotonic timing, response validation, and bounded response bodies.
- Keep throughput transfers sequential by default.
- Add independent throughput timeout and throttled progress.
- Review default endpoint compatibility and privacy; do not silently change defaults.
- Verify upload success semantics and ensure request-body transmission is included in timing.

Acceptance: local controlled HTTP test servers verify exact byte counts, early EOF, status errors, timeout, upload body size, successful response requirements, rate calculation, progress throttling, and cancellation. No external endpoint is contacted.

### Stage 5 — orchestration, persistence, and reporting integration
- Run the new core-batch scheduler through the existing benchmark service.
- Make selected multi-node runs use one consistent run ID if the CLI currently splits them; preserve per-node/core target identity.
- Keep run/sample retention, latest/history/compare reports, sorting, and pruning semantics correct.
- Store effective concurrency, timeout, endpoint, payload, and methodology settings.
- Preserve metric-only modes and the full-mode latency gate.

Acceptance: service/database tests cover all-active and selected-node batches, all three cores, mixed compatibility, partial failures, retention, interrupted/cancelled histories, and no stale fallback.

### Stage 6 — offline performance and fault-injection tests
- Add synthetic benchmarks for scheduler overhead and batch scaling.
- Compare process starts, elapsed orchestration time, peak child count, and bounded concurrency against the old per-pair baseline.
- Inject failures at config generation, validation, startup, listener readiness, latency, download, upload, persistence, and cancellation.
- No real remote proxy nodes or public speed-test endpoints.

Acceptance: demonstrate fewer core starts (up to one per selected core batch), bounded active requests, no leaked child/listener/config, correct partial persistence, and no system network mutation.

### Stage 7 — separately approved real-world validation
- Only after offline stages pass and the user explicitly approves, compare the same nodes/endpoints across Proxyctl, Throne, and v2rayN under controlled conditions.
- Keep one active core at a time; do not run Proxyctl TUN mode.
- Record environment, endpoint, sample counts, payload sizes, timeout, and test order.
- Repeat tests in alternating order to reduce time-of-day/server-load bias.
- Compare latency medians and throughput medians, not one lucky sample.
- Do not change defaults based on one run.

Acceptance: user reviews results and approves any final default changes.

## 7. Test strategy

All ordinary automated tests must be offline:
- fake adapter configs and native config validation fixtures;
- fake managed child processes and local loopback HTTP servers;
- controlled response delays, byte counts, status codes, truncated bodies, and connection resets;
- concurrency counters and cancellation tokens;
- redb persistence/retention/report regression tests;
- failure injection for every process and transfer boundary.

No test may launch a real proxy core, alter system networking, contact public measurement endpoints, enable system proxy, or touch TUN unless a distinct explicit user approval covers that exact test.

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| One bad node breaks a batch config | Pre-filter compatibility; isolate native validation failures; per-node fallback |
| Combined config routes traffic to the wrong node | Unique inbound/outbound tags and ports; explicit mapping tests for every adapter |
| Batch config consumes too much memory | One core only; bounded node batch size if needed; measure peak RSS |
| Concurrent latency probes distort latency | Conservative bounded concurrency; no throughput overlap; three-sample median |
| Reused connections make latency look artificially fast | Explicit cold/warm methodology and recorded policy |
| Throughput concurrency distorts rates | One transfer at a time by default |
| Cancellation leaves a child or worker behind | One owner for child + workers; cancel requests, stop core, join workers, reap child |
| History mixes different methodologies | Persist methodology version and effective settings; do not compare incompatible versions silently |
| v2rayN/Throne endpoint differences bias comparison | Controlled same-node, same-endpoint, alternating-order comparison |

## 9. Completion definition

The optimization is complete only when all offline stages pass local verification, docs and CLI behavior agree, and the user has separately approved and completed real-world comparative validation. Passing offline tests does not establish that new latency/throughput defaults outperform Throne or v2rayN in the user's network.
