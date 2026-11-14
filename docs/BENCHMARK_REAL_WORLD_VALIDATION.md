# Real-world benchmark validation runbook

> Status: prepared; user-run validation only
> Scope: real URLs and explicitly selected stored proxy nodes
> Safety: this document does not authorize automatic tests, core activation, TUN, or system network changes by Proxyctl

## 1. Before network testing

Complete the offline verification batch first:

```sh
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

The ordinary test suite must remain offline. These commands must not launch managed proxy cores or contact public measurement endpoints. Record the output and resolve failures before continuing.

Confirm the intended nodes and managed core installations:

```sh
proxyctl list
proxyctl cores
proxyctl config
```

Use only Proxyctl-managed core binaries. Do not start Throne, v2rayN, or V2rayA at the same time as a Proxyctl-managed core during the comparison. Do not use TUN mode; TUN activation remains disabled.

## 2. Endpoint selection

Proxyctl's current defaults are:

- Real latency: `https://www.google.com/generate_204`
- Download: `https://cachefly.cachefly.net/10mb.test`
- Upload: `https://speed.cloudflare.com/__up`

The default transfer payloads are 1 MiB each (hard maximum 1 MiB), with a 3-second deadline per download/upload request. These defaults contact third-party services and disclose ordinary connection metadata such as source IP and request timing. Use endpoints whose terms and telemetry you accept. A custom upload URL must accept the documented HTTP POST body and return a successful HTTP status. Do not put credentials or secret tokens in command-line URLs; URLs are persisted in benchmark run settings and may be visible in local reports/database backups.

Use the same endpoint URLs, payload sizes, and timeout values for every client in a comparison. Do not assume unrelated speed-test services produce directly comparable results.

## 3. First real-network smoke test

Choose one known-good stored node ID and test it through one installed managed core. Start with latency-only:

```sh
proxyctl test --node NODE_ID --core sing-box --latency-only \
  --latency-url https://www.google.com/generate_204 \
  --latency-timeout-secs 5 --concurrency 1
```

Replace `NODE_ID` with the actual stored node number. Repeat for Xray and Mihomo only if those managed cores are installed. Each invocation starts only the selected Proxyctl-managed core, uses a loopback-only benchmark listener, and stops it before returning. It does not change system proxy, DNS, routes, firewall, or TUN.

If latency succeeds, run one full test for that node/core:

```sh
proxyctl test --node NODE_ID --core sing-box \
  --latency-url https://www.google.com/generate_204 \
  --download-url https://cachefly.cachefly.net/10mb.test \
  --upload-url https://speed.cloudflare.com/__up \
  --download-max-bytes 1048576 --upload-bytes 1048576 \
  --latency-timeout-secs 5 --request-timeout-secs 3 --concurrency 1
```

Use the same settings when repeating with other cores. In full mode, download and upload are skipped when all three real-latency samples fail. Metric-only download/upload modes intentionally bypass that gate.

## 4. Multi-node and comparative run

After the single-node smoke test behaves correctly, select a small representative set of node IDs and run:

```sh
proxyctl test --node NODE_ID_1 NODE_ID_2 --all-cores \
  --latency-url https://www.google.com/generate_204 \
  --download-url https://cachefly.cachefly.net/10mb.test \
  --upload-url https://speed.cloudflare.com/__up \
  --download-max-bytes 1048576 --upload-bytes 1048576 \
  --latency-timeout-secs 5 --request-timeout-secs 3 --concurrency 3
```

For a fair comparison with Throne or v2rayN:

1. Use the same imported node links and endpoint URLs wherever the other client permits.
2. Keep payload sizes and timeout limits equivalent.
3. Run one client/core at a time; ensure no duplicate core or competing test is active.
4. Alternate client order between repetitions (for example Proxyctl → Throne → v2rayN, then v2rayN → Proxyctl → Throne).
5. Repeat at different times if possible; record network conditions and endpoint.
6. Compare three-sample medians and inspect individual sample statuses. Do not compare a failed or latency-gated throughput result as a measured zero.
7. Do not change Proxyctl defaults based on a single run.

## 5. Inspect and preserve results

```sh
proxyctl report --history
proxyctl report --compare
proxyctl report --verbose
```

Proxyctl retains at most the latest three finalized histories per node/core target. Export or record results externally before additional runs if older comparison data must be preserved.

## 6. Stop conditions

Stop testing and retain the report if any of the following occurs:

- a managed core does not stop cleanly;
- system connectivity is disrupted;
- an unexpected system proxy, DNS, route, firewall, or TUN change is observed;
- the benchmark repeatedly times out or produces incomplete transfers;
- the endpoint rejects the request or its behavior is unclear.

Do not attempt to repair system networking by running more benchmark commands. The benchmark is not intended to mutate system networking.
