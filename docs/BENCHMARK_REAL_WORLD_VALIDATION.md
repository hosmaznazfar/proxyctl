# Real-world benchmark validation runbook

> Status: user-run validation in progress
> Scope: real URLs and explicitly selected stored proxy nodes
> Safety: this document does not authorize automatic tests, core activation, TUN, or system network changes by Proxyctl

## 1. Offline verification gate

Before comparing real network performance, run:

```fish
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

The ordinary test suite must remain offline. Do not launch managed proxy cores or contact public measurement endpoints during these checks.

Confirm the intended nodes and managed core installations:

```fish
proxyctl list
proxyctl cores
proxyctl config
```

Use only Proxyctl-managed core binaries. Do not start Throne, v2rayN, or V2rayA at the same time as a Proxyctl-managed core during a comparison. Do not use TUN mode; TUN activation remains disabled.

## 2. Endpoint selection and measurement profiles

Current defaults:

- Real latency: `https://www.google.com/generate_204`
- Download: `https://cachefly.cachefly.net/10mb.test`
- Upload: `https://speed.cloudflare.com/__up`

The selected endpoint URLs are persisted in benchmark settings. They may disclose ordinary connection metadata such as source IP and request timing. Use endpoints whose terms and telemetry you accept. Do not put credentials or secret tokens in command-line URLs.

| Setting | Quick (default) | Accurate |
|---|---:|---:|
| Download streams | 1 | 3 concurrent |
| Aggregate download cap | 1 MiB | 8 MiB |
| Download time budget | 5 seconds | 20 seconds |
| Warm-up | None | Best-effort 64 KiB, excluded from timing |
| Upload | 1 MiB, sequential | Same |

Download cap can be overridden with `--download-max-bytes` (hard maximum 32 MiB). Upload can be overridden with `--upload-bytes` (hard maximum 1 MiB). The upload measurement requires the complete synthetic request body and a successful HTTP response; partial uploads are not scored. Each metric retains three samples, and reports use successful samples only. A useful partial download is explicitly marked and is never presented as a complete transfer.

Use the same endpoint URLs, payload sizes, profile, and timeout values for every client in a comparison. Do not assume unrelated speed-test services produce directly comparable results. A custom upload URL must accept the documented HTTP POST body and return a successful HTTP status.

## 3. Verify the profiles on a known-good node

First verify Quick through each compatible core:

```fish
proxyctl test --node NODE_ID --all-cores --profile quick
```

Then verify Accurate download independently of the latency gate:

```fish
proxyctl test --node NODE_ID --all-cores --profile accurate --download-only
```

Metric-only download/upload modes intentionally bypass the full-mode latency gate. This is useful when validating throughput profile behavior separately from latency reliability. Start with one known-good node and avoid running other proxy clients or speed tests concurrently.

For a focused per-core check:

```fish
proxyctl test --node NODE_ID --core xray --download-only --profile accurate
```

After download profile verification, test upload independently:

```fish
proxyctl test --node NODE_ID --all-cores --upload-only
```

Upload settings are currently the same for Quick and Accurate. Intermittent upload failures should be retained as failures; do not treat them as zero throughput or relax the success criteria.

In full mode, throughput is gated on at least one successful real-latency sample for that node/core pair. If all latency samples fail, use the metric-only commands above to isolate throughput.

## 4. Same-node comparison with Throne and v2rayN

Choose a small representative set of nodes that are confirmed working in each client. Use the same imported link, measurement endpoint, profile-equivalent payload size, and timeout limits wherever each client allows them.

1. Run only one client/core at a time. Ensure no duplicate core or competing speed test is active.
2. Use equivalent protocol/inbound settings where possible; Proxyctl defaults to a local SOCKS5 measurement inbound. Its HTTP alternative is selected with `--proxy-type http`.
3. Alternate client order between repetitions (for example Proxyctl → Throne → v2rayN, then v2rayN → Proxyctl → Throne).
4. Repeat at different times if possible; record network conditions and endpoint.
5. Compare three-sample medians and inspect individual sample statuses and transferred bytes. Do not compare a failed or latency-gated throughput result as a measured zero.
6. Do not change Proxyctl defaults based on a single run.

Example Proxyctl commands:

```fish
# Quick, all cores
proxyctl test --node NODE_ID --all-cores --profile quick

# Accurate download, all cores
proxyctl test --node NODE_ID --all-cores --profile accurate --download-only

# Upload-only, all cores
proxyctl test --node NODE_ID --all-cores --upload-only
```

## 5. Inspect and preserve results

```fish
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
