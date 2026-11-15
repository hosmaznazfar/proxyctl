# Core Adapter Architecture

Each supported core has an explicit adapter implementation:

- `src/cores/adapters/sing_box.rs`
- `src/cores/adapters/xray.rs`
- `src/cores/adapters/mihomo.rs`

The shared `CoreAdapter` trait is a contract, not a place for core-specific configuration switches. Every adapter must implement:

- semantic compatibility evaluation;
- single-node native config generation;
- benchmark batch config generation;
- loopback-only interactive activation config;
- native TUN config generation (generation only; runtime activation remains separately gated);
- loopback-only single-node benchmark config;
- native config validation.

## Where core-specific options belong

Put native field names, defaults, enum spellings, and feature-specific config choices in that core's adapter. Do not add a `match CoreId` to shared config-generation code to handle a new core.

Shared code may own genuinely common behavior such as parsing the adapter's generated JSON document, checking duplicate benchmark IDs/ports, serializing JSON, and common semantic validation. It must not translate a feature into a core's native schema.

For a new core:

1. Add its `CoreId` and installer/catalog metadata.
2. Implement the complete `CoreAdapter` contract in a dedicated adapter.
3. Add its declarative protocol/transport capability profile.
4. Add core-owned tests for native outbound options, activation listener, benchmark listener, TUN safety flags, and batch routing.
5. Add native validation fixtures/commands for supported versions.
6. Add it to the cross-core conformance matrix only after its core-specific tests pass.

## Configuration safety invariants

- Interactive and benchmark listeners bind only to `127.0.0.1`.
- Interactive activation exposes the intended local mixed SOCKS5/HTTP endpoint.
- Benchmark configs expose only the configured local listener and route each batch listener to its matching outbound.
- Generated TUN config must keep automatic route, DNS, and firewall integration disabled until the separately gated TUN lifecycle is implemented and approved.
- A native option that cannot be represented must be reported as unsupported; it must not be silently discarded.
- Secrets must not appear in diagnostics or persisted runtime metadata.

## Test layers

Core-specific config contract tests live alongside each adapter and assert that adapter-owned native fields and safety defaults remain stable. Shared adapter tests verify cross-core invariants. Benchmark batch tests cover one, ten, and fifty targets and ensure listener-to-outbound routing remains one-to-one.

Run the offline adapter checks with:

```fish
cargo fmt --all -- --check
cargo test cores::adapters
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

These checks do not start a real proxy core or change system networking.
