# Core Adapter Architecture

Each supported core has an explicit adapter implementation:

- `src/cores/adapters/sing_box.rs`
- `src/cores/adapters/xray.rs`
- `src/cores/adapters/mihomo.rs`

The shared `CoreAdapter` trait is a contract, not a place for core-specific configuration switches. Every adapter implements:

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
- Generated TUN config must keep automatic route, DNS, and firewall integration disabled until the separately gated TUN lifecycle owns those resources.
- A native option that cannot be represented must be reported as unsupported; it must not be silently discarded.
- Secrets must not appear in diagnostics or persisted runtime metadata.

## Native TUN attachment contracts

The adapter reports how its core obtains the TUN device. This is separate from whether the complete privileged runtime lifecycle is enabled.

| Core | Adapter attachment mode | Generated TUN behavior | Native supervisor |
|---|---|---|---|
| sing-box | `NativeDeviceCreation` | Adds a named TUN inbound (`tun-proxyctl`); disables automatic route and DNS integration; marks the proxy outbound. | Enabled on Linux |
| Mihomo | `NativeDeviceCreation` | Enables the named TUN device (`tun-proxyctl`); disables auto-route, auto-redirect, and DNS integration; marks proxy outbound traffic. | Enabled on Linux |
| Xray | `ExternalDescriptorEnvironment` (`XRAY_TUN_FD`) | Generates an Xray native `tun` inbound with the configured interface name, addresses, MTU, sniffing, and marked proxy outbound. | Deliberately disabled pending reconciliation |

### Xray is not yet enabled

Xray currently has two different contracts that must not be conflated:

- Its adapter generates a native Xray `tun` inbound with a named interface.
- Its attachment metadata and legacy `xray_launcher` describe an externally supplied descriptor, including a separate systemd/helper-based launch path.

The new single-executable native supervisor accepts only `NativeDeviceCreation` and currently enables sing-box and Mihomo. Do not change Xray's attachment mode or enable it in that supervisor until the adapter, config, process launch, device ownership, readiness, stop, and recovery paths all agree on one model.

The legacy descriptor/systemd launcher is compatibility code, not the architecture for new native sessions. New TUN sessions must continue to use one installed `proxyctl` executable, TUN-only sudo elevation, and no separately installed helper package or persistent service.

### Ownership rules

- `NativeDeviceCreation` means the selected core creates and owns its named TUN device. Proxyctl's privileged supervisor still owns routes, policy rules, session records, readiness, monitoring, and recovery.
- An externally supplied descriptor means another component creates and owns the TUN device and passes an already-open file descriptor to the core. It is not interchangeable with native device creation.
- Never combine a broker-created exclusive descriptor with a core configuration that independently creates a persistent named device.
- Never enable activation from adapter metadata alone. The process attachment, end-to-end readiness, session commit, monitor, stop, and journaled recovery contracts must all be complete.

## Test layers

Core-specific config contract tests live alongside each adapter and assert that adapter-owned native fields and safety defaults remain stable. Shared adapter tests verify cross-core invariants. Benchmark batch tests cover one, ten, and fifty targets and ensure listener-to-outbound routing remains one-to-one.

Run the offline adapter checks locally:

```fish
cargo fmt --all -- --check
cargo test cores::adapters
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo build --release --locked
```

These checks do not start a real proxy core or change system networking.
