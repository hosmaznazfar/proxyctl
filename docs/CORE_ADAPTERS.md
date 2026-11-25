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
| Xray | `ExternalDescriptorEnvironment` (`XRAY_TUN_FD`) | Generates a native Xray `tun` inbound with a fixed interface name, gateway addresses, MTU, sniffing, and marked proxy outbound. Linux can either create the device itself or adopt a supplied FD. | Deliberately disabled pending descriptor lifecycle integration |

### Xray descriptor integration is not yet complete

Xray's Linux TUN implementation has two distinct startup paths:

1. Without `XRAY_TUN_FD`, Xray opens `/dev/net/tun`, creates the named interface, configures its MTU and gateway addresses, and owns its link setup/teardown.
2. With `XRAY_TUN_FD`, Xray validates and adopts the supplied TUN descriptor. In this path, Xray does **not** own the interface and its Linux `Start` path does not configure the link, MTU, gateway addresses, or routes. The component that creates the descriptor must own those operations.

This behavior is documented by the [Xray TUN configuration reference](https://xtls.github.io/en/config/inbounds/tun.html) and implemented in [Xray's Linux TUN source](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_linux.go) (`NewTun`, `openFromEnv`, `Start`, and `Close`).

Proxyctl's generated config currently sets a fixed name and gateway addresses, but the supervisor's journaled `apply_native` path creates a persistent named interface and does not retain a descriptor for Xray. Conversely, the existing direct launcher can transfer a descriptor, but no complete single-process supervisor path currently creates, retains, configures, journals, and recovers that descriptor-backed interface. Merely changing Xray's adapter mode or removing its allowlist rejection would therefore be incorrect.

The agreed integration direction is to keep Xray's explicit descriptor contract and move descriptor ownership into the same privileged `proxyctl __tun-supervisor` process:

- create one generation-scoped TUN descriptor inside the supervisor (no separately installed helper or persistent daemon);
- keep the owning descriptor alive for the complete session and pass only a close-on-exec duplicate to Xray through `XRAY_TUN_FD`;
- make Proxyctl, not Xray, own link-up, MTU, gateway-address, route, and policy-rule setup for this FD path;
- extend the write-ahead journal and recovery model to cover the descriptor-owned interface and the case where parent-death termination automatically removes it;
- verify the exact Xray process holds the expected interface descriptor before end-to-end readiness and durable session commit;
- close/release the descriptor only after the exact Xray process has stopped and generation-scoped cleanup is safe.

The current native supervisor enables only sing-box and Mihomo. Keep Xray rejected until all of these ownership, journaling, startup, readiness, stop, and crash-recovery requirements are implemented together.

### Ownership rules

- `NativeDeviceCreation` means the selected core creates and owns its named TUN device. Proxyctl's privileged supervisor still owns routes, policy rules, session records, readiness, monitoring, and recovery.
- `ExternalDescriptorEnvironment` means Proxyctl (or another explicitly designated owner) creates and configures the TUN device, then passes an already-open descriptor to the core. The core does not become the interface's lifecycle owner.
- A descriptor-backed Xray session must not also ask Xray to create a second TUN device. The descriptor's actual interface name must match the generated config.
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
