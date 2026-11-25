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
| Xray | `NativeDeviceCreation` | Generates a native Xray `tun` inbound with the fixed interface name, gateway addresses, MTU, sniffing, and marked proxy outbound. Proxyctl creates the generation-owned persistent interface first; Xray opens that named device and configures its MTU and gateway addresses. Automatic route/DNS integration remains disabled. | Enabled on Linux through the same supervisor |

### Xray native named-device lifecycle

Xray's Linux TUN inbound supports both a native named-device path and an optional externally supplied descriptor path. Proxyctl uses the native named-device path, matching the single-application, TUN-only elevation model verified in v2rayN:

1. The privileged Proxyctl supervisor creates and journals one generation-owned persistent TUN interface with the fixed name `tun-proxyctl`. Its initial `TUNSETIFF` uses `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`; after `TUNSETPERSIST`, the creating descriptor is closed.
2. Xray starts directly as the selected root-owned session child. Its Linux native inbound opens `/dev/net/tun`, attaches to the existing name with `TUNSETIFF`, and looks up that link. Xray first attempts `IFF_VNET_HDR` and falls back to the ordinary TUN flags if that attachment/offload mode is unavailable.
3. Xray's native `Start` sets the interface MTU, brings the link up, and assigns its configured IPv4/IPv6 gateway addresses. Its generated config leaves automatic route and DNS integration disabled. Proxyctl remains the sole owner of routes and policy rules through the write-ahead journal.
4. Proxyctl verifies that the exact Xray process has attached to the expected interface by inspecting its live `/proc/<pid>/fdinfo` entries and matching the interface name and ifindex, then runs the same dual-stack end-to-end readiness checks and commits the session receipt.
5. Xray's native `Close` removes the addresses it added, brings the link down, and closes its queue descriptor; it does not clear Proxyctl's persistent-device ownership. The supervisor stops/reaps the exact core before generation-scoped recovery clears persistence and removes the interface, routes, and policy rules.

The optional `XRAY_TUN_FD` path is deliberately not used. When Xray adopts an external FD, its Linux `Start` path does not configure link state, MTU, gateway addresses, or routes; that would require a separate Proxyctl-owned interface-configuration lifecycle. Avoid that unnecessary descriptor path because the native named-device mode already fits the supervisor architecture.

This behavior is documented by the [Xray TUN configuration reference](https://xtls.github.io/en/config/inbounds/tun.html) and implemented in [Xray's Linux TUN source](https://github.com/XTLS/Xray-core/blob/main/proxy/tun/tun_linux.go) (`NewTun`, `openFromEnv`, `Start`, and `Close`). The exact behavior must still be verified against the installed Xray version during local integration testing.

### Ownership rules

- `NativeDeviceCreation` means the selected core opens or creates its named TUN device from native config. Proxyctl may pre-create a generation-owned persistent interface so journaled routes and policy rules can be installed before the core starts. The supervisor still owns the interface's persistence, session records, readiness, monitoring, and recovery.
- `ExternalDescriptorEnvironment` means Proxyctl (or another explicitly designated owner) creates and configures the TUN device, then passes an already-open descriptor to the core. The core does not become the interface's lifecycle owner.
- Xray's optional descriptor mode is not used by the supervised lifecycle; its native named-device mode avoids split ownership of link/address configuration.
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
