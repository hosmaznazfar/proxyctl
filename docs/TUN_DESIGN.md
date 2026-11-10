# Linux TUN design

> Status: research complete; implementation gated on privilege and recovery design  
> Scope: first implementation target is Linux  
> Goal: use the selected proxy core's native TUN implementation with minimal additional resource use

## Research findings

Proxyctl was compared with v2rayN's current implementation and the native capabilities of sing-box, Xray, and Mihomo.

### v2rayN

v2rayN builds TUN configuration into the selected core's generated configuration instead of running an independent tun2socks service:

- sing-box receives a native `tun` inbound with interface name, MTU, address, stack, auto-route, strict-route, and route exclusions.
- Xray receives a native `tun` inbound with gateway addresses, MTU, auto system routes, optional outbound-interface binding, and optional DNS-to-gateway behavior.
- Its Linux core manager elevates TUN launches through a sudo-managed process. That is a functional reference, not a security model Proxyctl should copy without review.
- Its local listener generation uses the core's native mixed-protocol support rather than two independent local ports.

References:
- [v2rayN CoreManager.cs](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Manager/CoreManager.cs)
- [v2rayN CoreAdminManager.cs](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Manager/CoreAdminManager.cs)
- [v2rayN SingboxInboundService.cs](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Services/CoreConfig/Singbox/SingboxInboundService.cs)
- [v2rayN V2rayInboundService.cs](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Services/CoreConfig/V2ray/V2rayInboundService.cs)

### Native core options

| Core | Native TUN support | Lightweight default direction | Important safety behavior |
|---|---|---|---|
| sing-box | `tun` inbound | `system` stack | `auto_route`; route loop protection via auto-detected outbound interface |
| Xray | `tun` inbound | Core-managed lightweight TCP/IP stack | `autoSystemRoutingTable`; `autoOutboundsInterface` prevents loops |
| Mihomo | `tun` configuration | `system` stack | `auto-route`; core-managed interface and routes |

Official references:
- [sing-box TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [sing-box route configuration](https://sing-box.sagernet.org/configuration/route/)
- [Xray TUN inbound](https://xtls.github.io/en/config/inbounds/tun.html)
- [Mihomo configuration](https://wiki.metacubex.one/en/config/inbound/tun/)

## Decisions

### Keep the core as the TUN engine

- Do not implement a TUN device, packet stack, tun2socks bridge, or routing daemon in Proxyctl.
- Do not add a Rust TUN dependency.
- Reuse the already selected and already running managed core; only one core can be active.
- Keep TUN configuration in the same private, generated per-activation config as the selected node.
- Prefer the operating-system `system` stack. Do not choose gVisor or another userspace stack by default when the core provides a system-stack option.
- TUN remains opt-in. Normal `proxyctl use`, benchmarks, setup, and updates do not enable it.

### Keep DNS and firewall out of the first implementation

- Do not set system proxy settings.
- Do not change system DNS or resolver configuration.
- Do not add, flush, or rewrite nftables/iptables rules.
- Do not install custom firewall kill-switch rules in the first release.
- Do not enable Xray `autoSystemDnsToGateway`; its Linux behavior depends on systemd-resolved and changes system resolver state.
- DNS traffic handling must be explicit in core routing configuration and must not silently take over the host resolver.

### Route loop prevention is mandatory

When the system default route points to the TUN interface, the proxy core's own outbound connection to the remote proxy server must continue using the physical uplink. Each supported core must have a verified native outbound-interface mechanism or an equally safe equivalent. If the physical egress interface cannot be determined and pinned safely, TUN activation must fail before changing routes.

### Privilege model remains a release blocker

Linux TUN device creation and route configuration require networking privileges. v2rayN currently launches its core through a sudo-managed process for this case, but running the complete proxy core as root expands the impact of a core compromise.

Proxyctl must choose and test one of these approaches before enabling TUN:

1. A narrowly scoped privileged launcher that grants only the operations required to create the TUN device and install/remove the owned routes, while the core itself runs unprivileged; or
2. An explicitly confirmed elevated core launch, with exact child-process identity tracking, no stored password, and a clear explanation that the selected core runs with elevated privileges.

Do not silently fall back to root, modify file capabilities on managed core binaries, persist sudo credentials, or introduce an always-running privileged daemon. If neither approach can be made reliable on the host, refuse TUN activation and leave ordinary local proxy activation available.

## Ownership, rollback, and recovery requirements

Before any system mutation, record a private baseline and an ownership manifest containing:

- selected node and core identifiers;
- exact executable path, PID, process start ticks, and pidfd-backed identity where available;
- generated configuration path and TUN interface name;
- route/interface identifiers that the selected core is expected to create;
- the pre-activation default routes and relevant interface state;
- activation phase and cleanup status.

The manifest must not contain proxy credentials. It must be written atomically with private permissions before the process is allowed to mutate system networking.

The core should own its native TUN interface and native route lifecycle. Proxyctl must not delete a route merely because it points at an interface with a familiar name. On stop, terminate only the verified managed process, wait for the core to close its TUN descriptor and clean up its routes, then compare the read-only network state with the baseline. If cleanup is incomplete, preserve the manifest and report the exact remaining differences. Do not attempt broad automatic cleanup that could damage another VPN, Docker, NetworkManager, or user-managed route.

A later explicit recovery command may remove only resources whose ownership can be proven from the manifest and whose current state still matches the recorded resource identity. Ambiguous state must require manual intervention.

## Required tests before enabling TUN

- Core config generation and native config validation for every supported core/version.
- Loopback mixed SOCKS5/HTTP listener remains present in TUN and non-TUN activation modes.
- No TUN or route changes for ordinary activation and benchmarks.
- Failure before spawn leaves no state or networking changes.
- Failure during startup terminates only the exact child and confirms core cleanup.
- Normal stop verifies TUN interface and route cleanup.
- SIGTERM timeout and forced termination behavior are explicitly tested.
- Crash/reboot/stale manifest recovery never removes foreign interfaces or routes.
- Simulated existing VPN, Docker bridges, multiple default routes, IPv6-only routes, and DNS manager states.
- No test may modify the developer's real network; use fake processes and temporary fixtures.

## Current implementation boundary

Only `proxyctl tun status` is exposed. It is read-only. There is no `tun on/off` command, no `--tun` activation flag, and no automatic system networking changes until the privilege and recovery gates above are implemented and verified.
