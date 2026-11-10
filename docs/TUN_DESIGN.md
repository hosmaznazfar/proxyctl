# Linux TUN design

> Status: opt-in Linux TUN activation implemented for sing-box, Xray, and Mihomo; native config validation and guarded systemd lifecycle are covered by automated tests. No live TUN test was run against the host network.  
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

### Privilege isolation (implemented)

Linux TUN device creation and route configuration require `CAP_NET_ADMIN`. Proxyctl uses a transient systemd system service instead of running the core as root. It authenticates with `sudo -v` through the user's terminal, then runs the core with the invoking UID/GID, `CapabilityBoundingSet=CAP_NET_ADMIN`, `AmbientCapabilities=CAP_NET_ADMIN`, and `NoNewPrivileges=yes`. The service is cgroup-owned by systemd, has a bounded stop timeout, and no restart policy. Proxyctl verifies MainPID, process start ticks, canonical executable, UID, and capability masks before accepting readiness. No file capabilities are changed, no password is stored, and no permanent privileged daemon is installed. Residual privilege risk: CAP_NET_ADMIN is broad within the host network namespace and can be used for firewall operations too. Generated configs disable firewall auto-redirect, but the selected core must still be trusted; this capability is not a per-route or per-interface sandbox.

If systemd, sudo authorization, iproute2, or TUN device access is unavailable, or a foreign TUN/TAP interface is already present, TUN activation fails before the previous activation is stopped. Ordinary loopback activation remains independent of these requirements.

## Ownership, rollback, and recovery requirements

Before systemd starts the service, Proxyctl first preflights the same transient capability policy with a one-shot `true` service that makes no network changes. It then atomically writes a private manifest with the unique transient unit name, selected node/core, managed executable path, config path, invoking UID, and a baseline of sysfs interfaces, IPv4/IPv6 routes from all iproute2 tables, IPv4/IPv6 policy rules, default routes, resolver nameservers, and the `resolv.conf` target. The manifest contains no proxy credentials. The core owns its native TUN interface and route lifecycle; systemd owns the exact service cgroup. Stop verifies the recorded MainPID and process identity before stopping only that unique unit, then compares the full route/rule/interface/DNS baseline. If anything differs, Proxyctl retains the manifest and config for manual inspection. It never deletes routes, interfaces, firewall rules, or resolver settings itself.

## Verification and remaining operational boundary

Automated coverage includes per-core TUN config generation with the mixed listener, DNS-disabled and firewall-auto-redirect-disabled settings, native config validation for supported fixtures, a pure systemd command-construction test proving CAP_NET_ADMIN-only policy, capability-mask tests, legacy state compatibility, and fake-process activation lifecycle tests. These tests do not start a TUN core or modify the host network. A live TUN smoke test remains an explicit user operation and should be performed only after reviewing `proxyctl tun status`. CI must never create a host TUN interface or alter host routes.

## Current implementation boundary

The exposed operations are `proxyctl tun status` (read-only), ordinary `proxyctl use NODE --core CORE`, explicit TUN `proxyctl use NODE --core CORE --tun`, and `proxyctl stop`. There is no separate `tun on/off` command. Only explicit `--tun` creates a TUN interface and changes routes; DNS and firewall settings are not modified. If baseline inspection or cleanup verification fails, activation is refused or the private manifest is retained for manual recovery.
