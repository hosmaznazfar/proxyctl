# Core compatibility: initial adapter subset

This matrix describes only the currently implemented adapter subset. It is not a claim that every transport or security mode for a protocol is supported.

| Protocol / feature | sing-box | Xray | Mihomo |
|---|---:|---:|---:|
| VLESS, basic TCP | Yes | Yes | Yes |
| VLESS, TLS + SNI | Yes | Yes | Yes |
| VMess, basic TCP | Yes | Yes | Yes |
| VMess, TLS + SNI | Yes | Yes | Yes |
| Trojan, TCP + TLS | Yes | Yes | Yes |
| Shadowsocks, basic TCP | Yes | Yes | Yes |
| Hysteria2, basic TLS | Yes | No | Yes |
| REALITY | Not yet | Not yet | Not yet |
| WebSocket / gRPC / XHTTP | Not yet | Not yet | Not yet |
| VMess non-TCP transports | Not yet | Not yet | Not yet |
| Shadowsocks plugins / obfuscation | Not yet | Not yet | Not yet |
| Hysteria2 obfuscation | Not yet | Not yet | Not yet |

## Safety contract

- The parser retains repeated URI query parameters and structured VMess values.
- The adapter checks every retained option against its explicit supported-option set.
- An unrecognized or unmapped option produces an unsupported result; it is never silently discarded.
- The generated document is serialized as JSON. For Mihomo this relies on JSON being accepted as a YAML-compatible configuration document.
- Validation is delegated to the selected managed binary:
  - sing-box: `sing-box check -c CONFIG`
  - Xray: `xray run -test -c CONFIG`
  - Mihomo: `mihomo -t -f CONFIG`
- Run `proxyctl check <NODE_ID>` to validate against every installed compatible core, or add `--core sing-box|xray|mihomo` to select one.
- Validation uses a private temporary file with mode 0600 on Unix and removes it on success or failure.
- The validation command invokes only the core's config-check mode; it never starts a proxy process or changes system networking.

## Current limitations

The adapters are an initial conservative implementation. The `check` command now owns the temporary config lifecycle and invokes the installed managed binary's validation mode. The command does not start a core. The compatibility table must be expanded only alongside fixtures and successful validation against the supported managed core versions.

VMess options such as `net=ws` and VLESS options such as `type=ws` are intentionally rejected until their complete transport mappings are implemented. REALITY is rejected rather than approximated as ordinary TLS.
