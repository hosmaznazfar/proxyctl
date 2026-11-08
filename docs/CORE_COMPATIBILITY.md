# Core compatibility: initial adapter subset

This matrix describes only the currently implemented adapter subset. It is not a claim that every transport or security mode for a protocol is supported.

| Protocol / feature | sing-box | Xray | Mihomo |
|---|---:|---:|---:|
| VLESS, basic TCP | Yes | Yes | Yes |
| VLESS, TLS + SNI | Yes | Yes | Yes |
| VLESS, TLS + ALPN | Yes | Yes | Yes |
| VLESS, TLS + client fingerprint | Yes | Yes | Yes |
| VLESS, TLS + Vision flow | Implemented; native validation pending | Implemented; native validation pending | Implemented; native validation pending |
| VMess, basic TCP | Yes | Yes | Yes |
| VMess, TLS + SNI | Yes | Yes | Yes |
| VMess, TLS + ALPN | Yes | Yes | Yes |
| VMess, TLS + client fingerprint | Yes | Yes | Yes |
| Trojan, TCP + TLS (including ALPN and client fingerprint) | Yes | Yes | Yes |
| Shadowsocks, basic TCP | Yes | Yes | Yes |
| Hysteria2, basic TLS (including ALPN) | Yes | No | Yes |
| TLS skip verification (`insecure`) | Implemented; native validation pending | Implemented; deprecated upstream | Implemented; native validation pending |
| Certificate SHA-256 pin (`pcs` / `pinSHA256`) | Unsupported in managed sing-box 1.14.4 | Implemented; native validation pending | Implemented; native validation pending |
| Separate certificate-name verification (`vcn`) | Unsupported | Implemented; native validation pending | Implemented; native validation pending |
| REALITY | Not yet | Not yet | Not yet |
| WebSocket (VLESS, VMess, Trojan) | Implemented; native validation pending | Implemented; native validation pending | Implemented; native validation pending |
| gRPC (standard mode) | Implemented; native validation pending | Implemented; native validation pending | Implemented; native validation pending* |
| gRPC authority / multi mode | Unsupported | Implemented; native validation pending | Unsupported |
| HTTP/2 (VLESS/VMess) | Implemented; native validation pending | Unsupported in current Xray schema | Implemented; native validation pending |
| HTTPUpgrade | Implemented; native validation pending | Implemented; native validation pending | Implemented; native validation pending |
| XHTTP (VLESS) | Unsupported | Implemented; native validation pending | Implemented; native validation pending |
| XHTTP (VMess) | Unsupported | Implemented; native validation pending | Unsupported |
| VMess transport coverage | Partial; see transport matrix | Partial; see transport matrix | Partial; see transport matrix |
| Shadowsocks plugins / obfuscation | Not yet | Not yet | Not yet |
| Hysteria2 obfuscation | Not yet | Not yet | Not yet |

## Safety contract

- The parser retains repeated URI query parameters and structured VMess values.
- The adapter checks every retained option against its explicit supported-option set.
- ALPN accepts comma-separated URI values, repeated URI `alpn` keys, and VMess JSON string arrays; values are normalized into an ordered list.
- Repeated ALPN keys are intentional multi-value input. Other repeated keys remain unsupported because their semantics are ambiguous.
- ALPN requires TLS. Empty, repeated, oversized, or control-character-containing ALPN identifiers are rejected.
- The `fp` option maps to sing-box `tls.utls`, Xray `tlsSettings.fingerprint`, and Mihomo `client-fingerprint`. The VMess JSON `security` alias is treated as its cipher (`scy`), not as TLS security; VMess TLS is read from its `tls` field. The common supported values are `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, and `random`.
- Client fingerprints require TLS and are supported for VLESS, VMess, and Trojan. They are rejected for Hysteria2 (QUIC) and Shadowsocks. sing-box uTLS is documented upstream as not recommended; this mapping is explicit opt-in from the imported node's `fp` value.
- `pcs` is a full-certificate SHA-256 pin, not a uTLS client fingerprint. It maps to Xray `pinnedPeerCertSha256` and Mihomo `fingerprint`. Managed sing-box 1.14.4 exposes a public-key SHA-256 pin instead, which is not equivalent, so Proxyctl rejects `pcs` for that version.
- Hysteria2 `pinSHA256` uses the same full-certificate pin semantics and currently maps to Mihomo only. Hysteria2 `insecure` maps to sing-box `tls.insecure` and Mihomo `skip-cert-verify`.
- `vcn` is separate certificate-name verification, not SNI. It maps to Xray `verifyPeerCertByName` and Mihomo `name-cert-verify`; sing-box 1.14.4 has no equivalent field and rejects it.
- `insecure` / `allowInsecure` is parsed as a boolean and maps to sing-box `insecure`, Xray `allowInsecure` (deprecated upstream), and Mihomo `skip-cert-verify`. Empty optional VMess JSON fields are treated as absent, while non-empty unknown fields remain explicit incompatibilities.
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

WebSocket (including early data), standard gRPC, HTTP/2, HTTPUpgrade, XHTTP, and VLESS Vision flow now have shared normalized representations and adapter mappings. VMess JSON is normalized according to its own field meanings: `net` selects transport, `type` can describe gRPC/XHTTP mode, `host` is gRPC authority or transport host, and `path` is the gRPC service name or transport path. Xray alone currently maps gRPC authority and multi mode. sing-box HTTP/2 uses its HTTP transport; current Xray schemas have removed the legacy HTTP/2 transport, so Proxyctl rejects it there; Mihomo uses its `h2` transport. HTTPUpgrade maps to sing-box/Xray native transports and Mihomo's WebSocket transport with `v2ray-http-upgrade: true`. XHTTP is rejected by sing-box, mapped for VLESS by Xray/Mihomo, and mapped for VMess by Xray only. URI host/path values are normalized without conflating WebSocket Host, HTTP/2 hosts, gRPC authority, or TLS SNI. Unit fixtures cover all implemented transports and security options. Mihomo requires an explicit gRPC service name; sing-box and Xray allow it to be omitted. Native validation against installed managed binaries is still required before treating these mappings as verified. Non-standard gRPC modes outside `gun`/`multi` remain unsupported. REALITY is rejected rather than approximated as ordinary TLS.


## Compatibility evaluation rules

The compatibility matrix describes the current implementation only. The long-term design is capability-driven and evaluated per core (and, where schemas differ, per core version).

- Source parsing and semantic normalization are core-independent. Adapters consume normalized domain values and must not reinterpret URI query parameters.
- A normalized feature can be supported by one core and unsupported by another. Do not reduce the shared model to the lowest common denominator.
- **Supported** means every meaningful setting is represented in the generated native configuration.
- **Unsupported** means the input is recognized but this core/version cannot represent it faithfully.
- **Invalid** means the source values are malformed, contradictory, or violate the protocol's semantics.
- Unknown source fields are retained and reported as unmapped; they are never silently discarded.
- Original source text and structured source fields remain available even when the current adapter cannot use them.
- Transport HTTP Host and TLS SNI are separate fields. They must not be conflated.
- VMess JSON fields are interpreted according to VMess source semantics. In particular, `net` selects transport while `type` may describe a transport-specific header mode; it must not be treated as the VLESS URI `type` parameter.
- Native validation with the corresponding core binary/version is required before marking a new mapping supported.

* Mihomo's gRPC mapping is considered compatible only when a non-empty service name is supplied.

## Transport capability status

The following table records the current implementation state. All `implemented` entries still require native validation against the supported managed core versions:

| Normalized transport | sing-box | Xray | Mihomo | Implementation status |
|---|---|---|---|---|
| TCP | Existing basic subset | Existing basic subset | Existing basic subset | Implemented baseline |
| WebSocket | Implemented; validation pending | Implemented; validation pending | Implemented; validation pending | Unit fixtures added |
| gRPC (standard) | Implemented; validation pending | Implemented; validation pending | Implemented; validation pending* | Unit fixtures added |
| gRPC authority / multi | Unsupported | Implemented; validation pending | Unsupported | Xray-specific fixtures added |
| HTTP/2 | Implemented; validation pending | Unsupported in current schema | Implemented; validation pending | Unit fixtures added |
| HTTPUpgrade | Implemented; validation pending | Implemented; validation pending | Implemented; validation pending | Unit fixtures added |
| XHTTP (VLESS) | Unsupported | Implemented; validation pending | Implemented; validation pending | Unit fixtures added |
| XHTTP (VMess) | Unsupported | Implemented; validation pending | Unsupported | VMess fixture added |

Each cell must be updated only after schema research, adapter tests, and native validation against the supported managed core version. Core/version differences are expected.

## Reference projects and research use

The architecture research uses public projects as references, not dependencies:

- L×Box / singbox-launcher: registry-oriented protocol definitions and conformance fixture concepts.
- microsubsproxy: separation between protocol parsers, a common node model, and output renderers.
- v2rayN: real-world VMess JSON and share-link field conventions.
- Hiddify and subconverter: broad subscription-format and cross-client interoperability cases.

Their behavior is not treated as a normative protocol specification. Upstream core documentation/source and protocol specifications remain authoritative for native config mappings. Any copied fixture must be sanitized and attributed; no live credentials or endpoints belong in the repository.

Primary implementation references:

- [sing-box v1.14.4 configuration source](https://github.com/SagerNet/sing-box/tree/v1.14.4/option) and [V2Ray transport documentation](https://github.com/SagerNet/sing-box/tree/v1.14.4/docs/configuration/shared).
- [Xray configuration documentation](https://github.com/XTLS/Xray-docs-next/tree/main/docs/en/config), including transport and TLS settings.
- [Mihomo proxy configuration documentation](https://wiki.metacubex.one/en/config/proxies/) and transport-specific options.
- [v2rayN formatter sources](https://github.com/2dust/v2rayN/tree/master/v2rayN/ServiceLib/Handler/Fmt) and [VMess DTO definitions](https://github.com/2dust/v2rayN/tree/master/v2rayN/ServiceLib/Models/Dto), used to verify source-specific field meanings such as VMess `net`/`type`, `pcs`, `vcn`, and `insecure`.

