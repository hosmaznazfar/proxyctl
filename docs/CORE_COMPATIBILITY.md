# Core compatibility: validated adapter subset

This matrix describes the implemented and tested adapter subset. The opt-in native conformance matrix has passed against the managed binaries listed below; this does not imply support for every transport or security mode.

Compatibility outcomes are distinct: **Supported** means every retained option was mapped for that core; **Unsupported** means the input is valid but the core or adapter cannot implement a feature; **Invalid** means the input is malformed, contradictory, or semantically invalid. Unknown options are preserved in the source node and reported as unsupported rather than silently dropped.

| Protocol / feature | sing-box | Xray | Mihomo |
|---|---:|---:|---:|
| VLESS, basic TCP | Yes | Yes | Yes |
| VLESS, TLS + SNI | Yes | Yes | Yes |
| VLESS, TLS + ALPN | Yes | Yes | Yes |
| VLESS, TLS + client fingerprint | Yes | Yes | Yes |
| VLESS, TLS + Vision flow | Native validated | Native validated | Native validated |
| VMess, basic TCP | Yes | Yes | Yes |
| VMess, TLS + SNI | Yes | Yes | Yes |
| VMess, TLS + ALPN | Yes | Yes | Yes |
| VMess, TLS + client fingerprint | Yes | Yes | Yes |
| Trojan, TCP + TLS (including ALPN and client fingerprint) | Yes | Yes | Yes |
| Shadowsocks, basic TCP | Yes | Yes | Yes |
| Hysteria2, basic TLS (including ALPN) | Yes | No | Yes |
| TLS skip verification (`insecure`) | Unit-tested; not in native fixture matrix | Unit-tested; deprecated upstream | Unit-tested; not in native fixture matrix |
| Certificate SHA-256 pin (`pcs` / `pinSHA256`) | Unsupported in managed sing-box 1.14.4 | Unit-tested; not in native fixture matrix | Unit-tested; not in native fixture matrix |
| Separate certificate-name verification (`vcn`) | Unsupported | Unit-tested; not in native fixture matrix | Unit-tested; not in native fixture matrix |
| REALITY (VLESS) | Native validated | Native validated | Native validated |
| REALITY (VMess) | Unsupported | Native validated | Unsupported |
| WebSocket (VLESS, VMess, Trojan) | VLESS fixture native-validated | VLESS fixture native-validated | VLESS fixture native-validated |
| gRPC (standard mode) | VLESS fixture native-validated | VLESS fixture native-validated | VLESS fixture native-validated* |
| gRPC authority / multi mode | Unsupported | Native validated | Unsupported |
| HTTP/2 (VLESS/VMess) | VLESS fixture native-validated | Unsupported in current Xray schema | VLESS fixture native-validated |
| HTTPUpgrade | VLESS fixture native-validated | VLESS fixture native-validated | VLESS fixture native-validated |
| XHTTP (VLESS) | Unsupported | Native validated | Native validated |
| XHTTP (VMess) | Unsupported | Native validated | Unsupported |
| VMess transport coverage | Partial; see transport matrix | Partial; see transport matrix | Partial; see transport matrix |
| Shadowsocks SIP003 obfs-local / v2ray-plugin | Native validated | Unsupported | Native validated |
| Hysteria2 obfuscation (Salamander, Gecko) | Native validated | Unsupported | Native validated |

## Safety contract

- The parser retains repeated URI query parameters and structured VMess values. The source transport alias `raw` is normalized to TCP without changing the preserved original URL. For VLESS URI and VMess JSON, `http`, `h2`, and `http2` normalize to the shared HTTP/2 transport representation; adapters serialize that representation using each core's native key.
- The adapter checks every retained option against its explicit supported-option set.
- ALPN accepts comma-separated URI values, repeated URI `alpn` keys, and VMess JSON string arrays; values are normalized into an ordered list.
- Repeated ALPN keys are intentional multi-value input. Other repeated keys remain unsupported because their semantics are ambiguous.
- ALPN requires TLS. Empty, repeated, oversized, or control-character-containing ALPN identifiers are rejected.
- The `fp` option maps to sing-box `tls.utls`, Xray `tlsSettings.fingerprint`, and Mihomo `client-fingerprint`. The VMess JSON `security` alias is treated as its cipher (`scy`), not as TLS security; VMess TLS is read from its `tls` field. The common supported values are `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, and `random`.
- Client fingerprints require TLS and are supported for VLESS, VMess, and Trojan. They are rejected for Hysteria2 (QUIC) and Shadowsocks. sing-box uTLS is documented upstream as not recommended; this mapping is explicit opt-in from the imported node's `fp` value.
- `pcs` is a full-certificate SHA-256 pin, not a uTLS client fingerprint. It maps to Xray `pinnedPeerCertSha256` and Mihomo `fingerprint`. Managed sing-box 1.14.4 exposes `certificate_public_key_sha256`, which hashes only the certificate public key and is not equivalent, so Proxyctl rejects `pcs` for that installed version. Upstream sing-box added the distinct full-certificate `certificate_sha256` field in 1.15.0; supporting it requires version-aware capability evaluation and native validation against that version. Do not map a full-certificate pin to the public-key field.
- Hysteria2 `pinSHA256` uses the same full-certificate pin semantics and currently maps to Mihomo only. Hysteria2 `insecure` maps to sing-box `tls.insecure` and Mihomo `skip-cert-verify`.
- `vcn` is separate certificate-name verification, not SNI. It maps to Xray `verifyPeerCertByName` and Mihomo `name-cert-verify`; sing-box 1.14.4 has no equivalent field and rejects it.
- `insecure` / `allowInsecure` is parsed as a boolean and maps to sing-box `insecure`, Xray `allowInsecure` (deprecated upstream), and Mihomo `skip-cert-verify`. Empty optional VMess JSON fields are treated as absent, while non-empty unknown fields remain explicit incompatibilities.
- An unrecognized or unmapped option produces an unsupported result; it is never silently discarded.
- VLESS REALITY requires pbk (or publicKey), fp, and an optional even-length hexadecimal sid up to 16 characters. It maps to sing-box tls.reality + tls.utls, Xray streamSettings.realitySettings (the client public key uses the current password field), and Mihomo reality-opts. Xray additionally accepts VMess REALITY; this batch deliberately keeps sing-box and Mihomo REALITY limited to VLESS. Xray transport restrictions are enforced. Native binary validation remains pending.
- Xray REALITY uses the current client-side `password` key for the public key; the legacy `publicKey` config key is no longer current. Xray REALITY transport is restricted to RAW, XHTTP, and gRPC. sing-box and Mihomo optional REALITY fields are limited to those their native schemas expose.
- Optional REALITY SpiderX and ML-DSA-65 verification fields are emitted only for Xray. sing-box and Mihomo reject these fields rather than dropping them.
- Hysteria2 obfuscation accepts `obfs=salamander` or `obfs=gecko` only when a matching `obfs-password` is supplied. Gecko-only `obfs-min-packet-size` and `obfs-max-packet-size` are validated and mapped to sing-box `obfs.min_packet_size/max_packet_size` and Mihomo `obfs-min-packet-size/obfs-max-packet-size`; Xray does not implement Hysteria2. Native validation against the managed sing-box 1.14.4 and Mihomo 1.19.33 binaries remains required.
- Shadowsocks SIP003 supports only `obfs-local` and `v2ray-plugin` in this adapter batch. sing-box receives the plugin name and original escaped option string; Mihomo receives its native plugin name and structured options. Xray has no documented outbound SIP003 plugin fields and rejects plugin-enabled nodes. Other plugin types and unknown plugin options are unsupported, not discarded.
- XHTTP extras accept only the documented shared subset used by Xray and Mihomo. Xray-only VMess XHTTP may use direct VMess request headers; VLESS XHTTP uses the structured `extra` object for advanced headers and padding/reuse settings. Mihomo rejects explicit `mode=auto` because its documented modes are `stream-one`, `stream-up`, and `packet-up`.
- The generated document is serialized as JSON. For Mihomo this relies on JSON being accepted as a YAML-compatible configuration document.
- Validation is delegated to the selected managed binary:
  - sing-box: `sing-box check -c CONFIG`
  - Xray: `xray run -test -c CONFIG`
  - Mihomo: `mihomo -t -f CONFIG`
- Run `proxyctl check <NODE_ID>` to validate against every installed compatible core, or add `--core sing-box|xray|mihomo` to select one.
- Validation uses a private temporary file with mode 0600 on Unix and removes it on success or failure.
- The opt-in native fixture matrix is run with `cargo test --test native_adapter_validation -- --ignored --nocapture`. It requires all three proxyctl-managed core binaries to be installed. **The matrix passed: 51 supported fixture/core combinations across 23 sanitized fixtures**, checking expected per-core compatibility and validating every supported fixture using only each core's config-check mode; unsupported combinations are asserted but not sent to the binary. The validated local managed versions were sing-box 1.14.4, Xray 26.11.9, and Mihomo 1.19.33. It never starts a proxy or changes system networking.
- The validation command invokes only the core's config-check mode; it never starts a proxy process or changes system networking.

## Current limitations

The adapters provide a conservative, tested initial implementation. The `check` command owns the temporary config lifecycle and invokes the installed managed binary's validation mode. The command does not start a core. Expand the compatibility table only alongside fixtures and successful validation against the relevant managed core versions.

WebSocket (including early data), standard gRPC, HTTP/2, HTTPUpgrade, XHTTP (including the validated shared subset of Xray/Mihomo extra settings), and VLESS Vision flow now have shared normalized representations and adapter mappings. VMess JSON is normalized according to its own field meanings: `net` selects transport, `type` can describe gRPC/XHTTP mode, `host` is gRPC authority or transport host, and `path` is the gRPC service name or transport path. Xray alone currently maps gRPC authority and multi mode. sing-box HTTP/2 uses its HTTP transport; current Xray schemas have removed the legacy HTTP/2 transport, so Proxyctl rejects it there; Mihomo uses its `h2` transport. HTTPUpgrade maps to sing-box/Xray native transports and Mihomo's WebSocket transport with `v2ray-http-upgrade: true`. XHTTP is rejected by sing-box, mapped for VLESS by Xray/Mihomo, and mapped for VMess by Xray only. URI host/path values are normalized without conflating WebSocket Host, HTTP/2 hosts, gRPC authority, or TLS SNI. Unit fixtures cover all implemented transports and security options. Mihomo requires an explicit gRPC service name; sing-box and Xray allow it to be omitted. The opt-in native fixture matrix has validated the mappings represented by its 23 fixtures against the managed core versions recorded above. Non-standard gRPC modes outside `gun`/`multi` remain unsupported. REALITY is mapped explicitly per core and is never approximated as ordinary TLS.


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

The following table records implementation and native-fixture status. `Native validated` means the corresponding fixture/core combination passed the opt-in matrix against the managed versions recorded above; it does not certify untested option combinations:

| Normalized transport | sing-box | Xray | Mihomo | Implementation status |
|---|---|---|---|---|
| TCP | Existing basic subset | Existing basic subset | Existing basic subset | Implemented baseline |
| WebSocket | VLESS fixture native-validated | VLESS fixture native-validated | VLESS fixture native-validated | Native fixture passed |
| WebSocket early data | Native validated | Native validated; custom header unsupported | Native validated | Native fixture passed |
| VLESS Vision flow | Native validated | Native validated | Native validated | Native fixture passed |
| gRPC (standard) | VLESS fixture native-validated | VLESS fixture native-validated | VLESS fixture native-validated* | Native fixture passed |
| gRPC authority / multi | Unsupported | Native validated | Unsupported | Xray native fixture passed |
| HTTP/2 | VLESS fixture native-validated | Unsupported in current schema | VLESS fixture native-validated | Native fixture passed |
| HTTPUpgrade | VLESS fixture native-validated | VLESS fixture native-validated | VLESS fixture native-validated | Native fixture passed |
| XHTTP (VLESS) | Unsupported | Native validated | Native validated | Native fixture passed |
| XHTTP (VMess) | Unsupported | Native validated | Unsupported | Native fixture passed |

Update each cell only after schema research, adapter tests, and native validation against the relevant managed core version. Core/version differences are expected.

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

