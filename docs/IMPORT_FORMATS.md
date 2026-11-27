# Import format coverage and implementation contract

This document separates **share-link parsing** from **structured profile import**. They are different source formats and must not be treated as interchangeable.

## Current behavior

The current `proxyctl import FILE` implementation reads a newline-delimited list of individual proxy URLs. The parser recognizes:

| Source scheme | Current parser |
|---|---:|
| VLESS | Supported |
| VMess (base64 JSON payload) | Supported |
| Trojan | Supported |
| Shadowsocks SIP002 | Supported |
| Hysteria2 / hy2 | Supported |
| Other share-link schemes | Unsupported |

The parser preserves repeated URI query parameters and structured VMess JSON option values. The adapters then decide whether each retained setting can be represented by sing-box, Xray, or Mihomo. A successful parse does not imply compatibility with every core.

**sing-box and Xray JSON outbound profiles are now accepted by `import FILE`.** The current increment extracts recognized outbound types and preserves native settings in option entries. Mihomo/Clash YAML proxy-list import (`proxies:`) is now supported. Plain-text Base64 subscription payloads are decoded conservatively when the decoded text is clearly a URL list or JSON profile. YAML entries that are unsupported or malformed are reported individually with one-based positions inside `proxies[]`; diagnostics use fixed messages and never echo source values. Import diagnostics and complete protocol-field compatibility are still being expanded.

## Format scope

The importer uses a format-aware pipeline with independent decoders and one shared normalized node model:

| Input format | Primary source shape | Planned extraction |
|---|---|---|
| Share-link list | One URI per line | Existing URI parser |
| sing-box JSON | `outbounds[]` | Supported proxy outbound types and their protocol-specific fields |
| Xray JSON | `outbounds[]` | Supported proxy outbound protocols and `streamSettings` |
| Mihomo / Clash YAML | `proxies[]` | Supported proxy entries and protocol-specific options (implemented) |
| Base64 subscription | UTF-8 Base64 payload | Conservative decoding to clearly recognizable URL lists, JSON profiles, or Mihomo YAML profiles; other data remains unchanged |

The initial structured-profile scope is **proxy endpoint extraction**. Routing rules, DNS policy, inbounds, listeners, selectors, groups, health checks, and profile-level policy are not node connection settings. They must be reported as out-of-scope profile data rather than silently presented as imported nodes.

## Required importer contract

1. **Detect format before parsing.** Use explicit structural signatures (for example, sing-box `outbounds`, Xray `outbounds` plus protocol settings, or Mihomo `proxies`). Do not guess from filename extensions alone.
2. **Keep source decoding separate from core adapters.** Each format decoder maps its native fields into the core-independent `ProxyNode` model. Adapters remain responsible for sing-box, Xray, and Mihomo output.
3. **Preserve source values.** Keep original source material protected as sensitive data, and retain every recognized option including structured values and repeated values where the source format permits them.
4. **Never silently drop meaningful settings.** Every field must be classified as mapped, intentionally irrelevant to a standalone node, unsupported by the importer, or conflicting/invalid. Unsupported or lossy fields produce import warnings with human-readable default text and optional developer detail.
5. **Separate profile-level and node-level data.** A profile's routing/DNS/inbound configuration cannot be represented by a single node. Explain this distinction in the import summary.
6. **Fail closed on ambiguous credentials or semantics.** Do not infer missing protocol credentials, convert one TLS/REALITY mode into another, or coerce transport fields across protocols.
7. **Keep diagnostics secret-safe.** Warnings and failures must never print UUIDs, passwords, private keys, subscription URLs, or raw source fragments.
8. **Report per-core compatibility after normalization.** One imported node may be valid for one core and unsupported by another. Do not reject a valid source node solely because one target core cannot represent it.
9. **Make batch imports transactional only at the record level.** A malformed entry should not discard unrelated valid entries. The summary must distinguish added, duplicate, invalid, and warning counts.
10. **Test fixtures must be synthetic.** No live endpoints, credentials, subscription URLs, or copied personal profiles belong in the repository.

## Field mapping checklist

Structured decoders must explicitly cover, where present and meaningful:

- Endpoint: server/address, port, display name/tag.
- Credentials: UUID/user ID, password, Shadowsocks method, protocol-specific authentication.
- Transport: TCP/raw, WebSocket, gRPC, HTTP/2, HTTPUpgrade, XHTTP, and any source transport not yet supported.
- Transport details: host/authority, path/service name, headers, gRPC mode, WebSocket early data, XHTTP mode and extras.
- TLS: enabled state, server name/SNI, ALPN, uTLS fingerprint, insecure verification flag.
- REALITY: public key, short ID, SpiderX, ML-DSA verification material.
- Protocol options: VLESS flow/encryption, VMess cipher/alter ID, Shadowsocks plugin and options, Hysteria2 obfuscation and packet sizing.
- Advanced source fields: multiplex, packet encoding, ECH, certificate pins/name verification, detours, interface binding, routing marks, and any other non-default field. If not representable in the node model, warn rather than discard.

This is a checklist, not a claim that every field is supported by every core. Native schema/version validation remains required before a mapping is marked supported.

## Reference behavior and compatibility boundaries

- v2rayN accepts multiple profile types and imports share links, QR codes, and subscriptions. Its formatter behavior is useful for source-field interpretation, especially VMess JSON and URI aliases.
- Throne supports a broad protocol set and multiple subscription/config formats. Its parser diagnostics and import report separation are useful architectural references.
- sing-box and Mihomo core capabilities are not equivalent to the import capabilities of every GUI client built around those cores. Core schema support must be evaluated separately from client UI behavior.
- sing-box 1.14.5 does not define a VLESS `encryption` outbound field and does not provide XHTTP in its documented V2Ray transport set. Non-`none` VLESS encryption and XHTTP must therefore remain unsupported for that sing-box version.
- Mihomo 1.19.34 supports XHTTP `mode: auto`; that mode must not be rejected merely because another core uses a different set of modes.

## Required tests for each decoder

- Minimal valid fixture for every supported protocol.
- Full fixture with every supported optional field populated.
- Missing required credentials, server, or port.
- Invalid types (string where object/array is required, malformed booleans, invalid ports).
- Unknown protocol and unknown transport.
- Unsupported meaningful fields trigger a warning and are not silently lost.
- Conflicting aliases and duplicate fields are rejected or reported deterministically.
- Secret redaction in debug output, errors, warnings, and CLI summaries.
- Duplicate node detection remains stable across equivalent source formats.
- Each normalized node is evaluated independently against all three core adapters.
- Generated configs are valid JSON and native validation fixtures are added only after the relevant core version accepts them.

## Reference links

- [v2rayN formatter sources](https://github.com/2dust/v2rayN/tree/master/v2rayN/ServiceLib/Handler/Fmt)
- [v2rayN profile documentation](https://github.com/2dust/v2rayN)
- [Throne import diagnostics](https://github.com/throneproj/Throne/blob/dev/include/configs/ParseDiagnostics.h)
- [Throne import report](https://github.com/throneproj/Throne/blob/dev/include/configs/sub/ImportReport.hpp)
- [sing-box outbound configuration](https://github.com/SagerNet/sing-box/blob/v1.14.5/docs/configuration/outbound/)
- [Mihomo proxy configuration](https://wiki.metacubex.one/en/config/proxies/)
