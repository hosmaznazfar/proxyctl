# Structured profile import

Proxyctl accepts structured JSON profiles containing an `outbounds[]` array from sing-box or Xray, and Mihomo/Clash YAML profiles containing a `proxies[]` sequence. The decoders normalize supported proxy endpoints into the shared `ProxyNode` model and preserve recognized protocol-specific settings as structured option entries.

## JSON extraction

The JSON decoder recognizes sing-box outbound objects through `type` and Xray outbound objects through `protocol`. It extracts endpoint, tag, protocol credential, and the source settings needed by the adapters. Supported protocol kinds currently include VLESS, VMess, Trojan, Shadowsocks, and Hysteria2 aliases.

## YAML extraction

The Mihomo decoder recognizes VLESS, VMess, Trojan, Shadowsocks, and Hysteria2 proxy entries. Nested values such as TLS and transport options are retained as structured options. Required endpoint and credential fields are validated before a node is accepted; the importer does not synthesize missing credentials.

## Diagnostics and safety

Every skipped JSON outbound or YAML proxy entry is reported with its one-based position in the source array/sequence and a fixed reason. Diagnostics never include raw source fragments, endpoint credentials, UUIDs, passwords, or other imported values. Valid entries are still imported when other entries are unsupported or malformed.

Base64 subscription text is decoded conservatively only when the decoded UTF-8 payload has a recognizable supported shape (proxy URL lines, JSON object, or Mihomo `proxies:` document). Ambiguous input is retained unchanged.

Profile routing, DNS, inbounds, listeners, selectors, groups, health checks, and other profile-level policy are outside the standalone node model. Their presence does not imply that those policies are imported or applied.

Fixtures are synthetic and use reserved/invalid domains and placeholder credentials.
