# Structured JSON parsing foundation

Proxyctl now has an independent JSON profile decoder for outbound arrays. The first increment recognizes sing-box outbound objects and Xray outbound objects, extracting endpoint, tag, protocol credential and retaining native protocol/settings fields as structured option entries.

This decoder is intentionally not yet wired into the CLI file-import pipeline. It does not claim YAML support or complete protocol coverage. Unsupported outbound kinds are skipped; integration work must add user-visible diagnostics before this becomes the default import behavior. Profile routing, DNS and inbound configuration are outside the node model.

Fixtures are synthetic and use reserved/invalid domains and placeholder credentials.
