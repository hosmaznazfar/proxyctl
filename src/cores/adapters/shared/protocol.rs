use crate::domain::{Protocol, ProxyNode, TransportKind};

use super::{
    alpn_protocols, normalize_transport, option_string, reject_unknown_options, validate_string_options,
};

fn vmess_alter_id(node: &ProxyNode) -> Result<Option<u32>, String> {
    if let Some(value) = node.option("aid") {
        return match value {
            serde_json::Value::String(value) if value.is_empty() => Ok(None),
            serde_json::Value::String(value) => value
                .parse::<u32>()
                .map(Some)
                .map_err(|_| "VMess alter ID is invalid".into()),
            serde_json::Value::Number(value) => value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .map(Some)
                .ok_or_else(|| "VMess alter ID is invalid".into()),
            serde_json::Value::Null => Ok(None),
            _ => Err("VMess alter ID must be an unsigned integer".into()),
        };
    }
    node.options
        .get("aid")
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| "VMess alter ID is invalid".into())
        })
        .transpose()
}

pub(crate) fn validate_common(node: &ProxyNode) -> Result<(), String> {
    if node.server.is_empty() || node.port == 0 {
        return Err("server and port must be valid".into());
    }
    if matches!(node.protocol, Protocol::Vless | Protocol::Vmess) && node.identity.is_none() {
        return Err("protocol identity is missing".into());
    }
    if matches!(
        node.protocol,
        Protocol::Trojan | Protocol::Shadowsocks | Protocol::Hysteria2
    ) && node.secret.is_none()
    {
        return Err("protocol secret is missing".into());
    }

    const VLESS_OPTIONS: &[&str] = &[
        "security", "tls", "sni", "encryption", "flow", "type", "host", "path",
        "serviceName", "service_name", "authority", "mode", "ed", "eh", "maxEarlyData",
        "earlyDataHeaderName", "max_early_data", "early_data_header_name", "max-early-data",
        "early-data-header-name", "pcs", "insecure", "allowInsecure", "vcn", "alpn", "fp",
    ];
    const VMESS_OPTIONS: &[&str] = &[
        "security", "tls", "sni", "aid", "scy", "net", "type", "host", "path", "headers",
        "serviceName", "service_name", "authority", "mode", "ed", "eh", "maxEarlyData",
        "earlyDataHeaderName", "max_early_data", "early_data_header_name", "max-early-data",
        "early-data-header-name", "pcs", "insecure", "allowInsecure", "vcn", "alpn", "fp",
    ];
    const TROJAN_OPTIONS: &[&str] = &[
        "security", "tls", "sni", "type", "host", "path", "serviceName", "service_name",
        "authority", "mode", "ed", "eh", "maxEarlyData", "earlyDataHeaderName",
        "max_early_data", "early_data_header_name", "max-early-data", "early-data-header-name",
        "pcs", "insecure", "allowInsecure", "vcn", "alpn", "fp",
    ];
    const HYSTERIA2_OPTIONS: &[&str] = &[
        "security", "tls", "sni", "insecure", "allowInsecure", "pinSHA256", "pcs", "alpn", "fp",
    ];

    let supported = match node.protocol {
        Protocol::Vless => VLESS_OPTIONS,
        Protocol::Vmess => VMESS_OPTIONS,
        Protocol::Trojan => TROJAN_OPTIONS,
        Protocol::Hysteria2 => HYSTERIA2_OPTIONS,
        Protocol::Shadowsocks => &[],
    };
    reject_unknown_options(node, &supported)?;
    validate_string_options(node)?;
    if !node.option_entries.is_empty() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in &node.option_entries {
            if entry.key != "alpn" && !seen.insert(entry.key.as_str()) {
                return Err(format!(
                    "option '{}' is repeated and cannot be mapped safely",
                    entry.key
                ));
            }
        }
    }
    alpn_protocols(node)?;
    let transport = normalize_transport(node)?;
    if node.protocol == Protocol::Vmess
        && option_string(node, "type").is_some_and(|value| {
            value != "none"
                && !(matches!(&transport.kind, TransportKind::Grpc)
                    && ["gun", "multi"].contains(&value))
                && !(matches!(&transport.kind, TransportKind::XHttp)
                    && ["auto", "packet-up", "stream-up", "stream-one"].contains(&value))
        })
    {
        return Err("VMess transport-specific header modes are not implemented for this network".into());
    }
    if !matches!(&transport.kind, TransportKind::Tcp | TransportKind::WebSocket | TransportKind::Grpc | TransportKind::Http2 | TransportKind::HttpUpgrade | TransportKind::XHttp) {
        return Err("transport is not implemented by this adapter batch".into());
    }

    if let Some(fingerprint) = option_string(node, "fp") {
        const SUPPORTED_FINGERPRINTS: &[&str] = &[
            "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random",
        ];
        if !SUPPORTED_FINGERPRINTS.contains(&fingerprint) {
            return Err("TLS fingerprint is not supported; use a common browser fingerprint".into());
        }
        if matches!(node.protocol, Protocol::Hysteria2) {
            return Err("TLS client fingerprints are not supported for Hysteria2".into());
        }
    }

    if node.protocol != Protocol::Vmess
        && option_string(node, "security").is_some()
        && option_string(node, "tls").is_some()
    {
        return Err(
            "both security and tls options were supplied; refusing ambiguous TLS settings".into(),
        );
    }

    if node.protocol == Protocol::Vless {
        if option_string(node, "encryption").is_some_and(|value| value != "none") {
            return Err("only VLESS encryption=none is currently mapped".into());
        }
        if option_string(node, "flow").is_some_and(|value| value != "xtls-rprx-vision") {
            return Err("only VLESS xtls-rprx-vision flow is currently mapped".into());
        }
        if option_string(node, "type").is_some_and(|value| !["tcp", "raw", "ws", "grpc", "h2", "httpupgrade", "xhttp"].contains(&value)) {
            return Err("only VLESS TCP, WebSocket, gRPC, HTTP/2, HTTP Upgrade, and XHTTP transports are currently mapped".into());
        }
    }
    if node.protocol == Protocol::Vmess {
        if option_string(node, "net").is_some_and(|value| !["tcp", "raw", "ws", "grpc", "h2", "httpupgrade", "xhttp"].contains(&value)) {
            return Err("only VMess TCP, WebSocket, gRPC, HTTP/2, HTTPUpgrade, and XHTTP transports are currently mapped".into());
        }
        let _ = vmess_alter_id(node)?;
        if option_string(node, "scy").is_some()
            && option_string(node, "security").is_some()
            && option_string(node, "scy") != option_string(node, "security")
        {
            return Err("VMess scy and security cipher aliases conflict".into());
        }
        if option_string(node, "scy")
            .or_else(|| option_string(node, "security"))
            .is_some_and(|value| {
                !["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"].contains(&value)
            })
        {
            return Err("VMess cipher is not supported by this adapter".into());
        }
    }
    Ok(())
}

