//! Source-option to shared transport normalization.
//!
//! This module contains no core-specific configuration keys. Native serializers live in
//! individual adapters and consume the normalized Transport value.

use std::collections::BTreeMap;

use crate::domain::{Protocol, ProxyNode, Transport, TransportKind};

use super::option_string;

pub(crate) fn normalize_transport(node: &ProxyNode) -> Result<Transport, String> {
    let network_key = if node.protocol == Protocol::Vmess { "net" } else { "type" };
    let network = option_string(node, network_key).unwrap_or("tcp").to_ascii_lowercase();

    let kind = match network.as_str() {
        "" | "tcp" => TransportKind::Tcp,
        "ws" | "websocket" => TransportKind::WebSocket,
        "grpc" => TransportKind::Grpc,
        "http" => TransportKind::Http,
        "h2" | "http2" => TransportKind::Http2,
        "httpupgrade" | "http-upgrade" => TransportKind::HttpUpgrade,
        "xhttp" => TransportKind::XHttp,
        other => TransportKind::Unknown(other.to_owned()),
    };

    if !matches!(&kind, TransportKind::Tcp | TransportKind::WebSocket) {
        return Err(format!("transport '{network}' is not implemented by this adapter batch"));
    }

    let path = option_string(node, "path").map(str::to_owned);
    let mut headers = BTreeMap::new();

    if let Some(host) = option_string(node, "host") {
        if !host.is_empty() {
            headers.insert("Host".to_owned(), host.to_owned());
        }
    }

    // Some VMess JSON producers encode request headers as an object. Preserve and map
    // string-valued headers; reject malformed structures rather than dropping them.
    if let Some(value) = node.option("headers") {
        let object = value
            .as_object()
            .ok_or_else(|| "VMess headers must be a JSON object".to_owned())?;
        for (key, value) in object {
            let value = value
                .as_str()
                .ok_or_else(|| "transport header values must be strings".to_owned())?;
            if key.is_empty() || key.chars().any(char::is_control) {
                return Err("transport header names must be non-empty and contain no control characters".into());
            }
            if headers.insert(key.clone(), value.to_owned()).is_some() {
                return Err("transport Host/header values are ambiguous".into());
            }
        }
    }

    if matches!(&kind, TransportKind::Tcp) && (path.is_some() || !headers.is_empty()) {
        return Err("path or host/header was supplied for TCP transport".into());
    }

    Ok(Transport {
        kind,
        path,
        headers,
        service_name: None,
        mode: None,
    })
}
