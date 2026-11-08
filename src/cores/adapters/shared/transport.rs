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

    if !matches!(&kind, TransportKind::Tcp | TransportKind::WebSocket | TransportKind::Grpc | TransportKind::Http2 | TransportKind::HttpUpgrade | TransportKind::XHttp) {
        return Err(format!("transport '{network}' is not implemented by this adapter batch"));
    }

    let path = option_string(node, "path").map(str::to_owned);
    let mut headers = BTreeMap::new();
    let mut hosts = Vec::new();
    let mut host = None;
    let source_host = option_string(node, "host").filter(|value| !value.is_empty());
    if matches!(&kind, TransportKind::WebSocket) {
        if let Some(host) = source_host {
            headers.insert("Host".to_owned(), host.to_owned());
        }
    } else if matches!(&kind, TransportKind::HttpUpgrade) {
        host = source_host.map(str::to_owned);
    } else if matches!(&kind, TransportKind::XHttp | TransportKind::HttpUpgrade) {
        host = source_host.map(str::to_owned);
    } else if matches!(&kind, TransportKind::Http2) {
        if let Some(host) = source_host {
            hosts.extend(host.split(',').map(str::trim).filter(|host| !host.is_empty()).map(str::to_owned));
            if hosts.is_empty() || hosts.iter().any(|host| host.chars().any(char::is_control)) {
                return Err("HTTP/2 host list is invalid".into());
            }
        }
    } else if source_host.is_some() {
        return Err("host is not supported for this transport".into());
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

    let mode = option_string(node, "mode").map(str::to_owned);
    if matches!(&kind, TransportKind::XHttp) {
        if node.protocol != Protocol::Vless {
            return Err("XHTTP transport is only supported for VLESS".into());
        }
        if mode.as_deref().is_some_and(|value| !["auto", "packet-up", "stream-up", "stream-one"].contains(&value)) {
            return Err("XHTTP mode is invalid".into());
        }
    } else if mode.is_some() && !matches!(&kind, TransportKind::Grpc) {
        return Err("mode is only mapped for gRPC and XHTTP transports".into());
    }

    let service_name = if matches!(&kind, TransportKind::Grpc) {
        let value = if node.protocol == Protocol::Vmess {
            option_string(node, "path")
        } else {
            option_string(node, "serviceName").or_else(|| option_string(node, "service_name"))
        };
        if !headers.is_empty() {
            return Err("HTTP Host headers are not valid gRPC service-name settings".into());
        }
        value.map(str::to_owned)
    } else {
        None
    };

    if matches!(&kind, TransportKind::Tcp) && (path.is_some() || !headers.is_empty() || !hosts.is_empty()) {
        return Err("path or host/header was supplied for TCP transport".into());
    }
    if matches!(&kind, TransportKind::Grpc) && path.is_some() && node.protocol != Protocol::Vmess {
        return Err("gRPC URI service names must use the serviceName parameter".into());
    }
    if !matches!(&kind, TransportKind::WebSocket | TransportKind::HttpUpgrade) && !headers.is_empty() {
        return Err("HTTP headers are only mapped for WebSocket in this adapter batch".into());
    }

    Ok(Transport {
        kind,
        path,
        headers,
        hosts,
        host,
        service_name,
        mode,
    })
}
