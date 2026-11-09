//! Source-option to shared transport normalization.
//!
//! This module contains no core-specific configuration keys. Native serializers live in
//! individual adapters and consume the normalized Transport value.

use std::collections::BTreeMap;

use crate::domain::{Protocol, ProxyNode, Transport, TransportKind};

use super::option_string;

pub(crate) fn normalize_transport(node: &ProxyNode) -> Result<Transport, String> {
    let network_key = if node.protocol == Protocol::Vmess {
        "net"
    } else {
        "type"
    };
    let network = option_string(node, network_key)
        .unwrap_or("tcp")
        .to_ascii_lowercase();

    let kind = match network.as_str() {
        "" | "tcp" | "raw" => TransportKind::Tcp,
        "ws" | "websocket" => TransportKind::WebSocket,
        "grpc" => TransportKind::Grpc,
        "http" => TransportKind::Http,
        "h2" | "http2" => TransportKind::Http2,
        "httpupgrade" | "http-upgrade" => TransportKind::HttpUpgrade,
        "xhttp" => TransportKind::XHttp,
        other => TransportKind::Unknown(other.to_owned()),
    };

    if !matches!(
        &kind,
        TransportKind::Tcp
            | TransportKind::WebSocket
            | TransportKind::Grpc
            | TransportKind::Http2
            | TransportKind::HttpUpgrade
            | TransportKind::XHttp
    ) {
        return Err("transport type is not supported by this adapter batch".into());
    }

    if matches!(&kind, TransportKind::Http2)
        && !matches!(node.protocol, Protocol::Vless | Protocol::Vmess)
    {
        return Err("HTTP/2 transport is only mapped for VLESS and VMess".into());
    }

    let path = if matches!(&kind, TransportKind::Grpc) && node.protocol != Protocol::Vmess {
        None
    } else {
        option_string(node, "path").map(str::to_owned)
    };
    let mut headers = BTreeMap::new();
    let mut hosts = Vec::new();
    let mut host = None;
    let mut authority = None;
    let source_host = option_string(node, "host");
    if matches!(&kind, TransportKind::WebSocket) {
        if let Some(host) = source_host {
            headers.insert("Host".to_owned(), host.to_owned());
        }
    } else if matches!(&kind, TransportKind::Grpc) {
        let authority_values = [option_string(node, "authority"), source_host]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if authority_values
            .windows(2)
            .any(|values| values[0] != values[1])
        {
            return Err("gRPC authority aliases conflict".into());
        }
        authority = authority_values.first().map(|value| (*value).to_owned());
    } else if matches!(&kind, TransportKind::XHttp | TransportKind::HttpUpgrade) {
        host = source_host.map(str::to_owned);
    } else if matches!(&kind, TransportKind::Http2) {
        if let Some(host) = source_host {
            let values = host.split(',').map(str::trim).collect::<Vec<_>>();
            if values
                .iter()
                .any(|value| value.is_empty() || value.chars().any(char::is_control))
            {
                return Err("HTTP/2 host list is invalid".into());
            }
            hosts.extend(values.into_iter().map(str::to_owned));
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
            if key.is_empty()
                || key.chars().any(char::is_control)
                || value.chars().any(char::is_control)
            {
                return Err(
                    "transport header names must be non-empty and contain no control characters"
                        .into(),
                );
            }
            if headers
                .keys()
                .any(|existing| existing.eq_ignore_ascii_case(key))
            {
                return Err("transport Host/header values are ambiguous".into());
            }
            let key = if key.eq_ignore_ascii_case("host") {
                "Host".to_owned()
            } else {
                key.clone()
            };
            if headers.insert(key, value.to_owned()).is_some() {
                return Err("transport Host/header values are ambiguous".into());
            }
        }
    }

    let mut mode = option_string(node, "mode").map(str::to_owned);
    if matches!(&kind, TransportKind::Grpc) {
        if node.protocol == Protocol::Vmess {
            let type_mode = match option_string(node, "type") {
                Some("gun" | "multi") => option_string(node, "type").map(str::to_owned),
                Some("none") | None => None,
                Some(_) => return Err("VMess gRPC mode must be gun or multi".into()),
            };
            if mode.is_some() && type_mode.is_some() && mode != type_mode {
                return Err("VMess gRPC mode fields conflict".into());
            }
            mode = type_mode.or(mode);
        }
        if mode
            .as_deref()
            .is_some_and(|value| !["gun", "multi"].contains(&value))
        {
            return Err("gRPC mode must be gun or multi".into());
        }
    }
    let early_data_raw = option_string(node, "ed")
        .or_else(|| option_string(node, "maxEarlyData"))
        .or_else(|| option_string(node, "max_early_data"))
        .or_else(|| option_string(node, "max-early-data"));
    let max_early_data = early_data_raw
        .map(|value| {
            value.parse::<u32>().map_err(|_| {
                "WebSocket early-data size must be a valid unsigned integer".to_owned()
            })
        })
        .transpose()?;
    let early_data_header_name = option_string(node, "eh")
        .or_else(|| option_string(node, "earlyDataHeaderName"))
        .or_else(|| option_string(node, "early_data_header_name"))
        .or_else(|| option_string(node, "early-data-header-name"))
        .map(str::to_owned);
    if max_early_data.is_some_and(|value| value > 8192) {
        return Err("WebSocket early-data size must not exceed 8192 bytes".into());
    }
    if early_data_header_name
        .as_deref()
        .is_some_and(|value| value.is_empty() || value.chars().any(char::is_control))
    {
        return Err("WebSocket early-data header name is invalid".into());
    }
    if early_data_header_name.is_some() && max_early_data.is_none() {
        return Err("WebSocket early-data header requires an early-data size".into());
    }
    if (max_early_data.is_some() || early_data_header_name.is_some())
        && !matches!(&kind, TransportKind::WebSocket)
    {
        return Err("early-data options are only mapped for WebSocket".into());
    }
    if matches!(&kind, TransportKind::XHttp) {
        if !matches!(node.protocol, Protocol::Vless | Protocol::Vmess) {
            return Err("XHTTP transport is only supported for VLESS and VMess".into());
        }
        if node.protocol == Protocol::Vmess {
            let type_mode = option_string(node, "type").map(str::to_owned);
            if mode.is_some() && type_mode.is_some() && mode != type_mode {
                return Err("VMess XHTTP mode fields conflict".into());
            }
            mode = type_mode.or(mode);
        }
        if mode
            .as_deref()
            .is_some_and(|value| !["auto", "packet-up", "stream-up", "stream-one"].contains(&value))
        {
            return Err("XHTTP mode is invalid".into());
        }
    } else if mode.is_some() && !matches!(&kind, TransportKind::Grpc) {
        return Err("mode is only mapped for gRPC and XHTTP transports".into());
    }

    let service_name = if matches!(&kind, TransportKind::Grpc) {
        let service_values = [
            option_string(node, "serviceName"),
            option_string(node, "service_name"),
            option_string(node, "path"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        if service_values
            .windows(2)
            .any(|values| values[0] != values[1])
        {
            return Err("gRPC service-name aliases conflict".into());
        }
        if !headers.is_empty() {
            return Err("HTTP headers are not valid gRPC settings".into());
        }
        service_values.first().map(|value| (*value).to_owned())
    } else {
        None
    };

    if path
        .as_deref()
        .is_some_and(|value| value.chars().any(char::is_control))
    {
        return Err("transport path contains control characters".into());
    }
    if host
        .as_deref()
        .is_some_and(|value| value.chars().any(char::is_control))
    {
        return Err("transport host contains control characters".into());
    }
    if authority
        .as_deref()
        .is_some_and(|value| value.chars().any(char::is_control))
    {
        return Err("gRPC authority contains control characters".into());
    }
    if service_name
        .as_deref()
        .is_some_and(|value| value.chars().any(char::is_control))
    {
        return Err("gRPC service name contains control characters".into());
    }
    if matches!(&kind, TransportKind::HttpUpgrade)
        && host.is_some()
        && headers.keys().any(|key| key.eq_ignore_ascii_case("host"))
    {
        return Err("HTTP Upgrade host and Host header were both supplied".into());
    }
    if matches!(&kind, TransportKind::Tcp)
        && (path.is_some() || host.is_some() || !headers.is_empty() || !hosts.is_empty())
    {
        return Err("path or host/header was supplied for TCP transport".into());
    }
    if !matches!(&kind, TransportKind::WebSocket | TransportKind::HttpUpgrade)
        && !headers.is_empty()
    {
        return Err("HTTP headers are only mapped for WebSocket in this adapter batch".into());
    }

    Ok(Transport {
        kind,
        path,
        headers,
        hosts,
        host,
        authority,
        service_name,
        mode,
        max_early_data,
        early_data_header_name,
    })
}
