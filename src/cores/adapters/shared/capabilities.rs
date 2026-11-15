//! Declarative per-core feature capabilities and compatibility evaluation.

use crate::domain::{Protocol, ProxyNode, TransportKind};

use super::{
    Compatibility, normalize_transport, option_string, reality_options, shadowsocks_plugin,
    tls_options, validate_common,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct CoreCapabilities {
    name: &'static str,
    shadowsocks_plugins: bool,
    reality_transport_limited: bool,
    vmess_xhttp: bool,
    xhttp_auto_mode: bool,
    websocket_early_data_header: Option<&'static str>,
    hysteria2: bool,
    reality_vless: bool,
    reality_vmess: bool,
    reality_optional_fields: bool,
    tcp: bool,
    websocket: bool,
    grpc: bool,
    http2: bool,
    http_upgrade: bool,
    xhttp: bool,
    grpc_service_name_required: bool,
    grpc_authority: bool,
    grpc_multi_mode: bool,
    certificate_sha256_pin: bool,
    verify_peer_cert_by_name: bool,
}

impl CoreCapabilities {
    fn supports_transport(self, transport: &TransportKind) -> bool {
        match transport {
            TransportKind::Tcp => self.tcp,
            TransportKind::WebSocket => self.websocket,
            TransportKind::Grpc => self.grpc,
            TransportKind::Http2 => self.http2,
            TransportKind::HttpUpgrade => self.http_upgrade,
            TransportKind::XHttp => self.xhttp,
            TransportKind::Unknown(_) => false,
        }
    }
}

pub(crate) const SING_BOX: CoreCapabilities = CoreCapabilities {
    name: "sing-box",
    shadowsocks_plugins: true,
    reality_transport_limited: true,
    vmess_xhttp: false,
    xhttp_auto_mode: true,
    websocket_early_data_header: None,
    hysteria2: true,
    reality_vless: true,
    reality_vmess: false,
    reality_optional_fields: false,
    tcp: true,
    websocket: true,
    grpc: true,
    http2: true,
    http_upgrade: true,
    xhttp: false,
    grpc_service_name_required: false,
    grpc_authority: false,
    grpc_multi_mode: false,
    certificate_sha256_pin: false,
    verify_peer_cert_by_name: false,
};

pub(crate) const XRAY: CoreCapabilities = CoreCapabilities {
    name: "Xray",
    shadowsocks_plugins: false,
    reality_transport_limited: true,
    vmess_xhttp: true,
    xhttp_auto_mode: true,
    websocket_early_data_header: Some("Sec-WebSocket-Protocol"),
    hysteria2: false,
    reality_vless: true,
    reality_vmess: true,
    reality_optional_fields: true,
    tcp: true,
    websocket: true,
    grpc: true,
    // The legacy HTTP/2 transport was removed from current Xray transport schemas.
    http2: false,
    http_upgrade: true,
    xhttp: true,
    grpc_service_name_required: false,
    grpc_authority: true,
    grpc_multi_mode: true,
    certificate_sha256_pin: true,
    verify_peer_cert_by_name: true,
};

pub(crate) const MIHOMO: CoreCapabilities = CoreCapabilities {
    name: "Mihomo",
    shadowsocks_plugins: true,
    reality_transport_limited: true,
    vmess_xhttp: false,
    xhttp_auto_mode: false,
    websocket_early_data_header: None,
    hysteria2: true,
    reality_vless: true,
    reality_vmess: false,
    reality_optional_fields: false,
    tcp: true,
    websocket: true,
    grpc: true,
    http2: true,
    http_upgrade: true,
    xhttp: true,
    grpc_service_name_required: true,
    grpc_authority: false,
    grpc_multi_mode: false,
    certificate_sha256_pin: true,
    verify_peer_cert_by_name: true,
};

fn compatibility_failure(reason: String) -> Compatibility {
    let normalized = reason.to_ascii_lowercase();
    if normalized.starts_with("option '") && normalized.contains("is not supported") {
        return Compatibility::unsupported(reason);
    }
    if normalized.starts_with("transport '") && normalized.contains("is not supported") {
        return Compatibility::unsupported(reason);
    }
    let invalid_markers = [
        "invalid",
        "fingerprint is not supported",
        "must be",
        "must not",
        "conflict",
        "ambiguous",
        "repeated",
        "empty",
        "missing",
        "malformed",
        "control characters",
        "was supplied while",
        "requires tls",
        "certificate sha-256 pin must",
    ];
    if invalid_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return Compatibility::invalid(reason);
    }

    let unsupported_markers = [
        "not supported",
        "not implemented",
        "does not support",
        "does not implement",
        "unsupported",
        "removed",
        "currently mapped",
        "not enabled",
        "requires an explicit",
        "requires the sec-websocket-protocol",
    ];
    if unsupported_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return Compatibility::unsupported(reason);
    }

    Compatibility::invalid(reason)
}

/// Validate the shared semantic node against one core's explicit capability set.
pub(crate) fn validate_for_core(capabilities: &'static CoreCapabilities, node: &ProxyNode) -> Result<(), Compatibility> {
    let core = capabilities.name;

    validate_common(node).map_err(compatibility_failure)?;
    tls_options(node).map_err(compatibility_failure)?;

    // Report valid Hysteria2 nodes as unsupported by Xray only after validating
    // their shared protocol semantics, so malformed source values remain Invalid.
    if node.protocol == Protocol::Hysteria2 && !capabilities.hysteria2 {
        return Err(Compatibility::unsupported(format!(
            "{core} does not implement Hysteria2"
        )));
    }
    if shadowsocks_plugin(node)
        .map_err(compatibility_failure)?
        .is_some()
        && !capabilities.shadowsocks_plugins
    {
        return Err(compatibility_failure(
            format!("{core} does not implement Shadowsocks SIP003 plugins"),
        ));
    }
    let reality = reality_options(node).map_err(compatibility_failure)?;
    if let Some(reality) = reality.as_ref() {
        let protocol_supported = match node.protocol {
            Protocol::Vless => capabilities.reality_vless,
            Protocol::Vmess => capabilities.reality_vmess,
            _ => false,
        };
        if !protocol_supported {
            return Err(compatibility_failure(format!(
                "{core} does not support REALITY for this protocol"
            )));
        }
        if !capabilities.reality_optional_fields
            && (reality.get("spider_x").is_some() || reality.get("mldsa65_verify").is_some())
        {
            return Err(compatibility_failure(format!(
                "{core} does not support the supplied optional REALITY fields"
            )));
        }
        let transport = normalize_transport(node).map_err(compatibility_failure)?;
        if capabilities.reality_transport_limited
            && !matches!(
                &transport.kind,
                TransportKind::Tcp | TransportKind::Grpc | TransportKind::XHttp
            )
        {
            return Err(compatibility_failure(
                "Xray REALITY supports only TCP/RAW, gRPC, and XHTTP transports".into(),
            ));
        }
        if capabilities.reality_transport_limited
            && matches!(
                &transport.kind,
                TransportKind::Http2 | TransportKind::HttpUpgrade | TransportKind::WebSocket
            )
        {
            return Err(compatibility_failure(
                "REALITY is not supported with this transport mapping".into(),
            ));
        }
    }

    if option_string(node, "vcn").is_some() && !capabilities.verify_peer_cert_by_name {
        return Err(compatibility_failure(format!(
            "{core} does not support separate certificate-name verification"
        )));
    }

    if option_string(node, "pcs")
        .or_else(|| option_string(node, "pinSHA256"))
        .is_some()
        && !capabilities.certificate_sha256_pin
    {
        return Err(compatibility_failure(format!(
            "{core} does not support the imported certificate SHA-256 pin"
        )));
    }

    let transport = normalize_transport(node).map_err(compatibility_failure)?;
    if matches!(&transport.kind, TransportKind::XHttp)
        && node.protocol == Protocol::Vmess
        && !capabilities.vmess_xhttp
    {
        return Err(compatibility_failure(format!(
            "{core} does not support VMess XHTTP"
        )));
    }
    if matches!(&transport.kind, TransportKind::XHttp)
        && !capabilities.xhttp_auto_mode
        && transport.mode.as_deref() == Some("auto")
    {
        return Err(compatibility_failure(
            format!("{core} XHTTP does not support the explicit auto mode"),
        ));
    }

    if !capabilities.supports_transport(&transport.kind) {
        return Err(compatibility_failure(format!(
            "{core} does not support this transport"
        )));
    }

    if let Some(required_header) = capabilities.websocket_early_data_header
        && matches!(&transport.kind, TransportKind::WebSocket)
        && transport.early_data_header_name.as_deref().is_some_and(|name| name != required_header)
    {
        return Err(compatibility_failure(
            format!("{core} WebSocket early data requires the Sec-WebSocket-Protocol header"),
        ));
    }

    if matches!(&transport.kind, TransportKind::Grpc)
        && transport.authority.is_some()
        && !capabilities.grpc_authority
    {
        return Err(compatibility_failure(format!(
            "{core} does not support gRPC authority"
        )));
    }

    if matches!(&transport.kind, TransportKind::Grpc)
        && transport.mode.as_deref() == Some("multi")
        && !capabilities.grpc_multi_mode
    {
        return Err(compatibility_failure(format!(
            "{core} does not support gRPC multi mode"
        )));
    }

    if matches!(&transport.kind, TransportKind::Grpc)
        && capabilities.grpc_service_name_required
        && transport.service_name.as_deref().is_none_or(str::is_empty)
    {
        return Err(compatibility_failure(format!(
            "{core} requires an explicit gRPC service name"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_profiles_keep_core_differences_explicit() {
        assert!(SING_BOX.reality_vless);
        assert!(!SING_BOX.reality_vmess);
        assert!(XRAY.reality_vmess);
        assert!(XRAY.reality_optional_fields);
        assert!(!MIHOMO.reality_optional_fields);
        assert!(!SING_BOX.xhttp);
        assert!(XRAY.xhttp);
        assert!(!XRAY.http2);
        assert!(XRAY.certificate_sha256_pin);
        assert!(!SING_BOX.certificate_sha256_pin);
        assert!(MIHOMO.certificate_sha256_pin);
        assert!(XRAY.verify_peer_cert_by_name);
        assert!(!SING_BOX.verify_peer_cert_by_name);
        assert!(MIHOMO.http2);
        assert!(MIHOMO.grpc_service_name_required);
        assert!(XRAY.grpc_authority);
        assert!(XRAY.grpc_multi_mode);
        assert!(!MIHOMO.grpc_authority);
        assert_eq!(XRAY.websocket_early_data_header, Some("Sec-WebSocket-Protocol"));
    }
}
