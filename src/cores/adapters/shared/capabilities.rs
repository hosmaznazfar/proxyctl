//! Declarative per-core feature capabilities and compatibility evaluation.

use crate::domain::{Protocol, ProxyNode, TransportKind};

use super::{
    Compatibility, normalize_transport, option_string, reality_options, shadowsocks_plugin,
    tls_options, validate_common,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct CoreCapabilities {
    pub(crate) name: &'static str,
    pub(crate) shadowsocks_plugins: bool,
    pub(crate) reality_requires_tcp_grpc_xhttp: bool,
    pub(crate) reality_disallows_legacy_transport: bool,
    pub(crate) vmess_xhttp: bool,
    pub(crate) xhttp_auto_mode: bool,
    pub(crate) websocket_early_data_header: Option<&'static str>,
    pub(crate) hysteria2: bool,
    pub(crate) reality_vless: bool,
    pub(crate) reality_vmess: bool,
    pub(crate) reality_optional_fields: bool,
    pub(crate) tcp: bool,
    pub(crate) websocket: bool,
    pub(crate) grpc: bool,
    pub(crate) http2: bool,
    pub(crate) http_upgrade: bool,
    pub(crate) xhttp: bool,
    pub(crate) grpc_service_name_required: bool,
    pub(crate) grpc_authority: bool,
    pub(crate) grpc_multi_mode: bool,
    pub(crate) certificate_sha256_pin: bool,
    pub(crate) verify_peer_cert_by_name: bool,
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
pub(crate) fn validate_for_core(
    capabilities: &'static CoreCapabilities,
    node: &ProxyNode,
) -> Result<(), Compatibility> {
    let core = capabilities.name;

    validate_common(node).map_err(compatibility_failure)?;
    tls_options(node).map_err(compatibility_failure)?;

    // Report valid Hysteria2 nodes as unsupported only after validating
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
        return Err(compatibility_failure(format!(
            "{core} does not implement Shadowsocks SIP003 plugins"
        )));
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
        if capabilities.reality_requires_tcp_grpc_xhttp
            && !matches!(
                &transport.kind,
                TransportKind::Tcp | TransportKind::Grpc | TransportKind::XHttp
            )
        {
            return Err(compatibility_failure(format!(
                "{core} REALITY supports only TCP/RAW, gRPC, and XHTTP transports"
            )));
        }
        if capabilities.reality_disallows_legacy_transport
            && matches!(
                &transport.kind,
                TransportKind::Http2 | TransportKind::HttpUpgrade | TransportKind::WebSocket
            )
        {
            return Err(compatibility_failure(format!(
                "{core} does not support REALITY with this transport mapping"
            )));
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
        return Err(compatibility_failure(format!(
            "{core} XHTTP does not support the explicit auto mode"
        )));
    }

    if !capabilities.supports_transport(&transport.kind) {
        return Err(compatibility_failure(format!(
            "{core} does not support this transport"
        )));
    }

    if let Some(required_header) = capabilities.websocket_early_data_header
        && matches!(&transport.kind, TransportKind::WebSocket)
        && transport
            .early_data_header_name
            .as_deref()
            .is_some_and(|name| name != required_header)
    {
        return Err(compatibility_failure(format!(
            "{core} WebSocket early data requires the Sec-WebSocket-Protocol header"
        )));
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
