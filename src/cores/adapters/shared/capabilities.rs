//! Declarative per-core feature capabilities and compatibility evaluation.

use crate::{
    cores::CoreId,
    domain::{Protocol, ProxyNode, TransportKind},
};

use super::{Compatibility, normalize_transport, option_string, tls_options, validate_common};

#[derive(Clone, Copy, Debug)]
struct CoreCapabilities {
    hysteria2: bool,
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
            TransportKind::Http | TransportKind::Unknown(_) => false,
        }
    }
}

const SING_BOX: CoreCapabilities = CoreCapabilities {
    hysteria2: true,
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

const XRAY: CoreCapabilities = CoreCapabilities {
    hysteria2: false,
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

const MIHOMO: CoreCapabilities = CoreCapabilities {
    hysteria2: true,
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

fn capabilities(core: CoreId) -> &'static CoreCapabilities {
    match core {
        CoreId::SingBox => &SING_BOX,
        CoreId::Xray => &XRAY,
        CoreId::Mihomo => &MIHOMO,
    }
}

fn compatibility_failure(reason: String) -> Compatibility {
    let normalized = reason.to_ascii_lowercase();
    let invalid_markers = [
        "invalid", "must be", "must not", "conflict", "ambiguous", "repeated",
        "empty", "missing", "malformed", "control characters", "was supplied while",
        "requires tls", "certificate sha-256 pin must",
    ];
    if invalid_markers.iter().any(|marker| normalized.contains(marker)) {
        return Compatibility::invalid(reason);
    }

    let unsupported_markers = [
        "not supported", "not implemented", "does not support", "unsupported",
        "removed", "currently mapped", "not enabled", "requires an explicit",
        "requires the sec-websocket-protocol",
    ];
    if unsupported_markers.iter().any(|marker| normalized.contains(marker)) {
        return Compatibility::unsupported(reason);
    }

    Compatibility::invalid(reason)
}

/// Validate the shared semantic node against one core's explicit capability set.
pub(crate) fn validate_for_core(
    core: CoreId,
    node: &ProxyNode,
) -> Result<(), Compatibility> {
    validate_common(node).map_err(compatibility_failure)?;
    tls_options(node).map_err(compatibility_failure)?;
    let capabilities = capabilities(core);

    if node.protocol == Protocol::Hysteria2 && !capabilities.hysteria2 {
        return Err(compatibility_failure(format!("{core} does not implement Hysteria2")));
    }

    if option_string(node, "vcn").is_some() && !capabilities.verify_peer_cert_by_name {
        return Err(compatibility_failure(format!("{core} does not support separate certificate-name verification")));
    }

    if option_string(node, "pcs").or_else(|| option_string(node, "pinSHA256")).is_some() && !capabilities.certificate_sha256_pin {
        return Err(compatibility_failure(format!("{core} does not support the imported certificate SHA-256 pin")));
    }

    let transport = normalize_transport(node)?;
    if matches!(&transport.kind, TransportKind::XHttp)
        && node.protocol == Protocol::Vmess
        && core != CoreId::Xray
    {
        return Err(compatibility_failure(format!("{core} does not support VMess XHTTP")));
    }

    if !capabilities.supports_transport(&transport.kind) {
        return Err(compatibility_failure(format!("{core} does not support this transport")));
    }

    if core == CoreId::Xray
        && matches!(&transport.kind, TransportKind::WebSocket)
        && transport
            .early_data_header_name
            .as_deref()
            .is_some_and(|name| name != "Sec-WebSocket-Protocol")
    {
        return Err(compatibility_failure("Xray WebSocket early data requires the Sec-WebSocket-Protocol header".into()));
    }

    if matches!(&transport.kind, TransportKind::Grpc)
        && transport.authority.is_some()
        && !capabilities.grpc_authority
    {
        return Err(compatibility_failure(format!("{core} does not support gRPC authority")));
    }

    if matches!(&transport.kind, TransportKind::Grpc)
        && transport.mode.as_deref() == Some("multi")
        && !capabilities.grpc_multi_mode
    {
        return Err(compatibility_failure(format!("{core} does not support gRPC multi mode")));
    }

    if matches!(&transport.kind, TransportKind::Grpc)
        && capabilities.grpc_service_name_required
        && transport.service_name.as_deref().is_none_or(str::is_empty)
    {
        return Err(compatibility_failure(format!("{core} requires an explicit gRPC service name")));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_registry_keeps_core_differences_explicit() {
        assert!(!capabilities(CoreId::SingBox).xhttp);
        assert!(capabilities(CoreId::Xray).xhttp);
        assert!(!capabilities(CoreId::Xray).http2);
        assert!(capabilities(CoreId::Xray).certificate_sha256_pin);
        assert!(!capabilities(CoreId::SingBox).certificate_sha256_pin);
        assert!(capabilities(CoreId::Mihomo).certificate_sha256_pin);
        assert!(capabilities(CoreId::Xray).verify_peer_cert_by_name);
        assert!(!capabilities(CoreId::SingBox).verify_peer_cert_by_name);
        assert!(capabilities(CoreId::Mihomo).http2);
        assert!(capabilities(CoreId::Mihomo).grpc_service_name_required);
        assert!(capabilities(CoreId::Xray).grpc_authority);
        assert!(capabilities(CoreId::Xray).grpc_multi_mode);
        assert!(!capabilities(CoreId::Mihomo).grpc_authority);
    }
}
