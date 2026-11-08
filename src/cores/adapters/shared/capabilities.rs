//! Declarative per-core feature capabilities and compatibility evaluation.

use crate::{
    cores::CoreId,
    domain::{Protocol, ProxyNode, TransportKind},
};

use super::{normalize_transport, validate_common};

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
};

fn capabilities(core: CoreId) -> &'static CoreCapabilities {
    match core {
        CoreId::SingBox => &SING_BOX,
        CoreId::Xray => &XRAY,
        CoreId::Mihomo => &MIHOMO,
    }
}

/// Validate the shared semantic node against one core's explicit capability set.
pub(crate) fn validate_for_core(core: CoreId, node: &ProxyNode) -> Result<(), String> {
    validate_common(node)?;
    let capabilities = capabilities(core);

    if node.protocol == Protocol::Hysteria2 && !capabilities.hysteria2 {
        return Err(format!("{core} does not implement Hysteria2"));
    }

    let transport = normalize_transport(node)?;
    if !capabilities.supports_transport(&transport.kind) {
        return Err(format!("{core} does not support this transport"));
    }

    if matches!(&transport.kind, TransportKind::Grpc)
        && capabilities.grpc_service_name_required
        && transport.service_name.as_deref().is_none_or(str::is_empty)
    {
        return Err(format!("{core} requires an explicit gRPC service name"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_registry_keeps_core_differences_explicit() {
        assert!(capabilities(CoreId::SingBox).xhttp == false);
        assert!(capabilities(CoreId::Xray).xhttp);
        assert!(!capabilities(CoreId::Xray).http2);
        assert!(capabilities(CoreId::Mihomo).http2);
        assert!(capabilities(CoreId::Mihomo).grpc_service_name_required);
    }
}
