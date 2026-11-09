use std::{path::Path, process::Command};

use anyhow::{Context, ensure};
use serde_json::json;

use crate::{
    cores::CoreId,
    domain::{Protocol, ProxyNode},
};

use super::{
    CoreAdapter, json_config,
    shared::{
        Compatibility, GeneratedConfig, normalize_transport, option_string, tls_options,
        validate_for_core,
    },
};

pub struct SingBoxAdapter;

impl CoreAdapter for SingBoxAdapter {
    fn core(&self) -> CoreId {
        CoreId::SingBox
    }

    fn compatibility(&self, node: &ProxyNode) -> Compatibility {
        match validate_for_core(CoreId::SingBox, node) {
            Ok(()) => Compatibility::supported(),
            Err(compatibility) => compatibility,
        }
    }
    fn generate_config(&self, node: &ProxyNode) -> anyhow::Result<GeneratedConfig> {
        let compatibility = self.compatibility(node);
        ensure!(
            compatibility.is_supported(),
            "{}",
            compatibility
                .reason
                .unwrap_or_else(|| "node is incompatible".into())
        );
        let mut outbound = match node.protocol {
            Protocol::Vless => json!({
                "type": "vless", "tag": "proxy", "server": node.server, "server_port": node.port,
                "uuid": node.identity.as_ref().map(|v| v.expose()).unwrap_or_default()
            }),
            Protocol::Vmess => json!({
                "type": "vmess", "tag": "proxy", "server": node.server, "server_port": node.port,
                "uuid": node.identity.as_ref().map(|v| v.expose()).unwrap_or_default(),
                "alter_id": node.options.get("aid").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0),
                "security": option_string(node, "scy").or_else(|| option_string(node, "security")).unwrap_or("auto")
            }),
            Protocol::Trojan => json!({
                "type": "trojan", "tag": "proxy", "server": node.server, "server_port": node.port,
                "password": node.secret.as_ref().map(|v| v.expose()).unwrap_or_default()
            }),
            Protocol::Shadowsocks => json!({
                "type": "shadowsocks", "tag": "proxy", "server": node.server, "server_port": node.port,
                "method": node.identity.as_ref().map(|v| v.expose()).unwrap_or_default(),
                "password": node.secret.as_ref().map(|v| v.expose()).unwrap_or_default()
            }),
            Protocol::Hysteria2 => json!({
                "type": "hysteria2", "tag": "proxy", "server": node.server, "server_port": node.port,
                "password": node.secret.as_ref().map(|v| v.expose()).unwrap_or_default()
            }),
        };
        if let Some(flow) = option_string(node, "flow") {
            outbound["flow"] = json!(flow);
        }
        let transport = normalize_transport(node).map_err(anyhow::Error::msg)?;
        if matches!(&transport.kind, crate::domain::TransportKind::WebSocket) {
            let mut ws = serde_json::Map::new();
            ws.insert("type".into(), json!("ws"));
            if let Some(path) = transport.path {
                ws.insert("path".into(), json!(path));
            }
            if !transport.headers.is_empty() {
                ws.insert("headers".into(), json!(transport.headers));
            }
            if let Some(max_early_data) = transport.max_early_data {
                ws.insert("max_early_data".into(), json!(max_early_data));
                ws.insert(
                    "early_data_header_name".into(),
                    json!(
                        transport
                            .early_data_header_name
                            .unwrap_or_else(|| "Sec-WebSocket-Protocol".into())
                    ),
                );
            }
            outbound["transport"] = serde_json::Value::Object(ws);
        } else if matches!(&transport.kind, crate::domain::TransportKind::Grpc) {
            let mut grpc = serde_json::Map::new();
            grpc.insert("type".into(), json!("grpc"));
            if let Some(service_name) = transport.service_name {
                grpc.insert("service_name".into(), json!(service_name));
            }
            outbound["transport"] = serde_json::Value::Object(grpc);
        } else if matches!(&transport.kind, crate::domain::TransportKind::Http2) {
            let mut http = serde_json::Map::new();
            http.insert("type".into(), json!("http"));
            if let Some(path) = transport.path {
                http.insert("path".into(), json!(path));
            }
            if !transport.hosts.is_empty() {
                http.insert("host".into(), json!(transport.hosts));
            }
            outbound["transport"] = serde_json::Value::Object(http);
        } else if matches!(&transport.kind, crate::domain::TransportKind::HttpUpgrade) {
            let mut upgrade = serde_json::Map::new();
            upgrade.insert("type".into(), json!("httpupgrade"));
            if let Some(host) = transport.host {
                upgrade.insert("host".into(), json!(host));
            }
            if let Some(path) = transport.path {
                upgrade.insert("path".into(), json!(path));
            }
            if !transport.headers.is_empty() {
                upgrade.insert("headers".into(), json!(transport.headers));
            }
            outbound["transport"] = serde_json::Value::Object(upgrade);
        }
        if let Some(mut tls) = tls_options(node).map_err(anyhow::Error::msg)? {
            if let Some(fingerprint) = tls
                .as_object_mut()
                .and_then(|options| options.remove("fingerprint"))
            {
                tls["utls"] = json!({"enabled": true, "fingerprint": fingerprint});
            }
            outbound
                .as_object_mut()
                .expect("outbound object")
                .insert("tls".into(), tls);
        }
        json_config(json!({ "outbounds": [outbound] }))
    }

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()> {
        let output = Command::new(executable)
            .arg("check")
            .arg("-c")
            .arg(config)
            .output()
            .context("could not run sing-box config validation")?;
        ensure!(
            output.status.success(),
            "sing-box rejected the generated configuration (exit status {:?})",
            output.status.code()
        );
        Ok(())
    }
}
