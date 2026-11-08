use std::{path::Path, process::Command};

use anyhow::{Context, ensure};
use serde_json::json;

use crate::{
    cores::CoreId,
    domain::{Protocol, ProxyNode},
};

use super::{
    CoreAdapter, json_config,
    shared::{Compatibility, GeneratedConfig, normalize_transport, tls_options, validate_common},
};

pub struct XrayAdapter;

impl CoreAdapter for XrayAdapter {
    fn core(&self) -> CoreId {
        CoreId::Xray
    }

    fn compatibility(&self, node: &ProxyNode) -> Compatibility {
        if node.protocol == Protocol::Hysteria2 {
            return Compatibility::unsupported("Xray does not implement Hysteria2");
        }
        match validate_common(node) {
            Err(reason) => Compatibility::unsupported(reason),
            Ok(()) => match tls_options(node) {
                Ok(_) => Compatibility::supported(),
                Err(reason) => Compatibility::unsupported(reason),
            },
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
        let (protocol, settings) = match node.protocol {
            Protocol::Vless => (
                "vless",
                json!({"vnext":[{"address":node.server,"port":node.port,"users":[{"id":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"encryption":"none","flow":node.options.get("flow").cloned().unwrap_or_default()}]}]}),
            ),
            Protocol::Vmess => (
                "vmess",
                json!({"vnext":[{"address":node.server,"port":node.port,"users":[{"id":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"alterId":node.options.get("aid").and_then(|v|v.parse::<u32>().ok()).unwrap_or(0),"security":node.options.get("scy").map(String::as_str).unwrap_or("auto")}]}]}),
            ),
            Protocol::Trojan => (
                "trojan",
                json!({"servers":[{"address":node.server,"port":node.port,"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default()}]}),
            ),
            Protocol::Shadowsocks => (
                "shadowsocks",
                json!({"servers":[{"address":node.server,"port":node.port,"method":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default()}]}),
            ),
            Protocol::Hysteria2 => unreachable!("Hysteria2 rejected by compatibility"),
        };
        let mut outbound = json!({"protocol":protocol,"tag":"proxy","settings":settings,"streamSettings":{"network":"tcp"}});
        let transport = normalize_transport(node).map_err(anyhow::Error::msg)?;
        if matches!(&transport.kind, crate::domain::TransportKind::WebSocket) {
            outbound["streamSettings"]["network"] = json!("ws");
            let mut ws = serde_json::Map::new();
            if let Some(path) = transport.path {
                ws.insert("path".into(), json!(path));
            }
            if !transport.headers.is_empty() {
                ws.insert("headers".into(), json!(transport.headers));
            }
            outbound["streamSettings"]["wsSettings"] = serde_json::Value::Object(ws);
        } else if matches!(&transport.kind, crate::domain::TransportKind::Grpc) {
            outbound["streamSettings"]["network"] = json!("grpc");
            let mut grpc = serde_json::Map::new();
            if let Some(service_name) = transport.service_name {
                grpc.insert("serviceName".into(), json!(service_name));
            }
            outbound["streamSettings"]["grpcSettings"] = serde_json::Value::Object(grpc);
        } else if matches!(&transport.kind, crate::domain::TransportKind::Http2) {
            outbound["streamSettings"]["network"] = json!("h2");
            let mut http = serde_json::Map::new();
            if let Some(path) = transport.path {
                http.insert("path".into(), json!(path));
            }
            if !transport.hosts.is_empty() {
                http.insert("host".into(), json!(transport.hosts));
            }
            outbound["streamSettings"]["httpSettings"] = serde_json::Value::Object(http);
        } else if matches!(&transport.kind, crate::domain::TransportKind::HttpUpgrade) {
            outbound["streamSettings"]["network"] = json!("httpupgrade");
            let mut upgrade = serde_json::Map::new();
            if let Some(host) = transport.host {
                upgrade.insert("host".into(), json!(host));
            }
            if let Some(path) = transport.path {
                upgrade.insert("path".into(), json!(path));
            }
            if !transport.headers.is_empty() {
                upgrade.insert("headers".into(), json!(transport.headers));
            }
            outbound["streamSettings"]["httpupgradeSettings"] = serde_json::Value::Object(upgrade);
        } else if matches!(&transport.kind, crate::domain::TransportKind::XHttp) {
            outbound["streamSettings"]["network"] = json!("xhttp");
            let mut xhttp = serde_json::Map::new();
            if let Some(host) = transport.host {
                xhttp.insert("host".into(), json!(host));
            }
            if let Some(path) = transport.path {
                xhttp.insert("path".into(), json!(path));
            }
            if let Some(mode) = transport.mode {
                xhttp.insert("mode".into(), json!(mode));
            }
            outbound["streamSettings"]["xhttpSettings"] = serde_json::Value::Object(xhttp);
        }
        if let Some(tls) = tls_options(node).map_err(anyhow::Error::msg)? {
            let mut tls_settings = serde_json::Map::new();
            tls_settings.insert("allowInsecure".into(), serde_json::Value::Bool(false));
            if let Some(sni) = tls.get("server_name") {
                tls_settings.insert("serverName".into(), sni.clone());
            }
            if let Some(alpn) = tls.get("alpn") {
                tls_settings.insert("alpn".into(), alpn.clone());
            }
            if let Some(fingerprint) = tls.get("fingerprint") {
                tls_settings.insert("fingerprint".into(), fingerprint.clone());
            }
            outbound["streamSettings"]["security"] = json!("tls");
            outbound["streamSettings"]["tlsSettings"] = serde_json::Value::Object(tls_settings);
        }
        json_config(json!({"outbounds":[outbound]}))
    }

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()> {
        let output = Command::new(executable)
            .arg("run")
            .arg("-test")
            .arg("-c")
            .arg(config)
            .output()
            .context("could not run Xray config validation")?;
        ensure!(
            output.status.success(),
            "Xray rejected the generated configuration (exit status {:?})",
            output.status.code()
        );
        Ok(())
    }
}
