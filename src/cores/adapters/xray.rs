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
        Compatibility, GeneratedConfig, normalize_transport, option_string, reality_options,
        tls_options, validate_for_core,
    },
};

pub struct XrayAdapter;

impl CoreAdapter for XrayAdapter {
    fn core(&self) -> CoreId {
        CoreId::Xray
    }

    fn compatibility(&self, node: &ProxyNode) -> Compatibility {
        match validate_for_core(CoreId::Xray, node) {
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
        let (protocol, settings) = match node.protocol {
            Protocol::Vless => (
                "vless",
                json!({"vnext":[{"address":node.server,"port":node.port,"users":[{"id":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"encryption":"none","flow":option_string(node, "flow").unwrap_or_default()}]}]}),
            ),
            Protocol::Vmess => (
                "vmess",
                json!({"vnext":[{"address":node.server,"port":node.port,"users":[{"id":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"alterId":node.options.get("aid").and_then(|v|v.parse::<u32>().ok()).unwrap_or(0),"security":option_string(node, "scy").or_else(|| option_string(node, "security")).unwrap_or("auto")}]}]}),
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
            let mut ws_path = transport.path.unwrap_or_default();
            if let Some(max_early_data) = transport.max_early_data {
                if ws_path.is_empty() {
                    ws_path.push('/');
                }
                let separator = if ws_path.contains('?') { '&' } else { '?' };
                ws_path.push(separator);
                ws_path.push_str(&format!("ed={max_early_data}"));
            }
            if !ws_path.is_empty() {
                ws.insert("path".into(), json!(ws_path));
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
            if let Some(authority) = transport.authority {
                grpc.insert("authority".into(), json!(authority));
            }
            if transport.mode.as_deref() == Some("multi") {
                grpc.insert("multiMode".into(), json!(true));
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
            if !transport.headers.is_empty() {
                xhttp.insert("headers".into(), json!(transport.headers));
            }
            if let Some(extra) = transport.xhttp_extra {
                xhttp.insert("extra".into(), extra);
            }
            outbound["streamSettings"]["xhttpSettings"] = serde_json::Value::Object(xhttp);
        }
        if let Some(reality) = reality_options(node).map_err(anyhow::Error::msg)? {
            let mut settings = serde_json::Map::new();
            settings.insert("fingerprint".into(), reality["fingerprint"].clone());
            settings.insert("password".into(), reality["public_key"].clone());
            settings.insert("shortId".into(), reality["short_id"].clone());
            if let Some(server_name) = reality.get("server_name") {
                settings.insert("serverName".into(), server_name.clone());
            }
            if let Some(spider_x) = reality.get("spider_x") {
                settings.insert("spiderX".into(), spider_x.clone());
            }
            if let Some(verify) = reality.get("mldsa65_verify") {
                settings.insert("mldsa65Verify".into(), verify.clone());
            }
            outbound["streamSettings"]["security"] = json!("reality");
            outbound["streamSettings"]["realitySettings"] = serde_json::Value::Object(settings);
        } else if let Some(tls) = tls_options(node).map_err(anyhow::Error::msg)? {
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
            if let Some(pin) = tls.get("certificate_sha256") {
                tls_settings.insert("pinnedPeerCertSha256".into(), pin.clone());
            }
            if let Some(insecure) = tls.get("insecure") {
                tls_settings.insert("allowInsecure".into(), insecure.clone());
            }
            if let Some(name) = tls.get("verify_peer_cert_by_name") {
                tls_settings.insert("verifyPeerCertByName".into(), name.clone());
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
