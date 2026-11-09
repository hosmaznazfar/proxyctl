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
        Compatibility, GeneratedConfig, normalize_transport, option_string, reality_options, tls_options,
        validate_for_core,
    },
};

pub struct MihomoAdapter;

impl CoreAdapter for MihomoAdapter {
    fn core(&self) -> CoreId {
        CoreId::Mihomo
    }

    fn compatibility(&self, node: &ProxyNode) -> Compatibility {
        match validate_for_core(CoreId::Mihomo, node) {
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
        let name = node
            .name
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("proxy");
        let mut proxy = match node.protocol {
            Protocol::Vless => {
                json!({"name":name,"type":"vless","server":node.server,"port":node.port,"uuid":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"network":"tcp"})
            }
            Protocol::Vmess => {
                json!({"name":name,"type":"vmess","server":node.server,"port":node.port,"uuid":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"alterId":node.options.get("aid").and_then(|v|v.parse::<u32>().ok()).unwrap_or(0),"cipher":option_string(node, "scy").or_else(|| option_string(node, "security")).unwrap_or("auto"),"network":"tcp"})
            }
            Protocol::Trojan => {
                json!({"name":name,"type":"trojan","server":node.server,"port":node.port,"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default(),"network":"tcp"})
            }
            Protocol::Shadowsocks => {
                json!({"name":name,"type":"ss","server":node.server,"port":node.port,"cipher":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default()})
            }
            Protocol::Hysteria2 => {
                json!({"name":name,"type":"hysteria2","server":node.server,"port":node.port,"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default()})
            }
        };
        if let Some(flow) = option_string(node, "flow") {
            proxy["flow"] = json!(flow);
        }
        if node.protocol == Protocol::Hysteria2
            && let Some(obfs) = option_string(node, "obfs")
        {
            proxy["obfs"] = json!(obfs);
            proxy["obfs-password"] = json!(
                option_string(node, "obfs-password")
                    .or_else(|| option_string(node, "obfs_password"))
                    .unwrap_or_default()
            );
        }

        let transport = normalize_transport(node).map_err(anyhow::Error::msg)?;
        if matches!(&transport.kind, crate::domain::TransportKind::WebSocket) {
            proxy["network"] = json!("ws");
            let mut ws = serde_json::Map::new();
            if let Some(path) = transport.path {
                ws.insert("path".into(), json!(path));
            }
            if !transport.headers.is_empty() {
                ws.insert("headers".into(), json!(transport.headers));
            }
            if let Some(max_early_data) = transport.max_early_data {
                ws.insert("max-early-data".into(), json!(max_early_data));
                ws.insert(
                    "early-data-header-name".into(),
                    json!(
                        transport
                            .early_data_header_name
                            .unwrap_or_else(|| "Sec-WebSocket-Protocol".into())
                    ),
                );
            }
            proxy["ws-opts"] = serde_json::Value::Object(ws);
        } else if matches!(&transport.kind, crate::domain::TransportKind::Grpc) {
            proxy["network"] = json!("grpc");
            let mut grpc = serde_json::Map::new();
            if let Some(service_name) = transport.service_name {
                grpc.insert("grpc-service-name".into(), json!(service_name));
            }
            proxy["grpc-opts"] = serde_json::Value::Object(grpc);
        } else if matches!(&transport.kind, crate::domain::TransportKind::Http2) {
            proxy["network"] = json!("h2");
            let mut http = serde_json::Map::new();
            if let Some(path) = transport.path {
                http.insert("path".into(), json!(path));
            }
            if !transport.hosts.is_empty() {
                http.insert("host".into(), json!(transport.hosts));
            }
            proxy["h2-opts"] = serde_json::Value::Object(http);
        } else if matches!(&transport.kind, crate::domain::TransportKind::HttpUpgrade) {
            proxy["network"] = json!("ws");
            let mut upgrade = serde_json::Map::new();
            upgrade.insert("v2ray-http-upgrade".into(), json!(true));
            if let Some(path) = transport.path {
                upgrade.insert("path".into(), json!(path));
            }
            let mut headers = transport.headers;
            if let Some(host) = transport.host {
                headers.insert("Host".into(), host);
            }
            if !headers.is_empty() {
                upgrade.insert("headers".into(), json!(headers));
            }
            proxy["ws-opts"] = serde_json::Value::Object(upgrade);
        } else if matches!(&transport.kind, crate::domain::TransportKind::XHttp) {
            proxy["network"] = json!("xhttp");
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
            proxy["xhttp-opts"] = serde_json::Value::Object(xhttp);
        }
        if let Some(reality) = reality_options(node).map_err(anyhow::Error::msg)? {
            proxy["tls"] = json!(true);
            proxy["reality-opts"] = json!({
                "public-key": reality["public_key"],
                "short-id": reality["short_id"]
            });
            proxy["client-fingerprint"] = reality["fingerprint"].clone();
            if let Some(server_name) = reality.get("server_name") {
                proxy["servername"] = server_name.clone();
            }
        } else if let Some(tls) = tls_options(node).map_err(anyhow::Error::msg)? {
            proxy["tls"] = json!(true);
            if let Some(sni) = tls.get("server_name") {
                proxy["servername"] = sni.clone();
            }
            if let Some(alpn) = tls.get("alpn") {
                proxy["alpn"] = alpn.clone();
            }
            if let Some(fingerprint) = tls.get("fingerprint") {
                proxy["client-fingerprint"] = fingerprint.clone();
            }
            if let Some(pin) = tls.get("certificate_sha256") {
                proxy["fingerprint"] = pin.clone();
            }
            if let Some(insecure) = tls.get("insecure") {
                proxy["skip-cert-verify"] = insecure.clone();
            }
            if let Some(name) = tls.get("verify_peer_cert_by_name") {
                proxy["name-cert-verify"] = name.clone();
            }
        }
        json_config(json!({
            "allow-lan": false,
            "mode": "rule",
            "proxies": [proxy],
            "proxy-groups": [{"name":"PROXY","type":"select","proxies":[name]}],
            "rules": ["MATCH,PROXY"]
        }))
    }

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()> {
        let output = Command::new(executable)
            .arg("-t")
            .arg("-f")
            .arg(config)
            .output()
            .context("could not run Mihomo config validation")?;
        ensure!(
            output.status.success(),
            "Mihomo rejected the generated configuration (exit status {:?})",
            output.status.code()
        );
        Ok(())
    }
}
