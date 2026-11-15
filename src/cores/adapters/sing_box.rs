use std::{path::Path, process::Command};

use anyhow::ensure;
use serde_json::json;

use crate::{
    cores::CoreId,
    domain::{Protocol, ProxyNode},
};

use super::{
    CoreAdapter, json_config,
    shared::{
        Compatibility, CoreCapabilities, GeneratedConfig, normalize_transport, option_string,
        reality_options, shadowsocks_plugin, tls_options, validate_for_core,
    },
    summarize_validation_failure,
};

const CAPABILITIES: CoreCapabilities = CoreCapabilities {
    name: "sing-box",
    shadowsocks_plugins: true,
    reality_requires_tcp_grpc_xhttp: false,
    reality_disallows_legacy_transport: true,
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

pub struct SingBoxAdapter;

impl CoreAdapter for SingBoxAdapter {
    fn core(&self) -> CoreId {
        CoreId::SingBox
    }

    fn compatibility(&self, node: &ProxyNode) -> Compatibility {
        match validate_for_core(&CAPABILITIES, node) {
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
        if let Some(plugin) = shadowsocks_plugin(node).map_err(anyhow::Error::msg)? {
            outbound["plugin"] = json!(plugin.sing_box_name);
            outbound["plugin_opts"] = json!(plugin.sing_box_options);
        }
        if let Some(flow) = option_string(node, "flow") {
            outbound["flow"] = json!(flow);
        }
        if node.protocol == Protocol::Hysteria2
            && let Some(obfs) = option_string(node, "obfs")
        {
            outbound["obfs"] = json!({
                "type": obfs,
                "password": option_string(node, "obfs-password")
                    .or_else(|| option_string(node, "obfs_password"))
                    .unwrap_or_default()
            });
            if let Some(value) = option_string(node, "obfs-min-packet-size") {
                outbound["obfs"]["min_packet_size"] = json!(
                    value
                        .parse::<u16>()
                        .expect("validated Gecko minimum packet size")
                );
            }
            if let Some(value) = option_string(node, "obfs-max-packet-size") {
                outbound["obfs"]["max_packet_size"] = json!(
                    value
                        .parse::<u16>()
                        .expect("validated Gecko maximum packet size")
                );
            }
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
        if let Some(reality) = reality_options(node).map_err(anyhow::Error::msg)? {
            let mut tls = json!({
                "enabled": true,
                "reality": {
                    "enabled": true,
                    "public_key": reality["public_key"],
                    "short_id": reality["short_id"]
                },
                "utls": {
                    "enabled": true,
                    "fingerprint": reality["fingerprint"]
                }
            });
            if let Some(server_name) = reality.get("server_name") {
                tls["server_name"] = server_name.clone();
            }
            outbound["tls"] = tls;
        } else if let Some(mut tls) = tls_options(node).map_err(anyhow::Error::msg)? {
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

    fn generate_benchmark_batch_config(
        &self,
        targets: &[super::BenchmarkTarget<'_>],
    ) -> anyhow::Result<GeneratedConfig> {
        use serde_json::Value;
        super::benchmark_batch::validate_targets(self, targets)?;
        let mut outbounds = Vec::with_capacity(targets.len());
        let mut inbounds = Vec::with_capacity(targets.len());
        let mut rules = Vec::with_capacity(targets.len());
        for target in targets {
            let mut document = super::benchmark_batch::node_config(self, target.node)?;
            let node_outbounds = document
                .get_mut("outbounds")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| {
                    anyhow::anyhow!("sing-box node config must contain an outbound array")
                })?;
            ensure!(
                node_outbounds.len() == 1,
                "sing-box node config must contain exactly one proxy outbound"
            );
            let mut outbound = node_outbounds.remove(0);
            let outbound_tag = format!("proxyctl-benchmark-out-{}", target.node_id);
            let inbound_tag = format!("proxyctl-benchmark-in-{}", target.node_id);
            outbound["tag"] = json!(outbound_tag);
            outbounds.push(outbound);
            inbounds.push(json!({
                "type": match target.proxy_type {
                    crate::domain::BenchmarkProxyType::Socks5 => "socks",
                    crate::domain::BenchmarkProxyType::Http => "http",
                },
                "tag": inbound_tag, "listen": "127.0.0.1", "listen_port": target.listen_port
            }));
            rules.push(json!({"inbound": [inbound_tag], "outbound": outbound_tag}));
        }
        let final_outbound = format!("proxyctl-benchmark-out-{}", targets[0].node_id);
        json_config(
            json!({"inbounds": inbounds, "outbounds": outbounds, "route": {
                "rules": rules, "final": final_outbound
            }}),
        )
    }

    fn generate_activation_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig> {
        let generated = self.generate_config(node)?;
        let mut document: serde_json::Value = serde_json::from_slice(&generated.content)?;
        document["inbounds"] = json!([{
            "type": "mixed", "tag": "proxy-in", "listen": "127.0.0.1", "listen_port": listen_port
        }]);
        document["route"] = json!({"final": "proxy"});
        json_config(document)
    }

    fn generate_tun_activation_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig> {
        let generated = self.generate_activation_config(node, listen_port)?;
        let mut document: serde_json::Value = serde_json::from_slice(&generated.content)?;
        document["inbounds"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("sing-box activation inbounds must be an array"))?
            .push(json!({
                "type": "tun", "tag": "tun-in", "interface_name": "tun-proxyctl",
                "address": ["198.18.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 1500,
                "auto_route": false, "strict_route": false, "dns_mode": "disabled"
            }));
        document["route"] = json!({"final": "proxy", "auto_detect_interface": true});
        json_config(document)
    }

    fn generate_benchmark_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig> {
        let generated = self.generate_config(node)?;
        let mut document: serde_json::Value = serde_json::from_slice(&generated.content)?;
        document["inbounds"] = json!([{
            "type": "http", "tag": "benchmark-in", "listen": "127.0.0.1", "listen_port": listen_port
        }]);
        document["route"] = json!({"final": "proxy"});
        json_config(document)
    }

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()> {
        let mut command = Command::new(executable);
        command.arg("check").arg("-c").arg(config);
        let output =
            super::validation::run_validator(command, "could not run sing-box config validation")?;
        ensure!(
            output.status.success(),
            "sing-box rejected the generated configuration (exit status {:?}; {})",
            output.status.code(),
            summarize_validation_failure(&output.stdout, &output.stderr)
        );
        Ok(())
    }
}

#[cfg(test)]
mod config_contract_tests {
    use super::*;
    use crate::parser::parse_proxy_url;

    #[test]
    fn sing_box_activation_benchmark_and_tun_options_stay_core_native() {
        assert!(CAPABILITIES.hysteria2 && CAPABILITIES.reality_vless);
        assert!(
            !CAPABILITIES.reality_requires_tcp_grpc_xhttp
                && CAPABILITIES.reality_disallows_legacy_transport
        );
        assert!(!CAPABILITIES.reality_vmess && !CAPABILITIES.xhttp);
        assert!(!CAPABILITIES.certificate_sha256_pin);
        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();
        let activation: serde_json::Value = serde_json::from_slice(
            &SingBoxAdapter
                .generate_activation_config(&node, 43128)
                .unwrap()
                .content,
        )
        .unwrap();
        assert_eq!(activation["inbounds"][0]["type"], "mixed");
        assert_eq!(activation["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(activation["inbounds"][0]["listen_port"], 43128);

        let benchmark: serde_json::Value = serde_json::from_slice(
            &SingBoxAdapter
                .generate_benchmark_config(&node, 43129)
                .unwrap()
                .content,
        )
        .unwrap();
        assert_eq!(benchmark["inbounds"][0]["type"], "http");
        assert_eq!(benchmark["inbounds"][0]["listen_port"], 43129);

        let tun: serde_json::Value = serde_json::from_slice(
            &SingBoxAdapter
                .generate_tun_activation_config(&node, 43128)
                .unwrap()
                .content,
        )
        .unwrap();
        assert_eq!(tun["inbounds"][1]["type"], "tun");
        assert_eq!(tun["inbounds"][1]["auto_route"], false);
        assert_eq!(tun["inbounds"][1]["dns_mode"], "disabled");
    }
}
