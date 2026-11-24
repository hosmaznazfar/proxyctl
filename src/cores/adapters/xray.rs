use std::{path::Path, process::Command};

use anyhow::ensure;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    cores::CoreId,
    domain::{Protocol, ProxyNode},
};

use super::{
    CoreAdapter, json_config,
    shared::{
        Compatibility, CoreCapabilities, GeneratedConfig, normalize_transport, option_string,
        reality_options, tls_options, validate_for_core,
    },
};

const CAPABILITIES: CoreCapabilities = CoreCapabilities {
    name: "Xray",
    shadowsocks_plugins: false,
    reality_requires_tcp_grpc_xhttp: true,
    reality_disallows_legacy_transport: false,
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
    http2: false,
    http_upgrade: true,
    xhttp: true,
    grpc_service_name_required: false,
    grpc_authority: true,
    grpc_multi_mode: true,
    certificate_sha256_pin: true,
    verify_peer_cert_by_name: true,
};

pub struct XrayAdapter;

impl CoreAdapter for XrayAdapter {
    fn core(&self) -> CoreId {
        CoreId::Xray
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
            if let Some(host) = transport.headers.get("Host") {
                // Xray's native WebSocket schema uses wsSettings.host (not headers.Host).
                ws.insert("host".into(), json!(host));
            }
            let additional_headers = transport
                .headers
                .into_iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
                .map(|(name, value)| (name, json!(value)))
                .collect::<serde_json::Map<_, _>>();
            if !additional_headers.is_empty() {
                ws.insert("headers".into(), json!(additional_headers));
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
                    anyhow::anyhow!("Xray node config must contain an outbound array")
                })?;
            ensure!(
                node_outbounds.len() == 1,
                "Xray node config must contain exactly one proxy outbound"
            );
            let mut outbound = node_outbounds.remove(0);
            let outbound_tag = format!("proxyctl-benchmark-out-{}", target.node_id);
            let inbound_tag = format!("proxyctl-benchmark-in-{}", target.node_id);
            outbound["tag"] = json!(outbound_tag);
            outbounds.push(outbound);
            // Match the already-used activation listener. Xray's mixed inbound
            // accepts both HTTP CONNECT and SOCKS5, avoiding divergent benchmark-only
            // listener settings for the same proxy outbound.
            inbounds.push(json!({
                "listen": "127.0.0.1", "port": target.listen_port,
                "protocol": "mixed",
                "settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
                "tag": inbound_tag
            }));
            rules.push(
                json!({"type": "field", "inboundTag": [inbound_tag], "outboundTag": outbound_tag}),
            );
        }
        json_config(
            json!({"inbounds": inbounds, "outbounds": outbounds, "routing": {
                "domainStrategy": "AsIs", "rules": rules
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
            "listen": "127.0.0.1", "port": listen_port, "protocol": "mixed",
            "settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"}, "tag": "proxy-in"
        }]);
        json_config(document)
    }

    #[cfg(target_os = "linux")]
    fn tun_attachment_mode(&self) -> super::TunAttachmentMode {
        super::TunAttachmentMode::ExternalDescriptorEnvironment {
            variable: super::XRAY_TUN_FD_ENV,
        }
    }

    fn generate_tun_activation_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
        mark: super::TunOutboundMark,
    ) -> anyhow::Result<GeneratedConfig> {
        let generated = self.generate_activation_config(node, listen_port)?;
        let mut document: serde_json::Value = serde_json::from_slice(&generated.content)?;
        document["inbounds"]
            .as_array_mut()
            .ok_or_else(|| anyhow::anyhow!("Xray activation inbounds must be an array"))?
            .push(json!({
                "tag": "tun-in", "protocol": "tun", "port": 0,
                "settings": {
                    "name": super::XRAY_TUN_INTERFACE_NAME, "mtu": 1500,
                    "gateway": ["198.18.0.1/30", "fdfe:dcba:9876::1/126"],
                    "autoSystemRoutingTable": [], "autoOutboundsInterface": "auto",
                    "autoSystemDnsToGateway": false
                },
                "sniffing": {
                    "enabled": true,
                    "destOverride": ["http", "tls"],
                    "routeOnly": true
                }
            }));
        let outbounds = document
            .get_mut("outbounds")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(|| anyhow::anyhow!("Xray TUN config must contain an outbound array"))?;
        anyhow::ensure!(
            outbounds.len() == 1 && outbounds[0]["tag"] == "proxy",
            "Xray TUN config must contain exactly the tagged proxy outbound"
        );
        outbounds[0]["streamSettings"]["sockopt"]["mark"] = json!(mark.value());
        json_config(document)
    }

    fn generate_benchmark_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig> {
        let generated = self.generate_config(node)?;
        let mut document: serde_json::Value = serde_json::from_slice(&generated.content)?;
        // Keep benchmark traffic on the same proven loopback listener contract
        // as managed activation. The mixed inbound accepts both HTTP CONNECT and SOCKS5.
        document["inbounds"] = json!([{
            "listen": "127.0.0.1", "port": listen_port, "protocol": "mixed",
            "settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
            "tag": "benchmark-in"
        }]);
        json_config(document)
    }

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()> {
        let mut command = Command::new(executable);
        command.arg("run").arg("-test").arg("-c").arg(config);
        let output =
            super::validation::run_validator(command, "could not run Xray config validation")?;
        ensure!(
            output.status.success(),
            "Xray rejected the generated configuration (exit status {:?}; {}).{}",
            output.status.code(),
            summarize_validation_failure(&output.stdout, &output.stderr),
            if std::env::var_os("PROXYCTL_SHOW_CORE_DIAGNOSTICS").is_some() {
                format!(
                    "\nXray native diagnostics (PROXYCTL_SHOW_CORE_DIAGNOSTICS is enabled; may contain server addresses, paths, or other sensitive config values):\n{}",
                    detailed_validation_output(&output.stdout, &output.stderr)
                )
            } else {
                "\nFor the exact Xray error, rerun with PROXYCTL_SHOW_CORE_DIAGNOSTICS=1 (native output may contain sensitive values).".to_owned()
            }
        );
        Ok(())
    }
}

/// Format the native validator output for an explicit, local debugging opt-in.
/// Bound each stream so a malformed core cannot flood the terminal.
fn detailed_validation_output(stdout: &[u8], stderr: &[u8]) -> String {
    const MAX_STREAM_BYTES: usize = 8 * 1024;
    fn excerpt(bytes: &[u8]) -> String {
        let shown = &bytes[..bytes.len().min(MAX_STREAM_BYTES)];
        let mut text = String::from_utf8_lossy(shown).trim().to_owned();
        if bytes.len() > shown.len() {
            text.push_str(&format!(
                "\n... truncated {} additional bytes",
                bytes.len() - shown.len()
            ));
        }
        if text.is_empty() {
            "(empty)".to_owned()
        } else {
            text
        }
    }

    format!("stdout:\n{}\nstderr:\n{}", excerpt(stdout), excerpt(stderr))
}

fn summarize_validation_failure(stdout: &[u8], stderr: &[u8]) -> String {
    // Xray's "run -test" command loads and builds configuration without starting
    // the server. Keep its potentially sensitive output private, but attach stream
    // sizes and a stable digest so an opaque failure can be correlated precisely.
    let diagnostic = format!(
        "{} {}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    )
    .to_ascii_lowercase();
    let stage = if diagnostic.trim().is_empty() {
        "Xray exited unsuccessfully without writing a diagnostic"
    } else if diagnostic.contains("unknown field")
        || diagnostic.contains("unknown config field")
        || diagnostic.contains("unknown configuration field")
    {
        "Xray rejected an unrecognized configuration field"
    } else if diagnostic.contains("protocol tun")
        || diagnostic.contains("tun inbound")
        || diagnostic.contains("inbound detour config for protocol tun")
        || diagnostic.contains("failed to build inbound handler for protocol tun")
    {
        "Xray failed while loading or building the TUN inbound configuration"
    } else if diagnostic.contains("protocol mixed")
        || diagnostic.contains("mixed inbound")
        || diagnostic.contains("failed to build inbound")
        || diagnostic.contains("invalid inbound")
    {
        "Xray rejected the loopback mixed HTTP/SOCKS inbound"
    } else if diagnostic.contains("failed to build sockopt")
        || diagnostic.contains("sockopt")
        || diagnostic.contains("socket option")
    {
        "Xray rejected the proxy outbound socket options"
    } else if diagnostic.contains("failed to build outbound")
        || diagnostic.contains("failed to load outbound detour config")
        || diagnostic.contains("invalid outbound")
        || diagnostic.contains("outbound handler")
    {
        "Xray rejected the proxy outbound configuration"
    } else if diagnostic.contains("reality") {
        "Xray rejected the proxy REALITY settings"
    } else if diagnostic.contains("tls") || diagnostic.contains("certificate") {
        "Xray rejected the proxy TLS or certificate settings"
    } else if diagnostic.contains("failed to parse")
        || diagnostic.contains("invalid character")
        || diagnostic.contains("unexpected end of json")
        || diagnostic.contains("invalid json")
        || diagnostic.contains("json syntax")
    {
        "Xray could not parse the generated JSON configuration"
    } else if diagnostic.contains("failed to create server") {
        "Xray parsed the configuration but failed while constructing its server"
    } else if diagnostic.contains("failed to load config files")
        || diagnostic.contains("failed to load config")
        || diagnostic.contains("failed to build config")
    {
        "Xray failed while loading or building the generated configuration"
    } else {
        "Xray returned an unclassified configuration validation error"
    };

    let mut hasher = Sha256::new();
    hasher.update(stdout);
    hasher.update([0]);
    hasher.update(stderr);
    let digest = hasher.finalize();
    let fingerprint = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    format!(
        "{stage}; captured stdout={} bytes, stderr={} bytes; diagnostic fingerprint=sha256:{fingerprint}; raw diagnostics withheld",
        stdout.len(),
        stderr.len()
    )
}

#[cfg(test)]
mod validation_diagnostic_tests {
    use super::summarize_validation_failure;

    #[test]
    fn detailed_diagnostics_include_both_streams_and_are_bounded() {
        let output = super::detailed_validation_output(b"field: bad value", b"decoder failed");
        assert!(output.contains("stdout:\nfield: bad value"));
        assert!(output.contains("stderr:\ndecoder failed"));

        let oversized = vec![b'x'; 9 * 1024];
        let output = super::detailed_validation_output(&oversized, b"");
        assert!(output.contains("truncated 1024 additional bytes"));
        assert!(output.len() < 9 * 1024);
    }

    #[test]
    fn validation_diagnostics_identify_the_specific_xray_failure_stage() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"failed to load inbound detour config for protocol tun: private-host",
                "TUN inbound configuration",
            ),
            (
                b"failed to build inbound handler for protocol mixed: private-host",
                "loopback mixed HTTP/SOCKS inbound",
            ),
            (
                b"failed to build outbound handler for protocol vless: private-host",
                "proxy outbound configuration",
            ),
            (b"failed to build sockopt: private-value", "socket options"),
            (
                b"failed to create server: private-host",
                "constructing its server",
            ),
            (
                b"failed to load config files: invalid character",
                "parse the generated JSON",
            ),
            (
                b"failed to load config files: opaque wrapped error",
                "loading or building the generated configuration",
            ),
        ];

        for (diagnostic, expected) in cases {
            let summary = summarize_validation_failure(b"", diagnostic);
            assert!(
                summary.contains(expected),
                "diagnostic {diagnostic:?} produced {summary:?}"
            );
            assert!(!summary.contains("private-host"));
            assert!(!summary.contains("private-value"));
        }
    }

    #[test]
    fn validation_diagnostics_keep_unknown_tls_and_reality_categories() {
        assert!(
            summarize_validation_failure(b"", b"unknown field private-value")
                .contains("unrecognized configuration field")
        );
        assert!(
            summarize_validation_failure(b"", b"TLS certificate private-host")
                .contains("TLS or certificate")
        );
        assert!(summarize_validation_failure(b"", b"REALITY private-value").contains("REALITY"));
    }

    #[test]
    fn opaque_validation_failures_include_safe_stream_metadata_and_fingerprint() {
        let empty = summarize_validation_failure(b"", b"");
        assert!(empty.contains("without writing a diagnostic"));
        assert!(empty.contains("stdout=0 bytes, stderr=0 bytes"));
        assert!(empty.contains("diagnostic fingerprint=sha256:"));
        assert!(empty.contains("raw diagnostics withheld"));

        let opaque = summarize_validation_failure(b"", b"private-host private-credential");
        assert!(opaque.contains("unclassified configuration validation error"));
        assert!(opaque.contains("stderr=") && opaque.contains(" bytes;"));
        assert!(!opaque.contains("private-host"));
        assert!(!opaque.contains("private-credential"));
    }

    #[test]
    fn validation_classifier_prefers_the_nested_component_over_loader_wrapper() {
        let summary = summarize_validation_failure(
            b"",
            b"failed to load config files: failed to build inbound handler for protocol tun",
        );
        assert!(summary.contains("TUN inbound configuration"));
    }

    #[test]
    fn validation_classifier_reads_stdout_when_stderr_is_empty() {
        let summary = summarize_validation_failure(
            b"failed to build outbound handler for protocol vless",
            b"",
        );
        assert!(summary.contains("proxy outbound configuration"));
        assert!(summary.contains("stdout=") && summary.contains("stderr=0 bytes"));
    }
}

#[cfg(test)]
mod config_contract_tests {
    use super::*;
    use crate::parser::parse_proxy_url;

    #[test]
    fn xray_activation_benchmark_and_tun_options_stay_core_native() {
        #[cfg(target_os = "linux")]
        assert_eq!(
            super::XrayAdapter.tun_attachment_mode(),
            super::super::TunAttachmentMode::ExternalDescriptorEnvironment {
                variable: super::super::XRAY_TUN_FD_ENV
            }
        );
        const {
            assert!(!CAPABILITIES.hysteria2 && CAPABILITIES.reality_vmess);
            assert!(CAPABILITIES.reality_optional_fields && CAPABILITIES.xhttp);
            assert!(CAPABILITIES.certificate_sha256_pin && CAPABILITIES.grpc_authority);
        }
        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();
        let activation: serde_json::Value = serde_json::from_slice(
            &XrayAdapter
                .generate_activation_config(&node, 43128)
                .unwrap()
                .content,
        )
        .unwrap();
        assert_eq!(activation["inbounds"][0]["protocol"], "mixed");
        assert_eq!(activation["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(activation["inbounds"][0]["port"], 43128);
        assert_eq!(activation["inbounds"][0]["settings"]["udp"], true);

        let benchmark: serde_json::Value = serde_json::from_slice(
            &XrayAdapter
                .generate_benchmark_config(&node, 43129)
                .unwrap()
                .content,
        )
        .unwrap();
        assert_eq!(benchmark["inbounds"][0]["protocol"], "mixed");
        assert_eq!(benchmark["inbounds"][0]["settings"]["auth"], "noauth");
        assert_eq!(benchmark["inbounds"][0]["settings"]["udp"], true);
        assert_eq!(benchmark["inbounds"][0]["port"], 43129);

        let tun: serde_json::Value = serde_json::from_slice(
            &XrayAdapter
                .generate_tun_activation_config(
                    &node,
                    43128,
                    super::super::TunOutboundMark::new(0x42, 0xff).unwrap(),
                )
                .unwrap()
                .content,
        )
        .unwrap();
        assert_eq!(tun["inbounds"][1]["protocol"], "tun");
        assert_eq!(tun["inbounds"][1]["port"], 0);
        assert_eq!(
            tun["inbounds"][1]["settings"]["name"],
            super::super::XRAY_TUN_INTERFACE_NAME
        );
        assert_eq!(
            tun["inbounds"][1]["settings"]["autoOutboundsInterface"],
            "auto"
        );
        assert_eq!(
            tun["inbounds"][1]["settings"]["autoSystemRoutingTable"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            tun["inbounds"][1]["settings"]["autoSystemDnsToGateway"],
            false
        );
        assert_eq!(tun["inbounds"][1]["sniffing"]["enabled"], true);
        assert_eq!(
            tun["inbounds"][1]["sniffing"]["destOverride"],
            serde_json::json!(["http", "tls"])
        );
        assert_eq!(tun["inbounds"][1]["sniffing"]["routeOnly"], true);

        assert_eq!(
            tun["outbounds"][0]["streamSettings"]["sockopt"]["mark"],
            0x42
        );
        assert!(tun["inbounds"][0].get("sockopt").is_none());
        assert!(tun["inbounds"][1].get("streamSettings").is_none());
        assert!(
            activation["outbounds"][0]["streamSettings"]
                .get("sockopt")
                .is_none()
        );
    }
}
