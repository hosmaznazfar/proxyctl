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
    name: "Mihomo",
    shadowsocks_plugins: true,
    reality_requires_tcp_grpc_xhttp: false,
    reality_disallows_legacy_transport: true,
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

pub struct MihomoAdapter;

impl CoreAdapter for MihomoAdapter {
    fn core(&self) -> CoreId {
        CoreId::Mihomo
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
        if let Some(plugin) = shadowsocks_plugin(node).map_err(anyhow::Error::msg)? {
            proxy["plugin"] = json!(plugin.mihomo_name);
            proxy["plugin-opts"] = plugin.mihomo_options;
        }
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
            if let Some(value) = option_string(node, "obfs-min-packet-size") {
                proxy["obfs-min-packet-size"] = json!(
                    value
                        .parse::<u16>()
                        .expect("validated Gecko minimum packet size")
                );
            }
            if let Some(value) = option_string(node, "obfs-max-packet-size") {
                proxy["obfs-max-packet-size"] = json!(
                    value
                        .parse::<u16>()
                        .expect("validated Gecko maximum packet size")
                );
            }
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
            if !transport.headers.is_empty() {
                xhttp.insert("headers".into(), json!(transport.headers));
            }
            if let Some(extra) = transport.xhttp_extra {
                let extra = extra.as_object().expect("validated XHTTP extra object");
                const KEYS: &[(&str, &str)] = &[
                    ("headers", "headers"),
                    ("xPaddingBytes", "x-padding-bytes"),
                    ("xPaddingObfsMode", "x-padding-obfs-mode"),
                    ("xPaddingKey", "x-padding-key"),
                    ("xPaddingHeader", "x-padding-header"),
                    ("xPaddingPlacement", "x-padding-placement"),
                    ("xPaddingMethod", "x-padding-method"),
                    ("uplinkHTTPMethod", "uplink-http-method"),
                    ("sessionIDPlacement", "session-placement"),
                    ("sessionIDKey", "session-key"),
                    ("sessionIDTable", "session-table"),
                    ("sessionIDLength", "session-length"),
                    ("seqPlacement", "seq-placement"),
                    ("seqKey", "seq-key"),
                    ("uplinkDataPlacement", "uplink-data-placement"),
                    ("uplinkDataKey", "uplink-data-key"),
                    ("uplinkChunkSize", "uplink-chunk-size"),
                    ("noGRPCHeader", "no-grpc-header"),
                    ("scMaxEachPostBytes", "sc-max-each-post-bytes"),
                    ("scMinPostsIntervalMs", "sc-min-posts-interval-ms"),
                ];
                for (source, target) in KEYS {
                    if let Some(value) = extra.get(*source) {
                        xhttp.insert((*target).into(), value.clone());
                    }
                }
                if let Some(xmux) = extra.get("xmux").and_then(serde_json::Value::as_object) {
                    let mut reuse = serde_json::Map::new();
                    const XMUX_KEYS: &[(&str, &str)] = &[
                        ("maxConcurrency", "max-concurrency"),
                        ("maxConnections", "max-connections"),
                        ("cMaxReuseTimes", "c-max-reuse-times"),
                        ("hMaxRequestTimes", "h-max-request-times"),
                        ("hMaxReusableSecs", "h-max-reusable-secs"),
                        ("hKeepAlivePeriod", "h-keep-alive-period"),
                    ];
                    for (source, target) in XMUX_KEYS {
                        if let Some(value) = xmux.get(*source) {
                            reuse.insert((*target).into(), value.clone());
                        }
                    }
                    xhttp.insert("reuse-settings".into(), serde_json::Value::Object(reuse));
                }
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

    fn generate_benchmark_batch_config(
        &self,
        targets: &[super::BenchmarkTarget<'_>],
    ) -> anyhow::Result<GeneratedConfig> {
        super::benchmark_batch::validate_targets(self, targets)?;
        let mut proxies = Vec::with_capacity(targets.len());
        let mut listeners = Vec::with_capacity(targets.len());
        for target in targets {
            let document = super::benchmark_batch::node_config(self, target.node)?;
            let proxy = document
                .get("proxies")
                .and_then(serde_json::Value::as_array)
                .and_then(|entries| entries.first())
                .ok_or_else(|| anyhow::anyhow!("Mihomo node config must contain a proxy entry"))?;
            let mut proxy = proxy.clone();
            let proxy_name = format!("proxyctl-benchmark-out-{}", target.node_id);
            let listener_name = format!("proxyctl-benchmark-in-{}", target.node_id);
            proxy["name"] = json!(proxy_name);
            proxies.push(proxy);
            listeners.push(json!({
                "name": listener_name, "type": "mixed", "port": target.listen_port,
                "listen": "127.0.0.1", "proxy": proxy_name
            }));
        }
        json_config(json!({
            "allow-lan": false, "mode": "rule", "proxies": proxies, "listeners": listeners
        }))
    }

    fn generate_activation_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig> {
        let generated = self.generate_config(node)?;
        let mut document: serde_json::Value = serde_json::from_slice(&generated.content)?;
        document["mixed-port"] = json!(listen_port);
        document["bind-address"] = json!("127.0.0.1");
        document["allow-lan"] = json!(false);
        json_config(document)
    }

    fn tun_attachment_mode(&self) -> super::TunAttachmentMode {
        super::TunAttachmentMode::NativeDeviceCreation
    }

    fn generate_tun_activation_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
        mark: super::TunOutboundMark,
    ) -> anyhow::Result<GeneratedConfig> {
        self.generate_tun_activation_config_for_family(
            node,
            listen_port,
            mark,
            crate::tun::address_family::ResolvedTunAddressFamily::DualStack,
        )
    }

    fn generate_tun_activation_config_for_family(
        &self,
        node: &ProxyNode,
        listen_port: u16,
        mark: super::TunOutboundMark,
        family: crate::tun::address_family::ResolvedTunAddressFamily,
    ) -> anyhow::Result<GeneratedConfig> {
        let generated = self.generate_activation_config(node, listen_port)?;
        let mut document: serde_json::Value = serde_json::from_slice(&generated.content)?;
        let ipv4_addresses = if family.includes_ipv4() {
            vec!["198.18.0.1/30"]
        } else {
            Vec::new()
        };
        let ipv6_addresses = if family.includes_ipv6() {
            vec!["fdfe:dcba:9876::1/126"]
        } else {
            Vec::new()
        };
        document["tun"] = json!({
            "enable": true,
            "device": "tun-proxyctl",
            "mtu": 1500,
            "inet4-address": ipv4_addresses,
            "inet6-address": ipv6_addresses,
            "auto-route": false,
            "auto-redirect": false,
            // Proxyctl routes application DNS packets into this TUN itself. Intercept
            // those packets here, without asking Mihomo to rewrite the host resolver
            // or install its own Linux redirect rules.
            "dns-mode": "disabled",
            "dns-hijack": ["any:53", "tcp://any:53"],
            "strict-route": false,
            "auto-detect-interface": true
        });
        // Keep ordinary DNS inside Mihomo. Bootstrap and proxy-node lookups use
        // literal-IP resolvers; regular lookups use Cloudflare DoH over PROXY so
        // DNS traffic follows the selected proxy instead of leaking to the LAN.
        document["dns"] = json!({
            "enable": true,
            "ipv6": true,
            "default-nameserver": ["1.1.1.1", "8.8.8.8"],
            "proxy-server-nameserver": ["1.1.1.1", "8.8.8.8"],
            "nameserver": ["https://cloudflare-dns.com/dns-query#PROXY"]
        });
        // Mihomo's global routing-mark is the default mark for proxy outbound connections.
        // Keep core IPv6 capability independent from the application TUN family; the
        // kernel policy routes only selected application destinations through this device.
        document["ipv6"] = json!(true);
        document["routing-mark"] = json!(mark.value());
        json_config(document)
    }

    fn generate_benchmark_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig> {
        let generated = self.generate_config(node)?;
        let mut document: serde_json::Value = serde_json::from_slice(&generated.content)?;
        document["port"] = json!(listen_port);
        document["bind-address"] = json!("127.0.0.1");
        document["allow-lan"] = json!(false);
        json_config(document)
    }

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()> {
        let mut command = Command::new(executable);
        command.arg("-t").arg("-f").arg(config);
        let output =
            super::validation::run_validator(command, "could not run Mihomo config validation")?;
        ensure!(
            output.status.success(),
            "Mihomo rejected the generated configuration (exit status {:?}; {})",
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
    fn mihomo_activation_benchmark_and_tun_options_stay_core_native() {
        assert_eq!(
            super::MihomoAdapter.tun_attachment_mode(),
            super::super::TunAttachmentMode::NativeDeviceCreation
        );
        let capabilities = std::hint::black_box(CAPABILITIES);
        assert!(capabilities.hysteria2 && capabilities.xhttp);
        assert!(
            !capabilities.reality_requires_tcp_grpc_xhttp
                && capabilities.reality_disallows_legacy_transport
        );
        assert!(capabilities.grpc_service_name_required);
        assert!(!capabilities.xhttp_auto_mode);
        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();
        let activation: serde_json::Value = serde_json::from_slice(
            &MihomoAdapter
                .generate_activation_config(&node, 43128)
                .unwrap()
                .content,
        )
        .unwrap();
        assert_eq!(activation["mixed-port"], 43128);
        assert_eq!(activation["bind-address"], "127.0.0.1");
        assert_eq!(activation["allow-lan"], false);

        let benchmark: serde_json::Value = serde_json::from_slice(
            &MihomoAdapter
                .generate_benchmark_config(&node, 43129)
                .unwrap()
                .content,
        )
        .unwrap();
        assert_eq!(benchmark["port"], 43129);
        assert_eq!(benchmark["bind-address"], "127.0.0.1");
        assert_eq!(benchmark["allow-lan"], false);

        let mark = super::super::TunOutboundMark::new(0x42, 0xff).unwrap();
        let tun: serde_json::Value = serde_json::from_slice(
            &MihomoAdapter
                .generate_tun_activation_config(&node, 43128, mark)
                .unwrap()
                .content,
        )
        .unwrap();
        assert_eq!(tun["mixed-port"], 43128);
        assert_eq!(tun["tun"]["enable"], true);
        assert_eq!(tun["tun"]["device"], "tun-proxyctl");
        assert_eq!(tun["tun"]["auto-route"], false);
        assert_eq!(tun["tun"]["auto-redirect"], false);
        assert_eq!(tun["tun"]["dns-mode"], "disabled");
        assert_eq!(tun["tun"]["auto-detect-interface"], true);
        assert_eq!(tun["tun"]["dns-hijack"][0], "any:53");
        assert_eq!(tun["tun"]["dns-hijack"][1], "tcp://any:53");
        assert_eq!(tun["dns"]["enable"], true);
        assert_eq!(tun["dns"]["ipv6"], true);
        assert_eq!(tun["dns"]["default-nameserver"][0], "1.1.1.1");
        assert_eq!(tun["dns"]["proxy-server-nameserver"][0], "1.1.1.1");
        assert_eq!(
            tun["dns"]["nameserver"][0],
            "https://cloudflare-dns.com/dns-query#PROXY"
        );
        assert_eq!(tun["routing-mark"], 0x42);
        assert_eq!(tun["ipv6"], true);
        assert_eq!(tun["tun"]["inet4-address"][0], "198.18.0.1/30");
        assert_eq!(tun["tun"]["inet6-address"][0], "fdfe:dcba:9876::1/126");
    }
}
