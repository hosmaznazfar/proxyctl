//! Core-independent adapter contract and dispatch.
mod mihomo;
mod shared;
mod sing_box;
mod xray;

pub mod validation;

use anyhow::Context;
use serde_json::Value;
use std::path::Path;

use crate::{cores::CoreId, domain::ProxyNode};

pub use shared::{Compatibility, CompatibilityStatus, GeneratedConfig};

/// A core adapter must either represent every retained connection option or explain why it
/// cannot. It must never emit a partial configuration after silently dropping an option.
pub trait CoreAdapter {
    fn core(&self) -> CoreId;
    fn compatibility(&self, node: &ProxyNode) -> Compatibility;
    fn generate_config(&self, node: &ProxyNode) -> anyhow::Result<GeneratedConfig>;
    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()>;
}

pub fn adapter(core: CoreId) -> &'static dyn CoreAdapter {
    match core {
        CoreId::SingBox => &sing_box::SingBoxAdapter,
        CoreId::Xray => &xray::XrayAdapter,
        CoreId::Mihomo => &mihomo::MihomoAdapter,
    }
}

/// Serialize the JSON document shared by the three native config adapters. JSON is also a
/// YAML 1.2 subset, so Mihomo can consume the generated JSON document as a config file.
pub(crate) fn json_config(value: Value) -> anyhow::Result<GeneratedConfig> {
    Ok(GeneratedConfig {
        format: "json",
        content: serde_json::to_vec_pretty(&value).context("could not serialize core config")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_proxy_url;

    #[test]
    fn all_adapters_generate_a_native_document_for_basic_vless() {
        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let adapter = adapter(core);
            assert!(adapter.compatibility(&node).is_supported(), "{core}");
            let generated = adapter.generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            assert!(document.is_object());
        }
    }

    #[test]
    fn adapters_map_websocket_transport_and_keep_host_separate_from_sni() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&host=cdn.example&path=%2Fsocket&security=tls&sni=tls.example",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let (network, path, host, sni) = match core {
                CoreId::SingBox => (
                    document["outbounds"][0]["transport"]["type"].as_str(),
                    document["outbounds"][0]["transport"]["path"].as_str(),
                    document["outbounds"][0]["transport"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["tls"]["server_name"].as_str(),
                ),
                CoreId::Xray => (
                    document["outbounds"][0]["streamSettings"]["network"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["path"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"].as_str(),
                ),
                CoreId::Mihomo => (
                    document["proxies"][0]["network"].as_str(),
                    document["proxies"][0]["ws-opts"]["path"].as_str(),
                    document["proxies"][0]["ws-opts"]["headers"]["Host"].as_str(),
                    document["proxies"][0]["servername"].as_str(),
                ),
            };
            assert_eq!(network, Some(if core == CoreId::SingBox { "ws" } else { "ws" }));
            assert_eq!(path, Some("/socket"), "{core}");
            assert_eq!(host, Some("cdn.example"), "{core}");
            assert_eq!(sni, Some("tls.example"), "{core}");
        }
    }

    #[test]
    fn adapters_map_grpc_service_names_with_core_specific_requirements() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=grpc&serviceName=proxy.Service&mode=gun&security=tls&sni=tls.example",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let compatibility = adapter(core).compatibility(&node);
            if core == CoreId::Mihomo {
                assert_eq!(compatibility.status, CompatibilityStatus::Supported);
            } else {
                assert!(compatibility.is_supported(), "{core}: {:?}", compatibility.reason);
            }
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let (network, service_name) = match core {
                CoreId::SingBox => (
                    document["outbounds"][0]["transport"]["type"].as_str(),
                    document["outbounds"][0]["transport"]["service_name"].as_str(),
                ),
                CoreId::Xray => (
                    document["outbounds"][0]["streamSettings"]["network"].as_str(),
                    document["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"].as_str(),
                ),
                CoreId::Mihomo => (
                    document["proxies"][0]["network"].as_str(),
                    document["proxies"][0]["grpc-opts"]["grpc-service-name"].as_str(),
                ),
            };
            assert_eq!(network, Some("grpc"), "{core}");
            assert_eq!(service_name, Some("proxy.Service"), "{core}");
        }
    }

    #[test]
    fn mihomo_requires_a_grpc_service_name() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=grpc",
        )
        .unwrap();
        assert_eq!(
            adapter(CoreId::Mihomo).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
        assert!(adapter(CoreId::SingBox).compatibility(&node).is_supported());
        assert!(adapter(CoreId::Xray).compatibility(&node).is_supported());
    }

    #[test]
    fn adapters_map_http2_transport_and_host_lists() {
        use base64::{Engine as _, engine::general_purpose};

        let vless = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=h2&host=one.example%2Ctwo.example&path=%2Fservice",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&vless).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let (network, hosts, path) = match core {
                CoreId::SingBox => (
                    document["outbounds"][0]["transport"]["type"].as_str(),
                    &document["outbounds"][0]["transport"]["host"],
                    document["outbounds"][0]["transport"]["path"].as_str(),
                ),
                CoreId::Xray => (
                    document["outbounds"][0]["streamSettings"]["network"].as_str(),
                    &document["outbounds"][0]["streamSettings"]["httpSettings"]["host"],
                    document["outbounds"][0]["streamSettings"]["httpSettings"]["path"].as_str(),
                ),
                CoreId::Mihomo => (
                    document["proxies"][0]["network"].as_str(),
                    &document["proxies"][0]["h2-opts"]["host"],
                    document["proxies"][0]["h2-opts"]["path"].as_str(),
                ),
            };
            assert_eq!(network, Some(if core == CoreId::SingBox { "http" } else { "h2" }), "{core}");
            assert_eq!(hosts, &serde_json::json!(["one.example", "two.example"]), "{core}");
            assert_eq!(path, Some("/service"), "{core}");
        }
        assert_eq!(
            adapter(CoreId::Xray).compatibility(&vless).status,
            CompatibilityStatus::Unsupported
        );

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"h2","host":"cdn.example","path":"/vmess"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{payload}")).unwrap();
        for core in [CoreId::SingBox, CoreId::Mihomo] {
            assert!(adapter(core).compatibility(&vmess).is_supported(), "{core}");
            let _: Value = serde_json::from_slice(
                &adapter(core).generate_config(&vmess).unwrap().content,
            )
            .unwrap();
        }
        assert_eq!(
            adapter(CoreId::Xray).compatibility(&vmess).status,
            CompatibilityStatus::Unsupported
        );
    }

    #[test]
    fn adapters_map_http_upgrade_without_conflating_host_and_sni() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=httpupgrade&host=upgrade.example&path=%2Fupgrade&security=tls&sni=tls.example",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let (transport, host, path, sni) = match core {
                CoreId::SingBox => (
                    document["outbounds"][0]["transport"]["type"].as_str(),
                    document["outbounds"][0]["transport"]["host"].as_str(),
                    document["outbounds"][0]["transport"]["path"].as_str(),
                    document["outbounds"][0]["tls"]["server_name"].as_str(),
                ),
                CoreId::Xray => (
                    document["outbounds"][0]["streamSettings"]["network"].as_str(),
                    document["outbounds"][0]["streamSettings"]["httpupgradeSettings"]["host"].as_str(),
                    document["outbounds"][0]["streamSettings"]["httpupgradeSettings"]["path"].as_str(),
                    document["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"].as_str(),
                ),
                CoreId::Mihomo => (
                    document["proxies"][0]["ws-opts"]["v2ray-http-upgrade"].as_bool().map(|v| if v { "httpupgrade" } else { "ws" }),
                    document["proxies"][0]["ws-opts"]["headers"]["Host"].as_str(),
                    document["proxies"][0]["ws-opts"]["path"].as_str(),
                    document["proxies"][0]["servername"].as_str(),
                ),
            };
            assert_eq!(transport, Some("httpupgrade"), "{core}");
            assert_eq!(host, Some("upgrade.example"), "{core}");
            assert_eq!(path, Some("/upgrade"), "{core}");
            assert_eq!(sni, Some("tls.example"), "{core}");
        }
    }

    #[test]
    fn xhttp_is_mapped_only_by_cores_with_verified_schema_support() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=xhttp&host=cdn.example&path=%2Fapi&mode=packet-up",
        )
        .unwrap();

        assert_eq!(
            adapter(CoreId::SingBox).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );

        let xray = adapter(CoreId::Xray).generate_config(&node).unwrap();
        let xray_doc: Value = serde_json::from_slice(&xray.content).unwrap();
        assert_eq!(
            xray_doc["outbounds"][0]["streamSettings"]["network"],
            "xhttp"
        );
        assert_eq!(
            xray_doc["outbounds"][0]["streamSettings"]["xhttpSettings"]["mode"],
            "packet-up"
        );
        assert_eq!(
            xray_doc["outbounds"][0]["streamSettings"]["xhttpSettings"]["host"],
            "cdn.example"
        );

        let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
        let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
        assert_eq!(mihomo_doc["proxies"][0]["network"], "xhttp");
        assert_eq!(mihomo_doc["proxies"][0]["xhttp-opts"]["mode"], "packet-up");
        assert_eq!(mihomo_doc["proxies"][0]["xhttp-opts"]["path"], "/api");
    }

    #[test]
    fn vmess_xhttp_is_supported_only_by_xray() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"xhttp","type":"stream-one","host":"cdn.example","path":"/xhttp","tls":"tls"}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();
        let xray = adapter(CoreId::Xray).generate_config(&node).unwrap();
        let document: Value = serde_json::from_slice(&xray.content).unwrap();
        assert_eq!(
            document["outbounds"][0]["streamSettings"]["xhttpSettings"]["mode"],
            "stream-one"
        );
        assert_eq!(
            adapter(CoreId::SingBox).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
        assert_eq!(
            adapter(CoreId::Mihomo).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
    }

    #[test]
    fn vmess_http_upgrade_uses_native_core_mappings() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"httpupgrade","host":"upgrade.example","path":"/upgrade","tls":"tls"}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(adapter(core).compatibility(&node).is_supported(), "{core}");
            let _: Value = serde_json::from_slice(
                &adapter(core).generate_config(&node).unwrap().content,
            )
            .unwrap();
        }
    }

    #[test]
    fn xhttp_rejects_unknown_modes() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=xhttp&mode=unknown",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert_eq!(
                adapter(core).compatibility(&node).status,
                CompatibilityStatus::Unsupported
            );
        }
    }

    #[test]
    fn websocket_early_data_is_mapped_per_core() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&path=%2Fws&ed=2048&eh=Sec-WebSocket-Protocol",
        )
        .unwrap();

        let sing_box = adapter(CoreId::SingBox).generate_config(&node).unwrap();
        let sing_box_doc: Value = serde_json::from_slice(&sing_box.content).unwrap();
        assert_eq!(sing_box_doc["outbounds"][0]["transport"]["max_early_data"], 2048);
        assert_eq!(
            sing_box_doc["outbounds"][0]["transport"]["early_data_header_name"],
            "Sec-WebSocket-Protocol"
        );

        let xray = adapter(CoreId::Xray).generate_config(&node).unwrap();
        let xray_doc: Value = serde_json::from_slice(&xray.content).unwrap();
        assert_eq!(
            xray_doc["outbounds"][0]["streamSettings"]["wsSettings"]["path"],
            "/ws?ed=2048"
        );

        let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
        let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
        assert_eq!(mihomo_doc["proxies"][0]["ws-opts"]["max-early-data"], 2048);
        assert_eq!(
            mihomo_doc["proxies"][0]["ws-opts"]["early-data-header-name"],
            "Sec-WebSocket-Protocol"
        );
    }

    #[test]
    fn xray_rejects_custom_websocket_early_data_header() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&ed=1024&eh=X-Custom-Early-Data",
        )
        .unwrap();
        assert_eq!(
            adapter(CoreId::Xray).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
        assert!(adapter(CoreId::SingBox).compatibility(&node).is_supported());
        assert!(adapter(CoreId::Mihomo).compatibility(&node).is_supported());
    }

    #[test]
    fn vmess_pcs_certificate_pin_maps_to_xray_and_mihomo() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","tls":"tls","pcs":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        let xray = adapter(CoreId::Xray).generate_config(&node).unwrap();
        let document: Value = serde_json::from_slice(&xray.content).unwrap();
        assert_eq!(
            document["outbounds"][0]["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            adapter(CoreId::SingBox).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
        let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
        let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
        assert_eq!(
            mihomo_doc["proxies"][0]["fingerprint"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn certificate_pin_requires_tls_and_valid_sha256() {
        let no_tls = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?pcs=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let malformed = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&pcs=not-a-hash",
        )
        .unwrap();
        assert!(!adapter(CoreId::Xray).compatibility(&no_tls).is_supported());
        assert!(!adapter(CoreId::Xray).compatibility(&malformed).is_supported());
    }

    #[test]
    fn vmess_grpc_authority_and_multi_mode_are_xray_specific() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"grpc","type":"multi","host":"grpc.example","path":"proxy.Service","tls":"tls"}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        let xray = adapter(CoreId::Xray).generate_config(&node).unwrap();
        let document: Value = serde_json::from_slice(&xray.content).unwrap();
        assert_eq!(
            document["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"],
            "proxy.Service"
        );
        assert_eq!(
            document["outbounds"][0]["streamSettings"]["grpcSettings"]["authority"],
            "grpc.example"
        );
        assert_eq!(
            document["outbounds"][0]["streamSettings"]["grpcSettings"]["multiMode"],
            true
        );
        assert_eq!(
            adapter(CoreId::SingBox).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
        assert_eq!(
            adapter(CoreId::Mihomo).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
    }

    #[test]
    fn vless_grpc_multi_mode_is_not_silently_downgraded() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=grpc&serviceName=proxy.Service&authority=grpc.example&mode=multi",
        )
        .unwrap();
        assert!(adapter(CoreId::Xray).compatibility(&node).is_supported());
        assert_eq!(
            adapter(CoreId::SingBox).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
        assert_eq!(
            adapter(CoreId::Mihomo).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
    }

    #[test]
    fn vmess_empty_optional_fields_are_treated_as_defaults() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"v":"2","ps":"empty-defaults","add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","aid":"0","scy":"","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"","alpn":"","fp":"","insecure":"0","vcn":"","pcs":""}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(adapter(core).compatibility(&node).is_supported(), "{core}");
            let generated = adapter(core).generate_config(&node).unwrap();
            let _: Value = serde_json::from_slice(&generated.content).unwrap();
        }
    }

    #[test]
    fn insecure_tls_option_maps_to_each_native_schema() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&insecure=1",
        )
        .unwrap();
        let sing_box = adapter(CoreId::SingBox).generate_config(&node).unwrap();
        let sing_box_doc: Value = serde_json::from_slice(&sing_box.content).unwrap();
        assert_eq!(sing_box_doc["outbounds"][0]["tls"]["insecure"], true);

        let xray = adapter(CoreId::Xray).generate_config(&node).unwrap();
        let xray_doc: Value = serde_json::from_slice(&xray.content).unwrap();
        assert_eq!(
            xray_doc["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"],
            true
        );

        let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
        let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
        assert_eq!(mihomo_doc["proxies"][0]["skip-cert-verify"], true);
    }

    #[test]
    fn certificate_name_verification_maps_only_where_supported() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&vcn=verify.example",
        )
        .unwrap();
        let xray = adapter(CoreId::Xray).generate_config(&node).unwrap();
        let xray_doc: Value = serde_json::from_slice(&xray.content).unwrap();
        assert_eq!(
            xray_doc["outbounds"][0]["streamSettings"]["tlsSettings"]["verifyPeerCertByName"],
            "verify.example"
        );
        let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
        let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
        assert_eq!(mihomo_doc["proxies"][0]["name-cert-verify"], "verify.example");
        assert_eq!(
            adapter(CoreId::SingBox).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
    }

    #[test]
    fn adapters_reject_unknown_transport_without_dropping_it() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=quic",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let compatibility = adapter(core).compatibility(&node);
            assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
            assert!(compatibility.reason.unwrap().contains("transport"));
        }
    }

    #[test]
    fn xray_explicitly_rejects_hysteria2() {
        let node = parse_proxy_url("hysteria2://secret@example.com:443").unwrap();
        let compatibility = adapter(CoreId::Xray).compatibility(&node);
        assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
    }

    #[test]
    fn basic_protocol_matrix_matches_the_initial_support_contract() {
        use base64::{Engine as _, engine::general_purpose};

        let vmess_payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","ps":"vmess"}"#,
        );
        let vmess_url = format!("vmess://{vmess_payload}");
        let cases: [(&str, bool); 5] = [
            (
                "vless://11111111-1111-4111-8111-111111111111@example.com:443",
                true,
            ),
            (vmess_url.as_str(), true),
            ("trojan://secret@example.com:443", true),
            ("ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388", true),
            ("hysteria2://secret@example.com:443", false),
        ];
        for (url, all_cores) in cases {
            let node = parse_proxy_url(url).unwrap();
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                let expected = all_cores || core != CoreId::Xray;
                let result = adapter(core).compatibility(&node);
                assert_eq!(
                    result.is_supported(),
                    expected,
                    "{core} / {}",
                    node.protocol
                );
                if expected {
                    let generated = adapter(core).generate_config(&node).unwrap();
                    let _: Value = serde_json::from_slice(&generated.content).unwrap();
                }
            }
        }
    }

    #[test]
    fn adapters_support_websocket_for_vless_and_vmess() {
        use base64::{Engine as _, engine::general_purpose};

        let vless =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&path=%2Fws")
                .unwrap();
        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"ws","path":"/vmess","host":"cdn.example","tls":"tls"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        for node in [&vless, &vmess] {
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                assert!(
                    adapter(core).compatibility(node).is_supported(),
                    "{core}: {:?}",
                    adapter(core).compatibility(node).reason
                );
                let _: Value = serde_json::from_slice(
                    &adapter(core).generate_config(node).unwrap().content,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn adapters_map_repeated_and_comma_separated_alpn_values() {
        let repeated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2&alpn=http%2F1.1",
        )
        .unwrap();
        let comma_separated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2%2Chttp%2F1.1",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            for node in [&repeated, &comma_separated] {
                let generated = adapter(core).generate_config(node).unwrap();
                let document: Value = serde_json::from_slice(&generated.content).unwrap();
                let alpn = match core {
                    CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                    CoreId::Xray => {
                        &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"]
                    }
                    CoreId::Mihomo => &document["proxies"][0]["alpn"],
                };
                assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
            }
        }
    }

    #[test]
    fn adapters_map_structured_vmess_alpn_arrays() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","tls":"tls","alpn":["h2","http/1.1"]}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Xray => &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }
    }

    #[test]
    fn adapters_map_alpn_for_trojan_and_supported_hysteria2_cores() {
        let trojan =
            parse_proxy_url("trojan://secret@example.com:443?alpn=h2&alpn=http%2F1.1").unwrap();
        let hysteria2 =
            parse_proxy_url("hysteria2://secret@example.com:443?alpn=h2&alpn=http%2F1.1").unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&trojan).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Xray => &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }

        for core in [CoreId::SingBox, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&hysteria2).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
                CoreId::Xray => unreachable!(),
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }
        assert!(
            !adapter(CoreId::Xray)
                .compatibility(&hysteria2)
                .is_supported()
        );
    }

    #[test]
    fn adapters_map_tls_client_fingerprints_for_supported_protocols() {
        use base64::{Engine as _, engine::general_purpose};

        let vless = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&fp=chrome",
        )
        .unwrap();
        let vmess_payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","tls":"tls","fp":"firefox"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{vmess_payload}")).unwrap();
        let trojan = parse_proxy_url("trojan://secret@example.com:443?fp=safari").unwrap();

        for (node, expected) in [(&vless, "chrome"), (&vmess, "firefox"), (&trojan, "safari")] {
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                let generated = adapter(core).generate_config(node).unwrap();
                let document: Value = serde_json::from_slice(&generated.content).unwrap();
                let fingerprint = match core {
                    CoreId::SingBox => &document["outbounds"][0]["tls"]["utls"]["fingerprint"],
                    CoreId::Xray => {
                        &document["outbounds"][0]["streamSettings"]["tlsSettings"]["fingerprint"]
                    }
                    CoreId::Mihomo => &document["proxies"][0]["client-fingerprint"],
                };
                assert_eq!(fingerprint.as_str(), Some(expected), "{core}");
                if core == CoreId::SingBox {
                    assert!(document["outbounds"][0]["tls"]["utls"]["enabled"].as_bool().unwrap());
                }
            }
        }
    }

    #[test]
    fn adapters_reject_invalid_or_inapplicable_tls_fingerprints() {
        let no_tls = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?fp=chrome",
        )
        .unwrap();
        let invalid = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&fp=unknown",
        )
        .unwrap();
        let hysteria2 = parse_proxy_url("hysteria2://secret@example.com:443?fp=chrome").unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&no_tls).is_supported());
            assert!(!adapter(core).compatibility(&invalid).is_supported());
            assert!(!adapter(core).compatibility(&hysteria2).is_supported());
        }
    }

    #[test]
    fn adapters_reject_alpn_without_tls_and_malformed_alpn() {
        let no_tls =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?alpn=h2")
                .unwrap();
        let empty_entry = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2%2C%2Chttp%2F1.1",
        )
        .unwrap();
        let duplicate_entry = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2&alpn=h2",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&no_tls).is_supported());
            assert!(!adapter(core).compatibility(&empty_entry).is_supported());
            assert!(!adapter(core).compatibility(&duplicate_entry).is_supported());
        }
    }

    #[test]
    fn adapters_reject_repeated_or_ambiguous_options() {
        let repeated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?sni=a.example&sni=b.example&security=tls",
        )
        .unwrap();
        let ambiguous = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&tls=tls",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&repeated).is_supported());
            assert!(!adapter(core).compatibility(&ambiguous).is_supported());
        }
    }
}    #[test]
    fn adapters_map_websocket_transport_and_keep_host_separate_from_sni() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&host=cdn.example&path=%2Fsocket&security=tls&sni=tls.example",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let (network, path, host, sni) = match core {
                CoreId::SingBox => (
                    document["outbounds"][0]["transport"]["type"].as_str(),
                    document["outbounds"][0]["transport"]["path"].as_str(),
                    document["outbounds"][0]["transport"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["tls"]["server_name"].as_str(),
                ),
                CoreId::Xray => (
                    document["outbounds"][0]["streamSettings"]["network"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["path"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"].as_str(),
                ),
                CoreId::Mihomo => (
                    document["proxies"][0]["network"].as_str(),
                    document["proxies"][0]["ws-opts"]["path"].as_str(),
                    document["proxies"][0]["ws-opts"]["headers"]["Host"].as_str(),
                    document["proxies"][0]["servername"].as_str(),
                ),
            };
            assert_eq!(network, Some("ws"), "{core}");
            assert_eq!(path, Some("/socket"), "{core}");
            assert_eq!(host, Some("cdn.example"), "{core}");
            assert_eq!(sni, Some("tls.example"), "{core}");
        }
    }

    #[test]
    fn adapters_reject_unknown_transport_without_dropping_it() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=quic",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let compatibility = adapter(core).compatibility(&node);
            assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
            assert!(compatibility.reason.unwrap().contains("transport"));
        }
    }

    #[test]
    fn all_adapters_generate_a_native_document_for_basic_vless() {
        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let adapter = adapter(core);
            assert!(adapter.compatibility(&node).is_supported(), "{core}");
            let generated = adapter.generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            assert!(document.is_object());
        }
    }

    #[test]
    fn adapters_map_websocket_transport_and_keep_host_separate_from_sni() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&host=cdn.example&path=%2Fsocket&security=tls&sni=tls.example",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let (network, path, host, sni) = match core {
                CoreId::SingBox => (
                    document["outbounds"][0]["transport"]["type"].as_str(),
                    document["outbounds"][0]["transport"]["path"].as_str(),
                    document["outbounds"][0]["transport"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["tls"]["server_name"].as_str(),
                ),
                CoreId::Xray => (
                    document["outbounds"][0]["streamSettings"]["network"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["path"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"].as_str(),
                ),
                CoreId::Mihomo => (
                    document["proxies"][0]["network"].as_str(),
                    document["proxies"][0]["ws-opts"]["path"].as_str(),
                    document["proxies"][0]["ws-opts"]["headers"]["Host"].as_str(),
                    document["proxies"][0]["servername"].as_str(),
                ),
            };
            assert_eq!(network, Some(if core == CoreId::SingBox { "ws" } else { "ws" }));
            assert_eq!(path, Some("/socket"), "{core}");
            assert_eq!(host, Some("cdn.example"), "{core}");
            assert_eq!(sni, Some("tls.example"), "{core}");
        }
    }

    #[test]
    fn adapters_reject_unknown_transport_without_dropping_it() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=quic",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let compatibility = adapter(core).compatibility(&node);
            assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
            assert!(compatibility.reason.unwrap().contains("transport"));
        }
    }

    #[test]
    fn xray_explicitly_rejects_hysteria2() {
        let node = parse_proxy_url("hysteria2://secret@example.com:443").unwrap();
        let compatibility = adapter(CoreId::Xray).compatibility(&node);
        assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
    }

    #[test]
    fn basic_protocol_matrix_matches_the_initial_support_contract() {
        use base64::{Engine as _, engine::general_purpose};

        let vmess_payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","ps":"vmess"}"#,
        );
        let vmess_url = format!("vmess://{vmess_payload}");
        let cases: [(&str, bool); 5] = [
            (
                "vless://11111111-1111-4111-8111-111111111111@example.com:443",
                true,
            ),
            (vmess_url.as_str(), true),
            ("trojan://secret@example.com:443", true),
            ("ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388", true),
            ("hysteria2://secret@example.com:443", false),
        ];
        for (url, all_cores) in cases {
            let node = parse_proxy_url(url).unwrap();
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                let expected = all_cores || core != CoreId::Xray;
                let result = adapter(core).compatibility(&node);
                assert_eq!(
                    result.is_supported(),
                    expected,
                    "{core} / {}",
                    node.protocol
                );
                if expected {
                    let generated = adapter(core).generate_config(&node).unwrap();
                    let _: Value = serde_json::from_slice(&generated.content).unwrap();
                }
            }
        }
    }

    #[test]
    fn adapters_support_websocket_for_vless_and_vmess() {
        use base64::{Engine as _, engine::general_purpose};

        let vless =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&path=%2Fws")
                .unwrap();
        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"ws","path":"/vmess","host":"cdn.example","tls":"tls"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        for node in [&vless, &vmess] {
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                assert!(
                    adapter(core).compatibility(node).is_supported(),
                    "{core}: {:?}",
                    adapter(core).compatibility(node).reason
                );
                let _: Value = serde_json::from_slice(
                    &adapter(core).generate_config(node).unwrap().content,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn adapters_map_repeated_and_comma_separated_alpn_values() {
        let repeated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2&alpn=http%2F1.1",
        )
        .unwrap();
        let comma_separated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2%2Chttp%2F1.1",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            for node in [&repeated, &comma_separated] {
                let generated = adapter(core).generate_config(node).unwrap();
                let document: Value = serde_json::from_slice(&generated.content).unwrap();
                let alpn = match core {
                    CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                    CoreId::Xray => {
                        &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"]
                    }
                    CoreId::Mihomo => &document["proxies"][0]["alpn"],
                };
                assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
            }
        }
    }

    #[test]
    fn adapters_map_structured_vmess_alpn_arrays() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","tls":"tls","alpn":["h2","http/1.1"]}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Xray => &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }
    }

    #[test]
    fn adapters_map_alpn_for_trojan_and_supported_hysteria2_cores() {
        let trojan =
            parse_proxy_url("trojan://secret@example.com:443?alpn=h2&alpn=http%2F1.1").unwrap();
        let hysteria2 =
            parse_proxy_url("hysteria2://secret@example.com:443?alpn=h2&alpn=http%2F1.1").unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&trojan).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Xray => &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }

        for core in [CoreId::SingBox, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&hysteria2).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
                CoreId::Xray => unreachable!(),
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }
        assert!(
            !adapter(CoreId::Xray)
                .compatibility(&hysteria2)
                .is_supported()
        );
    }

    #[test]
    fn adapters_map_tls_client_fingerprints_for_supported_protocols() {
        use base64::{Engine as _, engine::general_purpose};

        let vless = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&fp=chrome",
        )
        .unwrap();
        let vmess_payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","tls":"tls","fp":"firefox"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{vmess_payload}")).unwrap();
        let trojan = parse_proxy_url("trojan://secret@example.com:443?fp=safari").unwrap();

        for (node, expected) in [(&vless, "chrome"), (&vmess, "firefox"), (&trojan, "safari")] {
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                let generated = adapter(core).generate_config(node).unwrap();
                let document: Value = serde_json::from_slice(&generated.content).unwrap();
                let fingerprint = match core {
                    CoreId::SingBox => &document["outbounds"][0]["tls"]["utls"]["fingerprint"],
                    CoreId::Xray => {
                        &document["outbounds"][0]["streamSettings"]["tlsSettings"]["fingerprint"]
                    }
                    CoreId::Mihomo => &document["proxies"][0]["client-fingerprint"],
                };
                assert_eq!(fingerprint.as_str(), Some(expected), "{core}");
                if core == CoreId::SingBox {
                    assert!(document["outbounds"][0]["tls"]["utls"]["enabled"].as_bool().unwrap());
                }
            }
        }
    }

    #[test]
    fn adapters_reject_invalid_or_inapplicable_tls_fingerprints() {
        let no_tls = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?fp=chrome",
        )
        .unwrap();
        let invalid = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&fp=unknown",
        )
        .unwrap();
        let hysteria2 = parse_proxy_url("hysteria2://secret@example.com:443?fp=chrome").unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&no_tls).is_supported());
            assert!(!adapter(core).compatibility(&invalid).is_supported());
            assert!(!adapter(core).compatibility(&hysteria2).is_supported());
        }
    }

    #[test]
    fn adapters_reject_alpn_without_tls_and_malformed_alpn() {
        let no_tls =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?alpn=h2")
                .unwrap();
        let empty_entry = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2%2C%2Chttp%2F1.1",
        )
        .unwrap();
        let duplicate_entry = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2&alpn=h2",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&no_tls).is_supported());
            assert!(!adapter(core).compatibility(&empty_entry).is_supported());
            assert!(!adapter(core).compatibility(&duplicate_entry).is_supported());
        }
    }

    #[test]
    fn adapters_reject_repeated_or_ambiguous_options() {
        let repeated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?sni=a.example&sni=b.example&security=tls",
        )
        .unwrap();
        let ambiguous = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&tls=tls",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&repeated).is_supported());
            assert!(!adapter(core).compatibility(&ambiguous).is_supported());
        }
    }
}    #[test]
    fn adapters_support_websocket_for_vless_and_vmess() {
        use base64::{Engine as _, engine::general_purpose};

        let vless =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&path=%2Fws")
                .unwrap();
        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"ws","path":"/vmess","host":"cdn.example","tls":"tls"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        for node in [&vless, &vmess] {
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                assert!(
                    adapter(core).compatibility(node).is_supported(),
                    "{core}: {:?}",
                    adapter(core).compatibility(node).reason
                );
                let _: Value = serde_json::from_slice(
                    &adapter(core).generate_config(node).unwrap().content,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn all_adapters_generate_a_native_document_for_basic_vless() {
        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let adapter = adapter(core);
            assert!(adapter.compatibility(&node).is_supported(), "{core}");
            let generated = adapter.generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            assert!(document.is_object());
        }
    }

    #[test]
    fn adapters_map_websocket_transport_and_keep_host_separate_from_sni() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&host=cdn.example&path=%2Fsocket&security=tls&sni=tls.example",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let (network, path, host, sni) = match core {
                CoreId::SingBox => (
                    document["outbounds"][0]["transport"]["type"].as_str(),
                    document["outbounds"][0]["transport"]["path"].as_str(),
                    document["outbounds"][0]["transport"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["tls"]["server_name"].as_str(),
                ),
                CoreId::Xray => (
                    document["outbounds"][0]["streamSettings"]["network"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["path"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"].as_str(),
                ),
                CoreId::Mihomo => (
                    document["proxies"][0]["network"].as_str(),
                    document["proxies"][0]["ws-opts"]["path"].as_str(),
                    document["proxies"][0]["ws-opts"]["headers"]["Host"].as_str(),
                    document["proxies"][0]["servername"].as_str(),
                ),
            };
            assert_eq!(network, Some(if core == CoreId::SingBox { "ws" } else { "ws" }));
            assert_eq!(path, Some("/socket"), "{core}");
            assert_eq!(host, Some("cdn.example"), "{core}");
            assert_eq!(sni, Some("tls.example"), "{core}");
        }
    }

    #[test]
    fn adapters_reject_unknown_transport_without_dropping_it() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=quic",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let compatibility = adapter(core).compatibility(&node);
            assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
            assert!(compatibility.reason.unwrap().contains("transport"));
        }
    }

    #[test]
    fn xray_explicitly_rejects_hysteria2() {
        let node = parse_proxy_url("hysteria2://secret@example.com:443").unwrap();
        let compatibility = adapter(CoreId::Xray).compatibility(&node);
        assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
    }

    #[test]
    fn basic_protocol_matrix_matches_the_initial_support_contract() {
        use base64::{Engine as _, engine::general_purpose};

        let vmess_payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","ps":"vmess"}"#,
        );
        let vmess_url = format!("vmess://{vmess_payload}");
        let cases: [(&str, bool); 5] = [
            (
                "vless://11111111-1111-4111-8111-111111111111@example.com:443",
                true,
            ),
            (vmess_url.as_str(), true),
            ("trojan://secret@example.com:443", true),
            ("ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388", true),
            ("hysteria2://secret@example.com:443", false),
        ];
        for (url, all_cores) in cases {
            let node = parse_proxy_url(url).unwrap();
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                let expected = all_cores || core != CoreId::Xray;
                let result = adapter(core).compatibility(&node);
                assert_eq!(
                    result.is_supported(),
                    expected,
                    "{core} / {}",
                    node.protocol
                );
                if expected {
                    let generated = adapter(core).generate_config(&node).unwrap();
                    let _: Value = serde_json::from_slice(&generated.content).unwrap();
                }
            }
        }
    }

    #[test]
    fn adapters_support_websocket_for_vless_and_vmess() {
        use base64::{Engine as _, engine::general_purpose};

        let vless =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&path=%2Fws")
                .unwrap();
        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"ws","path":"/vmess","host":"cdn.example","tls":"tls"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        for node in [&vless, &vmess] {
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                assert!(
                    adapter(core).compatibility(node).is_supported(),
                    "{core}: {:?}",
                    adapter(core).compatibility(node).reason
                );
                let _: Value = serde_json::from_slice(
                    &adapter(core).generate_config(node).unwrap().content,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn adapters_map_repeated_and_comma_separated_alpn_values() {
        let repeated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2&alpn=http%2F1.1",
        )
        .unwrap();
        let comma_separated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2%2Chttp%2F1.1",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            for node in [&repeated, &comma_separated] {
                let generated = adapter(core).generate_config(node).unwrap();
                let document: Value = serde_json::from_slice(&generated.content).unwrap();
                let alpn = match core {
                    CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                    CoreId::Xray => {
                        &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"]
                    }
                    CoreId::Mihomo => &document["proxies"][0]["alpn"],
                };
                assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
            }
        }
    }

    #[test]
    fn adapters_map_structured_vmess_alpn_arrays() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","tls":"tls","alpn":["h2","http/1.1"]}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Xray => &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }
    }

    #[test]
    fn adapters_map_alpn_for_trojan_and_supported_hysteria2_cores() {
        let trojan =
            parse_proxy_url("trojan://secret@example.com:443?alpn=h2&alpn=http%2F1.1").unwrap();
        let hysteria2 =
            parse_proxy_url("hysteria2://secret@example.com:443?alpn=h2&alpn=http%2F1.1").unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&trojan).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Xray => &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }

        for core in [CoreId::SingBox, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&hysteria2).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
                CoreId::Xray => unreachable!(),
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }
        assert!(
            !adapter(CoreId::Xray)
                .compatibility(&hysteria2)
                .is_supported()
        );
    }

    #[test]
    fn adapters_map_tls_client_fingerprints_for_supported_protocols() {
        use base64::{Engine as _, engine::general_purpose};

        let vless = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&fp=chrome",
        )
        .unwrap();
        let vmess_payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","tls":"tls","fp":"firefox"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{vmess_payload}")).unwrap();
        let trojan = parse_proxy_url("trojan://secret@example.com:443?fp=safari").unwrap();

        for (node, expected) in [(&vless, "chrome"), (&vmess, "firefox"), (&trojan, "safari")] {
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                let generated = adapter(core).generate_config(node).unwrap();
                let document: Value = serde_json::from_slice(&generated.content).unwrap();
                let fingerprint = match core {
                    CoreId::SingBox => &document["outbounds"][0]["tls"]["utls"]["fingerprint"],
                    CoreId::Xray => {
                        &document["outbounds"][0]["streamSettings"]["tlsSettings"]["fingerprint"]
                    }
                    CoreId::Mihomo => &document["proxies"][0]["client-fingerprint"],
                };
                assert_eq!(fingerprint.as_str(), Some(expected), "{core}");
                if core == CoreId::SingBox {
                    assert!(document["outbounds"][0]["tls"]["utls"]["enabled"].as_bool().unwrap());
                }
            }
        }
    }

    #[test]
    fn adapters_reject_invalid_or_inapplicable_tls_fingerprints() {
        let no_tls = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?fp=chrome",
        )
        .unwrap();
        let invalid = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&fp=unknown",
        )
        .unwrap();
        let hysteria2 = parse_proxy_url("hysteria2://secret@example.com:443?fp=chrome").unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&no_tls).is_supported());
            assert!(!adapter(core).compatibility(&invalid).is_supported());
            assert!(!adapter(core).compatibility(&hysteria2).is_supported());
        }
    }

    #[test]
    fn adapters_reject_alpn_without_tls_and_malformed_alpn() {
        let no_tls =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?alpn=h2")
                .unwrap();
        let empty_entry = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2%2C%2Chttp%2F1.1",
        )
        .unwrap();
        let duplicate_entry = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2&alpn=h2",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&no_tls).is_supported());
            assert!(!adapter(core).compatibility(&empty_entry).is_supported());
            assert!(!adapter(core).compatibility(&duplicate_entry).is_supported());
        }
    }

    #[test]
    fn adapters_reject_repeated_or_ambiguous_options() {
        let repeated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?sni=a.example&sni=b.example&security=tls",
        )
        .unwrap();
        let ambiguous = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&tls=tls",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&repeated).is_supported());
            assert!(!adapter(core).compatibility(&ambiguous).is_supported());
        }
    }
}    #[test]
    fn adapters_map_websocket_transport_and_keep_host_separate_from_sni() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&host=cdn.example&path=%2Fsocket&security=tls&sni=tls.example",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let (network, path, host, sni) = match core {
                CoreId::SingBox => (
                    document["outbounds"][0]["transport"]["type"].as_str(),
                    document["outbounds"][0]["transport"]["path"].as_str(),
                    document["outbounds"][0]["transport"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["tls"]["server_name"].as_str(),
                ),
                CoreId::Xray => (
                    document["outbounds"][0]["streamSettings"]["network"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["path"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"].as_str(),
                ),
                CoreId::Mihomo => (
                    document["proxies"][0]["network"].as_str(),
                    document["proxies"][0]["ws-opts"]["path"].as_str(),
                    document["proxies"][0]["ws-opts"]["headers"]["Host"].as_str(),
                    document["proxies"][0]["servername"].as_str(),
                ),
            };
            assert_eq!(network, Some("ws"), "{core}");
            assert_eq!(path, Some("/socket"), "{core}");
            assert_eq!(host, Some("cdn.example"), "{core}");
            assert_eq!(sni, Some("tls.example"), "{core}");
        }
    }

    #[test]
    fn adapters_reject_unknown_transport_without_dropping_it() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=quic",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let compatibility = adapter(core).compatibility(&node);
            assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
            assert!(compatibility.reason.unwrap().contains("transport"));
        }
    }

    #[test]
    fn all_adapters_generate_a_native_document_for_basic_vless() {
        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let adapter = adapter(core);
            assert!(adapter.compatibility(&node).is_supported(), "{core}");
            let generated = adapter.generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            assert!(document.is_object());
        }
    }

    #[test]
    fn adapters_map_websocket_transport_and_keep_host_separate_from_sni() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&host=cdn.example&path=%2Fsocket&security=tls&sni=tls.example",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let (network, path, host, sni) = match core {
                CoreId::SingBox => (
                    document["outbounds"][0]["transport"]["type"].as_str(),
                    document["outbounds"][0]["transport"]["path"].as_str(),
                    document["outbounds"][0]["transport"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["tls"]["server_name"].as_str(),
                ),
                CoreId::Xray => (
                    document["outbounds"][0]["streamSettings"]["network"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["path"].as_str(),
                    document["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"].as_str(),
                    document["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"].as_str(),
                ),
                CoreId::Mihomo => (
                    document["proxies"][0]["network"].as_str(),
                    document["proxies"][0]["ws-opts"]["path"].as_str(),
                    document["proxies"][0]["ws-opts"]["headers"]["Host"].as_str(),
                    document["proxies"][0]["servername"].as_str(),
                ),
            };
            assert_eq!(network, Some(if core == CoreId::SingBox { "ws" } else { "ws" }));
            assert_eq!(path, Some("/socket"), "{core}");
            assert_eq!(host, Some("cdn.example"), "{core}");
            assert_eq!(sni, Some("tls.example"), "{core}");
        }
    }

    #[test]
    fn adapters_reject_unknown_transport_without_dropping_it() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=quic",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let compatibility = adapter(core).compatibility(&node);
            assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
            assert!(compatibility.reason.unwrap().contains("transport"));
        }
    }

    #[test]
    fn xray_explicitly_rejects_hysteria2() {
        let node = parse_proxy_url("hysteria2://secret@example.com:443").unwrap();
        let compatibility = adapter(CoreId::Xray).compatibility(&node);
        assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
    }

    #[test]
    fn basic_protocol_matrix_matches_the_initial_support_contract() {
        use base64::{Engine as _, engine::general_purpose};

        let vmess_payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","ps":"vmess"}"#,
        );
        let vmess_url = format!("vmess://{vmess_payload}");
        let cases: [(&str, bool); 5] = [
            (
                "vless://11111111-1111-4111-8111-111111111111@example.com:443",
                true,
            ),
            (vmess_url.as_str(), true),
            ("trojan://secret@example.com:443", true),
            ("ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388", true),
            ("hysteria2://secret@example.com:443", false),
        ];
        for (url, all_cores) in cases {
            let node = parse_proxy_url(url).unwrap();
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                let expected = all_cores || core != CoreId::Xray;
                let result = adapter(core).compatibility(&node);
                assert_eq!(
                    result.is_supported(),
                    expected,
                    "{core} / {}",
                    node.protocol
                );
                if expected {
                    let generated = adapter(core).generate_config(&node).unwrap();
                    let _: Value = serde_json::from_slice(&generated.content).unwrap();
                }
            }
        }
    }

    #[test]
    fn adapters_support_websocket_for_vless_and_vmess() {
        use base64::{Engine as _, engine::general_purpose};

        let vless =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&path=%2Fws")
                .unwrap();
        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"ws","path":"/vmess","host":"cdn.example","tls":"tls"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        for node in [&vless, &vmess] {
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                assert!(
                    adapter(core).compatibility(node).is_supported(),
                    "{core}: {:?}",
                    adapter(core).compatibility(node).reason
                );
                let _: Value = serde_json::from_slice(
                    &adapter(core).generate_config(node).unwrap().content,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn adapters_map_repeated_and_comma_separated_alpn_values() {
        let repeated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2&alpn=http%2F1.1",
        )
        .unwrap();
        let comma_separated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2%2Chttp%2F1.1",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            for node in [&repeated, &comma_separated] {
                let generated = adapter(core).generate_config(node).unwrap();
                let document: Value = serde_json::from_slice(&generated.content).unwrap();
                let alpn = match core {
                    CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                    CoreId::Xray => {
                        &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"]
                    }
                    CoreId::Mihomo => &document["proxies"][0]["alpn"],
                };
                assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
            }
        }
    }

    #[test]
    fn adapters_map_structured_vmess_alpn_arrays() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","tls":"tls","alpn":["h2","http/1.1"]}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Xray => &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }
    }

    #[test]
    fn adapters_map_alpn_for_trojan_and_supported_hysteria2_cores() {
        let trojan =
            parse_proxy_url("trojan://secret@example.com:443?alpn=h2&alpn=http%2F1.1").unwrap();
        let hysteria2 =
            parse_proxy_url("hysteria2://secret@example.com:443?alpn=h2&alpn=http%2F1.1").unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&trojan).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Xray => &document["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }

        for core in [CoreId::SingBox, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&hysteria2).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            let alpn = match core {
                CoreId::SingBox => &document["outbounds"][0]["tls"]["alpn"],
                CoreId::Mihomo => &document["proxies"][0]["alpn"],
                CoreId::Xray => unreachable!(),
            };
            assert_eq!(alpn, &serde_json::json!(["h2", "http/1.1"]), "{core}");
        }
        assert!(
            !adapter(CoreId::Xray)
                .compatibility(&hysteria2)
                .is_supported()
        );
    }

    #[test]
    fn adapters_map_tls_client_fingerprints_for_supported_protocols() {
        use base64::{Engine as _, engine::general_purpose};

        let vless = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&fp=chrome",
        )
        .unwrap();
        let vmess_payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","tls":"tls","fp":"firefox"}"#,
        );
        let vmess = parse_proxy_url(&format!("vmess://{vmess_payload}")).unwrap();
        let trojan = parse_proxy_url("trojan://secret@example.com:443?fp=safari").unwrap();

        for (node, expected) in [(&vless, "chrome"), (&vmess, "firefox"), (&trojan, "safari")] {
            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                let generated = adapter(core).generate_config(node).unwrap();
                let document: Value = serde_json::from_slice(&generated.content).unwrap();
                let fingerprint = match core {
                    CoreId::SingBox => &document["outbounds"][0]["tls"]["utls"]["fingerprint"],
                    CoreId::Xray => {
                        &document["outbounds"][0]["streamSettings"]["tlsSettings"]["fingerprint"]
                    }
                    CoreId::Mihomo => &document["proxies"][0]["client-fingerprint"],
                };
                assert_eq!(fingerprint.as_str(), Some(expected), "{core}");
                if core == CoreId::SingBox {
                    assert!(document["outbounds"][0]["tls"]["utls"]["enabled"].as_bool().unwrap());
                }
            }
        }
    }

    #[test]
    fn adapters_reject_invalid_or_inapplicable_tls_fingerprints() {
        let no_tls = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?fp=chrome",
        )
        .unwrap();
        let invalid = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&fp=unknown",
        )
        .unwrap();
        let hysteria2 = parse_proxy_url("hysteria2://secret@example.com:443?fp=chrome").unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&no_tls).is_supported());
            assert!(!adapter(core).compatibility(&invalid).is_supported());
            assert!(!adapter(core).compatibility(&hysteria2).is_supported());
        }
    }

    #[test]
    fn adapters_reject_alpn_without_tls_and_malformed_alpn() {
        let no_tls =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?alpn=h2")
                .unwrap();
        let empty_entry = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2%2C%2Chttp%2F1.1",
        )
        .unwrap();
        let duplicate_entry = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&alpn=h2&alpn=h2",
        )
        .unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&no_tls).is_supported());
            assert!(!adapter(core).compatibility(&empty_entry).is_supported());
            assert!(!adapter(core).compatibility(&duplicate_entry).is_supported());
        }
    }

    #[test]
    fn adapters_reject_repeated_or_ambiguous_options() {
        let repeated = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?sni=a.example&sni=b.example&security=tls",
        )
        .unwrap();
        let ambiguous = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&tls=tls",
        )
        .unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            assert!(!adapter(core).compatibility(&repeated).is_supported());
            assert!(!adapter(core).compatibility(&ambiguous).is_supported());
        }
    }
}
