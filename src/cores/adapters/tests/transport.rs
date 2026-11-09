use super::*;

#[test]
fn raw_transport_alias_normalizes_to_tcp() {
    let vless = parse_proxy_url(
        "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=raw",
    )
    .unwrap();
    let xray = adapter(CoreId::Xray).generate_config(&vless).unwrap();
    let document: Value = serde_json::from_slice(&xray.content).unwrap();
    assert_eq!(
        document["outbounds"][0]["streamSettings"]["network"],
        "tcp"
    );

    use base64::{Engine as _, engine::general_purpose};
    let payload = general_purpose::STANDARD.encode(
        br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"raw"}"#,
    );
    let vmess = parse_proxy_url(&format!("vmess://{payload}")).unwrap();
    assert!(adapter(CoreId::SingBox).compatibility(&vmess).is_supported());
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
                CompatibilityStatus::Invalid
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


