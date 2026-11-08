use super::*;

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
    fn vless_vision_flow_maps_to_all_three_core_schemas() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&flow=xtls-rprx-vision",
        )
        .unwrap();
        let sing_box = adapter(CoreId::SingBox).generate_config(&node).unwrap();
        let sing_box_doc: Value = serde_json::from_slice(&sing_box.content).unwrap();
        assert_eq!(sing_box_doc["outbounds"][0]["flow"], "xtls-rprx-vision");

        let xray = adapter(CoreId::Xray).generate_config(&node).unwrap();
        let xray_doc: Value = serde_json::from_slice(&xray.content).unwrap();
        assert_eq!(
            xray_doc["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );

        let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
        let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
        assert_eq!(mihomo_doc["proxies"][0]["flow"], "xtls-rprx-vision");
    }



#[test]
    fn vless_vision_flow_requires_tls_and_rejects_unknown_modes() {
        let no_tls = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?flow=xtls-rprx-vision",
        )
        .unwrap();
        let unknown = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&flow=unknown",
        )
        .unwrap();
        assert!(!adapter(CoreId::Xray).compatibility(&no_tls).is_supported());
        assert!(!adapter(CoreId::Xray).compatibility(&unknown).is_supported());
    }



#[test]
    fn vmess_security_alias_is_cipher_not_tls_security() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","security":"aes-128-gcm","net":"tcp","tls":"tls","sni":"tls.example"}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = adapter(core).generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            match core {
                CoreId::SingBox => {
                    assert_eq!(document["outbounds"][0]["security"], "aes-128-gcm");
                    assert_eq!(document["outbounds"][0]["tls"]["server_name"], "tls.example");
                }
                CoreId::Xray => {
                    assert_eq!(
                        document["outbounds"][0]["settings"]["vnext"][0]["users"][0]["security"],
                        "aes-128-gcm"
                    );
                    assert_eq!(
                        document["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"],
                        "tls.example"
                    );
                }
                CoreId::Mihomo => {
                    assert_eq!(document["proxies"][0]["cipher"], "aes-128-gcm");
                    assert_eq!(document["proxies"][0]["servername"], "tls.example");
                }
            }
        }
    }



#[test]
    fn vmess_boolean_tls_and_insecure_values_are_normalized() {
        use base64::{Engine as _, engine::general_purpose};

        let payload = general_purpose::STANDARD.encode(
            br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","security":"auto","net":"tcp","tls":true,"insecure":true}"#,
        );
        let node = parse_proxy_url(&format!("vmess://{payload}")).unwrap();
        let sing_box = adapter(CoreId::SingBox).generate_config(&node).unwrap();
        let sing_box_doc: Value = serde_json::from_slice(&sing_box.content).unwrap();
        assert_eq!(sing_box_doc["outbounds"][0]["tls"]["insecure"], true);

        let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
        let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
        assert_eq!(mihomo_doc["proxies"][0]["skip-cert-verify"], true);
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
    fn hysteria2_pin_sha256_maps_to_mihomo_but_not_sing_box_114() {
        let node = parse_proxy_url(
            "hysteria2://password@example.com:443?pinSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&insecure=1",
        )
        .unwrap();
        assert_eq!(
            adapter(CoreId::SingBox).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
        let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
        let document: Value = serde_json::from_slice(&mihomo.content).unwrap();
        assert_eq!(
            document["proxies"][0]["fingerprint"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(document["proxies"][0]["skip-cert-verify"], true);
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


