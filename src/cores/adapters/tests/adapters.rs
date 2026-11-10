use super::*;

#[test]
fn vmess_numeric_alter_id_is_preserved_and_validated() {
    use base64::{Engine as _, engine::general_purpose};

    let valid = general_purpose::STANDARD.encode(
        br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","aid":7}"#,
    );
    let node = parse_proxy_url(&format!("vmess://{valid}")).unwrap();
    let generated = adapter(CoreId::Xray).generate_config(&node).unwrap();
    let document: Value = serde_json::from_slice(&generated.content).unwrap();
    assert_eq!(
        document["outbounds"][0]["settings"]["vnext"][0]["users"][0]["alterId"],
        7
    );

    let invalid = general_purpose::STANDARD.encode(
        br#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","aid":-1}"#,
    );
    let node = parse_proxy_url(&format!("vmess://{invalid}")).unwrap();
    assert_eq!(
        adapter(CoreId::Xray).compatibility(&node).status,
        CompatibilityStatus::Invalid
    );
}

#[test]
fn all_adapters_generate_a_native_document_for_basic_vless() {
    let node =
        parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443").unwrap();
    for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
        let adapter = adapter(core);
        assert!(adapter.compatibility(&node).is_supported(), "{core}");
        let generated = adapter.generate_config(&node).unwrap();
        let document: Value = serde_json::from_slice(&generated.content).unwrap();
        assert!(document.is_object());
    }
}

#[test]
fn benchmark_configs_bind_only_to_loopback_for_each_core() {
    let node =
        parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443").unwrap();

    for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
        let generated = adapter(core)
            .generate_benchmark_config(&node, 43127)
            .unwrap();
        let document: Value = serde_json::from_slice(&generated.content).unwrap();
        match core {
            CoreId::SingBox => {
                assert_eq!(document["inbounds"][0]["type"], "http");
                assert_eq!(document["inbounds"][0]["listen"], "127.0.0.1");
                assert_eq!(document["inbounds"][0]["listen_port"], 43127);
                assert_eq!(document["route"]["final"], "proxy");
            }
            CoreId::Xray => {
                assert_eq!(document["inbounds"][0]["protocol"], "http");
                assert_eq!(document["inbounds"][0]["listen"], "127.0.0.1");
                assert_eq!(document["inbounds"][0]["port"], 43127);
            }
            CoreId::Mihomo => {
                assert_eq!(document["port"], 43127);
                assert_eq!(document["bind-address"], "127.0.0.1");
                assert_eq!(document["allow-lan"], false);
            }
        }
    }
}

#[test]
fn activation_configs_share_one_loopback_port_for_socks5_and_http() {
    let node =
        parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443").unwrap();

    for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
        let generated = adapter(core)
            .generate_activation_config(&node, 43128)
            .unwrap();
        let document: Value = serde_json::from_slice(&generated.content).unwrap();
        match core {
            CoreId::SingBox => {
                assert_eq!(document["inbounds"][0]["type"], "mixed");
                assert_eq!(document["inbounds"][0]["listen"], "127.0.0.1");
                assert_eq!(document["inbounds"][0]["listen_port"], 43128);
                assert_eq!(document["route"]["final"], "proxy");
            }
            CoreId::Xray => {
                assert_eq!(document["inbounds"][0]["protocol"], "mixed");
                assert_eq!(document["inbounds"][0]["listen"], "127.0.0.1");
                assert_eq!(document["inbounds"][0]["port"], 43128);
                assert_eq!(document["inbounds"][0]["settings"]["auth"], "noauth");
                assert_eq!(document["inbounds"][0]["settings"]["udp"], true);
            }
            CoreId::Mihomo => {
                assert_eq!(document["mixed-port"], 43128);
                assert_eq!(document["bind-address"], "127.0.0.1");
                assert_eq!(document["allow-lan"], false);
                assert!(document.get("port").is_none());
                assert!(document.get("socks-port").is_none());
            }
        }
    }
}

#[test]
fn tun_activation_configs_keep_mixed_listener_and_disable_dns_firewall_redirects() {
    let node =
        parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443").unwrap();
    for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
        let generated = adapter(core).generate_tun_activation_config(&node, 43129).unwrap();
        let document: Value = serde_json::from_slice(&generated.content).unwrap();
        match core {
            CoreId::SingBox => {
                assert_eq!(document["inbounds"][0]["type"], "mixed");
                assert_eq!(document["inbounds"][0]["listen"], "127.0.0.1");
                assert_eq!(document["inbounds"][0]["listen_port"], 43129);
                assert_eq!(document["inbounds"][1]["type"], "tun");
                assert_eq!(document["inbounds"][1]["interface_name"], "tun-proxyctl");
                assert_eq!(document["inbounds"][1]["auto_route"], true);
                assert_eq!(document["inbounds"][1]["dns_mode"], "disabled");
                assert_eq!(document["route"]["auto_detect_interface"], true);
            }
            CoreId::Xray => {
                assert_eq!(document["inbounds"][0]["protocol"], "mixed");
                assert_eq!(document["inbounds"][0]["listen"], "127.0.0.1");
                assert_eq!(document["inbounds"][0]["port"], 43129);
                assert_eq!(document["inbounds"][1]["protocol"], "tun");
                assert_eq!(document["inbounds"][1]["settings"]["autoOutboundsInterface"], "auto");
                assert_eq!(document["inbounds"][1]["settings"]["autoSystemDnsToGateway"], false);
            }
            CoreId::Mihomo => {
                assert_eq!(document["mixed-port"], 43129);
                assert_eq!(document["bind-address"], "127.0.0.1");
                assert_eq!(document["allow-lan"], false);
                assert_eq!(document["tun"]["stack"], "system");
                assert_eq!(document["tun"]["auto-route"], true);
                assert_eq!(document["tun"]["auto-detect-interface"], true);
                assert_eq!(document["tun"]["auto-redirect"], false);
                assert_eq!(document["tun"]["dns-mode"], "disabled");
                assert!(document["tun"]["dns-hijack"].as_array().unwrap().is_empty());
            }
        }
    }
}

#[test]
fn adapters_reject_unknown_transport_without_dropping_it() {
    let node =
        parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443?type=quic")
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

#[test]
fn hysteria2_obfuscation_maps_to_sing_box_and_mihomo() {
    let node = parse_proxy_url(
        "hysteria2://secret@example.com:443?obfs=salamander&obfs-password=obfs-secret",
    )
    .unwrap();

    let sing_box = adapter(CoreId::SingBox).generate_config(&node).unwrap();
    let sing_box_doc: Value = serde_json::from_slice(&sing_box.content).unwrap();
    assert_eq!(sing_box_doc["outbounds"][0]["obfs"]["type"], "salamander");
    assert_eq!(
        sing_box_doc["outbounds"][0]["obfs"]["password"],
        "obfs-secret"
    );

    let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
    let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
    assert_eq!(mihomo_doc["proxies"][0]["obfs"], "salamander");
    assert_eq!(mihomo_doc["proxies"][0]["obfs-password"], "obfs-secret");

    assert_eq!(
        adapter(CoreId::Xray).compatibility(&node).status,
        CompatibilityStatus::Unsupported
    );
}

#[test]
fn hysteria2_obfuscation_requires_a_supported_type_and_password() {
    let missing_password =
        parse_proxy_url("hysteria2://secret@example.com:443?obfs=salamander").unwrap();
    let missing_type =
        parse_proxy_url("hysteria2://secret@example.com:443?obfs-password=secret").unwrap();
    let unknown_type =
        parse_proxy_url("hysteria2://secret@example.com:443?obfs=unknown&obfs-password=secret")
            .unwrap();

    for node in [&missing_password, &missing_type, &unknown_type] {
        assert_eq!(
            adapter(CoreId::SingBox).compatibility(node).status,
            CompatibilityStatus::Invalid
        );
        assert_eq!(
            adapter(CoreId::Mihomo).compatibility(node).status,
            CompatibilityStatus::Invalid
        );
    }
}

#[test]
fn shadowsocks_obfs_local_plugin_maps_to_sing_box_and_mihomo() {
    let node = parse_proxy_url(
        "ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example",
    ).unwrap();

    let sing_box = adapter(CoreId::SingBox).generate_config(&node).unwrap();
    let sing_box_doc: Value = serde_json::from_slice(&sing_box.content).unwrap();
    assert_eq!(sing_box_doc["outbounds"][0]["plugin"], "obfs-local");
    assert_eq!(
        sing_box_doc["outbounds"][0]["plugin_opts"],
        "obfs=http;obfs-host=cdn.example"
    );

    let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
    let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
    assert_eq!(mihomo_doc["proxies"][0]["plugin"], "obfs");
    assert_eq!(mihomo_doc["proxies"][0]["plugin-opts"]["mode"], "http");
    assert_eq!(
        mihomo_doc["proxies"][0]["plugin-opts"]["host"],
        "cdn.example"
    );

    assert_eq!(
        adapter(CoreId::Xray).compatibility(&node).status,
        CompatibilityStatus::Unsupported
    );
}

#[test]
fn shadowsocks_v2ray_plugin_maps_to_sing_box_and_mihomo() {
    let node = parse_proxy_url(
        "ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dcdn.example%3Bpath%3D%2Fws",
    ).unwrap();

    let sing_box = adapter(CoreId::SingBox).generate_config(&node).unwrap();
    let sing_box_doc: Value = serde_json::from_slice(&sing_box.content).unwrap();
    assert_eq!(sing_box_doc["outbounds"][0]["plugin"], "v2ray-plugin");

    let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
    let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
    assert_eq!(mihomo_doc["proxies"][0]["plugin"], "v2ray-plugin");
    assert_eq!(mihomo_doc["proxies"][0]["plugin-opts"]["tls"], true);
    assert_eq!(
        mihomo_doc["proxies"][0]["plugin-opts"]["host"],
        "cdn.example"
    );
    assert_eq!(mihomo_doc["proxies"][0]["plugin-opts"]["path"], "/ws");
}

#[test]
fn unsupported_shadowsocks_plugin_options_are_not_dropped() {
    let node =
        parse_proxy_url("ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388/?plugin=unknown-plugin")
            .unwrap();
    for core in [CoreId::SingBox, CoreId::Mihomo] {
        assert_eq!(
            adapter(core).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
    }
}

#[test]
fn hysteria2_gecko_packet_size_controls_map_to_both_supported_cores() {
    let node = parse_proxy_url(
        "hysteria2://secret@example.com:443?obfs=gecko&obfs-password=secret&obfs-min-packet-size=512&obfs-max-packet-size=1200",
    ).unwrap();

    let sing_box = adapter(CoreId::SingBox).generate_config(&node).unwrap();
    let sing_box_doc: Value = serde_json::from_slice(&sing_box.content).unwrap();
    assert_eq!(sing_box_doc["outbounds"][0]["obfs"]["min_packet_size"], 512);
    assert_eq!(
        sing_box_doc["outbounds"][0]["obfs"]["max_packet_size"],
        1200
    );

    let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
    let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
    assert_eq!(mihomo_doc["proxies"][0]["obfs-min-packet-size"], 512);
    assert_eq!(mihomo_doc["proxies"][0]["obfs-max-packet-size"], 1200);
}

#[test]
fn hysteria2_packet_size_controls_require_gecko_and_valid_ranges() {
    let salamander = parse_proxy_url(
        "hysteria2://secret@example.com:443?obfs=salamander&obfs-password=secret&obfs-min-packet-size=512",
    ).unwrap();
    let invalid_range = parse_proxy_url(
        "hysteria2://secret@example.com:443?obfs=gecko&obfs-password=secret&obfs-min-packet-size=1200&obfs-max-packet-size=512",
    ).unwrap();

    for node in [&salamander, &invalid_range] {
        assert_eq!(
            adapter(CoreId::SingBox).compatibility(node).status,
            CompatibilityStatus::Invalid
        );
        assert_eq!(
            adapter(CoreId::Mihomo).compatibility(node).status,
            CompatibilityStatus::Invalid
        );
    }
}

#[test]
fn empty_shadowsocks_plugin_value_is_invalid_not_ignored() {
    let node = parse_proxy_url("ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388/?plugin=").unwrap();
    for core in [CoreId::SingBox, CoreId::Mihomo, CoreId::Xray] {
        assert_eq!(
            adapter(core).compatibility(&node).status,
            CompatibilityStatus::Invalid
        );
    }
}
