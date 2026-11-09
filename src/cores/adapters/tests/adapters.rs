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
    assert_eq!(sing_box_doc["outbounds"][0]["obfs"]["password"], "obfs-secret");

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
    let missing_password = parse_proxy_url(
        "hysteria2://secret@example.com:443?obfs=salamander",
    )
    .unwrap();
    let missing_type = parse_proxy_url(
        "hysteria2://secret@example.com:443?obfs-password=secret",
    )
    .unwrap();
    let unknown_type = parse_proxy_url(
        "hysteria2://secret@example.com:443?obfs=unknown&obfs-password=secret",
    )
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
    assert_eq!(sing_box_doc["outbounds"][0]["plugin_opts"], "obfs=http;obfs-host=cdn.example");

    let mihomo = adapter(CoreId::Mihomo).generate_config(&node).unwrap();
    let mihomo_doc: Value = serde_json::from_slice(&mihomo.content).unwrap();
    assert_eq!(mihomo_doc["proxies"][0]["plugin"], "obfs");
    assert_eq!(mihomo_doc["proxies"][0]["plugin-opts"]["mode"], "http");
    assert_eq!(mihomo_doc["proxies"][0]["plugin-opts"]["host"], "cdn.example");

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
    assert_eq!(mihomo_doc["proxies"][0]["plugin-opts"]["host"], "cdn.example");
    assert_eq!(mihomo_doc["proxies"][0]["plugin-opts"]["path"], "/ws");
}

#[test]
fn unsupported_shadowsocks_plugin_options_are_not_dropped() {
    let node = parse_proxy_url(
        "ss://YWVzLTI1Ni1nY206cGFzcw@ss.example:8388/?plugin=unknown-plugin",
    ).unwrap();
    for core in [CoreId::SingBox, CoreId::Mihomo] {
        assert_eq!(
            adapter(core).compatibility(&node).status,
            CompatibilityStatus::Unsupported
        );
    }
}
