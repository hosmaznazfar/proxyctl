//! Sanitized end-to-end import smoke tests for every currently supported share-link scheme.

use base64::{Engine as _, engine::general_purpose};
use proxyctl::{
    cores::{CoreId, adapters::adapter},
    parser::parse_proxy_url,
};

#[test]
fn every_supported_share_link_scheme_imports_and_reaches_a_core_adapter() {
    let vmess_payload = general_purpose::STANDARD.encode(
        br#"{"v":"2","ps":"fixture-vmess","add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","aid":"0","scy":"auto","net":"tcp","tls":"tls","sni":"vmess.example"}"#,
    );
    let fixtures = [
        (
            "VLESS",
            "vless://11111111-1111-4111-8111-111111111111@vless.example:443?security=tls&sni=vless.example",
        ),
        ("VMess", ""),
        (
            "Trojan",
            "trojan://fixture-password@trojan.example:443?sni=trojan.example",
        ),
        (
            "Shadowsocks",
            "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1wYXNzd29yZA@ss.example:8388#fixture-ss",
        ),
        (
            "Hysteria2",
            "hysteria2://fixture-password@hy2.example:443?sni=hy2.example",
        ),
    ];

    for (name, fixture) in fixtures {
        let owned;
        let url = if name == "VMess" {
            owned = format!("vmess://{vmess_payload}");
            owned.as_str()
        } else {
            fixture
        };
        let node = parse_proxy_url(url)
            .unwrap_or_else(|error| panic!("{name} fixture must import successfully: {error}"));
        let mut generated_by_any_core = false;

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let compatibility = adapter(core).compatibility(&node);
            if compatibility.is_supported() {
                let generated = adapter(core)
                    .generate_config(&node)
                    .unwrap_or_else(|error| panic!("{name} must map to {core}: {error}"));
                serde_json::from_slice::<serde_json::Value>(&generated.content).unwrap_or_else(
                    |error| panic!("{name} {core} config must be valid JSON: {error}"),
                );
                generated_by_any_core = true;
            }
        }

        assert!(
            generated_by_any_core,
            "{name} must be supported by at least one available core adapter"
        );
    }
}
