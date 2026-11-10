//! Opt-in native conformance checks for the sanitized adapter fixture matrix.
//!
//! Run with:
//! `cargo test --test native_adapter_validation -- --ignored --nocapture`
//!
//! The test uses only proxyctl-managed binaries and their config-check modes. It never starts a
//! proxy core or changes system networking.

use base64::{Engine as _, engine::general_purpose};
use proxyctl::{
    cores::{CoreId, adapters, core_binary_path},
    parser::parse_proxy_url,
};

struct Fixture {
    name: &'static str,
    url: String,
    supported_by: &'static [CoreId],
}

#[test]
#[ignore = "requires all three proxyctl-managed core binaries"]
fn validates_supported_adapter_fixtures_with_native_core_binaries() {
    let executables = CoreId::ALL
        .into_iter()
        .map(|core| {
            let path = core_binary_path(core).expect("managed core path should resolve");
            assert!(
                path.is_file(),
                "{core} is not installed at {}; run `proxyctl setup` first",
                path.display()
            );
            (core, path)
        })
        .collect::<Vec<_>>();

    let fixtures = fixtures();
    let mut validated = 0usize;
    let mut benchmark_configs_validated = 0usize;
    let mut activation_configs_validated = 0usize;

    for fixture in &fixtures {
        let node = parse_proxy_url(&fixture.url)
            .unwrap_or_else(|error| panic!("fixture '{}' failed to parse: {error}", fixture.name));

        for (core, executable) in &executables {
            let adapter = adapters::adapter(*core);
            let compatibility = adapter.compatibility(&node);
            let expected = fixture.supported_by.contains(core);

            assert_eq!(
                compatibility.is_supported(),
                expected,
                "fixture '{}' compatibility mismatch for {core}: {:?}",
                fixture.name,
                compatibility.reason
            );

            if !expected {
                continue;
            }

            let generated = adapter.generate_config(&node).unwrap_or_else(|error| {
                panic!(
                    "fixture '{}' config generation failed for {core}: {error:#}",
                    fixture.name
                )
            });
            if let Err(error) =
                adapters::validation::validate_generated_config(*core, &generated, executable)
            {
                let diagnostic = if *core == CoreId::Xray {
                    xray_validation_diagnostic(&generated, executable)
                } else {
                    String::new()
                };
                panic!(
                    "native validation failed for fixture '{}' on {core}: {error:#}\\n{diagnostic}",
                    fixture.name
                );
            }
            validated += 1;

            let benchmark_generated = adapter
                .generate_benchmark_config(&node, 43127)
                .unwrap_or_else(|error| {
                    panic!(
                        "fixture '{}' benchmark config generation failed for {core}: {error:#}",
                        fixture.name
                    )
                });
            if let Err(error) = adapters::validation::validate_generated_config(
                *core,
                &benchmark_generated,
                executable,
            ) {
                let diagnostic = if *core == CoreId::Xray {
                    xray_validation_diagnostic(&benchmark_generated, executable)
                } else {
                    String::new()
                };
                panic!(
                    "native benchmark config validation failed for fixture '{}' on {core}: {error:#}\\n{diagnostic}",
                    fixture.name
                );
            }
            benchmark_configs_validated += 1;

            let activation_generated = adapter
                .generate_activation_config(&node, 43128)
                .unwrap_or_else(|error| {
                    panic!(
                        "fixture '{}' activation config generation failed for {core}: {error:#}",
                        fixture.name
                    )
                });
            if let Err(error) = adapters::validation::validate_generated_config(
                *core,
                &activation_generated,
                executable,
            ) {
                let diagnostic = if *core == CoreId::Xray {
                    xray_validation_diagnostic(&activation_generated, executable)
                } else {
                    String::new()
                };
                panic!(
                    "native activation config validation failed for fixture '{}' on {core}: {error:#}\\n{diagnostic}",
                    fixture.name
                );
            }
            activation_configs_validated += 1;
        }
    }

    println!(
        "Native validation succeeded for {validated} standard configs, {benchmark_configs_validated} loopback benchmark configs, and {activation_configs_validated} shared SOCKS5/HTTP activation configs across {} fixtures.",
        fixtures.len()
    );
}

/// Re-run a failed Xray check and expose its native diagnostic. This is deliberately
/// limited to this integration test: its fixtures contain synthetic credentials only.
/// Production validation errors must never include core output or generated config content.
fn xray_validation_diagnostic(
    generated: &adapters::GeneratedConfig,
    executable: &std::path::Path,
) -> String {
    use std::{io::Write, process::Command};
    let mut config = tempfile::Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("temporary JSON config should be created");
    config
        .write_all(&generated.content)
        .expect("temporary config should be written");

    match Command::new(executable)
        .arg("run")
        .arg("-test")
        .arg("-c")
        .arg(config.path())
        .output()
    {
        Ok(output) => format!(
            "Xray diagnostic (stdout):\\n{}\\nXray diagnostic (stderr):\\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => format!("Could not collect Xray diagnostic: {error}"),
    }
}

fn fixtures() -> Vec<Fixture> {
    use CoreId::{Mihomo, SingBox, Xray};

    let all = &[SingBox, Xray, Mihomo];
    let sing_box_and_mihomo = &[SingBox, Mihomo];
    let xray_only = &[Xray];
    let xray_and_mihomo = &[Xray, Mihomo];

    let vmess = |json: &str| {
        format!(
            "vmess://{}",
            general_purpose::STANDARD.encode(json.as_bytes())
        )
    };

    let xhttp_extra = serde_json::json!({
        "headers": {"User-Agent": "proxyctl-native-test"},
        "xPaddingBytes": "100-500",
        "xPaddingObfsMode": true,
        "noGRPCHeader": false,
        "xmux": {
            "maxConcurrency": "16-32",
            "hMaxReusableSecs": "1800-3000"
        }
    });
    let encoded_extra = url::form_urlencoded::byte_serialize(xhttp_extra.to_string().as_bytes())
        .collect::<String>();
    // Xray expects ML-DSA-65 verification material as unpadded base64url encoding
    // of exactly 1,952 bytes; the deterministic bytes are synthetic test data.
    let mldsa_verify = general_purpose::URL_SAFE_NO_PAD.encode([0x42; 1952]);

    // Xray 26.7.11+ rejects unencrypted VLESS to public addresses. Use the reserved
    // private `.local` test domain for fixtures that intentionally omit TLS/REALITY.
    vec![
        Fixture {
            name: "basic VLESS",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443".into(),
            supported_by: all,
        },
        Fixture {
            name: "VLESS TLS, ALPN and fingerprint",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?security=tls&sni=tls.example.com&alpn=h2,http%2F1.1&fp=chrome".into(),
            supported_by: all,
        },
        Fixture {
            name: "VLESS Vision flow",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?security=tls&flow=xtls-rprx-vision".into(),
            supported_by: all,
        },
        Fixture {
            name: "VLESS REALITY",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?security=reality&sni=www.example.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef".into(),
            supported_by: all,
        },
        Fixture {
            name: "REALITY SpiderX",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?security=reality&sni=www.example.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&spx=%2Fdns-query".into(),
            supported_by: xray_only,
        },
        Fixture {
            name: "REALITY ML-DSA-65 verification",
            url: format!(
                "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?security=reality&sni=www.example.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123456789abcdef&mldsa65Verify={mldsa_verify}"
            ),
            supported_by: xray_only,
        },
        Fixture {
            name: "VMess REALITY",
            url: vmess(r#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"tcp","tls":"reality","sni":"www.example.com","fp":"chrome","pbk":"jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0","sid":"0123456789abcdef"}"#),
            supported_by: xray_only,
        },
        Fixture {
            name: "WebSocket Host distinct from TLS SNI",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?type=ws&host=cdn.example.com&path=%2Fsocket&security=tls&sni=tls.example.com".into(),
            supported_by: all,
        },
        Fixture {
            name: "WebSocket early data",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?type=ws&path=%2Fws&ed=2048&eh=Sec-WebSocket-Protocol".into(),
            supported_by: all,
        },
        Fixture {
            name: "standard gRPC",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?type=grpc&serviceName=proxy.Service".into(),
            supported_by: all,
        },
        Fixture {
            name: "gRPC authority and multi mode",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?type=grpc&serviceName=proxy.Service&authority=grpc.example.com&mode=multi".into(),
            supported_by: xray_only,
        },
        Fixture {
            name: "HTTP/2 transport",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?type=http&host=cdn.example.com&path=%2Fh2&security=tls&sni=tls.example.com".into(),
            supported_by: sing_box_and_mihomo,
        },
        Fixture {
            name: "HTTPUpgrade transport",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?type=httpupgrade&host=cdn.example.com&path=%2Fupgrade".into(),
            supported_by: all,
        },
        Fixture {
            name: "VLESS XHTTP",
            url: "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?type=xhttp&mode=packet-up&host=cdn.example.com&path=%2Fapi".into(),
            supported_by: xray_and_mihomo,
        },
        Fixture {
            name: "VLESS XHTTP extra settings",
            url: format!(
                "vless://11111111-1111-4111-8111-111111111111@proxy.local:443?type=xhttp&extra={encoded_extra}"
            ),
            supported_by: xray_and_mihomo,
        },
        Fixture {
            name: "VMess XHTTP",
            url: vmess(r#"{"add":"vmess.example","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"xhttp","type":"stream-one","host":"cdn.example.com","path":"/xhttp","tls":"tls"}"#),
            supported_by: xray_only,
        },
        Fixture {
            name: "Trojan TLS",
            url: "trojan://fixture-password@proxy.local:443?sni=tls.example.com&alpn=h2".into(),
            supported_by: all,
        },
        Fixture {
            name: "Shadowsocks basic",
            url: "ss://YWVzLTI1Ni1nY206cGFzcw@ss.example.com:8388".into(),
            supported_by: all,
        },
        Fixture {
            name: "Shadowsocks obfs-local",
            url: "ss://YWVzLTI1Ni1nY206cGFzcw@ss.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com".into(),
            supported_by: sing_box_and_mihomo,
        },
        Fixture {
            name: "Shadowsocks v2ray-plugin",
            url: "ss://YWVzLTI1Ni1nY206cGFzcw@ss.example.com:8388/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dcdn.example.com%3Bpath%3D%2Fws".into(),
            supported_by: sing_box_and_mihomo,
        },
        Fixture {
            name: "Hysteria2 basic TLS",
            url: "hysteria2://fixture-password@proxy.local:443?sni=tls.example.com&alpn=h3".into(),
            supported_by: sing_box_and_mihomo,
        },
        Fixture {
            name: "Hysteria2 Salamander obfuscation",
            url: "hysteria2://fixture-password@proxy.local:443?obfs=salamander&obfs-password=fixture-obfs-password".into(),
            supported_by: sing_box_and_mihomo,
        },
        Fixture {
            name: "Hysteria2 Gecko packet-size controls",
            url: "hysteria2://fixture-password@proxy.local:443?obfs=gecko&obfs-password=fixture-obfs-password&obfs-min-packet-size=512&obfs-max-packet-size=1200".into(),
            supported_by: sing_box_and_mihomo,
        },
    ]
}
