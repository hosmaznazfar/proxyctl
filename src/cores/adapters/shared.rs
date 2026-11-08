use serde_json::{Map, Value};

use crate::domain::{Protocol, ProxyNode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityStatus {
    Supported,
    Unsupported,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Compatibility {
    pub status: CompatibilityStatus,
    /// Safe diagnostic: must not contain credentials or option values.
    pub reason: Option<String>,
}

impl Compatibility {
    pub fn supported() -> Self {
        Self { status: CompatibilityStatus::Supported, reason: None }
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self { status: CompatibilityStatus::Unsupported, reason: Some(reason.into()) }
    }

    pub fn invalid(reason: impl Into<String>) -> Self {
        Self { status: CompatibilityStatus::Invalid, reason: Some(reason.into()) }
    }

    pub fn is_supported(&self) -> bool {
        self.status == CompatibilityStatus::Supported
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedConfig {
    pub format: &'static str,
    pub content: Vec<u8>,
}

pub(crate) fn option_string<'a>(node: &'a ProxyNode, key: &str) -> Option<&'a str> {
    node.option(key).and_then(Value::as_str).or_else(|| {
        if node.option_entries.is_empty() {
            node.options.get(key).map(String::as_str)
        } else {
            None
        }
    })
}

fn reject_unknown_options(node: &ProxyNode, supported: &[&str]) -> Result<(), String> {
    let keys = if node.option_entries.is_empty() {
        node.options.keys().map(String::as_str).collect::<Vec<_>>()
    } else {
        node.option_entries.iter().map(|entry| entry.key.as_str()).collect::<Vec<_>>()
    };
    if let Some(key) = keys.into_iter().find(|key| !supported.contains(&key)) {
        return Err(format!("option '{key}' is not supported by this adapter yet"));
    }
    Ok(())
}

pub(crate) fn validate_common(node: &ProxyNode) -> Result<(), String> {
    if node.server.is_empty() || node.port == 0 {
        return Err("server and port must be valid".into());
    }
    if matches!(node.protocol, Protocol::Vless | Protocol::Vmess) && node.identity.is_none() {
        return Err("protocol identity is missing".into());
    }
    if matches!(node.protocol, Protocol::Trojan | Protocol::Shadowsocks | Protocol::Hysteria2)
        && node.secret.is_none()
    {
        return Err("protocol secret is missing".into());
    }

    let mut supported = vec!["security", "tls", "sni"];
    match node.protocol {
        Protocol::Vless => supported.push("encryption"),
        Protocol::Vmess => {
            supported.push("aid");
            supported.push("scy");
        }
        Protocol::Trojan | Protocol::Shadowsocks | Protocol::Hysteria2 => {}
    }
    reject_unknown_options(node, &supported)?;

    if node.protocol == Protocol::Vless
        && option_string(node, "encryption").is_some_and(|value| value != "none")
    {
        return Err("only VLESS encryption=none is currently mapped".into());
    }
    if node.protocol == Protocol::Vmess {
        if option_string(node, "aid").is_some_and(|value| value.parse::<u32>().is_err()) {
            return Err("VMess alter ID is invalid".into());
        }
        if option_string(node, "scy").is_some_and(|value| !["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"].contains(&value)) {
            return Err("VMess cipher is not supported by this adapter".into());
        }
    }
    Ok(())
}

pub(crate) fn tls_options(node: &ProxyNode) -> Result<Option<Value>, String> {
    let default_tls = matches!(node.protocol, Protocol::Trojan | Protocol::Hysteria2);
    let security = option_string(node, "security")
        .or_else(|| option_string(node, "tls"))
        .unwrap_or(if default_tls { "tls" } else { "none" })
        .to_ascii_lowercase();
    match security.as_str() {
        "none" | "" | "false" | "0" => {
            if matches!(node.protocol, Protocol::Trojan | Protocol::Hysteria2) {
                return Err("Hysteria2 requires TLS".into());
            }
            Ok(None)
        }
        "tls" | "true" | "1" => {
            let mut tls = Map::new();
            tls.insert("enabled".into(), Value::Bool(true));
            if let Some(sni) = option_string(node, "sni") {
                tls.insert("server_name".into(), Value::String(sni.into()));
            }
            Ok(Some(Value::Object(tls)))
        }
        "reality" => Err("REALITY is not enabled in this adapter batch; refusing partial conversion".into()),
        _ => Err("unsupported TLS/security mode".into()),
    }
}
