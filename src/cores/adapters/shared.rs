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
        Self {
            status: CompatibilityStatus::Supported,
            reason: None,
        }
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            status: CompatibilityStatus::Unsupported,
            reason: Some(reason.into()),
        }
    }

    pub fn invalid(reason: impl Into<String>) -> Self {
        Self {
            status: CompatibilityStatus::Invalid,
            reason: Some(reason.into()),
        }
    }

    pub fn is_supported(&self) -> bool {
        self.status == CompatibilityStatus::Supported
    }
}

#[derive(Clone, Eq, PartialEq)]
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

/// Collect ALPN identifiers from URI query values or structured VMess arrays.
pub(crate) fn alpn_protocols(node: &ProxyNode) -> Result<Option<Vec<String>>, String> {
    let mut protocols = Vec::new();
    let mut was_supplied = false;

    if node.option_entries.is_empty() {
        if let Some(value) = node.options.get("alpn") {
            was_supplied = true;
            protocols.extend(value.split(',').map(str::to_owned));
        }
    } else {
        for entry in node
            .option_entries
            .iter()
            .filter(|entry| entry.key == "alpn")
        {
            was_supplied = true;
            match &entry.value {
                Value::String(value) => {
                    protocols.extend(value.split(',').map(str::to_owned));
                }
                Value::Array(values) => {
                    for value in values {
                        let value = value
                            .as_str()
                            .ok_or_else(|| "ALPN entries must be strings".to_owned())?;
                        protocols.extend(value.split(',').map(str::to_owned));
                    }
                }
                _ => return Err("ALPN must be a string or an array of strings".into()),
            }
        }
    }

    if !was_supplied {
        return Ok(None);
    }
    if protocols.is_empty() {
        return Err("ALPN list must not be empty".into());
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut normalized = Vec::with_capacity(protocols.len());
    for protocol in protocols {
        let protocol = protocol.trim();
        if protocol.is_empty() {
            return Err("ALPN contains an empty protocol identifier".into());
        }
        if protocol.len() > 255 || protocol.chars().any(char::is_control) {
            return Err("ALPN protocol identifiers must be at most 255 bytes and contain no control characters".into());
        }
        if !seen.insert(protocol.to_owned()) {
            return Err("ALPN protocol identifiers must not be repeated".into());
        }
        normalized.push(protocol.to_owned());
    }

    Ok(Some(normalized))
}

fn reject_unknown_options(node: &ProxyNode, supported: &[&str]) -> Result<(), String> {
    let keys = if node.option_entries.is_empty() {
        node.options.keys().map(String::as_str).collect::<Vec<_>>()
    } else {
        node.option_entries
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>()
    };
    if let Some(key) = keys.into_iter().find(|key| !supported.contains(key)) {
        return Err(format!(
            "option '{key}' is not supported by this adapter yet"
        ));
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
    if matches!(
        node.protocol,
        Protocol::Trojan | Protocol::Shadowsocks | Protocol::Hysteria2
    ) && node.secret.is_none()
    {
        return Err("protocol secret is missing".into());
    }

    let supported = match node.protocol {
        Protocol::Vless => vec!["security", "tls", "sni", "encryption", "type", "alpn", "fp"],
        Protocol::Vmess => vec!["security", "tls", "sni", "aid", "scy", "net", "alpn", "fp"],
        Protocol::Trojan => vec!["security", "tls", "sni", "alpn", "fp"],
        Protocol::Hysteria2 => vec!["security", "tls", "sni", "alpn", "fp"],
        Protocol::Shadowsocks => Vec::new(),
    };
    reject_unknown_options(node, &supported)?;
    if !node.option_entries.is_empty() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in &node.option_entries {
            if entry.key != "alpn" && !seen.insert(entry.key.as_str()) {
                return Err(format!(
                    "option '{}' is repeated and cannot be mapped safely",
                    entry.key
                ));
            }
        }
    }
    alpn_protocols(node)?;

    if let Some(fingerprint) = option_string(node, "fp") {
        const SUPPORTED_FINGERPRINTS: &[&str] = &[
            "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random",
        ];
        if !SUPPORTED_FINGERPRINTS.contains(&fingerprint) {
            return Err("TLS fingerprint is not supported; use a common browser fingerprint".into());
        }
        if matches!(node.protocol, Protocol::Hysteria2) {
            return Err("TLS client fingerprints are not supported for Hysteria2".into());
        }
    }

    if option_string(node, "security").is_some() && option_string(node, "tls").is_some() {
        return Err(
            "both security and tls options were supplied; refusing ambiguous TLS settings".into(),
        );
    }

    if node.protocol == Protocol::Vless {
        if option_string(node, "encryption").is_some_and(|value| value != "none") {
            return Err("only VLESS encryption=none is currently mapped".into());
        }
        if option_string(node, "type").is_some_and(|value| value != "tcp") {
            return Err("only VLESS type=tcp is currently mapped".into());
        }
    }
    if node.protocol == Protocol::Vmess {
        if option_string(node, "net").is_some_and(|value| value != "tcp") {
            return Err("only VMess net=tcp is currently mapped".into());
        }
        if option_string(node, "aid").is_some_and(|value| value.parse::<u32>().is_err()) {
            return Err("VMess alter ID is invalid".into());
        }
        if option_string(node, "scy").is_some_and(|value| {
            !["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"].contains(&value)
        }) {
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
                return Err("Trojan and Hysteria2 require TLS".into());
            }
            if option_string(node, "sni").is_some() {
                return Err("SNI was supplied while TLS is disabled".into());
            }
            if alpn_protocols(node)?.is_some() {
                return Err("ALPN was supplied while TLS is disabled".into());
            }
            if option_string(node, "fp").is_some() {
                return Err("TLS fingerprint was supplied while TLS is disabled".into());
            }
            Ok(None)
        }
        "tls" | "true" | "1" => {
            let mut tls = Map::new();
            tls.insert("enabled".into(), Value::Bool(true));
            if let Some(sni) = option_string(node, "sni") {
                tls.insert("server_name".into(), Value::String(sni.into()));
            }
            if let Some(protocols) = alpn_protocols(node)? {
                tls.insert(
                    "alpn".into(),
                    Value::Array(protocols.into_iter().map(Value::String).collect()),
                );
            }
            if let Some(fingerprint) = option_string(node, "fp") {
                tls.insert("fingerprint".into(), Value::String(fingerprint.into()));
            }
            Ok(Some(Value::Object(tls)))
        }
        "reality" => {
            Err("REALITY is not enabled in this adapter batch; refusing partial conversion".into())
        }
        _ => Err("unsupported TLS/security mode".into()),
    }
}
