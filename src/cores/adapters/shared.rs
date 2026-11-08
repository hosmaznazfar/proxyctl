use serde_json::{Map, Value};

use crate::domain::{OptionEntry, Protocol, ProxyNode};

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

pub(crate) fn option_values<'a>(node: &'a ProxyNode, key: &str) -> Vec<&'a Value> {
    if node.option_entries.is_empty() {
        return node.options.get(key).map(|value| vec![unsafe_string_value(value)]).unwrap_or_default();
    }
    node.option_entries
        .iter()
        .filter(|entry| entry.key == key)
        .map(|entry| &entry.value)
        .collect()
}

// This helper is intentionally avoided in normal adapter paths; legacy records are handled
// through legacy_option below to keep the domain model backwards-compatible.
fn unsafe_string_value(_value: &str) -> &'static Value {
    unreachable!("legacy string options are read through legacy_option")
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

pub(crate) fn reject_unknown_options(
    node: &ProxyNode,
    supported: &[&str],
) -> Result<(), String> {
    let keys = if node.option_entries.is_empty() {
        node.options.keys().map(String::as_str).collect::<Vec<_>>()
    } else {
        node.option_entries.iter().map(|entry| entry.key.as_str()).collect::<Vec<_>>()
    };
    if let Some(key) = keys.into_iter().find(|key| !supported.contains(key)) {
        return Err(format!("option '{key}' is not supported by this adapter yet"));
    }
    Ok(())
}

pub(crate) fn validate_common(node: &ProxyNode, supported: &[&str]) -> Result<(), String> {
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
    reject_unknown_options(node, supported)
}

pub(crate) fn tls_options(node: &ProxyNode) -> Result<Option<Value>, String> {
    let security = option_string(node, "security")
        .or_else(|| option_string(node, "tls"))
        .unwrap_or("none")
        .to_ascii_lowercase();
    match security.as_str() {
        "none" | "" | "false" | "0" => Ok(None),
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

pub(crate) fn option_entry(key: &str, value: &str) -> OptionEntry {
    OptionEntry { key: key.into(), value: Value::String(value.into()) }
}
