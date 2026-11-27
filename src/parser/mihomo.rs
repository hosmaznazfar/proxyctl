//! Mihomo/Clash proxy-list YAML parser.
use crate::domain::{OptionEntry, Protocol, ProxyNode, SecretString};
use serde_yaml::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProfileError {
    InvalidYaml,
    MissingProxies,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SkippedProxy {
    /// One-based position within the YAML `proxies` sequence.
    pub index: usize,
    /// A fixed, credential-free explanation; never contains source fragments.
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct ParsedProfile {
    pub nodes: Vec<ProxyNode>,
    pub skipped: Vec<SkippedProxy>,
}

pub fn parse_profile(input: &str) -> Result<Vec<ProxyNode>, ProfileError> {
    parse_profile_detailed(input).map(|profile| profile.nodes)
}

/// Parse every proxy entry and retain safe diagnostics for entries that cannot
/// become standalone ProxyNode records.
pub fn parse_profile_detailed(input: &str) -> Result<ParsedProfile, ProfileError> {
    let root: Value = serde_yaml::from_str(input).map_err(|_| ProfileError::InvalidYaml)?;
    let proxies = root
        .get("proxies")
        .and_then(Value::as_sequence)
        .ok_or(ProfileError::MissingProxies)?;

    let mut nodes = Vec::with_capacity(proxies.len());
    let mut skipped = Vec::new();
    for (index, value) in proxies.iter().enumerate() {
        match parse_proxy(value) {
            Some(node) => nodes.push(node),
            None => skipped.push(SkippedProxy {
                index: index + 1,
                reason: skip_reason(value),
            }),
        }
    }
    Ok(ParsedProfile { nodes, skipped })
}

fn skip_reason(value: &Value) -> &'static str {
    let Some(mapping) = value.as_mapping() else {
        return "proxy entry is not a YAML mapping";
    };
    let Some(kind) = mapping
        .get(Value::String("type".into()))
        .and_then(Value::as_str)
    else {
        return "proxy entry is missing a valid type";
    };
    if !matches!(
        kind.to_ascii_lowercase().as_str(),
        "vless" | "vmess" | "trojan" | "ss" | "shadowsocks" | "hysteria2" | "hy2"
    ) {
        return "proxy protocol is not supported";
    }
    "proxy entry is missing a valid server, port, or required credential field"
}

fn parse_proxy(v: &Value) -> Option<ProxyNode> {
    let p = match v.get("type")?.as_str()?.to_ascii_lowercase().as_str() {
        "vless" => Protocol::Vless,
        "vmess" => Protocol::Vmess,
        "trojan" => Protocol::Trojan,
        "ss" | "shadowsocks" => Protocol::Shadowsocks,
        "hysteria2" | "hy2" => Protocol::Hysteria2,
        _ => return None,
    };
    let server = v.get("server")?.as_str()?.to_owned();
    let port: u16 = v.get("port")?.as_u64()?.try_into().ok()?;
    if server.is_empty() || port == 0 {
        return None;
    }
    let name = v.get("name").and_then(Value::as_str).map(str::to_owned);
    let identity = match p {
        Protocol::Shadowsocks => v.get("cipher"),
        Protocol::Vless | Protocol::Vmess => v.get("uuid"),
        _ => None,
    }
    .and_then(Value::as_str);
    let secret = match p {
        Protocol::Trojan | Protocol::Hysteria2 | Protocol::Shadowsocks => v.get("password"),
        _ => None,
    }
    .and_then(Value::as_str);

    // Do not manufacture incomplete authentication data. For these supported
    // protocols the credential is part of the source node's identity.
    let credentials_valid = match p {
        Protocol::Vless | Protocol::Vmess => identity.is_some_and(|value| !value.is_empty()),
        Protocol::Shadowsocks => {
            identity.is_some_and(|value| !value.is_empty())
                && secret.is_some_and(|value| !value.is_empty())
        }
        Protocol::Trojan | Protocol::Hysteria2 => secret.is_some_and(|value| !value.is_empty()),
    };
    if !credentials_valid {
        return None;
    }

    let excluded = [
        "name", "type", "server", "port", "uuid", "password", "cipher",
    ];
    let entries = v
        .as_mapping()
        .map(|m| {
            m.iter()
                .filter_map(|(k, val)| {
                    let key = k.as_str()?;
                    if excluded.contains(&key) {
                        return None;
                    }
                    Some(OptionEntry {
                        key: key.to_owned(),
                        value: serde_json::to_value(val).ok()?,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let opts = entries
        .iter()
        .filter_map(|e| e.value.as_str().map(|s| (e.key.clone(), s.to_owned())))
        .collect::<BTreeMap<_, _>>();
    Some(
        ProxyNode::new(
            p,
            server,
            port,
            name,
            identity.map(SecretString::new),
            secret.map(SecretString::new),
            opts,
            SecretString::new("[Mihomo YAML profile]"),
        )
        .with_option_entries(entries),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_nested_options() {
        let n = parse_profile("proxies:\n - name: fixture\n   type: vless\n   server: edge.invalid\n   port: 443\n   uuid: synthetic\n   tls:\n     servername: tls.invalid\n   ws-opts:\n     path: /fixture\n").unwrap();
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].identity.as_ref().unwrap().expose(), "synthetic");
        assert_eq!(n[0].option("tls").unwrap()["servername"], "tls.invalid");
        assert_eq!(n[0].option("ws-opts").unwrap()["path"], "/fixture");
    }

    #[test]
    fn ss_credentials() {
        let n = parse_profile("proxies:\n - type: ss\n   server: ss.invalid\n   port: 8388\n   cipher: aes-128-gcm\n   password: synthetic\n").unwrap();
        assert_eq!(n[0].identity.as_ref().unwrap().expose(), "aes-128-gcm");
        assert_eq!(n[0].secret.as_ref().unwrap().expose(), "synthetic");
    }

    #[test]
    fn reports_each_unsupported_and_malformed_entry_without_source_values() {
        let profile = parse_profile_detailed(
            "proxies:\n - type: direct\n   password: must-not-appear\n - type: vless\n   server: edge.invalid\n   port: 70000\n   uuid: private-value\n - type: trojan\n   server: edge.invalid\n   port: 443\n",
        )
        .unwrap();
        assert!(profile.nodes.is_empty());
        assert_eq!(profile.skipped.len(), 3);
        assert_eq!(profile.skipped[0].index, 1);
        assert_eq!(profile.skipped[0].reason, "proxy protocol is not supported");
        assert_eq!(profile.skipped[1].index, 2);
        assert_eq!(profile.skipped[2].index, 3);
        let diagnostics = format!("{:?}", profile.skipped);
        assert!(!diagnostics.contains("must-not-appear"));
        assert!(!diagnostics.contains("private-value"));
    }

    #[test]
    fn rejects_zero_port_and_missing_credentials() {
        let profile = parse_profile_detailed(
            "proxies:\n - type: vless\n   server: edge.invalid\n   port: 0\n   uuid: synthetic\n - type: hysteria2\n   server: edge.invalid\n   port: 443\n",
        )
        .unwrap();
        assert!(profile.nodes.is_empty());
        assert_eq!(profile.skipped.len(), 2);
    }

    #[test]
    fn skips_non_mapping_and_missing_proxies() {
        let profile = parse_profile_detailed("proxies:\n - just-a-string\n").unwrap();
        assert_eq!(
            profile.skipped[0].reason,
            "proxy entry is not a YAML mapping"
        );
        assert_eq!(
            parse_profile("proxy-groups: []").unwrap_err(),
            ProfileError::MissingProxies
        );
    }
}
