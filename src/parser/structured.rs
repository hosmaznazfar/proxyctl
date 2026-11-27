//! Structured JSON profile parsing for sing-box and Xray outbound collections.
use crate::domain::{OptionEntry, Protocol, ProxyNode, SecretString};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProfileError {
    InvalidJson,
    MissingOutbounds,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SkippedOutbound {
    /// One-based position within the JSON `outbounds` array.
    pub index: usize,
    /// Fixed, credential-free explanation.
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct ParsedProfile {
    pub nodes: Vec<ProxyNode>,
    pub skipped: Vec<SkippedOutbound>,
}

pub fn parse_profile(input: &str) -> Result<Vec<ProxyNode>, ProfileError> {
    parse_profile_detailed(input).map(|profile| profile.nodes)
}

/// Parse recognized outbounds and retain safe diagnostics for every skipped entry.
pub fn parse_profile_detailed(input: &str) -> Result<ParsedProfile, ProfileError> {
    let root: Value = serde_json::from_str(input).map_err(|_| ProfileError::InvalidJson)?;
    let outbounds = root
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or(ProfileError::MissingOutbounds)?;
    let mut nodes = Vec::with_capacity(outbounds.len());
    let mut skipped = Vec::new();
    for (index, value) in outbounds.iter().enumerate() {
        match parse_outbound(value) {
            Some(node) => nodes.push(node),
            None => skipped.push(SkippedOutbound {
                index: index + 1,
                reason: skip_reason(value),
            }),
        }
    }
    Ok(ParsedProfile { nodes, skipped })
}

fn skip_reason(value: &Value) -> &'static str {
    let Some(object) = value.as_object() else {
        return "outbound entry is not a JSON object";
    };
    let kind = object
        .get("type")
        .or_else(|| object.get("protocol"))
        .and_then(Value::as_str);
    let Some(kind) = kind else {
        return "outbound entry has no recognized protocol field";
    };
    if !matches!(
        kind.to_ascii_lowercase().as_str(),
        "vless" | "vmess" | "trojan" | "shadowsocks" | "hysteria2" | "hy2"
    ) {
        return "outbound protocol is not supported";
    }
    "outbound entry is missing valid endpoint or credential fields"
}
fn parse_outbound(v: &Value) -> Option<ProxyNode> {
    if v.get("type").and_then(Value::as_str).is_some() {
        parse_singbox(v)
    } else if v.get("protocol").and_then(Value::as_str).is_some() {
        parse_xray(v)
    } else {
        None
    }
}
fn proto(s: &str) -> Option<Protocol> {
    match s.to_ascii_lowercase().as_str() {
        "vless" => Some(Protocol::Vless),
        "vmess" => Some(Protocol::Vmess),
        "trojan" => Some(Protocol::Trojan),
        "shadowsocks" => Some(Protocol::Shadowsocks),
        "hysteria2" | "hy2" => Some(Protocol::Hysteria2),
        _ => None,
    }
}
fn entries(v: &Value, exclude: &[&str]) -> Vec<OptionEntry> {
    v.as_object()
        .map(|o| {
            o.iter()
                .filter(|(k, _)| !exclude.contains(&k.as_str()))
                .map(|(k, x)| OptionEntry {
                    key: k.clone(),
                    value: x.clone(),
                })
                .collect()
        })
        .unwrap_or_default()
}
fn map(e: &[OptionEntry]) -> BTreeMap<String, String> {
    e.iter()
        .filter_map(|x| x.value.as_str().map(|s| (x.key.clone(), s.to_owned())))
        .collect()
}
fn node(
    p: Protocol,
    server: String,
    port: u16,
    name: Option<String>,
    identity: Option<&str>,
    secret: Option<&str>,
    e: Vec<OptionEntry>,
) -> ProxyNode {
    ProxyNode::new(
        p,
        server,
        port,
        name,
        identity.map(SecretString::new),
        secret.map(SecretString::new),
        map(&e),
        SecretString::new("[structured profile]"),
    )
    .with_option_entries(e)
}
fn parse_singbox(v: &Value) -> Option<ProxyNode> {
    let p = proto(v.get("type")?.as_str()?)?;
    let server = v.get("server")?.as_str()?.to_owned();
    let port: u16 = v.get("server_port")?.as_u64()?.try_into().ok()?;
    let name = v.get("tag").and_then(Value::as_str).map(str::to_owned);
    let identity = match p {
        Protocol::Vless | Protocol::Vmess => v.get("uuid").and_then(Value::as_str),
        Protocol::Shadowsocks => v.get("method").and_then(Value::as_str),
        _ => None,
    };
    let secret = match p {
        Protocol::Vless | Protocol::Vmess => None,
        _ => v.get("password").and_then(Value::as_str),
    };
    let e = entries(
        v,
        &[
            "type",
            "tag",
            "server",
            "server_port",
            "uuid",
            "password",
            "method",
        ],
    );
    Some(node(p, server, port, name, identity, secret, e))
}
fn parse_xray(v: &Value) -> Option<ProxyNode> {
    let p = proto(v.get("protocol")?.as_str()?)?;
    let settings = v.get("settings")?;
    let s = settings
        .get("vnext")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .or_else(|| {
            settings
                .get("servers")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
        })
        .unwrap_or(settings);
    let server = s.get("address")?.as_str()?.to_owned();
    let port: u16 = s.get("port")?.as_u64()?.try_into().ok()?;
    let user = s
        .get("users")
        .and_then(Value::as_array)
        .and_then(|a| a.first());
    let identity = match p {
        Protocol::Vless | Protocol::Vmess => user.and_then(|u| u.get("id")).and_then(Value::as_str),
        Protocol::Shadowsocks => s.get("method").and_then(Value::as_str),
        _ => None,
    };
    let secret = match p {
        Protocol::Vless | Protocol::Vmess => None,
        Protocol::Shadowsocks | Protocol::Trojan | Protocol::Hysteria2 => {
            s.get("password").and_then(Value::as_str)
        }
    };
    let name = v.get("tag").and_then(Value::as_str).map(str::to_owned);
    let mut e = Vec::new();
    for key in ["settings", "streamSettings"] {
        if let Some(x) = v.get(key) {
            e.push(OptionEntry {
                key: key.into(),
                value: x.clone(),
            });
        }
    }
    if let Some(x) = user.and_then(|u| u.get("flow")) {
        e.push(OptionEntry {
            key: "flow".into(),
            value: x.clone(),
        });
    }
    Some(node(p, server, port, name, identity, secret, e))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn singbox_fixture() {
        let n=parse_profile(r#"{"outbounds":[{"type":"vless","server":"edge.invalid","server_port":443,"uuid":"fixture","tls":{"enabled":true,"server_name":"tls.invalid"}}]}"#).unwrap();
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].option("tls").unwrap()["server_name"], "tls.invalid");
        assert_eq!(n[0].identity.as_ref().unwrap().expose(), "fixture");
        assert!(n[0].secret.is_none());
    }
    #[test]
    fn xray_vnext_fixture() {
        let n=parse_profile(r#"{"outbounds":[{"protocol":"vless","tag":"fixture","settings":{"vnext":[{"address":"vnext.invalid","port":443,"users":[{"id":"synthetic","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"reality.invalid"}}}]}"#).unwrap();
        assert_eq!(n[0].server, "vnext.invalid");
        assert_eq!(n[0].option("flow").unwrap(), "xtls-rprx-vision");
        assert_eq!(
            n[0].option("streamSettings").unwrap()["security"],
            "reality"
        );
    }
    #[test]
    fn singbox_shadowsocks_keeps_method_and_password_separate() {
        let n=parse_profile(r#"{"outbounds":[{"type":"shadowsocks","server":"ss.invalid","server_port":8388,"method":"chacha20-ietf-poly1305","password":"synthetic-secret"}]}"#).unwrap();
        assert_eq!(
            n[0].identity.as_ref().unwrap().expose(),
            "chacha20-ietf-poly1305"
        );
        assert_eq!(n[0].secret.as_ref().unwrap().expose(), "synthetic-secret");
    }
    #[test]
    fn xray_shadowsocks_servers_fixture() {
        let n=parse_profile(r#"{"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{"address":"ss.invalid","port":8388,"method":"aes-128-gcm","password":"synthetic-secret"}]}}]}"#).unwrap();
        assert_eq!(n[0].server, "ss.invalid");
        assert_eq!(n[0].identity.as_ref().unwrap().expose(), "aes-128-gcm");
        assert_eq!(n[0].secret.as_ref().unwrap().expose(), "synthetic-secret");
    }
    #[test]
    fn skips_direct() {
        assert_eq!(parse_profile(r#"{"outbounds":[{"type":"direct"},{"type":"vless","server":"x.invalid","server_port":1,"uuid":"x"}]}"#).unwrap().len(),1);
    }
    #[test]
    fn invalid() {
        assert_eq!(parse_profile("no"), Err(ProfileError::InvalidJson));
        assert_eq!(parse_profile("{}"), Err(ProfileError::MissingOutbounds));
    }
}
