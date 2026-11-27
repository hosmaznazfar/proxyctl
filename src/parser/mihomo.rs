//! Mihomo/Clash proxy-list YAML parser.
use crate::domain::{OptionEntry, Protocol, ProxyNode, SecretString};
use serde_yaml::Value;
use std::collections::BTreeMap;
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProfileError {
    InvalidYaml,
    MissingProxies,
}
pub fn parse_profile(input: &str) -> Result<Vec<ProxyNode>, ProfileError> {
    let root: Value = serde_yaml::from_str(input).map_err(|_| ProfileError::InvalidYaml)?;
    let proxies = root
        .get("proxies")
        .and_then(Value::as_sequence)
        .ok_or(ProfileError::MissingProxies)?;
    Ok(proxies.iter().filter_map(parse_proxy).collect())
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
        let n=parse_profile("proxies:\n - name: fixture\n   type: vless\n   server: edge.invalid\n   port: 443\n   uuid: synthetic\n   tls:\n     servername: tls.invalid\n   ws-opts:\n     path: /fixture\n").unwrap();
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].identity.as_ref().unwrap().expose(), "synthetic");
        assert_eq!(n[0].option("tls").unwrap()["servername"], "tls.invalid");
        assert_eq!(n[0].option("ws-opts").unwrap()["path"], "/fixture");
    }
    #[test]
    fn ss_credentials() {
        let n=parse_profile("proxies:\n - type: ss\n   server: ss.invalid\n   port: 8388\n   cipher: aes-128-gcm\n   password: synthetic\n").unwrap();
        assert_eq!(n[0].identity.as_ref().unwrap().expose(), "aes-128-gcm");
        assert_eq!(n[0].secret.as_ref().unwrap().expose(), "synthetic");
    }
    #[test]
    fn skips_unknown() {
        assert_eq!(
            parse_profile("proxies:\n - type: direct\n").unwrap().len(),
            0
        );
        assert_eq!(
            parse_profile("proxy-groups: []").unwrap_err(),
            ProfileError::MissingProxies
        );
    }
}
