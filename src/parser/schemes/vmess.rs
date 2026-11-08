use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;

use crate::domain::{OptionEntry, Protocol, ProxyNode, SecretString};

use super::super::ParseError;

pub fn parse(input: &str) -> Result<ProxyNode, ParseError> {
    let encoded = input
        .strip_prefix("vmess://")
        .ok_or(ParseError::MalformedUrl)?
        .split('#')
        .next()
        .unwrap_or_default();

    let decoded = decode_base64(encoded).ok_or(ParseError::InvalidCredentials)?;
    let value: Value =
        serde_json::from_slice(&decoded).map_err(|_| ParseError::InvalidVmessPayload)?;

    let server = value
        .get("add")
        .and_then(value_as_string)
        .filter(|value| !value.is_empty())
        .ok_or(ParseError::MissingServerOrPort)?
        .to_ascii_lowercase();
    let port = value
        .get("port")
        .and_then(value_as_string)
        .ok_or(ParseError::MissingServerOrPort)?
        .parse::<u16>()
        .map_err(|_| ParseError::InvalidPort)?;
    let identity = value
        .get("id")
        .and_then(value_as_string)
        .filter(|value| !value.is_empty())
        .map(SecretString::new);
    let name = value
        .get("ps")
        .and_then(value_as_string)
        .filter(|value| !value.is_empty());

    let entries = value
        .as_object()
        .into_iter()
        .flat_map(|object| object.iter())
        .filter(|(key, _)| !matches!(key.as_str(), "v" | "add" | "port" | "id" | "ps"))
        .map(|(key, value)| OptionEntry {
            key: key.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();
    let mut options = BTreeMap::new();
    for entry in &entries {
        if let Some(value) = value_as_string(&entry.value) {
            options.insert(entry.key.clone(), value);
        } else {
            options.insert(entry.key.clone(), entry.value.to_string());
        }
    }

    Ok(ProxyNode::new(
        Protocol::Vmess,
        server,
        port,
        name,
        identity,
        None,
        options,
        SecretString::new(input),
    )
    .with_option_entries(entries))
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let normalized = input.trim();
    [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
    ]
    .into_iter()
    .find_map(|engine| engine.decode(normalized).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vmess_json_payload() {
        let encoded = general_purpose::STANDARD.encode(
            br#"{"v":"2","ps":"test-node","add":"vmess.example","port":"8443","id":"uuid","aid":"0","net":"ws","tls":"tls"}"#,
        );
        let node = parse(&format!("vmess://{encoded}")).unwrap();

        assert_eq!(node.protocol, Protocol::Vmess);
        assert_eq!(node.server, "vmess.example");
        assert_eq!(node.port, 8443);
        assert_eq!(node.name.as_deref(), Some("test-node"));
        assert_eq!(node.options.get("net").map(String::as_str), Some("ws"));
    }

    #[test]
    fn preserves_structured_vmess_options() {
        let payload = br#"{"add":"vmess.example","port":"443","id":"uuid","ps":"test","net":"ws","headers":{"Host":"cdn.example"},"alpn":["h2","http/1.1"]}"#;
        let encoded = general_purpose::STANDARD.encode(payload);
        let node = parse(&format!("vmess://{encoded}")).unwrap();

        assert_eq!(node.option("headers").unwrap()["Host"], "cdn.example");
        assert_eq!(node.option("alpn").unwrap()[0], "h2");
    }
}
