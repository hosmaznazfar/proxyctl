use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose};
use serde_json::Value;

use crate::domain::{Protocol, ProxyNode, SecretString};

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

    let mut options = BTreeMap::new();
    if let Some(object) = value.as_object() {
        for (key, value) in object {
            if matches!(key.as_str(), "add" | "port" | "id" | "ps") {
                continue;
            }
            if let Some(value) = value_as_string(value) {
                options.insert(key.clone(), value);
            }
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
    ))
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
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
    use base64::Engine as _;

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
}
