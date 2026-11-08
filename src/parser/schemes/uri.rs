use std::collections::BTreeMap;

use percent_encoding::percent_decode_str;
use url::Url;

use crate::domain::{OptionEntry, Protocol, ProxyNode, SecretString};

use super::super::ParseError;

pub fn parse(input: &str, protocol: Protocol) -> Result<ProxyNode, ParseError> {
    let url = Url::parse(input).map_err(|_| ParseError::MalformedUrl)?;
    let server = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or(ParseError::MissingServerOrPort)?
        .to_ascii_lowercase();
    let port = url.port().ok_or(ParseError::MissingServerOrPort)?;

    let username = decode_component(url.username())?;
    let password = url.password().map(decode_component).transpose()?;
    let entries = url
        .query_pairs()
        .map(|(key, value)| OptionEntry {
            key: key.into_owned(),
            value: serde_json::Value::String(value.into_owned()),
        })
        .collect::<Vec<_>>();
    let mut options = BTreeMap::new();
    for entry in &entries {
        if let Some(value) = entry.value.as_str() {
            options.insert(entry.key.clone(), value.to_owned());
        }
    }

    let name = url
        .fragment()
        .map(decode_component)
        .transpose()?
        .filter(|value| !value.is_empty());

    let (identity, secret) = match protocol {
        Protocol::Vless | Protocol::Vmess => {
            (non_empty_secret(username), password.map(SecretString::new))
        }
        Protocol::Trojan | Protocol::Hysteria2 => {
            (None, non_empty_secret(password.unwrap_or(username)))
        }
        Protocol::Shadowsocks => return Err(ParseError::UnsupportedScheme),
    };

    Ok(ProxyNode::new(
        protocol,
        server,
        port,
        name,
        identity,
        secret,
        options,
        SecretString::new(input),
    )
    .with_option_entries(entries))
}

fn decode_component(value: &str) -> Result<String, ParseError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| ParseError::InvalidCredentials)
}

fn non_empty_secret(value: String) -> Option<SecretString> {
    (!value.is_empty()).then(|| SecretString::new(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_repeated_query_parameters_in_order() {
        let node = parse(
            "vless://uuid@example.com:443?alpn=h2&alpn=http%2F1.1",
            Protocol::Vless,
        )
        .unwrap();

        assert_eq!(node.option_entries.len(), 2);
        assert_eq!(node.option_entries[0].key, "alpn");
        assert_eq!(node.option_entries[0].value, "h2");
        assert_eq!(node.option_entries[1].value, "http/1.1");
        assert_eq!(node.options.get("alpn").map(String::as_str), Some("http/1.1"));
    }
}
