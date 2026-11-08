use std::collections::BTreeMap;

use percent_encoding::percent_decode_str;
use url::Url;

use crate::domain::{Protocol, ProxyNode, SecretString};

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
    let mut options = BTreeMap::new();

    for (key, value) in url.query_pairs() {
        options.insert(key.into_owned(), value.into_owned());
    }

    let name = url
        .fragment()
        .map(decode_component)
        .transpose()?
        .filter(|value| !value.is_empty());

    let (identity, secret) = match protocol {
        Protocol::Vless | Protocol::Vmess => (
            non_empty_secret(username),
            password.map(SecretString::new),
        ),
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
    ))
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
