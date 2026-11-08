use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose};
use percent_encoding::percent_decode_str;
use url::Url;

use crate::domain::{Protocol, ProxyNode, SecretString};

use super::super::ParseError;

pub fn parse(input: &str) -> Result<ProxyNode, ParseError> {
    let without_scheme = input
        .strip_prefix("ss://")
        .ok_or(ParseError::MalformedUrl)?;
    let (without_fragment, fragment) = split_once_or_all(without_scheme, '#');
    let (authority, query) = split_once_or_all(without_fragment, '?');
    let name = decode_component(fragment.unwrap_or_default())?.filter(|value| !value.is_empty());

    let (credentials, host_port) =
        if let Some((credentials, host_port)) = authority.rsplit_once('@') {
            (decode_credentials(credentials)?, host_port.to_owned())
        } else {
            let decoded = decode_base64(authority).ok_or(ParseError::InvalidCredentials)?;
            let decoded = String::from_utf8(decoded).map_err(|_| ParseError::InvalidCredentials)?;
            let (credentials, host_port) = decoded
                .rsplit_once('@')
                .ok_or(ParseError::InvalidCredentials)?;
            (decode_credentials(credentials)?, host_port.to_owned())
        };

    let parsed = Url::parse(&format!("ss://{host_port}")).map_err(|_| ParseError::MalformedUrl)?;
    let server = parsed
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or(ParseError::MissingServerOrPort)?
        .to_ascii_lowercase();
    let port = parsed.port().ok_or(ParseError::MissingServerOrPort)?;

    let mut options = BTreeMap::new();
    if let Some(query) = query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            options.insert(key.into_owned(), value.into_owned());
        }
    }

    let (method, password) = credentials
        .split_once(':')
        .ok_or(ParseError::InvalidCredentials)?;

    Ok(ProxyNode::new(
        Protocol::Shadowsocks,
        server,
        port,
        name,
        Some(SecretString::new(method)),
        Some(SecretString::new(password)),
        options,
        SecretString::new(input),
    ))
}

fn decode_credentials(value: &str) -> Result<String, ParseError> {
    if let Some(decoded) = decode_base64(value)
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .filter(|decoded| decoded.contains(':'))
    {
        return Ok(decoded);
    }

    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| ParseError::InvalidCredentials)
}

fn decode_component(value: &str) -> Result<Option<String>, ParseError> {
    if value.is_empty() {
        return Ok(None);
    }
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| Some(value.into_owned()))
        .map_err(|_| ParseError::InvalidCredentials)
}

fn decode_base64(input: &str) -> Option<Vec<u8>> {
    [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
    ]
    .into_iter()
    .find_map(|engine| engine.decode(input.trim()).ok())
}

fn split_once_or_all(input: &str, separator: char) -> (&str, Option<&str>) {
    match input.split_once(separator) {
        Some((left, right)) => (left, Some(right)),
        None => (input, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sip002_base64_userinfo() {
        let credentials =
            general_purpose::STANDARD_NO_PAD.encode("chacha20-ietf-poly1305:password");
        let node = parse(&format!("ss://{credentials}@ss.example:8388#office")).unwrap();

        assert_eq!(node.protocol, Protocol::Shadowsocks);
        assert_eq!(node.server, "ss.example");
        assert_eq!(node.port, 8388);
        assert_eq!(node.name.as_deref(), Some("office"));
        assert_eq!(
            node.identity.as_ref().map(|value| value.expose()),
            Some("chacha20-ietf-poly1305")
        );
        assert_eq!(
            node.secret.as_ref().map(|value| value.expose()),
            Some("password")
        );
    }
}
