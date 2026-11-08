//! Protocol URL parsing and normalization.
//!
//! Protocol parsers produce core-independent domain values. Core-specific serialization belongs
//! in the corresponding adapter, not in this module.

mod schemes;

use thiserror::Error;

use crate::domain::{Protocol, ProxyNode};

/// Errors returned while parsing a proxy URL.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ParseError {
    #[error("the URL is malformed")]
    MalformedUrl,
    #[error("the URL scheme is not supported")]
    UnsupportedScheme,
    #[error("the URL is missing a valid server or port")]
    MissingServerOrPort,
    #[error("the URL contains invalid credentials or encoded data")]
    InvalidCredentials,
    #[error("the VMess payload is not valid JSON")]
    InvalidVmessPayload,
    #[error("the URL contains an invalid port")]
    InvalidPort,
}

/// Parse one supported proxy URL into a normalized node.
pub fn parse_proxy_url(input: &str) -> Result<ProxyNode, ParseError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(ParseError::MalformedUrl);
    }

    let scheme = input
        .split_once("://")
        .map(|(scheme, _)| scheme)
        .ok_or(ParseError::MalformedUrl)?;

    let protocol = Protocol::from_scheme(scheme).ok_or(ParseError::UnsupportedScheme)?;

    match protocol {
        Protocol::Vmess => schemes::vmess::parse(input),
        Protocol::Shadowsocks => schemes::shadowsocks::parse(input),
        Protocol::Vless | Protocol::Trojan | Protocol::Hysteria2 => {
            schemes::uri::parse(input, protocol)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vless_uri_and_name() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=ws#edge",
        )
        .unwrap();

        assert_eq!(node.protocol, Protocol::Vless);
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.name.as_deref(), Some("edge"));
        assert_eq!(
            node.options.get("security").map(String::as_str),
            Some("tls")
        );
        assert_eq!(
            node.identity.as_ref().map(|value| value.expose()),
            Some("11111111-1111-4111-8111-111111111111")
        );
    }

    #[test]
    fn parses_trojan_password() {
        let node = parse_proxy_url("trojan://secret@example.com:443?sni=cdn.example#node").unwrap();
        assert_eq!(node.protocol, Protocol::Trojan);
        assert_eq!(
            node.secret.as_ref().map(|value| value.expose()),
            Some("secret")
        );
        assert_eq!(
            node.options.get("sni").map(String::as_str),
            Some("cdn.example")
        );
    }

    #[test]
    fn parses_hysteria2_scheme_alias() {
        let node = parse_proxy_url("hy2://password@example.com:443?sni=example.com").unwrap();
        assert_eq!(node.protocol, Protocol::Hysteria2);
        assert_eq!(node.port, 443);
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert_eq!(
            parse_proxy_url("ftp://example.com:21").unwrap_err(),
            ParseError::UnsupportedScheme
        );
    }

    #[test]
    fn rejects_missing_port() {
        assert_eq!(
            parse_proxy_url("vless://uuid@example.com").unwrap_err(),
            ParseError::MissingServerOrPort
        );
    }
}
