use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Protocol, SecretString};

/// A normalized, core-independent proxy node.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProxyNode {
    pub protocol: Protocol,
    pub server: String,
    pub port: u16,
    pub name: Option<String>,
    /// Protocol identity, such as a VLESS/VMess UUID or Shadowsocks method.
    pub identity: Option<SecretString>,
    /// Protocol password or secret.
    pub secret: Option<SecretString>,
    /// Parsed protocol options. This may contain sensitive values and must not be logged.
    pub options: BTreeMap<String, String>,
    /// Original imported URL, retained for faithful configuration generation.
    pub original_url: SecretString,
}

impl ProxyNode {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: Protocol,
        server: String,
        port: u16,
        name: Option<String>,
        identity: Option<SecretString>,
        secret: Option<SecretString>,
        options: BTreeMap<String, String>,
        original_url: SecretString,
    ) -> Self {
        Self {
            protocol,
            server,
            port,
            name,
            identity,
            secret,
            options,
            original_url,
        }
    }

    /// Return a stable SHA-256 fingerprint for connection identity.
    ///
    /// Display names and the original URL spelling are intentionally excluded.
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        add_part(&mut hasher, self.protocol.as_str().as_bytes());
        add_part(&mut hasher, self.server.to_ascii_lowercase().as_bytes());
        add_part(&mut hasher, self.port.to_string().as_bytes());

        if let Some(identity) = &self.identity {
            add_part(&mut hasher, identity.expose().as_bytes());
        }
        if let Some(secret) = &self.secret {
            add_part(&mut hasher, secret.expose().as_bytes());
        }
        for (key, value) in &self.options {
            add_part(&mut hasher, key.as_bytes());
            add_part(&mut hasher, value.as_bytes());
        }

        format!("{:x}", hasher.finalize())
    }
}

fn add_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

impl fmt::Debug for ProxyNode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyNode")
            .field("protocol", &self.protocol)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("name", &self.name)
            .field("identity", &self.identity.as_ref().map(|_| "[REDACTED]"))
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .field("options", &"[REDACTED]")
            .field("original_url", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_ignores_display_name() {
        let first = node_with_name("one");
        let second = node_with_name("two");
        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn fingerprint_changes_when_secret_changes() {
        let mut first = node_with_name("one");
        let mut second = first.clone();
        first.secret = Some(SecretString::new("secret-a"));
        second.secret = Some(SecretString::new("secret-b"));
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn debug_output_does_not_reveal_url_or_options() {
        let mut node = node_with_name("test");
        node.secret = Some(SecretString::new("private-password"));
        node.options.insert("token".into(), "private-token".into());
        let debug = format!("{node:?}");
        assert!(!debug.contains("private-password"));
        assert!(!debug.contains("private-token"));
        assert!(!debug.contains("vless://"));
    }

    fn node_with_name(name: &str) -> ProxyNode {
        ProxyNode::new(
            Protocol::Vless,
            "example.com".into(),
            443,
            Some(name.into()),
            Some(SecretString::new("uuid")),
            None,
            BTreeMap::new(),
            SecretString::new("vless://uuid@example.com:443"),
        )
    }
}
