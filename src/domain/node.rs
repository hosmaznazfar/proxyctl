use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{Protocol, SecretString};

/// One source option, retained in order and without collapsing repeated query keys.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OptionEntry {
    pub key: String,
    pub value: Value,
}

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
    /// Backwards-compatible last-value index for existing records and display.
    /// New adapter code must use option_entries instead.
    pub options: BTreeMap<String, String>,
    /// Complete parsed option sequence. Defaults to empty for records written by older versions.
    #[serde(default)]
    pub option_entries: Vec<OptionEntry>,
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
        let option_entries = options
            .iter()
            .map(|(key, value)| OptionEntry {
                key: key.clone(),
                value: Value::String(value.clone()),
            })
            .collect();
        Self {
            protocol,
            server,
            port,
            name,
            identity,
            secret,
            options,
            option_entries,
            original_url,
        }
    }

    /// Replace the compatibility map with the last value for each key while retaining
    /// every source entry (including repeated keys and structured VMess values).
    pub fn with_option_entries(mut self, entries: Vec<OptionEntry>) -> Self {
        self.options.clear();
        for entry in &entries {
            if let Some(value) = option_value_as_string(&entry.value) {
                self.options.insert(entry.key.clone(), value);
            }
        }
        self.option_entries = entries;
        self
    }

    /// Return the last value for an option key, matching common URL semantics.
    pub fn option(&self, key: &str) -> Option<&Value> {
        self.option_entries
            .iter()
            .rev()
            .find(|entry| entry.key == key)
            .map(|entry| &entry.value)
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
        if self.option_entries.is_empty() {
            for (key, value) in &self.options {
                add_part(&mut hasher, key.as_bytes());
                add_part(&mut hasher, value.as_bytes());
            }
        } else {
            let mut entries = self
                .option_entries
                .iter()
                .map(|entry| (entry.key.as_str(), entry.value.to_string()))
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (key, value) in entries {
                add_part(&mut hasher, key.as_bytes());
                add_part(&mut hasher, value.as_bytes());
            }
        }

        format!("{:x}", hasher.finalize())
    }
}

fn option_value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
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
            .field("option_entries", &"[REDACTED]")
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
    fn fingerprint_includes_repeated_options() {
        let base = node_with_name("one");
        let first = base.clone().with_option_entries(vec![
            OptionEntry {
                key: "alpn".into(),
                value: Value::String("h2".into()),
            },
            OptionEntry {
                key: "alpn".into(),
                value: Value::String("http/1.1".into()),
            },
        ]);
        let second = base.with_option_entries(vec![OptionEntry {
            key: "alpn".into(),
            value: Value::String("h2".into()),
        }]);
        assert_ne!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn fingerprint_ignores_query_option_order_but_keeps_duplicates() {
        let base = node_with_name("one");
        let first = base.clone().with_option_entries(vec![
            OptionEntry {
                key: "a".into(),
                value: Value::String("1".into()),
            },
            OptionEntry {
                key: "b".into(),
                value: Value::String("2".into()),
            },
        ]);
        let reordered = base.clone().with_option_entries(vec![
            OptionEntry {
                key: "b".into(),
                value: Value::String("2".into()),
            },
            OptionEntry {
                key: "a".into(),
                value: Value::String("1".into()),
            },
        ]);
        let duplicated = base.with_option_entries(vec![
            OptionEntry {
                key: "a".into(),
                value: Value::String("1".into()),
            },
            OptionEntry {
                key: "a".into(),
                value: Value::String("1".into()),
            },
            OptionEntry {
                key: "b".into(),
                value: Value::String("2".into()),
            },
        ]);
        assert_eq!(first.fingerprint(), reordered.fingerprint());
        assert_ne!(first.fingerprint(), duplicated.fingerprint());
    }

    #[test]
    fn debug_output_does_not_reveal_url_or_options() {
        let mut node = node_with_name("test");
        node.secret = Some(SecretString::new("private-password"));
        node.options.insert("token".into(), "private-token".into());
        node.option_entries.push(OptionEntry {
            key: "token".into(),
            value: Value::String("private-token".into()),
        });
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
