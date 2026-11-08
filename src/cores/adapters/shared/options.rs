use std::collections::BTreeSet;

use serde_json::Value;

use crate::domain::ProxyNode;

pub(crate) fn option_string<'a>(node: &'a ProxyNode, key: &str) -> Option<&'a str> {
    node.option(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            if node.option_entries.is_empty() {
                node.options
                    .get(key)
                    .map(String::as_str)
                    .filter(|value| !value.is_empty())
            } else {
                None
            }
        })
}

/// Collect ALPN identifiers from URI query values or structured VMess arrays.
pub(crate) 