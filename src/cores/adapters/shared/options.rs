use serde_json::Value;

use crate::domain::{Protocol, ProxyNode};

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

pub(crate) fn reject_unknown_options(node: &ProxyNode, supported: &[&str]) -> Result<(), String> {
    let keys = if node.option_entries.is_empty() {
        node.options.keys().map(String::as_str).collect::<Vec<_>>()
    } else {
        node.option_entries
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>()
    };
    if let Some(key) = keys.into_iter().find(|key| !supported.contains(key)) {
        return Err(format!(
            "option '{key}' is not supported by this adapter yet"
        ));
    }
    Ok(())
}

pub(crate) fn validate_string_options(node: &ProxyNode) -> Result<(), String> {
    const STRING_OPTIONS: &[&str] = &[
        "security", "sni", "encryption", "flow", "type", "host", "path", "serviceName",
        "service_name", "authority", "mode", "net", "scy", "ed", "eh", "maxEarlyData",
        "earlyDataHeaderName", "max_early_data", "early_data_header_name", "max-early-data",
        "early-data-header-name", "pcs", "pinSHA256", "vcn", "fp",
    ];
    for key in STRING_OPTIONS {
        if let Some(value) = node.option(key)
            && !matches!(value, Value::String(_) | Value::Null)
        {
            return Err(format!("option '{key}' must be a string"));
        }
    }
    if node.protocol != Protocol::Vmess
        && let Some(value) = node.option("tls")
        && !matches!(value, Value::String(_) | Value::Null)
    {
        return Err("TLS option must be a string".into());
    }
    Ok(())
}

