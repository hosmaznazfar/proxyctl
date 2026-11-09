use serde_json::{Map, Value};

use crate::domain::{Protocol, ProxyNode};

use super::ShadowsocksPlugin;

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


/// Parse the SIP003 plugin query value into the supported native representations.
pub(crate) fn shadowsocks_plugin(
    node: &ProxyNode,
) -> Result<Option<ShadowsocksPlugin>, String> {
    if node.protocol != Protocol::Shadowsocks {
        return Ok(None);
    }
    let Some(value) = node.option("plugin") else {
        return Ok(None);
    };
    let raw = value
        .as_str()
        .ok_or_else(|| "Shadowsocks plugin option must be a string".to_owned())?;
    if raw.is_empty() {
        return Err("Shadowsocks plugin option must not be empty".into());
    }
    let (segments, raw_options) = split_sip003(raw)?;
    let name = segments.first().map(String::as_str).unwrap_or_default();
    let mut options = std::collections::BTreeMap::new();
    for segment in segments.iter().skip(1) {
        if segment.is_empty() {
            return Err("Shadowsocks plugin contains an empty option segment".into());
        }
        let (key, value) = segment
            .split_once('=')
            .map(|(key, value)| (key, Some(value)))
            .unwrap_or((segment.as_str(), None));
        if key.is_empty() || key.chars().any(char::is_control) {
            return Err("Shadowsocks plugin option name is invalid".into());
        }
        if options.insert(key.to_owned(), value.map(str::to_owned)).is_some() {
            return Err("Shadowsocks plugin option is repeated".into());
        }
    }

    let (mihomo_name, mihomo_options) = match name {
        "obfs-local" | "simple-obfs" => {
            let mode = options.get("obfs").and_then(|value| value.as_deref())
                .ok_or_else(|| "Shadowsocks obfs-local requires obfs=http or obfs=tls".to_owned())?;
            if !["http", "tls"].contains(&mode) {
                return Err("Shadowsocks obfs-local mode must be http or tls".into());
            }
            if options.keys().any(|key| !["obfs", "obfs-host"].contains(&key.as_str())) {
                return Err("Shadowsocks obfs-local contains an unsupported plugin option".into());
            }
            let mut mapped = Map::new();
            mapped.insert("mode".into(), Value::String(mode.to_owned()));
            if let Some(host) = options.get("obfs-host").and_then(|value| value.as_deref()) {
                if host.is_empty() || host.chars().any(char::is_control) {
                    return Err("Shadowsocks obfs host is invalid".into());
                }
                mapped.insert("host".into(), Value::String(host.to_owned()));
            }
            ("obfs".to_owned(), Value::Object(mapped))
        }
        "v2ray-plugin" => {
            let mode = options.get("mode").and_then(|value| value.as_deref()).unwrap_or("websocket");
            if mode != "websocket" {
                return Err("Shadowsocks v2ray-plugin supports websocket mode only in this adapter".into());
            }
            if options.keys().any(|key| !["mode", "tls", "host", "path", "mux"].contains(&key.as_str())) {
                return Err("Shadowsocks v2ray-plugin contains an unsupported plugin option".into());
            }
            let mut mapped = Map::new();
            mapped.insert("mode".into(), Value::String("websocket".into()));
            for key in ["host", "path"] {
                if let Some(value) = options.get(key).and_then(|value| value.as_deref()) {
                    if value.chars().any(char::is_control) {
                        return Err("Shadowsocks v2ray-plugin option contains control characters".into());
                    }
                    mapped.insert(key.into(), Value::String(value.to_owned()));
                }
            }
            if options.contains_key("tls") {
                if options.get("tls").is_some_and(|value| value.is_some()) {
                    return Err("Shadowsocks v2ray-plugin tls flag must not have a value".into());
                }
                mapped.insert("tls".into(), Value::Bool(true));
            }
            if let Some(mux) = options.get("mux") {
                let enabled = match mux.as_deref() {
                    None | Some("true") | Some("1") => true,
                    Some("false") | Some("0") => false,
                    _ => return Err("Shadowsocks v2ray-plugin mux must be a boolean".into()),
                };
                mapped.insert("mux".into(), Value::Bool(enabled));
            }
            ("v2ray-plugin".to_owned(), Value::Object(mapped))
        }
        _ => return Err("Shadowsocks SIP003 plugin is not supported by this adapter".into()),
    };
    Ok(Some(ShadowsocksPlugin {
        sing_box_name: (if name == "simple-obfs" { "obfs-local" } else { name }).to_owned(),
        sing_box_options: raw_options,
        mihomo_name,
        mihomo_options,
    }))
}

fn split_sip003(input: &str) -> Result<(Vec<String>, String), String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    let mut raw_first_separator = None;
    for (index, ch) in input.char_indices() {
        if escaped {
            if ![':', ';', '=', '\\'].contains(&ch) {
                return Err("Shadowsocks plugin escape sequence is invalid".into());
            }
            current.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ';' {
            if raw_first_separator.is_none() {
                raw_first_separator = Some(index);
            }
            segments.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if escaped {
        return Err("Shadowsocks plugin ends with an incomplete escape".into());
    }
    segments.push(current);
    let raw_options = raw_first_separator
        .map(|index| input[index + 1..].to_owned())
        .unwrap_or_default();
    Ok((segments, raw_options))
}

pub(crate) fn validate_string_options(node: &ProxyNode) -> Result<(), String> {
    const STRING_OPTIONS: &[&str] = &[
        "security",
        "sni",
        "encryption",
        "flow",
        "type",
        "host",
        "path",
        "serviceName",
        "service_name",
        "authority",
        "mode",
        "net",
        "scy",
        "ed",
        "eh",
        "maxEarlyData",
        "earlyDataHeaderName",
        "max_early_data",
        "early_data_header_name",
        "max-early-data",
        "early-data-header-name",
        "pcs",
        "pinSHA256",
        "vcn",
        "fp",
        "plugin",
        "pbk",
        "publicKey",
        "sid",
        "spx",
        "mldsa65Verify",
        "obfs",
        "obfs-password",
        "obfs_password",
        "obfs-min-packet-size",
        "obfs-max-packet-size",
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
