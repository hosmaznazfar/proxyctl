use serde_json::{Map, Value};

use crate::domain::{Protocol, ProxyNode};

use super::option_string;

/// Collect ALPN identifiers from URI query values or structured VMess arrays.
pub(crate) fn alpn_protocols(node: &ProxyNode) -> Result<Option<Vec<String>>, String> {
    let mut protocols = Vec::new();
    let mut was_supplied = false;

    if node.option_entries.is_empty() {
        if let Some(value) = node.options.get("alpn") {
            was_supplied = true;
            if !value.is_empty() || node.protocol != Protocol::Vmess {
                protocols.extend(value.split(',').map(str::to_owned));
            }
        }
    } else {
        for entry in node
            .option_entries
            .iter()
            .filter(|entry| entry.key == "alpn")
        {
            was_supplied = true;
            match &entry.value {
                Value::String(value) => {
                    if !value.is_empty() || node.protocol != Protocol::Vmess {
                        protocols.extend(value.split(',').map(str::to_owned));
                    }
                }
                Value::Array(values) => {
                    for value in values {
                        let value = value
                            .as_str()
                            .ok_or_else(|| "ALPN entries must be strings".to_owned())?;
                        protocols.extend(value.split(',').map(str::to_owned));
                    }
                }
                _ => return Err("ALPN must be a string or an array of strings".into()),
            }
        }
    }

    if !was_supplied {
        return Ok(None);
    }
    if protocols.is_empty() {
        if node.protocol == Protocol::Vmess {
            return Ok(None);
        }
        return Err("ALPN list must not be empty".into());
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut normalized = Vec::with_capacity(protocols.len());
    for protocol in protocols {
        let protocol = protocol.trim();
        if protocol.is_empty() {
            return Err("ALPN contains an empty protocol identifier".into());
        }
        if protocol.len() > 255 || protocol.chars().any(char::is_control) {
            return Err("ALPN protocol identifiers must be at most 255 bytes and contain no control characters".into());
        }
        if !seen.insert(protocol.to_owned()) {
            return Err("ALPN protocol identifiers must not be repeated".into());
        }
        normalized.push(protocol.to_owned());
    }

    Ok(Some(normalized))
}

fn parse_bool_string(value: &str) -> Result<bool, String> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err("TLS boolean option is invalid".into()),
    }
}

fn bool_option(node: &ProxyNode, key: &str) -> Result<Option<bool>, String> {
    if let Some(value) = node.option(key) {
        return match value {
            Value::Bool(value) => Ok(Some(*value)),
            Value::Number(value) => match value.as_i64() {
                Some(0) => Ok(Some(false)),
                Some(1) => Ok(Some(true)),
                _ => Err("TLS boolean option is invalid".into()),
            },
            Value::String(value) if value.is_empty() => Ok(None),
            Value::String(value) => parse_bool_string(value).map(Some),
            Value::Null => Ok(None),
            _ => Err("TLS boolean option must be a boolean".into()),
        };
    }
    option_string(node, key).map(parse_bool_string).transpose()
}

fn insecure_option(node: &ProxyNode) -> Result<bool, String> {
    let insecure = bool_option(node, "insecure")?;
    let allow_insecure = bool_option(node, "allowInsecure")?;
    if insecure.is_some() && allow_insecure.is_some() && insecure != allow_insecure {
        return Err("insecure and allowInsecure options conflict".into());
    }
    Ok(insecure.or(allow_insecure).unwrap_or(false))
}

fn vmess_tls_mode(node: &ProxyNode) -> Result<Option<String>, String> {
    if let Some(value) = node.option("tls") {
        return match value {
            Value::Bool(true) => Ok(Some("tls".into())),
            Value::Bool(false) => Ok(Some("none".into())),
            Value::Number(value) => match value.as_i64() {
                Some(0) => Ok(Some("none".into())),
                Some(1) => Ok(Some("tls".into())),
                _ => Err("VMess TLS option is invalid".into()),
            },
            Value::String(value) if value.is_empty() => Ok(None),
            Value::String(value) => Ok(Some(value.to_ascii_lowercase())),
            Value::Null => Ok(None),
            _ => Err("VMess TLS option must be a string or boolean".into()),
        };
    }
    Ok(option_string(node, "tls").map(str::to_ascii_lowercase))
}

/// Normalize client-side REALITY options without conflating them with ordinary TLS.
pub(crate) fn reality_options(node: &ProxyNode) -> Result<Option<Value>, String> {
    let security = if node.protocol == Protocol::Vmess {
        vmess_tls_mode(node)?
    } else {
        option_string(node, "security")
            .or_else(|| option_string(node, "tls"))
            .map(str::to_ascii_lowercase)
    };
    if security.as_deref() != Some("reality") {
        if ["pbk", "publicKey", "sid", "spx", "mldsa65Verify"]
            .iter()
            .any(|key| node.option(key).is_some_and(|value| !value.is_null()))
        {
            return Err("REALITY parameters require security=reality".into());
        }
        return Ok(None);
    }

    let public_key = option_string(node, "pbk")
        .or_else(|| option_string(node, "publicKey"))
        .ok_or_else(|| "REALITY public key is missing".to_owned())?;
    let fingerprint = option_string(node, "fp")
        .ok_or_else(|| "REALITY client fingerprint is required".to_owned())?;
    let short_id = option_string(node, "sid").unwrap_or_default();
    if short_id.len() > 16
        || !short_id.len().is_multiple_of(2)
        || !short_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(
            "REALITY short ID must be an even-length hexadecimal value of at most 16 characters"
                .into(),
        );
    }
    if public_key.chars().any(char::is_control) || fingerprint.chars().any(char::is_control) {
        return Err(
            "REALITY public key and fingerprint must not contain control characters".into(),
        );
    }
    if node.option("pbk").is_some_and(|value| !value.is_null())
        && node
            .option("publicKey")
            .is_some_and(|value| !value.is_null())
        && node.option("pbk") != node.option("publicKey")
    {
        return Err("REALITY public-key aliases conflict".into());
    }
    if insecure_option(node)?
        || option_string(node, "vcn").is_some()
        || option_string(node, "pcs").is_some()
        || option_string(node, "pinSHA256").is_some()
        || alpn_protocols(node)?.is_some()
    {
        return Err("ordinary TLS verification, certificate pin, and ALPN options cannot be combined with REALITY".into());
    }

    let mut reality = Map::new();
    reality.insert("public_key".into(), Value::String(public_key.into()));
    reality.insert("short_id".into(), Value::String(short_id.into()));
    reality.insert("fingerprint".into(), Value::String(fingerprint.into()));
    if let Some(server_name) = option_string(node, "sni") {
        if server_name.chars().any(char::is_control) {
            return Err("REALITY server name contains control characters".into());
        }
        reality.insert("server_name".into(), Value::String(server_name.into()));
    }
    if let Some(spider_x) = option_string(node, "spx") {
        if !spider_x.starts_with('/') || spider_x.chars().any(char::is_control) {
            return Err("REALITY SpiderX must be a path beginning with '/'".into());
        }
        reality.insert("spider_x".into(), Value::String(spider_x.into()));
    }
    if let Some(verify) = option_string(node, "mldsa65Verify") {
        if verify.chars().any(char::is_control) {
            return Err("REALITY ML-DSA verification key contains control characters".into());
        }
        reality.insert("mldsa65_verify".into(), Value::String(verify.into()));
    }
    Ok(Some(Value::Object(reality)))
}

pub(crate) fn tls_options(node: &ProxyNode) -> Result<Option<Value>, String> {
    let default_tls = matches!(node.protocol, Protocol::Trojan | Protocol::Hysteria2);
    let insecure = insecure_option(node)?;
    let verify_peer_cert_by_name = option_string(node, "vcn");
    let certificate_pin = option_string(node, "pcs").or_else(|| option_string(node, "pinSHA256"));
    if option_string(node, "pcs").is_some()
        && option_string(node, "pinSHA256").is_some()
        && option_string(node, "pcs") != option_string(node, "pinSHA256")
    {
        return Err("certificate pin options conflict".into());
    }
    let security = if node.protocol == Protocol::Vmess {
        vmess_tls_mode(node)?
    } else {
        option_string(node, "security")
            .or_else(|| option_string(node, "tls"))
            .map(str::to_ascii_lowercase)
    }
    .unwrap_or(if default_tls {
        "tls".into()
    } else {
        "none".into()
    });
    match security.as_str() {
        "none" | "" | "false" | "0" => {
            if matches!(node.protocol, Protocol::Trojan | Protocol::Hysteria2) {
                return Err("Trojan and Hysteria2 require TLS".into());
            }
            if option_string(node, "flow").is_some() {
                return Err("VLESS flow requires TLS".into());
            }
            if option_string(node, "sni").is_some() {
                return Err("SNI was supplied while TLS is disabled".into());
            }
            if alpn_protocols(node)?.is_some() {
                return Err("ALPN was supplied while TLS is disabled".into());
            }
            if option_string(node, "fp").is_some() {
                return Err("TLS fingerprint was supplied while TLS is disabled".into());
            }
            if certificate_pin.is_some() {
                return Err("certificate pin was supplied while TLS is disabled".into());
            }
            if insecure {
                return Err(
                    "insecure certificate verification was requested while TLS is disabled".into(),
                );
            }
            if verify_peer_cert_by_name.is_some() {
                return Err(
                    "certificate name verification was supplied while TLS is disabled".into(),
                );
            }
            Ok(None)
        }
        "tls" | "true" | "1" => {
            let mut tls = Map::new();
            tls.insert("enabled".into(), Value::Bool(true));
            if insecure {
                tls.insert("insecure".into(), Value::Bool(true));
            }
            if let Some(name) = verify_peer_cert_by_name {
                if name.chars().any(char::is_control) {
                    return Err("certificate verification name contains control characters".into());
                }
                tls.insert(
                    "verify_peer_cert_by_name".into(),
                    Value::String(name.into()),
                );
            }
            if let Some(sni) = option_string(node, "sni") {
                if sni.chars().any(char::is_control) {
                    return Err("TLS server name contains control characters".into());
                }
                tls.insert("server_name".into(), Value::String(sni.into()));
            }
            if let Some(protocols) = alpn_protocols(node)? {
                tls.insert(
                    "alpn".into(),
                    Value::Array(protocols.into_iter().map(Value::String).collect()),
                );
            }
            if let Some(fingerprint) = option_string(node, "fp") {
                tls.insert("fingerprint".into(), Value::String(fingerprint.into()));
            }
            if let Some(pin) = certificate_pin {
                let normalized = pin.replace(':', "");
                if normalized.len() != 64
                    || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(
                        "certificate SHA-256 pin must contain exactly 64 hexadecimal digits".into(),
                    );
                }
                tls.insert(
                    "certificate_sha256".into(),
                    Value::String(normalized.to_ascii_lowercase()),
                );
            }
            Ok(Some(Value::Object(tls)))
        }
        "reality" => Ok(None),
        _ => Err("unsupported TLS/security mode".into()),
    }
}
