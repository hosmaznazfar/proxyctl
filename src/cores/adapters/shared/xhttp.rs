use std::collections::BTreeMap;

use serde_json::Value;

use crate::domain::{ProxyNode, TransportKind};

/// Parse and validate the common XHTTP extra-settings subset.
/// Core-specific serialization is deliberately left to the native adapters.
pub(crate) fn normalize_xhttp_extra(
    node: &ProxyNode,
    kind: &TransportKind,
    headers: &BTreeMap<String, String>,
) -> Result<Option<Value>, String> {
    if !matches!(kind, TransportKind::XHttp) {
        if node.option("extra").is_some() {
            return Err("extra settings are only supported for XHTTP transport".into());
        }
        return Ok(None);
    }

    let extra = node.option("extra")
        .map(|value| {
            let parsed: Value = match value {
                Value::String(raw) => serde_json::from_str(raw)
                    .map_err(|_| "XHTTP extra settings contain malformed JSON".to_owned())?,
                Value::Object(_) => value.clone(),
                _ => return Err("XHTTP extra settings must be a JSON object or encoded JSON string".into()),
            };
            let object = parsed.as_object()
                .ok_or_else(|| "XHTTP extra settings must be a JSON object".to_owned())?;
            const ALLOWED: &[&str] = &[
                "headers", "xPaddingBytes", "xPaddingObfsMode", "xPaddingKey",
                "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod",
                "uplinkHTTPMethod", "sessionIDPlacement", "sessionIDKey",
                "sessionIDTable", "sessionIDLength", "seqPlacement", "seqKey",
                "uplinkDataPlacement", "uplinkDataKey", "uplinkChunkSize",
                "noGRPCHeader", "scMaxEachPostBytes", "scMinPostsIntervalMs", "xmux",
            ];
            if let Some(key) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
                return Err(format!("XHTTP extra option '{key}' is not supported by this adapter batch"));
            }
            if let Some(value) = object.get("headers") {
                let headers = value.as_object()
                    .ok_or_else(|| "XHTTP extra headers must be an object".to_owned())?;
                for (key, value) in headers {
                    let value = value.as_str()
                        .ok_or_else(|| "XHTTP extra header values must be strings".to_owned())?;
                    if key.is_empty() || key.eq_ignore_ascii_case("host")
                        || key.chars().any(char::is_control)
                        || value.chars().any(char::is_control)
                    {
                        return Err("XHTTP extra header name or value is invalid".into());
                    }
                }
            }
            const STRING_KEYS: &[&str] = &[
                "xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod",
                "uplinkHTTPMethod", "sessionIDPlacement", "sessionIDKey", "sessionIDTable",
                "seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey",
            ];
            for key in STRING_KEYS {
                if object.get(*key).is_some_and(|value| !value.is_string()) {
                    return Err(format!("XHTTP extra option '{key}' must be a string"));
                }
            }
            const RANGE_KEYS: &[&str] = &[
                "xPaddingBytes", "sessionIDLength", "uplinkChunkSize",
                "scMaxEachPostBytes", "scMinPostsIntervalMs",
            ];
            for key in RANGE_KEYS {
                if object.get(*key).is_some_and(|value| !value.is_string() && !value.is_number()) {
                    return Err(format!("XHTTP extra option '{key}' must be a range string or number"));
                }
            }
            for key in ["xPaddingObfsMode", "noGRPCHeader"] {
                if object.get(key).is_some_and(|value| !value.is_boolean()) {
                    return Err(format!("XHTTP {key} must be a boolean"));
                }
            }
            if let Some(xmux) = object.get("xmux") {
                let xmux = xmux.as_object()
                    .ok_or_else(|| "XHTTP xmux settings must be an object".to_owned())?;
                const XMUX_ALLOWED: &[&str] = &[
                    "maxConcurrency", "maxConnections", "cMaxReuseTimes",
                    "hMaxRequestTimes", "hMaxReusableSecs", "hKeepAlivePeriod",
                ];
                if xmux.keys().any(|key| !XMUX_ALLOWED.contains(&key.as_str())) {
                    return Err("XHTTP xmux contains an unsupported setting".into());
                }
                for (key, value) in xmux {
                    let valid = if key == "hKeepAlivePeriod" {
                        value.is_number()
                    } else {
                        value.is_string() || value.is_number()
                    };
                    if !valid {
                        return Err(format!("XHTTP xmux option '{key}' has an invalid type"));
                    }
                }
            }
            Ok(parsed)
        })
        .transpose()?;

    if !headers.is_empty()
        && extra.as_ref().and_then(Value::as_object)
            .and_then(|object| object.get("headers")).is_some()
    {
        return Err("XHTTP headers were supplied both directly and inside extra".into());
    }
    Ok(extra)
}
