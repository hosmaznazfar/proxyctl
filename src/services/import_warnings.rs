//! Human-readable import diagnostics, separate from parsing and core serialization.

use crate::{
    cores::{CoreId, adapters::{CompatibilityStatus, adapter}},
    domain::{Protocol, ProxyNode},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportWarning {
    pub message: String,
    /// Credential-free adapter diagnostic; displayed only with --developer-details.
    pub developer_detail: String,
}

/// Analyze security posture and per-core compatibility without exposing imported secrets.
pub fn analyze(node: &ProxyNode) -> Vec<ImportWarning> {
    let mut warnings = Vec::new();
    let tls_enabled = ["security", "tls"].iter().any(|key| {
        node.option(key).is_some_and(|value| match value {
            serde_json::Value::Bool(value) => *value,
            serde_json::Value::Number(value) => value.as_i64() == Some(1),
            serde_json::Value::String(value) => matches!(
                value.to_ascii_lowercase().as_str(),
                "tls" | "true" | "1" | "reality"
            ),
            _ => false,
        })
    });
    let insecure = ["insecure", "allowInsecure"].iter().any(|key| {
        node.option(key).is_some_and(|value| match value {
            serde_json::Value::Bool(value) => *value,
            serde_json::Value::Number(value) => value.as_i64() == Some(1),
            serde_json::Value::String(value) => matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
            _ => false,
        })
    });

    if tls_enabled && insecure {
        warnings.push(ImportWarning {
            message: "TLS certificate verification is disabled. This makes interception by an untrusted network easier.".into(),
            developer_detail: "The imported insecure/allowInsecure option disables peer certificate verification.".into(),
        });
    } else if matches!(node.protocol, Protocol::Vless | Protocol::Vmess)
        && !tls_enabled && node.option("pbk").is_none() && node.option("publicKey").is_none()
    {
        warnings.push(ImportWarning {
            message: "This link does not enable TLS or REALITY. Traffic protection depends on the proxy protocol and server configuration.".into(),
            developer_detail: "No TLS or REALITY security mode was detected in the imported options.".into(),
        });
    }

    for core in CoreId::ALL {
        let compatibility = adapter(core).compatibility(node);
        let warning = match compatibility.status {
            CompatibilityStatus::Supported => None,
            CompatibilityStatus::Unsupported => Some(format!("{} cannot apply every setting in this link. Choose another compatible core for this node.", core)),
            CompatibilityStatus::Invalid => Some(format!("{} rejected this link's settings. Review the imported options before using this core.", core)),
        };
        if let Some(message) = warning {
            warnings.push(ImportWarning {
                message,
                developer_detail: compatibility.reason.unwrap_or_else(|| "The adapter could not validate this option combination.".into()),
            });
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_proxy_url;

    #[test]
    fn warns_about_disabled_certificate_verification_without_echoing_secrets() {
        let node = parse_proxy_url("trojan://super-secret@example.test:443?security=tls&allowInsecure=true").unwrap();
        let warnings = analyze(&node);
        assert!(warnings.iter().any(|warning| warning.message.contains("certificate verification is disabled")));
        assert!(!format!("{warnings:?}").contains("super-secret"));
    }

    #[test]
    fn reports_core_specific_compatibility() {
        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.test:443?type=xhttp&mode=auto").unwrap();
        let warnings = analyze(&node);
        assert!(warnings.iter().any(|warning| warning.message.contains("sing-box cannot apply")));
    }
}