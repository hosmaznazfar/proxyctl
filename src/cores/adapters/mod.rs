//! Core-independent adapter contract and dispatch.
mod mihomo;
mod shared;
mod sing_box;
mod xray;

use std::path::Path;
use anyhow::Context;
use serde_json::Value;

use crate::{cores::CoreId, domain::ProxyNode};

pub use shared::{Compatibility, CompatibilityStatus, GeneratedConfig};

/// A core adapter must either represent every retained connection option or explain why it
/// cannot. It must never emit a partial configuration after silently dropping an option.
pub trait CoreAdapter {
    fn core(&self) -> CoreId;
    fn compatibility(&self, node: &ProxyNode) -> Compatibility;
    fn generate_config(&self, node: &ProxyNode) -> anyhow::Result<GeneratedConfig>;
    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()>;
}

pub fn adapter(core: CoreId) -> &'static dyn CoreAdapter {
    match core {
        CoreId::SingBox => &sing_box::SingBoxAdapter,
        CoreId::Xray => &xray::XrayAdapter,
        CoreId::Mihomo => &mihomo::MihomoAdapter,
    }
}

/// Serialize the JSON document shared by the three native config adapters. JSON is also a
/// YAML 1.2 subset, so Mihomo can consume the generated JSON document as a config file.
pub(crate) fn json_config(value: Value) -> anyhow::Result<GeneratedConfig> {
    Ok(GeneratedConfig {
        format: "json",
        content: serde_json::to_vec_pretty(&value).context("could not serialize core config")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_proxy_url;

    #[test]
    fn all_adapters_generate_a_native_document_for_basic_vless() {
        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443").unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let adapter = adapter(core);
            assert!(adapter.compatibility(&node).is_supported(), "{core}");
            let generated = adapter.generate_config(&node).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            assert!(document.is_object());
        }
    }

    #[test]
    fn adapters_reject_unmapped_options_instead_of_dropping_them() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=ws&path=%2Fsocket",
        ).unwrap();
        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let compatibility = adapter(core).compatibility(&node);
            assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
            assert!(compatibility.reason.unwrap().contains("option"));
        }
    }

    #[test]
    fn xray_explicitly_rejects_hysteria2() {
        let node = parse_proxy_url("hysteria2://secret@example.com:443").unwrap();
        let compatibility = adapter(CoreId::Xray).compatibility(&node);
        assert_eq!(compatibility.status, CompatibilityStatus::Unsupported);
    }
}
