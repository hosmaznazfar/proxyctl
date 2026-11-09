//! Core-independent adapter contract and dispatch.
mod mihomo;
mod shared;
mod sing_box;
mod xray;

pub mod validation;

use anyhow::Context;
use serde_json::Value;
use std::path::Path;

use crate::{cores::CoreId, domain::ProxyNode};

pub use shared::{Compatibility, CompatibilityStatus, GeneratedConfig};

/// A core adapter must either represent every retained connection option or explain why it
/// cannot. It must never emit a partial configuration after silently dropping an option.
pub trait CoreAdapter {
    fn core(&self) -> CoreId;
    fn compatibility(&self, node: &ProxyNode) -> Compatibility;
    fn generate_config(&self, node: &ProxyNode) -> anyhow::Result<GeneratedConfig>;

    /// Add a loopback-only HTTP inbound for isolated benchmark traffic.
    fn generate_benchmark_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig> {
        use serde_json::json;

        let generated = self.generate_config(node)?;
        let mut document: serde_json::Value = serde_json::from_slice(&generated.content)?;
        match self.core() {
            CoreId::SingBox => {
                document["inbounds"] = json!([{
                    "type": "http",
                    "tag": "benchmark-in",
                    "listen": "127.0.0.1",
                    "listen_port": listen_port
                }]);
                document["route"] = json!({"final": "proxy"});
            }
            CoreId::Xray => {
                document["inbounds"] = json!([{
                    "listen": "127.0.0.1",
                    "port": listen_port,
                    "protocol": "http",
                    "settings": {},
                    "tag": "benchmark-in"
                }]);
            }
            CoreId::Mihomo => {
                document["port"] = json!(listen_port);
                document["bind-address"] = json!("127.0.0.1");
                document["allow-lan"] = json!(false);
            }
        }
        json_config(document)
    }

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
mod tests;
