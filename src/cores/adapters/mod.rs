//! Core-independent adapter contract and dispatch.
mod benchmark_batch;
mod mihomo;
mod shared;
mod sing_box;
mod xray;

pub mod validation;

use std::path::Path;

use crate::{cores::CoreId, domain::ProxyNode};

pub use benchmark_batch::BenchmarkTarget;
pub use shared::{Compatibility, CompatibilityStatus, GeneratedConfig};

/// A core adapter must either represent every retained connection option or explain why it
/// cannot. It must never emit a partial configuration after silently dropping an option.
pub trait CoreAdapter {
    fn core(&self) -> CoreId;
    fn compatibility(&self, node: &ProxyNode) -> Compatibility;
    fn generate_config(&self, node: &ProxyNode) -> anyhow::Result<GeneratedConfig>;

    /// Generate a native benchmark configuration for a batch of nodes.
    fn generate_benchmark_batch_config(
        &self,
        targets: &[BenchmarkTarget<'_>],
    ) -> anyhow::Result<GeneratedConfig>;

    /// Add this core's loopback-only SOCKS5 + HTTP activation listener.
    fn generate_activation_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig>;

    /// Add this core's native TUN inbound. Activation remains gated by the TUN lifecycle.
    fn generate_tun_activation_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig>;

    /// Add this core's loopback-only HTTP/SOCKS benchmark listener.
    fn generate_benchmark_config(
        &self,
        node: &ProxyNode,
        listen_port: u16,
    ) -> anyhow::Result<GeneratedConfig>;

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()>;
}

/// Reduce native validator output to a fixed, credential-free diagnostic category.
pub(crate) fn summarize_validation_failure(stdout: &[u8], stderr: &[u8]) -> &'static str {
    let diagnostic = format!(
        "{} {}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    )
    .to_ascii_lowercase();

    if diagnostic.contains("unknown field")
        || diagnostic.contains("unknown config field")
        || diagnostic.contains("unknown configuration field")
    {
        "the core rejected an unrecognized configuration field; raw diagnostics withheld"
    } else if diagnostic.contains("failed to build inbound")
        || diagnostic.contains("invalid inbound")
        || diagnostic.contains("inbound config")
    {
        "the core rejected the loopback HTTP inbound; raw diagnostics withheld"
    } else if diagnostic.contains("failed to build outbound")
        || diagnostic.contains("invalid outbound")
        || diagnostic.contains("proxy outbound")
    {
        "the core rejected the proxy outbound settings; raw diagnostics withheld"
    } else if diagnostic.contains("reality") {
        "the core rejected the proxy REALITY settings; raw diagnostics withheld"
    } else if diagnostic.contains("tls") || diagnostic.contains("certificate") {
        "the core rejected the proxy TLS or certificate settings; raw diagnostics withheld"
    } else if diagnostic.contains("failed to parse")
        || diagnostic.contains("invalid character")
        || diagnostic.contains("unexpected end of json")
        || diagnostic.contains("invalid json")
        || diagnostic.contains("yaml:")
    {
        "the core could not parse the generated configuration; raw diagnostics withheld"
    } else {
        "the core returned a native configuration validation error; raw diagnostics withheld"
    }
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

#[cfg(test)]
mod validation_diagnostic_tests {
    use super::summarize_validation_failure;

    #[test]
    fn native_validation_diagnostics_are_allowlisted() {
        let cases = [
            (
                b"unknown field secret-value".as_slice(),
                "unrecognized configuration field",
            ),
            (
                b"failed to build inbound with private-address".as_slice(),
                "loopback HTTP inbound",
            ),
            (
                b"failed to build outbound with credential".as_slice(),
                "proxy outbound settings",
            ),
            (
                b"TLS certificate verification setting".as_slice(),
                "TLS or certificate",
            ),
            (
                b"invalid JSON document".as_slice(),
                "parse the generated configuration",
            ),
        ];

        for (diagnostic, expected) in cases {
            let summary = summarize_validation_failure(diagnostic, b"");
            assert!(summary.contains(expected));
            assert!(!summary.contains("secret-value"));
            assert!(!summary.contains("private-address"));
            assert!(!summary.contains("credential"));
        }
    }
}
