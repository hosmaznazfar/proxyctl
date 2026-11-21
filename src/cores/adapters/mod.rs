//! Core-independent adapter contract and dispatch.
mod benchmark_batch;
mod mihomo;
mod shared;
mod sing_box;
mod xray;
#[cfg(target_os = "linux")]
pub mod xray_tun_fd;

pub mod validation;

use anyhow::Context;
use serde_json::Value;
use std::path::Path;

use crate::{cores::CoreId, domain::ProxyNode};

pub use benchmark_batch::BenchmarkTarget;
/// Linux interface name shared by Xray's generated TUN config and broker attachment checks.
pub const XRAY_TUN_INTERFACE_NAME: &str = "tun-proxyctl";
/// Linux environment variable used by Xray to adopt an externally supplied TUN fd.
pub const XRAY_TUN_FD_ENV: &str = "XRAY_TUN_FD";
pub use shared::{Compatibility, CompatibilityStatus, GeneratedConfig};

/// Socket mark used only by a core's proxy outbound during TUN operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunOutboundMark {
    value: u32,
    mask: u32,
}

impl TunOutboundMark {
    pub fn new(value: u32, mask: u32) -> anyhow::Result<Self> {
        anyhow::ensure!(
            value != 0 && value <= i32::MAX as u32 && mask != 0 && value & !mask == 0,
            "TUN outbound socket mark must be non-zero, fit the common native-core range, and fit its non-zero policy mask"
        );
        Ok(Self { value, mask })
    }

    pub fn value(self) -> u32 {
        self.value
    }

    pub fn mask(self) -> u32 {
        self.mask
    }
}

/// How a core obtains its TUN device. This describes the native core contract only; it does
/// not imply that Proxyctl currently launches the core with a transferred descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunAttachmentMode {
    /// The core accepts an externally supplied descriptor through a documented environment key.
    ExternalDescriptorEnvironment { variable: &'static str },
    /// The core creates or opens the device itself from its native configuration.
    /// This is not compatible with broker-owned descriptor transfer and needs a separate
    /// native-device lifecycle backend before it can be activated by Proxyctl.
    NativeDeviceCreation,
    /// No supported TUN attachment contract is available in this adapter.
    Unsupported,
}

impl TunAttachmentMode {
    /// Return the environment key only when the core can consume an externally supplied fd.
    pub const fn external_descriptor_environment(self) -> Option<&'static str> {
        match self {
            Self::ExternalDescriptorEnvironment { variable } => Some(variable),
            Self::NativeDeviceCreation | Self::Unsupported => None,
        }
    }
}

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

    /// Describe how the native core obtains its TUN device.
    fn tun_attachment_mode(&self) -> TunAttachmentMode {
        TunAttachmentMode::Unsupported
    }

    /// Generate a marked TUN config. The mark is mandatory so an unmarked TUN config
    /// cannot accidentally be selected by a future activation path. Unsupported adapters fail closed.
    fn generate_tun_activation_config(
        &self,
        _node: &ProxyNode,
        _listen_port: u16,
        _mark: TunOutboundMark,
    ) -> anyhow::Result<GeneratedConfig> {
        anyhow::bail!(
            "{} does not have a verified proxy-outbound-only socket mark option",
            self.core()
        )
    }

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
mod tun_mark_tests {
    use super::{TunAttachmentMode, TunOutboundMark};

    #[cfg(target_os = "linux")]
    #[test]
    fn core_tun_attachment_inventory_matches_verified_launch_contracts() {
        assert_eq!(
            super::adapter(crate::cores::CoreId::Xray)
                .tun_attachment_mode()
                .external_descriptor_environment(),
            Some(super::XRAY_TUN_FD_ENV)
        );
        assert_eq!(
            super::adapter(crate::cores::CoreId::SingBox).tun_attachment_mode(),
            TunAttachmentMode::NativeDeviceCreation
        );
        assert_eq!(
            super::adapter(crate::cores::CoreId::Mihomo).tun_attachment_mode(),
            TunAttachmentMode::NativeDeviceCreation
        );
    }

    #[test]
    fn only_external_descriptor_modes_advertise_broker_fd_adoption() {
        assert_eq!(
            TunAttachmentMode::ExternalDescriptorEnvironment { variable: "XRAY_TUN_FD" }
                .external_descriptor_environment(),
            Some("XRAY_TUN_FD")
        );
        assert_eq!(TunAttachmentMode::NativeDeviceCreation.external_descriptor_environment(), None);
        assert_eq!(TunAttachmentMode::Unsupported.external_descriptor_environment(), None);
    }

    #[test]
    fn outbound_mark_must_be_nonzero_and_fit_the_policy_mask() {
        assert_eq!(TunOutboundMark::new(0x42, 0xff).unwrap().value(), 0x42);
        assert_eq!(TunOutboundMark::new(0x42, 0xff).unwrap().mask(), 0xff);
        assert!(TunOutboundMark::new(0, 0xff).is_err());
        assert!(TunOutboundMark::new(0x42, 0).is_err());
        assert!(TunOutboundMark::new(0x100, 0xff).is_err());
        assert!(TunOutboundMark::new(0x8000_0000, 0xffff_ffff).is_err());
    }
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
