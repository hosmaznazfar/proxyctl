//! Shared validation and normalization primitives used by core adapters.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityStatus {
    Supported,
    Unsupported,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Compatibility {
    pub status: CompatibilityStatus,
    /// Safe diagnostic: must not contain credentials or option values.
    pub reason: Option<String>,
}

impl Compatibility {
    pub fn supported() -> Self {
        Self {
            status: CompatibilityStatus::Supported,
            reason: None,
        }
    }

    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            status: CompatibilityStatus::Unsupported,
            reason: Some(reason.into()),
        }
    }

    pub fn invalid(reason: impl Into<String>) -> Self {
        Self {
            status: CompatibilityStatus::Invalid,
            reason: Some(reason.into()),
        }
    }

    pub fn is_supported(&self) -> bool {
        self.status == CompatibilityStatus::Supported
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GeneratedConfig {
    pub format: &'static str,
    pub content: Vec<u8>,
}

mod capabilities;
mod options;
mod protocol;
mod tls;
mod transport;

pub(crate) use capabilities::validate_for_core;
pub(crate) use options::{option_string, reject_unknown_options, validate_string_options};
pub(crate) use protocol::validate_common;
pub(crate) use tls::{alpn_protocols, tls_options};
pub(crate) use transport::normalize_transport;
