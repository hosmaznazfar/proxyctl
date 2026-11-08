//! Shared validation and normalization primitives used by core adapters.

mod capabilities;
mod options;
mod protocol;
mod tls;
mod transport;

pub(crate) use capabilities::validate_for_core;
pub(crate) use options::{option_string, reject_unknown_options, validate_string_options};
pub(crate) use tls::alpn_protocols;
pub(crate) use protocol::validate_common;
pub(crate) use tls::tls_options;
pub(crate) use transport::normalize_transport;
