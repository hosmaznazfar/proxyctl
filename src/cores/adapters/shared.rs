//! Shared validation and normalization primitives used by core adapters.

mod capabilities;
mod options;
mod protocol;
mod tls;
mod transport;

pub(crate) use capabilities::validate_for_core;
pub(crate) use options::option_string;
pub(crate) use protocol::validate_common;
pub(crate) use tls::tls_options;
pub(crate) use transport::normalize_transport;
