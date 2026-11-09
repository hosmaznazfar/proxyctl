//! Core-independent normalized transport semantics.

use std::collections::BTreeMap;

/// Transport selected by a source protocol configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportKind {
    Tcp,
    WebSocket,
    Grpc,
    Http,
    Http2,
    HttpUpgrade,
    XHttp,
    Unknown(String),
}

/// Normalized transport settings. Host headers are deliberately distinct from TLS SNI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transport {
    pub kind: TransportKind,
    pub path: Option<String>,
    pub headers: BTreeMap<String, String>,
    /// HTTP/2 authority host alternatives, distinct from WebSocket headers and TLS SNI.
    pub hosts: Vec<String>,
    /// HTTP Upgrade authority host, distinct from TLS SNI.
    pub host: Option<String>,
    /// gRPC authority; not the HTTP Host header and not TLS SNI.
    pub authority: Option<String>,
    pub service_name: Option<String>,
    pub mode: Option<String>,
    pub max_early_data: Option<u32>,
    pub early_data_header_name: Option<String>,
}

impl Transport {
    pub fn tcp() -> Self {
        Self {
            kind: TransportKind::Tcp,
            path: None,
            headers: BTreeMap::new(),
            hosts: Vec::new(),
            host: None,
            authority: None,
            service_name: None,
            mode: None,
            max_early_data: None,
            early_data_header_name: None,
        }
    }
}
