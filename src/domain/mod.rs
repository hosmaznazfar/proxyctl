//! Core, storage-independent domain types.

mod benchmark;
mod node;
mod protocol;
mod secret;
mod transport;

pub use benchmark::{
    BenchmarkMetric, BenchmarkRun, BenchmarkRunStatus, BenchmarkSample, BenchmarkSampleStatus,
    BenchmarkSettings, median_successful_samples, throughput_bps,
};
pub use node::{OptionEntry, ProxyNode};
pub use protocol::Protocol;
pub use secret::SecretString;
pub use transport::{Transport, TransportKind};
