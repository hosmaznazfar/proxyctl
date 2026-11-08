//! Core, storage-independent domain types.

mod node;
mod protocol;
mod secret;
mod transport;

pub use node::{OptionEntry, ProxyNode};
pub use protocol::Protocol;
pub use secret::SecretString;
pub use transport::{Transport, TransportKind};
