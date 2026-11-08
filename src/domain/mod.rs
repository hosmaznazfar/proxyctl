//! Core, storage-independent domain types.

mod node;
mod protocol;
mod secret;

pub use node::ProxyNode;
pub use protocol::Protocol;
pub use secret::SecretString;
