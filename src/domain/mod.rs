//! Core, storage-independent domain types.

mod node;
mod protocol;
mod secret;

pub use node::{OptionEntry, ProxyNode};
pub use protocol::Protocol;
pub use secret::SecretString;
