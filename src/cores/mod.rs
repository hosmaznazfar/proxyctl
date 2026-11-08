//! Managed core catalog, paths, and installation adapters.
mod catalog;
mod paths;
pub mod archive;
pub mod installer;
pub mod releases;
pub use catalog::CoreId;
pub use paths::{core_install_directory, managed_cores_directory};
