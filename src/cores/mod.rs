//! Managed core catalog, paths, and installation adapters.
pub mod archive;
mod catalog;
pub mod installer;
mod paths;
pub mod releases;
pub use catalog::CoreId;
pub use paths::{
    core_binary_path, core_install_directory, managed_cores_directory, managed_cores_path,
};
