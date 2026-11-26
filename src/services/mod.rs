//! Application services.
//!
//! Services contain use-case logic and coordinate domain interfaces. They must not depend on
//! clap's CLI types.

pub mod display_config;

pub mod activation;
pub mod benchmark;
pub mod cores;
pub mod listener_config;
pub mod node_selection;
pub mod nodes;
pub mod pruning;
pub mod reporting;
pub mod sorting;
pub mod tun_config;
#[cfg(target_os = "linux")]
pub mod tun_handoff;
pub mod tun_preparation;
pub mod updates;
pub mod validation;

pub mod shell_completion;
