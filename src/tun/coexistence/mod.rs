//! External VPN coexistence primitives.
//!
//! Process/cgroup discovery and nftables integration are deliberately separate from
//! route planning and the TUN lifecycle. The first backend targets this host's
//! unified cgroup v2 hierarchy; later Linux backends can implement the same contract.

#[cfg(target_os = "linux")]
pub mod cgroup_v2;

#[cfg(target_os = "linux")]
pub use cgroup_v2::{CgroupV2Target, inspect_process};
