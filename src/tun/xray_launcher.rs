//! Xray Linux launcher using the broker-owned TUN descriptor.
//!
//! This is a core-specific launch primitive. It does not activate routes, commit a lifecycle
//! manifest, or prove traffic readiness; the caller must compose those steps and keep public
//! activation gated until the full lifecycle is connected.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    os::fd::AsFd,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
};

use crate::{
    cores::adapters::xray_tun_fd::XrayTunDescriptor,
    tun::{mutation_helper_launcher::MutationHelper, process::ProcessIdentity},
};

/// Spawn Xray with the descriptor retained by the exact broker activation generation.
///
/// Xray's documented Linux `XRAY_TUN_FD` input causes it to duplicate and consume this
/// externally supplied TUN descriptor. The broker's original descriptor remains owned by
/// the helper; this process receives a duplicate with close-on-exec cleared only in its child.
pub fn spawn_xray_from_broker(
    helper: &MutationHelper,
    activation_id: &str,
    generation: u64,
    executable: &Path,
    config: &Path,
) -> Result<(Child, ProcessIdentity)> {
    ensure!(executable.is_absolute() && executable.is_file(), "Xray executable must be an existing absolute file");
    ensure!(config.is_absolute() && config.is_file(), "Xray config must be an existing absolute file");

    let broker_descriptor = helper.attach_descriptor(activation_id, generation)
        .context("cannot obtain the broker-owned TUN descriptor for Xray")?;
    let inherited = XrayTunDescriptor::duplicate(broker_descriptor.as_fd())
        .context("cannot prepare the Xray TUN descriptor for child inheritance")?;

    let mut command = Command::new(executable);
    command.arg("run").arg("-c").arg(config)
        .arg0("proxyctl-core")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    inherited.configure_command(&mut command)?;

    let mut child = command.spawn().context("cannot spawn Xray with the broker-owned TUN descriptor")?;
    drop(inherited);
    drop(broker_descriptor);

    let identity = match ProcessIdentity::capture(child.id()) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("cannot capture the spawned Xray process identity");
        }
    };
    Ok((child, identity))
}
