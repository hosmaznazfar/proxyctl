//! Systemd user-service backend for the CLI-independent TUN recovery supervisor.
//!
//! The service runs as the activation user; privileged kernel cleanup remains inside the
//! persistent mutation helper. This module never installs units or changes the host network.
#![cfg(target_os = "linux")]

use super::recovery::{RecoverySupervisor, SupervisorIdentity};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    process::Command,
};

#[derive(Debug, Clone)]
pub struct SystemdRecoverySupervisor {
    systemd_run: PathBuf,
    systemctl: PathBuf,
    executable: PathBuf,
    runtime: PathBuf,
}

impl SystemdRecoverySupervisor {
    pub fn new(systemd_run: impl Into<PathBuf>, systemctl: impl Into<PathBuf>, executable: impl Into<PathBuf>, runtime: impl Into<PathBuf>) -> Self {
        Self { systemd_run: systemd_run.into(), systemctl: systemctl.into(), executable: executable.into(), runtime: runtime.into() }
    }

    fn validate_identity(&self, identity: &SupervisorIdentity) -> Result<()> {
        identity.validate()?;
        ensure!(identity.manifest_path == self.runtime.join("tun-manifest.json").to_string_lossy().as_ref(),
            "supervisor identity points outside the configured runtime directory");
        ensure!(self.runtime.is_absolute(), "supervisor runtime directory must be absolute");
        let runtime = fs::symlink_metadata(&self.runtime).context("cannot inspect supervisor runtime directory")?;
        ensure!(runtime.is_dir() && !runtime.file_type().is_symlink(), "supervisor runtime must be a real directory");
        ensure!(fs::canonicalize(&self.runtime)? == self.runtime,
            "supervisor runtime path must not contain symlinked or non-canonical components");
        // SAFETY: geteuid is a read-only query of the current effective user.
        ensure!(runtime.uid() == unsafe { libc::geteuid() }, "supervisor runtime directory has a foreign owner");
        ensure!(runtime.permissions().mode() & 0o077 == 0, "supervisor runtime directory must be private");

        let executable = fs::symlink_metadata(&self.executable).context("cannot inspect recovery supervisor executable")?;
        ensure!(executable.is_file() && !executable.file_type().is_symlink(), "recovery supervisor executable must be a regular non-symlink file");
        // SAFETY: geteuid is a read-only query of the current effective user.
        ensure!(executable.uid() == unsafe { libc::geteuid() }, "recovery supervisor executable must be owned by the activation user");
        ensure!(executable.permissions().mode() & 0o111 != 0, "recovery supervisor executable is not executable");
        ensure!(executable.permissions().mode() & 0o022 == 0, "recovery supervisor executable must not be group- or world-writable");
        for tool in [&self.systemd_run, &self.systemctl] {
            let metadata = fs::symlink_metadata(tool).with_context(|| format!("cannot inspect {}", tool.display()))?;
            ensure!(metadata.is_file() && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.permissions().mode() & 0o111 != 0
                && metadata.permissions().mode() & 0o022 == 0,
                "systemd command must be a root-owned, non-writable executable regular file");
        }
        Ok(())
    }

    fn unit(identity: &SupervisorIdentity) -> String { format!("{}.service", identity.service_name) }

    fn active_state(&self, identity: &SupervisorIdentity) -> Result<Option<String>> {
        self.validate_identity(identity)?;
        let output = Command::new(&self.systemctl)
            .args(["--user", "show", "--property=ActiveState", "--value"])
            .arg(Self::unit(identity)).output()
            .context("could not query the systemd user service state")?;
        ensure!(output.status.success(),
            "systemctl could not query the TUN recovery service: {}",
            String::from_utf8_lossy(&output.stderr).trim());
        let state = String::from_utf8(output.stdout)
            .context("systemd returned a non-UTF-8 service state")?
            .trim()
            .to_owned();
        match state.as_str() {
            "active" | "activating" | "reloading" | "deactivating" => Ok(Some(state)),
            "inactive" | "failed" => Ok(None),
            _ => anyhow::bail!("systemd returned an unrecognized service state: {state:?}"),
        }
    }
}

impl RecoverySupervisor for SystemdRecoverySupervisor {
    fn start(&mut self, identity: &SupervisorIdentity) -> Result<()> {
        self.validate_identity(identity)?;
        if self.active_state(identity)?.is_some() { return Ok(()); }
        let unit_arg = format!("--unit={}", Self::unit(identity));
        let output = Command::new(&self.systemd_run)
            .args(["--user", "--quiet", "--no-block", "--collect", &unit_arg,
                "--property=Restart=on-failure", "--property=RestartSec=1s", "--property=StartLimitIntervalSec=0", "--"])
            .arg(&self.executable).arg(&self.runtime).output()
            .context("could not start the TUN recovery supervisor user service")?;
        if !output.status.success() {
            // A concurrent start may have won after the initial state query. Accept only
            // when systemd now reports this exact generation's unit as active/activating.
            if self.active_state(identity)?.is_some() {
                return Ok(());
            }
            anyhow::bail!("systemd-run rejected the TUN recovery service: {}",
                String::from_utf8_lossy(&output.stderr).trim());
        }
        Ok(())
    }

    fn is_alive(&mut self, identity: &SupervisorIdentity) -> Result<bool> {
        Ok(self.active_state(identity)?.is_some())
    }

    fn stop(&mut self, identity: &SupervisorIdentity) -> Result<()> {
        self.validate_identity(identity)?;
        if self.active_state(identity)?.is_none() { return Ok(()); }
        let output = Command::new(&self.systemctl).args(["--user", "stop"]).arg(Self::unit(identity))
            .output().context("could not stop the TUN recovery supervisor user service")?;
        ensure!(output.status.success(), "systemctl could not stop the TUN recovery service: {}",
            String::from_utf8_lossy(&output.stderr).trim());
        Ok(())
    }
}
