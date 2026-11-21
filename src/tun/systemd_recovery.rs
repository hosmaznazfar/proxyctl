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
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct SystemdRecoverySupervisor {
    systemd_run: PathBuf,
    systemctl: PathBuf,
    executable: PathBuf,
    runtime: PathBuf,
}

impl SystemdRecoverySupervisor {
    /// Construct the only currently supported automatic recovery backend.
    pub fn for_current_manager(
        executable: impl Into<PathBuf>,
        runtime: impl Into<PathBuf>,
    ) -> Result<Self> {
        ensure!(
            super::service_manager::ServiceManager::detect()
                == super::service_manager::ServiceManager::Systemd,
            "automatic TUN recovery currently requires systemd"
        );
        Ok(Self::new(
            "/usr/bin/systemd-run",
            "/usr/bin/systemctl",
            executable,
            runtime,
        ))
    }

    pub fn new(systemd_run: impl Into<PathBuf>, systemctl: impl Into<PathBuf>, executable: impl Into<PathBuf>, runtime: impl Into<PathBuf>) -> Self {
        Self { systemd_run: systemd_run.into(), systemctl: systemctl.into(), executable: executable.into(), runtime: runtime.into() }
    }

    fn validate_identity(&self, identity: &SupervisorIdentity) -> Result<()> {
        identity.validate()?;
        ensure!(identity.manifest_path == self.runtime.join("tun-manifest.json").to_string_lossy().as_ref(),
            "supervisor identity points outside the configured runtime directory");
        ensure!(
            self.runtime.is_absolute() && self.runtime.as_os_str().len() <= 4096,
            "supervisor runtime directory must be a bounded absolute path"
        );
        for path in [&self.executable, &self.systemd_run, &self.systemctl] {
            ensure!(
                path.is_absolute()
                    && path.components().all(|component| matches!(
                        component,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    ))
                    && path.file_name().is_some()
                    && path.as_os_str().len() <= 4096,
                "recovery supervisor and systemd command paths must be normalized absolute file paths"
            );
        }
        let runtime = fs::symlink_metadata(&self.runtime).context("cannot inspect supervisor runtime directory")?;
        ensure!(runtime.is_dir() && !runtime.file_type().is_symlink(), "supervisor runtime must be a real directory");
        ensure!(fs::canonicalize(&self.runtime)? == self.runtime,
            "supervisor runtime path must not contain symlinked or non-canonical components");
        // SAFETY: geteuid is a read-only query of the current effective user.
        ensure!(runtime.uid() == unsafe { libc::geteuid() }, "supervisor runtime directory has a foreign owner");
        ensure!(runtime.permissions().mode() & 0o077 == 0, "supervisor runtime directory must be private");
        ensure!(runtime.permissions().mode() & 0o7000 == 0, "supervisor runtime directory must not have special permission bits");
        ensure!(runtime.permissions().mode() & 0o700 == 0o700, "supervisor runtime directory must be owner-readable, writable, and searchable");

        let executable = fs::symlink_metadata(&self.executable).context("cannot inspect recovery supervisor executable")?;
        ensure!(executable.is_file() && !executable.file_type().is_symlink(), "recovery supervisor executable must be a regular non-symlink file");
        // SAFETY: geteuid is a read-only query of the current effective user.
        ensure!(
            executable.uid() == 0 || executable.uid() == unsafe { libc::geteuid() },
            "recovery supervisor executable must be owned by root or the activation user"
        );
        ensure!(executable.permissions().mode() & 0o111 != 0, "recovery supervisor executable is not executable");
        ensure!(executable.permissions().mode() & 0o022 == 0, "recovery supervisor executable must not be group- or world-writable");
        ensure!(executable.permissions().mode() & 0o7000 == 0, "recovery supervisor executable must not have special permission bits");
        ensure!(executable.nlink() == 1, "recovery supervisor executable must not have external hard links");
        for tool in [&self.systemd_run, &self.systemctl] {
            let metadata = fs::symlink_metadata(tool).with_context(|| format!("cannot inspect {}", tool.display()))?;
            ensure!(metadata.is_file() && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.permissions().mode() & 0o111 != 0
                && metadata.permissions().mode() & 0o022 == 0
                && metadata.permissions().mode() & 0o7000 == 0
                && metadata.nlink() == 1,
                "systemd command must be a root-owned, non-writable executable regular file");
        }
        Ok(())
    }

    fn unit(identity: &SupervisorIdentity) -> String { format!("{}.service", identity.service_name) }

    fn validate_startable_manifest(&self, identity: &SupervisorIdentity) -> Result<()> {
        let store = super::manifest_store::ManifestStore::open(self.runtime.clone())?;
        let snapshot = store.load()?.context("cannot start recovery service without a durable activation manifest")?;
        ensure!(
            snapshot.manifest.activation_id == identity.activation_id
                && snapshot.generation == identity.generation,
            "recovery service identity does not match the persisted activation generation"
        );
        match snapshot.phase {
            super::recovery::SupervisorPhase::Prepared => ensure!(
                snapshot.core_process.is_none(),
                "Prepared activation unexpectedly has a bound core process"
            ),
            super::recovery::SupervisorPhase::Running => ensure!(
                snapshot.core_process.is_some(),
                "Running activation has no bound core process"
            ),
            phase => anyhow::bail!("cannot start a recovery service for activation phase {phase:?}"),
        }
        Ok(())
    }

    fn generation_is_cleaned(&self, identity: &SupervisorIdentity) -> Result<bool> {
        let store = super::manifest_store::ManifestStore::open(self.runtime.clone())?;
        let Some(snapshot) = store.load()? else { return Ok(true); };
        ensure!(
            snapshot.manifest.activation_id == identity.activation_id
                && snapshot.generation == identity.generation,
            "a different activation replaced the recovery service generation"
        );
        Ok(snapshot.phase == super::recovery::SupervisorPhase::Cleaned)
    }

    fn active_state(&self, identity: &SupervisorIdentity) -> Result<Option<String>> {
        self.validate_identity(identity)?;
        let output = Command::new(&self.systemctl)
            .args(["--user", "is-active"])
            .arg(Self::unit(identity))
            .output()
            .context("could not query the TUN recovery service state")?;
        let state = String::from_utf8(output.stdout)
            .context("systemd returned a non-UTF-8 service state")?
            .trim()
            .to_owned();
        if output.status.success() {
            return match state.as_str() {
                "active" | "activating" | "reloading" | "deactivating" => Ok(Some(state)),
                _ => anyhow::bail!("systemd returned an unrecognized active service state: {state:?}"),
            };
        }
        match output.status.code() {
            // systemctl is-active: 3 means inactive; 4 means no such unit.
            Some(3) | Some(4) => Ok(None),
            _ => anyhow::bail!(
                "systemctl could not query the TUN recovery service ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        }
    }
}

impl RecoverySupervisor for SystemdRecoverySupervisor {
    fn start(&mut self, identity: &SupervisorIdentity) -> Result<()> {
        self.validate_identity(identity)?;
        self.validate_startable_manifest(identity)?;
        if self.active_state(identity)?.is_some() { return Ok(()); }
        let unit_arg = format!("--unit={}", Self::unit(identity));
        let output = Command::new(&self.systemd_run)
            .arg("--user")
            .arg("--quiet")
            .arg("--no-block")
            .arg("--collect")
            .arg(&unit_arg)
            .arg("--property=Restart=on-failure")
            .arg("--property=RestartSec=1s")
            .arg("--property=StartLimitIntervalSec=0")
            .arg("--property=UMask=0077")
            .arg("--property=PrivateTmp=yes")
            .arg("--property=ProtectSystem=full")
            .arg("--property=ProtectHome=read-only")
            .arg(format!("--property=ReadWritePaths={}", self.runtime.display()))
            .arg("--property=ProtectKernelTunables=yes")
            .arg("--property=ProtectKernelModules=yes")
            .arg("--property=ProtectControlGroups=yes")
            .arg("--property=RestrictSUIDSGID=yes")
            .arg("--property=LockPersonality=yes")
            .arg("--property=MemoryDenyWriteExecute=yes")
            .arg("--property=RestrictRealtime=yes")
            .arg("--")
            .arg(&self.executable)
            .arg(&self.runtime)
            .arg(&identity.activation_id)
            .arg(identity.generation.to_string())
            .output()
            .context("could not start the TUN recovery supervisor user service")?;
        if !output.status.success() {
            // A concurrent start may have won after the initial state query. Accept only
            // when systemd now reports this exact generation's unit as active/activating.
            if self.active_state(identity)?.is_none() {
                anyhow::bail!("systemd-run rejected the TUN recovery service: {}",
                    String::from_utf8_lossy(&output.stderr).trim());
            }
        }

        // --no-block confirms only that the manager accepted the request. Wait briefly
        // until the exact transient unit is visible as active/activating before returning.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if self.active_state(identity)?.is_some() || self.generation_is_cleaned(identity)? {
                return Ok(());
            }
            ensure!(Instant::now() < deadline,
                "systemd accepted the recovery service but it did not become active before the startup deadline");
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn is_alive(&mut self, identity: &SupervisorIdentity) -> Result<bool> {
        Ok(self.active_state(identity)?.is_some())
    }

    fn stop(&mut self, identity: &SupervisorIdentity) -> Result<()> {
        self.validate_identity(identity)?;
        let store = super::manifest_store::ManifestStore::open(self.runtime.clone())?;
        if let Some(snapshot) = store.load()? {
            ensure!(
                snapshot.manifest.activation_id == identity.activation_id
                    && snapshot.generation == identity.generation
                    && snapshot.phase == super::recovery::SupervisorPhase::Cleaned,
                "refusing to stop the recovery supervisor while its activation is not durably cleaned"
            );
        }
        if self.active_state(identity)?.is_none() { return Ok(()); }
        let output = Command::new(&self.systemctl)
            .args(["--user", "stop", "--no-block"])
            .arg(Self::unit(identity))
            .output()
            .context("could not request stop of the TUN recovery supervisor user service")?;
        ensure!(output.status.success(), "systemctl could not stop the TUN recovery service: {}",
            String::from_utf8_lossy(&output.stderr).trim());

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if self.active_state(identity)?.is_none() {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "TUN recovery supervisor did not stop before the bounded shutdown deadline"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_name_contains_the_complete_activation_uuid() {
        let identity = SupervisorIdentity::for_activation(
            "12345678-1234-4234-8234-123456789abc",
            "/run/user/1000/proxyctl/tun-manifest.json",
            4,
        ).unwrap();
        assert_eq!(
            SystemdRecoverySupervisor::unit(&identity),
            "proxyctl-tun-12345678-1234-4234-8234-123456789abc.service"
        );
    }
}
