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


/// Execute a systemd control command with a strict wall-clock deadline. Output is captured
/// only after the child exits; on timeout the child is killed and reaped.
fn run_bounded(mut command: Command, timeout: Duration, context: &'static str) -> Result<std::process::Output> {
    command.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().context(context)?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("{context}: command exceeded its bounded deadline");
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context(context);
            }
        }
    }
    child.wait_with_output().context(context)
}

/// The recovery supervisor runs in the per-user systemd manager. Without lingering,
/// that manager may be stopped at logout while the system-level core service and TUN
/// routes remain active. Refuse activation unless systemd is configured to keep the
/// user's manager alive independently of login sessions.
fn ensure_user_manager_lingering() -> Result<()> {
    const LOGINCTL: &str = "/usr/bin/loginctl";
    let uid = unsafe { libc::geteuid() }.to_string();
    let mut child = Command::new(LOGINCTL)
        .args(["show-user", &uid, "--property=Linger", "--value"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("cannot query systemd user lingering state with loginctl")?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("loginctl linger-state query exceeded its two-second deadline");
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("cannot inspect loginctl linger-state query");
            }
        }
    }
    let output = child
        .wait_with_output()
        .context("cannot collect loginctl linger-state response")?;
    ensure!(
        output.status.success(),
        "loginctl could not determine whether the current user's systemd manager lingers"
    );
    let value = String::from_utf8(output.stdout)
        .context("loginctl returned a non-UTF-8 linger-state value")?;
    validate_linger_value(&value)
}

fn validate_linger_value(value: &str) -> Result<()> {
    ensure!(
        value.trim() == "yes",
        "TUN recovery requires a persistent systemd user manager; enable it with sudo loginctl enable-linger $(id -un) before activation"
    );
    Ok(())
}

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
        ensure_user_manager_lingering()?;
        Ok(Self::new(
            "/usr/bin/systemd-run",
            "/usr/bin/systemctl",
            executable,
            runtime,
        ))
    }

    pub fn new(
        systemd_run: impl Into<PathBuf>,
        systemctl: impl Into<PathBuf>,
        executable: impl Into<PathBuf>,
        runtime: impl Into<PathBuf>,
    ) -> Self {
        Self {
            systemd_run: systemd_run.into(),
            systemctl: systemctl.into(),
            executable: executable.into(),
            runtime: runtime.into(),
        }
    }

    fn validate_identity(&self, identity: &SupervisorIdentity) -> Result<()> {
        identity.validate()?;
        ensure!(
            identity.manifest_path
                == self
                    .runtime
                    .join("tun-manifest.json")
                    .to_string_lossy()
                    .as_ref(),
            "supervisor identity points outside the configured runtime directory"
        );
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
        let runtime = fs::symlink_metadata(&self.runtime)
            .context("cannot inspect supervisor runtime directory")?;
        ensure!(
            runtime.is_dir() && !runtime.file_type().is_symlink(),
            "supervisor runtime must be a real directory"
        );
        ensure!(
            fs::canonicalize(&self.runtime)? == self.runtime,
            "supervisor runtime path must not contain symlinked or non-canonical components"
        );
        // SAFETY: geteuid is a read-only query of the current effective user.
        ensure!(
            runtime.uid() == unsafe { libc::geteuid() },
            "supervisor runtime directory has a foreign owner"
        );
        ensure!(
            runtime.permissions().mode() & 0o077 == 0,
            "supervisor runtime directory must be private"
        );
        ensure!(
            runtime.permissions().mode() & 0o7000 == 0,
            "supervisor runtime directory must not have special permission bits"
        );
        ensure!(
            runtime.permissions().mode() & 0o700 == 0o700,
            "supervisor runtime directory must be owner-readable, writable, and searchable"
        );

        let executable = fs::symlink_metadata(&self.executable)
            .context("cannot inspect recovery supervisor executable")?;
        ensure!(
            executable.is_file() && !executable.file_type().is_symlink(),
            "recovery supervisor executable must be a regular non-symlink file"
        );
        // SAFETY: geteuid is a read-only query of the current effective user.
        ensure!(
            executable.uid() == 0 || executable.uid() == unsafe { libc::geteuid() },
            "recovery supervisor executable must be owned by root or the activation user"
        );
        ensure!(
            executable.permissions().mode() & 0o111 != 0,
            "recovery supervisor executable is not executable"
        );
        ensure!(
            executable.permissions().mode() & 0o022 == 0,
            "recovery supervisor executable must not be group- or world-writable"
        );
        ensure!(
            executable.permissions().mode() & 0o7000 == 0,
            "recovery supervisor executable must not have special permission bits"
        );
        ensure!(
            executable.nlink() == 1,
            "recovery supervisor executable must not have external hard links"
        );
        for tool in [&self.systemd_run, &self.systemctl] {
            let metadata = fs::symlink_metadata(tool)
                .with_context(|| format!("cannot inspect {}", tool.display()))?;
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == 0
                    && metadata.permissions().mode() & 0o111 != 0
                    && metadata.permissions().mode() & 0o022 == 0
                    && metadata.permissions().mode() & 0o7000 == 0
                    && metadata.nlink() == 1,
                "systemd command must be a root-owned, non-writable executable regular file"
            );
        }
        Ok(())
    }

    fn unit(identity: &SupervisorIdentity) -> String {
        format!("{}.service", identity.service_name)
    }

    fn validate_startable_manifest(&self, identity: &SupervisorIdentity) -> Result<()> {
        let store = super::manifest_store::ManifestStore::open(self.runtime.clone())?;
        let snapshot = store
            .load()?
            .context("cannot start recovery service without a durable activation manifest")?;
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
            phase => {
                anyhow::bail!("cannot start a recovery service for activation phase {phase:?}")
            }
        }
        Ok(())
    }

    fn generation_is_cleaned(&self, identity: &SupervisorIdentity) -> Result<bool> {
        let store = super::manifest_store::ManifestStore::open(self.runtime.clone())?;
        let Some(snapshot) = store.load()? else {
            return Ok(true);
        };
        ensure!(
            snapshot.manifest.activation_id == identity.activation_id
                && snapshot.generation == identity.generation,
            "a different activation replaced the recovery service generation"
        );
        Ok(snapshot.phase == super::recovery::SupervisorPhase::Cleaned)
    }

    fn active_state(&self, identity: &SupervisorIdentity) -> Result<Option<String>> {
        self.validate_identity(identity)?;
        let mut command = Command::new(&self.systemctl);
        command.args(["--user", "is-active"]).arg(Self::unit(identity));
        let output = run_bounded(command, Duration::from_secs(2), "could not query the TUN recovery service state")?;
        let state = String::from_utf8(output.stdout)
            .context("systemd returned a non-UTF-8 service state")?
            .trim()
            .to_owned();
        if output.status.success() {
            return match state.as_str() {
                "active" | "activating" | "reloading" | "deactivating" => Ok(Some(state)),
                _ => anyhow::bail!(
                    "systemd returned an unrecognized active service state: {state:?}"
                ),
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
        if self.active_state(identity)?.is_some() {
            return Ok(());
        }
        let unit_arg = format!("--unit={}", Self::unit(identity));
        let mut command = Command::new(&self.systemd_run);
        command.arg("--user")
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
            .arg(format!(
                "--property=ReadWritePaths={}",
                self.runtime.display()
            ))
            .arg("--property=ProtectKernelTunables=yes")
            .arg("--property=ProtectKernelModules=yes")
            .arg("--property=ProtectControlGroups=yes")
            .arg("--property=LockPersonality=yes")
            .arg("--property=MemoryDenyWriteExecute=yes")
            .arg("--property=RestrictRealtime=yes")
            // The user supervisor only coordinates process identity, durable state, and
            // Unix-socket broker requests; it must never acquire ambient kernel authority.
            .arg("--property=NoNewPrivileges=yes")
            .arg("--property=CapabilityBoundingSet=")
            .arg("--property=AmbientCapabilities=")
            .arg("--property=RestrictSUIDSGID=yes")
            .arg("--property=RestrictNamespaces=yes")
            .arg("--property=RestrictAddressFamilies=AF_UNIX")
            .arg("--")
            .arg(&self.executable)
            .arg(&self.runtime)
            .arg(&identity.activation_id)
            .arg(identity.generation.to_string());
        let output = run_bounded(command, Duration::from_secs(3), "could not start the TUN recovery supervisor user service")?;
        if !output.status.success() {
            // A concurrent start may have won after the initial state query. Accept only
            // when systemd now reports this exact generation's unit as active/activating.
            if self.active_state(identity)?.is_none() {
                anyhow::bail!(
                    "systemd-run rejected the TUN recovery service: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
        }

        // --no-block confirms only that the manager accepted the request. Wait briefly
        // until the exact transient unit is visible as active/activating before returning.
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if self.active_state(identity)?.is_some() || self.generation_is_cleaned(identity)? {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "systemd accepted the recovery service but it did not become active before the startup deadline"
            );
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
        if self.active_state(identity)?.is_none() {
            return Ok(());
        }
        let mut command = Command::new(&self.systemctl);
        command.args(["--user", "stop", "--no-block"]).arg(Self::unit(identity));
        let output = run_bounded(command, Duration::from_secs(2), "could not request stop of the TUN recovery supervisor user service")?;
        ensure!(
            output.status.success(),
            "systemctl could not stop the TUN recovery service: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );

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
    fn linger_gate_accepts_only_explicit_yes() {
        assert!(validate_linger_value("yes\n").is_ok());
        assert!(validate_linger_value("no\n").is_err());
        assert!(validate_linger_value("").is_err());
        assert!(validate_linger_value("unknown\n").is_err());
        assert!(validate_linger_value("yes extra\n").is_err());
    }

    #[test]
    fn unit_name_contains_the_complete_activation_uuid_and_generation() {
        let identity = SupervisorIdentity::for_activation(
            "12345678-1234-4234-8234-123456789abc",
            "/run/user/1000/proxyctl/tun-manifest.json",
            4,
        )
        .unwrap();
        assert_eq!(
            SystemdRecoverySupervisor::unit(&identity),
            "proxyctl-tun-12345678-1234-4234-8234-123456789abc-g4.service"
        );
    }
}
