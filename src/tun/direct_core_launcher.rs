//! Direct, single-executable launch support for privileged TUN core processes.
//!
//! This path deliberately does not use systemd, a helper executable, a shell, or arbitrary
//! caller-supplied arguments. The privileged Proxyctl supervisor owns the child process and
//! records its exact PID/start-time/executable identity for recovery.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::fd::{FromRawFd, OwnedFd},
    os::unix::fs::{MetadataExt, PermissionsExt},
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
};

use crate::{
    cores::CoreId,
    tun::{
        launch_spec::CoreKind,
        process::{ProcessHandle, ProcessIdentity, read_process_owner_uid},
    },
};

/// A live child owned by the privileged Proxyctl supervisor.
pub struct SupervisedCore {
    pub child: Child,
    pub identity: ProcessIdentity,
    /// Installed immediately after the exact child identity is captured, before attachment
    /// polling or end-to-end readiness can block for several seconds.
    _signal_guard: super::native_supervisor::SignalForwardingGuard,
}

/// Construct the fixed native argument vector for a core and staged config.
///
/// No node data, user arguments, shell fragments, or environment values are accepted here.
pub fn core_arguments(core: CoreKind, config: &Path) -> Result<Vec<String>> {
    ensure!(
        config.is_absolute(),
        "staged core configuration path must be absolute"
    );
    let path = config
        .to_str()
        .context("staged core configuration path is not valid UTF-8")?;
    Ok(match core {
        CoreKind::SingBox | CoreKind::Xray => vec!["run".into(), "-c".into(), path.into()],
        CoreKind::Mihomo => vec!["-f".into(), path.into()],
    })
}

/// Spawn one selected core directly as root, retaining only its exact process identity.
///
/// All supported cores open the generation-owned persistent named TUN device from their
/// native configuration. No core receives an inherited descriptor or special environment key.
pub fn spawn_core(
    core: CoreKind,
    managed_core_root: &Path,
    config: &Path,
    invoking_uid: u32,
    foreground: bool,
) -> Result<SupervisedCore> {
    ensure!(
        unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0,
        "managed TUN cores may only be spawned by the real/effective-root supervisor"
    );
    ensure!(invoking_uid != 0, "invoking user UID must be non-zero");

    let executable = super::core_paths::resolve_managed_core(managed_core_root, invoking_uid, core)
        .context("cannot revalidate the selected managed core immediately before launch")?;
    let executable_metadata = fs::symlink_metadata(&executable)
        .context("cannot inspect selected managed core executable before launch")?;
    ensure!(
        executable_metadata.file_type().is_file()
            && executable_metadata.uid() == invoking_uid
            && executable_metadata.permissions().mode() & 0o111 != 0
            && executable_metadata.permissions().mode() & 0o022 == 0
            && executable_metadata.nlink() == 1,
        "selected managed core must remain an invoking-user-owned, non-writable executable regular file"
    );

    let config_metadata = fs::symlink_metadata(config)
        .context("cannot inspect staged TUN configuration before launch")?;
    ensure!(
        config_metadata.file_type().is_file()
            && config_metadata.uid() == 0
            && config_metadata.permissions().mode() & 0o7777 == 0o600
            && config_metadata.nlink() == 1,
        "core configuration must be a root-owned, single-link 0600 regular file"
    );

    let executable = fs::canonicalize(&executable)
        .context("cannot canonicalize selected managed core executable")?;
    let config =
        fs::canonicalize(config).context("cannot canonicalize staged TUN configuration")?;
    let arguments = core_arguments(core, &config)?;

    let mut command = Command::new(&executable);
    command
        .args(&arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(if foreground {
            // The supervisor reserves its stdout for the one-shot JSON acknowledgement.
            // Duplicate stderr so foreground core logs remain visible without corrupting it.
            // SAFETY: dup returns a new descriptor owned by the resulting OwnedFd.
            let duplicated = unsafe { libc::dup(libc::STDERR_FILENO) };
            ensure!(
                duplicated >= 0,
                "cannot duplicate supervisor stderr for foreground core output"
            );
            Stdio::from(unsafe { OwnedFd::from_raw_fd(duplicated) })
        } else {
            Stdio::null()
        })
        .stderr(if foreground {
            Stdio::inherit()
        } else {
            Stdio::null()
        });

    // The supervisor is the core's direct parent. If it is killed or crashes, the kernel
    // terminates this child so an unmonitored root core cannot outlive its session owner.
    let supervisor_pid = unsafe { libc::getpid() };
    // SAFETY: the pre-exec hook uses only async-signal-safe syscalls and does not access
    // parent-owned Rust state beyond the copied PID.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGTERM as libc::c_ulong,
                0,
                0,
                0,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != supervisor_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("cannot spawn managed {} TUN core", core.as_str()))?;

    let identity_result = (|| -> Result<ProcessIdentity> {
        let identity = ProcessIdentity::capture(child.id())
            .context("cannot capture exact managed core process identity")?;
        ensure!(
            identity.executable == executable && identity.verify()?,
            "spawned core executable identity does not match the selected managed binary"
        );
        Ok(identity)
    })();
    let identity = match identity_result {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("spawned core failed executable identity verification");
        }
    };

    // Install signal ownership as soon as the exact child identity is available. In
    // particular, do not wait for TUN attachment/readiness: those checks can block while
    // the supervisor already owns journaled kernel state.
    let signal_guard = match super::native_supervisor::SignalForwardingGuard::install(
        identity.clone(),
        foreground,
    ) {
        Ok(guard) => guard,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("cannot install TUN core signal forwarding immediately after spawn");
        }
    };

    let verification = (|| -> Result<()> {
        let process = ProcessHandle::open(identity.clone())
            .context("cannot pin spawned core process identity with pidfd")?;
        ensure!(
            read_process_owner_uid(&process)? == 0,
            "managed TUN core did not retain root credentials"
        );
        ensure!(
            !process.is_exited()?,
            "managed TUN core exited immediately after launch"
        );
        Ok(())
    })();
    if let Err(error) = verification {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error).context("spawned core failed privileged process verification");
    }

    Ok(SupervisedCore { child, identity, _signal_guard: signal_guard })
}

/// Convert the closed launch-protocol enum to the domain core enum.
pub fn domain_core(core: CoreKind) -> CoreId {
    match core {
        CoreKind::SingBox => CoreId::SingBox,
        CoreKind::Xray => CoreId::Xray,
        CoreKind::Mihomo => CoreId::Mihomo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_arguments_are_closed_and_use_only_the_staged_config() {
        let config = Path::new("/run/proxyctl/1000/config-test.json");
        assert_eq!(
            core_arguments(CoreKind::SingBox, config).unwrap(),
            ["run", "-c", "/run/proxyctl/1000/config-test.json"]
        );
        assert_eq!(
            core_arguments(CoreKind::Xray, config).unwrap(),
            ["run", "-c", "/run/proxyctl/1000/config-test.json"]
        );
        assert_eq!(
            core_arguments(CoreKind::Mihomo, config).unwrap(),
            ["-f", "/run/proxyctl/1000/config-test.json"]
        );
        assert!(core_arguments(CoreKind::Xray, Path::new("relative.json")).is_err());
    }

    #[test]
    fn protocol_core_mapping_is_exhaustive() {
        assert_eq!(domain_core(CoreKind::SingBox), CoreId::SingBox);
        assert_eq!(domain_core(CoreKind::Xray), CoreId::Xray);
        assert_eq!(domain_core(CoreKind::Mihomo), CoreId::Mihomo);
    }
}
