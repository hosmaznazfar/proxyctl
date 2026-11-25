//! Direct, single-executable launch support for privileged TUN core processes.
//!
//! This path deliberately does not use systemd, a helper executable, a shell, or arbitrary
//! caller-supplied arguments. The privileged Proxyctl supervisor owns the child process and
//! records its exact PID/start-time/executable identity for recovery.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    os::fd::BorrowedFd,
    path::Path,
    process::{Child, Command, Stdio},
};

use crate::{
    cores::{CoreId, adapters::xray_tun_fd::XrayTunDescriptor},
    tun::{
        launch_spec::CoreKind,
        process::{ProcessHandle, ProcessIdentity, read_process_owner_uid},
    },
};

/// A live child owned by the privileged Proxyctl supervisor.
pub struct SupervisedCore {
    pub child: Child,
    pub identity: ProcessIdentity,
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
/// Xray must receive the broker-created descriptor through its documented
/// XRAY_TUN_FD contract. Sing-box and Mihomo use their persistent named TUN device and
/// must not receive an inherited descriptor.
pub fn spawn_core(
    core: CoreKind,
    managed_core_root: &Path,
    config: &Path,
    invoking_uid: u32,
    xray_descriptor: Option<BorrowedFd<'_>>,
) -> Result<SupervisedCore> {
    ensure!(
        unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0,
        "managed TUN cores may only be spawned by the real/effective-root supervisor"
    );
    ensure!(invoking_uid != 0, "invoking user UID must be non-zero");

    let executable = super::core_paths::resolve_managed_core(
        managed_core_root,
        invoking_uid,
        domain_core(core),
    )
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
    let config = fs::canonicalize(config)
        .context("cannot canonicalize staged TUN configuration")?;
    let arguments = core_arguments(core, &config)?;

    match (core, xray_descriptor) {
        (CoreKind::Xray, Some(_)) | (CoreKind::SingBox | CoreKind::Mihomo, None) => {}
        (CoreKind::Xray, None) => {
            anyhow::bail!("Xray TUN launch requires its generation-bound broker descriptor")
        }
        (CoreKind::SingBox | CoreKind::Mihomo, Some(_)) => {
            anyhow::bail!("native-device TUN cores must not inherit an external descriptor")
        }
    }

    let mut command = Command::new(&executable);
    command
        .args(&arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/root")
        .env("LANG", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Keep the duplicated descriptor alive until spawn has completed. The parent copy stays
    // CLOEXEC; only the forked child clears CLOEXEC in its pre-exec hook.
    let descriptor_guard = xray_descriptor
        .map(XrayTunDescriptor::duplicate)
        .transpose()
        .context("cannot duplicate the generation-bound Xray TUN descriptor")?;
    if let Some(descriptor) = &descriptor_guard {
        descriptor.configure_command(&mut command)?;
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("cannot spawn managed {} TUN core", core.as_str()))?;
    drop(descriptor_guard);

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

    Ok(SupervisedCore { child, identity })
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
