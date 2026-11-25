//! Root-owned runtime layout and invoking-user provenance for the Linux TUN supervisor.
//!
//! This module creates only the supervisor's private runtime directories. It does not
//! stage configuration, launch a core, or mutate host networking.
use anyhow::{Context, ensure};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::PathBuf,
};

const RUNTIME_ROOT: &str = "/run/proxyctl";
const RUNTIME_ROOT_MODE: u32 = 0o755;
const USER_RUNTIME_MODE: u32 = 0o700;

/// Identify the unprivileged caller from sudo and cross-check Linux's audit login UID.
///
/// The JSON launch request deliberately contains no UID. A mismatch or unset audit UID
/// fails closed rather than guessing which user's managed core directory to trust.
pub fn invoking_uid() -> anyhow::Result<u32> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getuid() } == 0,
        "TUN supervisor must execute with real and effective root credentials"
    );

    let sudo_uid = std::env::var("SUDO_UID")
        .context("SUDO_UID is missing; invoke the TUN supervisor through sudo")?
        .parse::<u32>()
        .context("SUDO_UID is not a valid numeric user ID")?;
    ensure!(sudo_uid != 0, "root cannot be the invoking TUN session owner");

    let login_uid = fs::read_to_string("/proc/self/loginuid")
        .context("cannot read Linux audit login UID")?
        .trim()
        .parse::<u32>()
        .context("Linux audit login UID is unset or invalid")?;
    ensure!(
        login_uid == sudo_uid,
        "sudo invoking UID does not match the Linux audit login UID"
    );

    Ok(sudo_uid)
}

/// Create and verify /run/proxyctl/<uid> as a root-owned, private runtime directory.
pub fn prepare_user_runtime(uid: u32) -> anyhow::Result<PathBuf> {
    ensure!(uid != 0, "runtime owner UID must be non-zero");

    verify_directory("/run", 0, 0o755, false)?;
    create_directory(RUNTIME_ROOT, RUNTIME_ROOT_MODE)?;
    verify_directory(RUNTIME_ROOT, 0, RUNTIME_ROOT_MODE, false)?;

    let user_path = PathBuf::from(RUNTIME_ROOT).join(uid.to_string());
    create_directory(&user_path, USER_RUNTIME_MODE)?;
    verify_directory(&user_path, 0, USER_RUNTIME_MODE, false)?;

    Ok(user_path)
}

fn create_directory(path: impl AsRef<std::path::Path>, mode: u32) -> anyhow::Result<()> {
    let path = path.as_ref();
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(false).mode(mode);
            builder
                .create(path)
                .with_context(|| format!("cannot create runtime directory {}", path.display()))
        }
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn verify_directory(
    path: impl AsRef<std::path::Path>,
    expected_uid: u32,
    expected_mode: u32,
    allow_group_write: bool,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect runtime directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "runtime path {} is not a real directory",
        path.display()
    );
    ensure!(
        metadata.uid() == expected_uid,
        "runtime directory {} has an unexpected owner",
        path.display()
    );
    let mode = metadata.permissions().mode() & 0o7777;
    ensure!(
        mode == expected_mode,
        "runtime directory {} has unsafe permissions {mode:o}",
        path.display()
    );
    if !allow_group_write {
        ensure!(
            mode & 0o022 == 0,
            "runtime directory {} is writable by group or other users",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_root_as_runtime_owner() {
        assert!(prepare_user_runtime(0).is_err());
    }

    #[test]
    fn runtime_path_uses_decimal_uid_component() {
        let expected = PathBuf::from("/run/proxyctl/1000");
        let actual = PathBuf::from(RUNTIME_ROOT).join(1000_u32.to_string());
        assert_eq!(actual, expected);
    }
}
