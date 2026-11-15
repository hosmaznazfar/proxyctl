//! Platform-specific private filesystem primitives for TUN recovery records.
use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

use anyhow::{Result, ensure};

#[cfg(unix)]
pub(super) fn verify_owner(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "TUN runtime file has a foreign owner"
    );
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn verify_owner(_metadata: &fs::Metadata) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage requires Unix file ownership support")
}

#[cfg(unix)]
pub(super) fn set_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn set_private_directory(_path: &Path) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage is supported only on Unix")
}

#[cfg(unix)]
pub(super) fn verify_private_directory(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "TUN runtime directory permissions are not private"
    );
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn verify_private_directory(_metadata: &fs::Metadata) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage is supported only on Unix")
}

#[cfg(unix)]
pub(super) fn set_private_file(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn set_private_file(_file: &File) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage is supported only on Unix")
}

#[cfg(unix)]
pub(super) fn verify_private_file(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "TUN manifest permissions are not private"
    );
    ensure!(
        metadata.nlink() == 1,
        "TUN manifest must not have external hard links"
    );
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn verify_private_file(_metadata: &fs::Metadata) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage is supported only on Unix")
}

#[cfg(unix)]
pub(super) fn open_private_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
pub(super) fn open_private_file(_path: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure TUN manifest storage is supported only on Unix",
    ))
}

pub(super) fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

