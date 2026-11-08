//! Private filesystem layout for proxyctl-managed core binaries.
use super::CoreId;
use crate::database::default_database_path;
use anyhow::Context;
use std::path::{Path, PathBuf};

/// Resolve the managed directory without creating or changing anything.
pub fn managed_cores_path() -> anyhow::Result<PathBuf> {
    let db = default_database_path()?;
    let data = db
        .parent()
        .context("proxyctl database path has no parent directory")?;
    Ok(data.join("cores"))
}
/// Create and secure the managed root directory.
pub fn managed_cores_directory() -> anyhow::Result<PathBuf> {
    let directory = managed_cores_path()?;
    let data = directory
        .parent()
        .context("managed core directory has no parent")?;
    std::fs::create_dir_all(data).context("could not create proxyctl data directory")?;
    set_private_permissions(data)?;
    std::fs::create_dir_all(&directory).context("could not create managed core directory")?;
    set_private_permissions(&directory)?;
    Ok(directory)
}
/// Create and secure a core-specific installation directory.
pub fn core_install_directory(core: CoreId) -> anyhow::Result<PathBuf> {
    let directory = managed_cores_directory()?.join(core.as_str());
    std::fs::create_dir_all(&directory).context("could not create managed core directory")?;
    set_private_permissions(&directory)?;
    Ok(directory)
}
/// Resolve an installed binary path without creating directories (safe for check-only commands).
pub fn core_binary_path(core: CoreId) -> anyhow::Result<PathBuf> {
    Ok(managed_cores_path()?
        .join(core.as_str())
        .join(core.executable_name()))
}
#[cfg(unix)]
fn set_private_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("could not secure private directory {}", path.display()))
}
#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}
