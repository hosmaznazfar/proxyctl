//! Private filesystem layout for proxyctl-managed core binaries.
use std::path::{Path, PathBuf};
use anyhow::Context;
use super::CoreId;
use crate::database::default_database_path;

pub fn managed_cores_directory() -> anyhow::Result<PathBuf> {
    let db = default_database_path()?;
    let data = db.parent().context("proxyctl database path has no parent directory")?;
    std::fs::create_dir_all(data).context("could not create proxyctl data directory")?;
    set_private_permissions(data)?;
    let directory = data.join("cores");
    std::fs::create_dir_all(&directory).context("could not create managed core directory")?;
    set_private_permissions(&directory)?;
    Ok(directory)
}
pub fn core_install_directory(core: CoreId) -> anyhow::Result<PathBuf> {
    let directory = managed_cores_directory()?.join(core.as_str());
    std::fs::create_dir_all(&directory).context("could not create managed core directory")?;
    set_private_permissions(&directory)?;
    Ok(directory)
}
pub fn core_binary_path(core: CoreId) -> anyhow::Result<PathBuf> {
    Ok(core_install_directory(core)?.join(core.executable_name()))
}
#[cfg(unix)]
fn set_private_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("could not secure private directory {}", path.display()))
}
#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> anyhow::Result<()> { Ok(()) }
