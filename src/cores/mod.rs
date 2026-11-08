//! Managed proxy-core catalog and private installation paths.
//!
//! This module describes external executables; it never searches PATH or modifies system
//! installations. Release acquisition and core-specific extraction live in adapter modules.

use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Context;

use crate::database::default_database_path;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoreId {
    SingBox,
    Xray,
    Mihomo,
}

impl CoreId {
    pub const ALL: [Self; 3] = [Self::SingBox, Self::Xray, Self::Mihomo];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingBox => "sing-box",
            Self::Xray => "xray",
            Self::Mihomo => "mihomo",
        }
    }

    pub const fn executable_name(self) -> &'static str {
        match self {
            Self::SingBox => "sing-box",
            Self::Xray => "xray",
            Self::Mihomo => "mihomo",
        }
    }

    pub const fn release_api(self) -> &'static str {
        match self {
            Self::SingBox => "https://api.github.com/repos/SagerNet/sing-box/releases/latest",
            Self::Xray => "https://api.github.com/repos/XTLS/Xray-core/releases/latest",
            Self::Mihomo => "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
        }
    }

    pub fn binary_path(self) -> anyhow::Result<PathBuf> {
        Ok(managed_cores_directory()?.join(self.as_str()).join(self.executable_name()))
    }

    pub fn is_installed(self) -> anyhow::Result<bool> {
        let path = self.binary_path()?;
        Ok(path.is_file())
    }
}

impl fmt::Display for CoreId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CoreId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|core| core.as_str() == normalized)
            .with_context(|| format!("unknown core '{value}'; expected sing-box, xray, or mihomo"))
    }
}

/// Resolve the private directory used only for proxyctl-managed core binaries.
pub fn managed_cores_directory() -> anyhow::Result<PathBuf> {
    let database_path = default_database_path()?;
    let data_directory = database_path
        .parent()
        .context("proxyctl database path has no parent directory")?;
    let directory = data_directory.join("cores");
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("could not create managed core directory {}", directory.display()))?;
    set_private_directory_permissions(&directory)?;
    Ok(directory)
}

/// Create a core-specific install directory without touching any system path.
pub fn core_install_directory(core: CoreId) -> anyhow::Result<PathBuf> {
    let directory = managed_cores_directory()?.join(core.as_str());
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("could not create managed directory for {core}"))?;
    set_private_directory_permissions(&directory)?;
    Ok(directory)
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("could not secure managed core directory {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_names_without_case_sensitivity() {
        assert_eq!("sing-box".parse::<CoreId>().unwrap(), CoreId::SingBox);
        assert_eq!("XRAY".parse::<CoreId>().unwrap(), CoreId::Xray);
        assert_eq!("Mihomo".parse::<CoreId>().unwrap(), CoreId::Mihomo);
        assert!("unknown".parse::<CoreId>().is_err());
    }

    #[test]
    fn core_descriptors_use_official_release_sources() {
        for core in CoreId::ALL {
            assert!(core.release_api().starts_with("https://api.github.com/repos/"));
            assert!(!core.executable_name().is_empty());
        }
    }
}
