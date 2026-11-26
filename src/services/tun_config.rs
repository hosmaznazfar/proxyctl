//! Persistent TUN address-family preference.
//!
//! This is separate from the shared listener configuration so TUN policy can evolve
//! without changing unrelated settings. The preference is resolved per activation and
//! the resolved family is carried in that activation's launch specification.

use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::PathBuf};

use crate::tun::address_family::TunAddressFamily;

const FILE_NAME: &str = "tun.json";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Config {
    address_family: TunAddressFamily,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            address_family: TunAddressFamily::Auto,
        }
    }
}

fn config_path() -> anyhow::Result<PathBuf> {
    let database = crate::database::default_database_path()?;
    let directory = database
        .parent()
        .context("Proxyctl data directory is unavailable")?;
    Ok(directory.join(FILE_NAME))
}

/// Load the saved preference. A missing file means the built-in auto default.
pub fn address_family() -> anyhow::Result<TunAddressFamily> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(TunAddressFamily::default());
    }
    let config: Config = serde_json::from_slice(&fs::read(&path)?)
        .context("Proxyctl TUN settings are invalid; refusing to guess an address family")?;
    Ok(config.address_family)
}

/// Persist a preference atomically with private directory/file permissions.
pub fn set_address_family(family: TunAddressFamily) -> anyhow::Result<()> {
    ensure!(
        matches!(
            family,
            TunAddressFamily::Auto
                | TunAddressFamily::Ipv4
                | TunAddressFamily::Ipv6
                | TunAddressFamily::DualStack
        ),
        "unsupported TUN address-family preference"
    );
    let path = config_path()?;
    let parent = path.parent().context("TUN config path has no parent")?;
    fs::create_dir_all(parent)?;
    set_private_dir(parent)?;
    let bytes = serde_json::to_vec_pretty(&Config {
        address_family: family,
    })?;
    let mut file = tempfile::Builder::new()
        .prefix(".proxyctl-tun-config-")
        .tempfile_in(parent)?;
    set_private_file(file.as_file())?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(&path)
        .context("could not atomically save Proxyctl TUN settings")?;
    Ok(())
}

/// Remove the TUN-specific settings file; the next read returns auto.
pub fn reset() -> anyhow::Result<()> {
    match fs::remove_file(config_path()?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn set_private_dir(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_private_dir(_path: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(file: &std::fs::File) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_private_file(_file: &std::fs::File) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_settings_default_to_auto() {
        assert_eq!(Config::default().address_family, TunAddressFamily::Auto);
    }

    #[test]
    fn preference_round_trips_through_json() {
        for family in [
            TunAddressFamily::Auto,
            TunAddressFamily::Ipv4,
            TunAddressFamily::Ipv6,
            TunAddressFamily::DualStack,
        ] {
            let bytes = serde_json::to_vec(&Config {
                address_family: family,
            })
            .unwrap();
            let decoded: Config = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded.address_family, family);
        }
    }

    #[test]
    fn malformed_or_unknown_settings_are_not_silently_accepted() {
        assert!(serde_json::from_str::<Config>(r#"{"address_family":"unknown"}"#).is_err());
        assert!(
            serde_json::from_str::<Config>(r#"{"address_family":"ipv4","extra":true}"#).is_err()
        );
    }
}
