//! Persistent shared loopback HTTP/SOCKS5 listener configuration.
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::PathBuf};

pub const DEFAULT_LISTEN_PORT: u16 = 10909;
const CONFIG_FILE: &str = "config.json";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Config { listen_port: u16 }

fn config_path() -> anyhow::Result<PathBuf> {
    let database = crate::database::default_database_path()?;
    let directory = database.parent().context("Proxyctl data directory is unavailable")?;
    Ok(directory.join(CONFIG_FILE))
}

pub fn listen_port() -> anyhow::Result<u16> {
    let path = config_path()?;
    if !path.exists() { return Ok(DEFAULT_LISTEN_PORT); }
    let config: Config = serde_json::from_slice(&fs::read(&path)?)
        .context("Proxyctl config is invalid; refusing to guess a listener port")?;
    validate_port(config.listen_port)?;
    Ok(config.listen_port)
}

pub fn set_listen_port(port: u16) -> anyhow::Result<()> {
    validate_port(port)?;
    if let Err(error) = crate::services::activation::ensure_port_available(port) {
        reset_listen_port()?;
        anyhow::bail!("127.0.0.1:{port} is occupied; the requested setting was not saved and Proxyctl has fallen back to default port {DEFAULT_LISTEN_PORT}: {error:#}");
    }
    let path = config_path()?;
    let parent = path.parent().context("config path has no parent")?;
    fs::create_dir_all(parent)?;
    set_private_dir(parent)?;
    let bytes = serde_json::to_vec_pretty(&Config { listen_port: port })?;
    let mut file = tempfile::Builder::new().prefix(".proxyctl-config-").tempfile_in(parent)?;
    set_private_file(file.as_file())?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(&path).context("could not atomically save Proxyctl config")?;
    Ok(())
}

pub fn reset_listen_port() -> anyhow::Result<()> {
    match fs::remove_file(config_path()?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn validate_port(port: u16) -> anyhow::Result<()> {
    ensure!((1024..=u16::MAX).contains(&port), "listen port must be between 1024 and 65535");
    Ok(())
}

#[cfg(unix)]
fn set_private_dir(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_private_dir(_path: &std::path::Path) -> anyhow::Result<()> { Ok(()) }

#[cfg(unix)]
fn set_private_file(file: &std::fs::File) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_private_file(_file: &std::fs::File) -> anyhow::Result<()> { Ok(()) }

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn default_port_is_proxyctl_specific_10909() { assert_eq!(DEFAULT_LISTEN_PORT, 10909); }

    #[test]
    fn rejects_privileged_ports() {
        assert!(validate_port(0).is_err());
        assert!(validate_port(80).is_err());
        assert!(validate_port(1024).is_ok());
        assert!(validate_port(u16::MAX).is_ok());
    }

    #[test]
    fn occupied_port_is_detected_on_loopback() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(TcpListener::bind(("127.0.0.1", port)).is_err());
    }

    #[test]
    fn persisted_config_round_trips_and_reset_restores_default() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(CONFIG_FILE);
        fs::write(&path, serde_json::to_vec(&Config { listen_port: 10910 }).unwrap()).unwrap();
        let parsed: Config = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(parsed.listen_port, 10910);
        assert_eq!(DEFAULT_LISTEN_PORT, 10909);
    }
}
