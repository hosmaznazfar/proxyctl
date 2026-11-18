//! Controller-side launch and collection of outbound socket-mark evidence.
//!
//! The helper executable is pinned to the root-owned installation path, invoked with a
//! minimal environment and one socket path, and must authenticate the current UID over
//! SO_PEERCRED. This module never changes kernel networking; it only obtains diagnostics.

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
#[cfg(target_os = "linux")]
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use super::{
    broker_transport::request_socket_mark_diagnostics,
    privilege_broker::{
        BROKER_REQUEST_VERSION, BrokerSocketTransport, SocketMarkBrokerRequest,
        SocketMarkBrokerResponse,
    },
    process::ProcessIdentity,
};

#[cfg(target_os = "linux")]
pub const INSTALLED_HELPER_PATH: &str = "/usr/libexec/proxyctl-tun-helper";
#[cfg(target_os = "linux")]
const HELPER_START_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const HELPER_EXIT_TIMEOUT: Duration = Duration::from_secs(2);

/// Launch the fixed installed helper and collect one exact-peer socket-mark observation.
#[cfg(target_os = "linux")]
pub fn observe_proxy_outbound_mark(
    runtime_directory: &Path,
    activation_id: &str,
    process: ProcessIdentity,
    expected_peer: std::net::SocketAddr,
    transport: BrokerSocketTransport,
    expected_mark: u32,
    mark_mask: u32,
) -> Result<SocketMarkBrokerResponse> {
    validate_activation_id(activation_id)?;
    validate_runtime_directory(runtime_directory)?;
    validate_helper(Path::new(INSTALLED_HELPER_PATH))?;

    let socket_path = runtime_directory.join(format!("broker-{activation_id}.sock"));
    ensure!(
        std::fs::symlink_metadata(&socket_path).is_err(),
        "broker socket path already exists; refusing to reuse it"
    );
    let request = SocketMarkBrokerRequest {
        version: BROKER_REQUEST_VERSION,
        process,
        expected_peer,
        transport,
        expected_mark,
        mark_mask,
    };
    request.validate()?;

    let mut child = Command::new(INSTALLED_HELPER_PATH)
        .arg("--socket")
        .arg(&socket_path)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot launch the dedicated TUN diagnostic helper")?;

    let result = (|| {
        let deadline = Instant::now() + HELPER_START_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                anyhow::bail!("diagnostic helper exited before accepting a request: {status}");
            }
            match std::fs::symlink_metadata(&socket_path) {
                Ok(metadata) => {
                    ensure!(
                        metadata.file_type().is_socket()
                            && metadata.uid() == unsafe { libc::geteuid() }
                            && metadata.permissions().mode() & 0o777 == 0o600
                            && metadata.nlink() == 1,
                        "diagnostic helper socket identity or permissions are unsafe"
                    );
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            ensure!(
                Instant::now() < deadline,
                "diagnostic helper did not create its socket before the startup deadline"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let response = request_socket_mark_diagnostics(
            &socket_path,
            &request,
            unsafe { libc::geteuid() },
            Duration::from_secs(2),
        )?;
        let exit_deadline = Instant::now() + HELPER_EXIT_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                ensure!(status.success(), "diagnostic helper exited unsuccessfully");
                ensure!(
                    std::fs::symlink_metadata(&socket_path).is_err(),
                    "diagnostic helper did not remove its private socket"
                );
                return Ok(response);
            }
            ensure!(
                Instant::now() < exit_deadline,
                "diagnostic helper did not exit after its single request"
            );
            thread::sleep(Duration::from_millis(10));
        }
    })();

    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(target_os = "linux")]
fn validate_activation_id(value: &str) -> Result<()> {
    ensure!(
        value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            }),
        "invalid activation identifier for diagnostic socket"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_runtime_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .context("cannot inspect private TUN runtime directory")?;
    ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0,
        "TUN runtime directory must be a real caller-owned private directory"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_helper(path: &Path) -> Result<()> {
    ensure!(
        path == Path::new(INSTALLED_HELPER_PATH),
        "diagnostic helper path is not the fixed installed path"
    );
    let metadata = std::fs::symlink_metadata(path)
        .context("dedicated diagnostic helper is not installed")?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o022 == 0
            && metadata.permissions().mode() & 0o6000 == 0
            && metadata.permissions().mode() & 0o111 != 0,
        "diagnostic helper must be a root-owned, non-writable, non-setuid executable"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn observe_proxy_outbound_mark(
    _runtime_directory: &std::path::Path,
    _activation_id: &str,
    _process: (),
    _expected_peer: std::net::SocketAddr,
    _transport: (),
    _expected_mark: u32,
    _mark_mask: u32,
) -> anyhow::Result<()> {
    anyhow::bail!("socket-mark observation is supported only on Linux");
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn validates_only_uuid_activation_names() {
        assert!(validate_activation_id("12345678-1234-4234-8234-123456789abc").is_ok());
        for invalid in ["", "../helper", "12345678-1234-1234-1234-123456789abc;id"] {
            assert!(validate_activation_id(invalid).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn helper_path_cannot_be_overridden() {
        assert!(validate_helper(Path::new("/tmp/fake-helper")).is_err());
    }
}
