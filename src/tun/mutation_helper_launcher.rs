//! Starts the persistent mutation helper for the current user runtime.
//! The helper is capability-confined by its installation file capabilities and
//! exposes only the typed mutation protocol.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const HELPER: &str = "/usr/libexec/proxyctl-tun-helper";
const READY_TIMEOUT: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(40);

pub struct MutationHelper {
    socket: PathBuf,
}

impl MutationHelper {
    /// Start helper only when its private socket is not already accepting connections.
    /// Runtime directory is caller-owned and private; stale sockets are never blindly removed.
    pub fn ensure_started(runtime: &Path) -> Result<Self> {
        fs::create_dir_all(runtime)?;
        fs::set_permissions(runtime, fs::Permissions::from_mode(0o700))?;
        let metadata = fs::symlink_metadata(runtime)?;
        ensure!(metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() },
            "helper runtime directory must be a caller-owned directory");
        ensure!(metadata.permissions().mode() & 0o077 == 0,
            "helper runtime directory must not be accessible to other users");
        let socket = runtime.join("tun-mutation.sock");
        if probe(&socket) {
            return Ok(Self { socket });
        }
        if socket.exists() {
            anyhow::bail!("mutation broker socket exists but is not accepting connections; refusing to unlink an unverified socket");
        }
        ensure!(Path::new(HELPER).is_file(),
            "TUN helper is not installed at {HELPER}; run packaging/install-tun-helper.sh");
        Command::new(HELPER)
            .arg("--mutation-socket")
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("could not start persistent TUN mutation helper")?;
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if probe(&socket) {
                return Ok(Self { socket });
            }
            std::thread::sleep(POLL);
        }
        anyhow::bail!("mutation helper did not become ready before deadline");
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }
}

fn probe(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}
