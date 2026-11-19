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

use super::mutation_broker::{self, MutationRequest, MutationResponse};

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
        if !runtime.exists() {
            fs::create_dir_all(runtime)?;
            fs::set_permissions(runtime, fs::Permissions::from_mode(0o700))?;
        }
        let metadata = fs::symlink_metadata(runtime)?;
        ensure!(metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.uid() == unsafe { libc::geteuid() },
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
        let helper_metadata = fs::symlink_metadata(HELPER)
            .with_context(|| format!("TUN helper is not installed at {HELPER}; run packaging/install-tun-helper.sh"))?;
        ensure!(
            helper_metadata.file_type().is_file(),
            "TUN helper must be a regular file, not a symlink"
        );
        ensure!(
            helper_metadata.uid() == 0,
            "TUN helper executable must be owned by root"
        );
        ensure!(
            helper_metadata.permissions().mode() & 0o022 == 0,
            "TUN helper executable must not be group- or world-writable"
        );
        ensure!(
            helper_metadata.permissions().mode() & 0o111 != 0,
            "TUN helper executable has no execute permission"
        );
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

    /// Recover the journal left by a prior activation generation. The broker verifies identity.
    pub fn recover_generation(&self, activation_id: &str, generation: u64) -> Result<MutationResponse> {
        self.recover(activation_id.to_owned(), generation)
    }

    /// Submit a typed activation operation to the broker.
    #[allow(clippy::too_many_arguments)]
    pub fn activate(&self, activation_id: String, generation: u64, interface_name: String, owner_uid: u32, owner_gid: u32, table_id: u32, bypass_priority: u32, proxy_priority: u32, core_mark: u32, core_mark_mask: u32) -> Result<MutationResponse> {
        self.call(&MutationRequest::Activate { version: 1, activation_id, generation, interface_name, owner_uid, owner_gid, table_id, bypass_priority, proxy_priority, core_mark, core_mark_mask })
    }

    /// Request recovery for an activation generation.
    pub fn recover(&self, activation_id: String, generation: u64) -> Result<MutationResponse> {
        self.call(&MutationRequest::Recover { version: 1, activation_id, generation })
    }

    /// Send a protocol request through the broker client.
    pub fn call(&self, request: &MutationRequest) -> Result<MutationResponse> {
        mutation_broker::call(&self.socket, request)
    }
}

fn probe(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}
