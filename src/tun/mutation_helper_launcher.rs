//! Starts the persistent mutation helper for the current user runtime.
//! The helper is capability-confined by its installation file capabilities and
//! exposes only the typed mutation protocol.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    fs::OpenOptions,
    os::unix::{
        fd::AsRawFd,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use super::mutation_broker::{self, MutationRequest, MutationResponse};

const HELPER: &str = "/usr/libexec/proxyctl-tun-helper";
const READY_TIMEOUT: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(40);
const START_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

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
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() },
            "helper runtime directory must be a caller-owned directory"
        );
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "helper runtime directory must not be accessible to other users"
        );
        ensure!(
            metadata.permissions().mode() & 0o7000 == 0,
            "helper runtime directory must not have special permission bits"
        );
        ensure!(
            metadata.permissions().mode() & 0o700 == 0o700,
            "helper runtime directory must be owner-readable, writable, and searchable"
        );
        let runtime =
            fs::canonicalize(runtime).context("cannot canonicalize helper runtime directory")?;
        ensure!(
            runtime.is_absolute() && runtime.as_os_str().len() <= 4096,
            "helper runtime directory must be a bounded absolute path"
        );
        let _start_lock = acquire_start_lock(&runtime.join("tun-mutation.lock"))?;
        let socket = runtime.join("tun-mutation.sock");
        ensure!(
            socket.as_os_str().len() < 108,
            "mutation broker socket path exceeds the Unix-domain socket path limit"
        );
        if probe(&socket) {
            return Ok(Self { socket });
        }
        if socket.exists() {
            anyhow::bail!(
                "mutation broker socket exists but is not accepting connections; refusing to unlink an unverified socket"
            );
        }
        let helper_metadata = fs::symlink_metadata(HELPER).with_context(|| {
            format!("TUN helper is not installed at {HELPER}; run packaging/install-tun-helper.sh")
        })?;
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
            helper_metadata.permissions().mode() & 0o7000 == 0,
            "TUN helper executable must not have special permission bits"
        );
        ensure!(
            helper_metadata.nlink() == 1,
            "TUN helper executable must not have external hard links"
        );
        ensure!(
            helper_metadata.permissions().mode() & 0o111 != 0,
            "TUN helper executable has no execute permission"
        );
        let mut child = Command::new(HELPER)
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
            match child.try_wait() {
                Ok(Some(status)) => {
                    anyhow::bail!("mutation helper exited before becoming ready: {status}");
                }
                Ok(None) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error).context("cannot inspect mutation helper startup process");
                }
            }
            std::thread::sleep(POLL);
        }
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("mutation helper did not become ready before deadline");
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// Recover the journal left by a prior activation generation. The broker verifies identity.
    pub fn recover_generation(
        &self,
        activation_id: &str,
        generation: u64,
    ) -> Result<MutationResponse> {
        self.recover(activation_id.to_owned(), generation)
    }

    /// Submit a typed activation operation to the broker.
    #[allow(clippy::too_many_arguments)]
    pub fn activate(
        &self,
        activation_id: String,
        generation: u64,
        interface_name: String,
        owner_uid: u32,
        owner_gid: u32,
        table_id: u32,
        bypass_priority: u32,
        proxy_priority: u32,
        core_mark: u32,
        core_mark_mask: u32,
    ) -> Result<MutationResponse> {
        self.call(&MutationRequest::Activate {
            version: 1,
            activation_id,
            generation,
            interface_name,
            owner_uid,
            owner_gid,
            table_id,
            bypass_priority,
            proxy_priority,
            core_mark,
            core_mark_mask,
        })
    }

    /// Create policy and a persistent named TUN device for a native core.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_native(
        &self,
        activation_id: String,
        generation: u64,
        interface_name: String,
        owner_uid: u32,
        owner_gid: u32,
        table_id: u32,
        bypass_priority: u32,
        proxy_priority: u32,
        core_mark: u32,
        core_mark_mask: u32,
    ) -> Result<MutationResponse> {
        self.call(&MutationRequest::ActivateNative {
            version: 1,
            activation_id,
            generation,
            interface_name,
            owner_uid,
            owner_gid,
            table_id,
            bypass_priority,
            proxy_priority,
            core_mark,
            core_mark_mask,
        })
    }

    /// Export the retained TUN descriptor for one exact activation generation.
    pub fn attach_descriptor(
        &self,
        activation_id: &str,
        generation: u64,
    ) -> Result<std::os::fd::OwnedFd> {
        mutation_broker::attach_descriptor(&self.socket, activation_id, generation)
    }

    /// Request recovery for an activation generation.
    pub fn recover(&self, activation_id: String, generation: u64) -> Result<MutationResponse> {
        self.call(&MutationRequest::Recover {
            version: 1,
            activation_id,
            generation,
        })
    }

    /// Send a protocol request through the broker client.
    pub fn call(&self, request: &MutationRequest) -> Result<MutationResponse> {
        mutation_broker::call(&self.socket, request)
    }
}

fn probe(path: &Path) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.permissions().mode() & 0o7000 != 0
        || metadata.nlink() != 1
    {
        return false;
    }
    mutation_broker::call(path, &MutationRequest::Ping { version: 1 }).is_ok()
}

/// Serialize helper discovery and startup across concurrent Proxyctl processes.
///
/// The lock file remains on disk; flock ownership is tied to the open file description,
/// so process exit releases the lock without stale-lock recovery or unsafe unlinking.
fn acquire_start_lock(path: &Path) -> Result<fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .context("cannot securely open TUN helper startup lock")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "TUN helper startup lock is not a regular file"
    );
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "TUN helper startup lock has a foreign owner"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "TUN helper startup lock is not private"
    );
    ensure!(
        metadata.permissions().mode() & 0o7000 == 0,
        "TUN helper startup lock has special permission bits"
    );
    ensure!(
        metadata.permissions().mode() & 0o700 == 0o600,
        "TUN helper startup lock must be owner-readable and writable only"
    );
    ensure!(
        metadata.nlink() == 1,
        "TUN helper startup lock has external hard links"
    );

    let deadline = Instant::now() + START_LOCK_TIMEOUT;
    loop {
        // SAFETY: flock is called with a valid descriptor owned by the lock file.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            ensure!(
                Instant::now() < deadline,
                "timed out waiting for another TUN helper startup"
            );
            continue;
        }
        if !matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK)) {
            return Err(error).context("cannot acquire TUN helper startup lock");
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for another TUN helper startup"
        );
        std::thread::sleep(POLL);
    }
}
