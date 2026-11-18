//! Narrow TUN privilege-broker contract and read-only candidate discovery.
//!
//! This module deliberately does not execute sudo/doas/pkexec or perform privileged work.
//! A candidate executable is not proof that authorization is available or safe.

use crate::tun::{manifest_store::ManifestSnapshot, recovery::SupervisorPhase};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};

#[cfg(target_os = "linux")]
use super::process::{ProcessHandle, ProcessIdentity};

pub const BROKER_REQUEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeBrokerKind {
    Sudo,
    Doas,
    Pkexec,
}

impl PrivilegeBrokerKind {
    fn executable_name(self) -> &'static str {
        match self {
            Self::Sudo => "sudo",
            Self::Doas => "doas",
            Self::Pkexec => "pkexec",
        }
    }
}

/// A binary found on PATH. This says nothing about its policy, authorization state, or safety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerCandidate {
    pub kind: PrivilegeBrokerKind,
    pub executable: PathBuf,
}

/// Resolve known broker candidates without invoking them or assuming a distribution layout.
#[cfg(target_os = "linux")]
pub fn discover_candidates(path: Option<&OsStr>) -> Vec<BrokerCandidate> {
    let Some(path) = path else {
        return Vec::new();
    };
    let directories = std::env::split_paths(path).collect::<Vec<_>>();
    [
        PrivilegeBrokerKind::Sudo,
        PrivilegeBrokerKind::Doas,
        PrivilegeBrokerKind::Pkexec,
    ]
    .into_iter()
    .filter_map(|kind| {
        directories
            .iter()
            .map(|directory| directory.join(kind.executable_name()))
            .find(|candidate| is_executable_file(candidate))
            .map(|executable| BrokerCandidate { kind, executable })
    })
    .collect()
}

#[cfg(not(target_os = "linux"))]
pub fn discover_candidates(_path: Option<&OsStr>) -> Vec<BrokerCandidate> {
    Vec::new()
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(_path: &Path) -> bool {
    false
}

/// Bind a broker listener only inside an already-existing, caller-owned private directory.
///
/// The parent must be a real directory (not a symlink), owned by the effective user,
/// with no group/other permission bits. Existing socket paths are never removed or reused.
#[cfg(target_os = "linux")]
pub fn bind_private_broker_listener(
    socket_path: &Path,
) -> Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    ensure!(
        socket_path.is_absolute(),
        "broker socket path must be absolute"
    );
    let parent = socket_path
        .parent()
        .context("broker socket path has no parent directory")?;
    let name = socket_path
        .file_name()
        .context("broker socket path has no filename")?;
    ensure!(
        !name.is_empty() && name != OsStr::new(".") && name != OsStr::new(".."),
        "broker socket filename is invalid"
    );

    let parent_metadata = std::fs::symlink_metadata(parent)
        .context("cannot inspect broker socket parent directory")?;
    ensure!(
        parent_metadata.file_type().is_dir(),
        "broker socket parent must be a real directory"
    );
    let effective_uid = unsafe { libc::geteuid() };
    ensure!(
        parent_metadata.uid() == effective_uid,
        "broker socket parent must be owned by the effective user (owner uid {}, effective uid {})",
        parent_metadata.uid(),
        effective_uid
    );
    ensure!(
        parent_metadata.permissions().mode() & 0o077 == 0,
        "broker socket parent must be inaccessible to group/other users (mode {:o})",
        parent_metadata.permissions().mode() & 0o777
    );
    ensure!(
        matches!(
            std::fs::symlink_metadata(socket_path),
            Err(ref error) if error.kind() == std::io::ErrorKind::NotFound
        ),
        "broker socket path already exists or cannot be safely inspected"
    );

    let listener =
        UnixListener::bind(socket_path).context("cannot bind private broker Unix socket")?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .context("cannot restrict broker socket permissions")?;
    let socket_metadata =
        std::fs::symlink_metadata(socket_path).context("cannot verify private broker socket")?;
    ensure!(
        socket_metadata.file_type().is_socket()
            && socket_metadata.uid() == effective_uid
            && socket_metadata.permissions().mode() & 0o777 == 0o600
            && socket_metadata.nlink() == 1,
        "broker socket filesystem identity or permissions are unsafe"
    );
    Ok(listener)
}

/// Kernel-authenticated credentials of a connected Unix-domain socket peer.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerPeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Read SO_PEERCRED from an already accepted Unix stream socket.
///
/// Credentials are supplied by the kernel for the process that established the connection;
/// they are not accepted from serialized request data.
#[cfg(target_os = "linux")]
pub fn read_broker_peer_credentials(
    stream: &std::os::unix::net::UnixStream,
) -> Result<BrokerPeerCredentials> {
    use std::os::fd::AsRawFd;

    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    ensure!(
        result == 0,
        "cannot authenticate broker IPC peer credentials"
    );
    ensure!(
        length as usize == std::mem::size_of::<libc::ucred>(),
        "broker IPC peer credentials have an unexpected size"
    );
    // SAFETY: getsockopt succeeded and returned exactly sizeof(struct ucred).
    let credentials = unsafe { credentials.assume_init() };
    ensure!(
        credentials.pid > 0,
        "broker IPC peer has an invalid process ID"
    );
    Ok(BrokerPeerCredentials {
        pid: credentials.pid as u32,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

/// Enforce same-user ownership before a helper inspects the requested managed process.
///
/// The helper must obtain target_uid from procfs only after pinning and verifying the
/// requested ProcessIdentity. This pure policy check never trusts a UID in the request.
#[cfg(target_os = "linux")]
pub fn authorize_socket_mark_request(
    request: &SocketMarkBrokerRequest,
    peer: BrokerPeerCredentials,
    target_uid: u32,
) -> Result<()> {
    request.validate()?;
    ensure!(peer.pid > 0, "broker IPC peer process ID is invalid");
    ensure!(
        peer.uid == target_uid,
        "broker may inspect only processes owned by the authenticated caller"
    );
    Ok(())
}

/// Authenticate a request against the kernel peer credentials and a pidfd-pinned target.
///
/// The target handle must have been opened from the request identity. Ownership is read
/// only after that identity and pidfd liveness are checked, then both are checked again
/// after the policy decision. This function performs no socket diagnostics.
#[cfg(target_os = "linux")]
pub fn authorize_socket_mark_request_for_process(
    request: &SocketMarkBrokerRequest,
    peer: BrokerPeerCredentials,
    target: &ProcessHandle,
) -> Result<()> {
    request.validate()?;
    ensure!(
        target.identity() == &request.process,
        "pinned broker target does not match the requested process identity"
    );
    ensure!(
        target.identity().verify()? && !target.is_exited()?,
        "broker target process is no longer the requested live process"
    );
    let target_uid = super::process::read_process_owner_uid(target)?;
    authorize_socket_mark_request(request, peer, target_uid)?;
    ensure!(
        target.identity().verify()? && !target.is_exited()?,
        "broker target process changed or exited during authorization"
    );
    Ok(())
}

/// Maximum time allowed to receive one complete broker request frame.
#[cfg(target_os = "linux")]
pub const MAX_BROKER_REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Read exactly one bounded request frame from an accepted private Unix stream.
///
/// The monotonic deadline applies to the whole frame, not each individual read, so a
/// peer cannot keep the helper occupied indefinitely by trickling bytes. The caller
/// must close the connection after this one request; pipelining is not supported.
#[cfg(target_os = "linux")]
pub fn read_socket_mark_request(
    stream: &mut std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
) -> Result<SocketMarkBrokerRequest> {
    use std::time::Instant;

    ensure!(
        !timeout.is_zero() && timeout <= MAX_BROKER_REQUEST_READ_TIMEOUT,
        "broker request read timeout is outside the permitted bound"
    );
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("broker request deadline overflow")?;
    let mut header = [0u8; 4];
    read_exact_before_deadline(stream, &mut header, deadline)?;
    let payload_length = u32::from_le_bytes(header) as usize;
    ensure!(
        payload_length > 0 && payload_length <= MAX_SOCKET_MARK_REQUEST_BYTES,
        "broker request frame length is invalid"
    );
    let mut frame = Vec::with_capacity(4 + payload_length);
    frame.extend_from_slice(&header);
    frame.resize(4 + payload_length, 0);
    read_exact_before_deadline(stream, &mut frame[4..], deadline)?;
    decode_socket_mark_request(&frame)
}

#[cfg(target_os = "linux")]
fn read_exact_before_deadline(
    stream: &mut std::os::unix::net::UnixStream,
    mut buffer: &mut [u8],
    deadline: std::time::Instant,
) -> Result<()> {
    use std::io::{ErrorKind, Read};

    while !buffer.is_empty() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        ensure!(
            !remaining.is_zero(),
            "broker request frame exceeded its deadline"
        );
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(buffer) {
            Ok(0) => anyhow::bail!("broker request frame ended before completion"),
            Ok(count) => buffer = &mut buffer[count..],
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                anyhow::bail!("broker request frame exceeded its deadline")
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Maximum serialized socket-mark broker request size (16 KiB).
pub const MAX_SOCKET_MARK_REQUEST_BYTES: usize = 16 * 1024;

/// Transport requested for the narrowly scoped socket-mark diagnostic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerSocketTransport {
    Tcp,
    Udp,
}

/// Read-only request to inspect marked sockets owned by one exact managed process.
///
/// The future helper must authenticate the caller using its IPC peer credentials, require
/// the target process to belong to that caller, pin it with pidfd, and recheck identity
/// before and after collection. The request grants no authority to inspect arbitrary
/// processes or mutate networking.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketMarkBrokerRequest {
    pub version: u32,
    pub process: ProcessIdentity,
    pub expected_peer: SocketAddr,
    pub transport: BrokerSocketTransport,
    pub expected_mark: u32,
    pub mark_mask: u32,
}

#[cfg(target_os = "linux")]
impl SocketMarkBrokerRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == BROKER_REQUEST_VERSION,
            "unsupported socket-mark broker request version"
        );
        self.process.validate()?;
        ensure!(
            !self.expected_peer.ip().is_unspecified()
                && !self.expected_peer.ip().is_multicast()
                && self.expected_peer.port() != 0,
            "socket-mark broker peer must be a unicast endpoint with a non-zero port"
        );
        ensure!(
            self.expected_mark > 0
                && self.expected_mark <= i32::MAX as u32
                && self.mark_mask > 0
                && self.expected_mark & !self.mark_mask == 0,
            "socket-mark broker policy is invalid"
        );
        Ok(())
    }
}

/// Maximum serialized broker response size (256 KiB).
#[cfg(target_os = "linux")]
pub const MAX_SOCKET_MARK_RESPONSE_BYTES: usize = 256 * 1024;
/// Maximum number of peer-matched diagnostic records returned to the controller.
#[cfg(target_os = "linux")]
pub const MAX_SOCKET_MARK_RESPONSE_RECORDS: usize = 1024;

/// Bounded candidate-only response from the read-only socket-mark diagnostic helper.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketMarkBrokerResponse {
    pub version: u32,
    pub expected_peer: SocketAddr,
    pub transport: BrokerSocketTransport,
    pub expected_mark: u32,
    pub mark_mask: u32,
    pub records: Vec<super::socket_diag_records::SocketDiagnosticRecord>,
}

#[cfg(target_os = "linux")]
impl SocketMarkBrokerResponse {
    pub fn validate(&self) -> Result<()> {
        use super::socket_diag_records::SocketAddressFamily;

        ensure!(self.version == BROKER_REQUEST_VERSION, "unsupported socket-mark broker response version");
        ensure!(
            !self.expected_peer.ip().is_unspecified()
                && !self.expected_peer.ip().is_multicast()
                && self.expected_peer.port() != 0,
            "socket-mark broker response peer is invalid"
        );
        ensure!(
            self.expected_mark > 0
                && self.expected_mark <= i32::MAX as u32
                && self.mark_mask > 0
                && self.expected_mark & !self.mark_mask == 0,
            "socket-mark broker response mark policy is invalid"
        );
        ensure!(
            !self.records.is_empty() && self.records.len() <= MAX_SOCKET_MARK_RESPONSE_RECORDS,
            "socket-mark broker response record count is invalid"
        );
        let expected_family = match self.expected_peer {
            SocketAddr::V4(_) => SocketAddressFamily::Ipv4,
            SocketAddr::V6(_) => SocketAddressFamily::Ipv6,
        };
        let mut inodes = std::collections::BTreeSet::new();
        for record in &self.records {
            ensure!(record.inode > 0 && inodes.insert(record.inode), "broker response contains a zero or duplicate socket inode");
            ensure!(
                record.family == expected_family
                    && record.remote_address == self.expected_peer.ip()
                    && record.remote_port == self.expected_peer.port()
                    && record.mark & self.mark_mask == self.expected_mark,
                "broker response contains a record outside the requested peer or mark policy"
            );
            ensure!(record.local_port > 0, "broker response contains an invalid local socket port");
            if self.transport == BrokerSocketTransport::Tcp {
                ensure!(record.state == 1, "broker TCP response contains a non-established socket");
            }
        }
        Ok(())
    }
}

/// Encode one bounded response frame. Only candidate records for the requested peer/mark
/// are permitted; the controller must still treat them as diagnostic evidence, not traffic proof.
#[cfg(target_os = "linux")]
pub fn encode_socket_mark_response(response: &SocketMarkBrokerResponse) -> Result<Vec<u8>> {
    response.validate()?;
    let payload = serde_json::to_vec(response)?;
    ensure!(!payload.is_empty() && payload.len() <= MAX_SOCKET_MARK_RESPONSE_BYTES, "socket-mark broker response exceeds the frame limit");
    let length = u32::try_from(payload.len())?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode exactly one response frame and reject unknown fields, trailing data, and invalid records.
#[cfg(target_os = "linux")]
pub fn decode_socket_mark_response(frame: &[u8]) -> Result<SocketMarkBrokerResponse> {
    ensure!(frame.len() >= 4, "socket-mark broker response header is truncated");
    let length = u32::from_le_bytes(frame[..4].try_into()?) as usize;
    ensure!(length > 0 && length <= MAX_SOCKET_MARK_RESPONSE_BYTES, "socket-mark broker response frame length is invalid");
    ensure!(frame.len() == 4 + length, "socket-mark broker response frame length does not match its payload");
    let response: SocketMarkBrokerResponse = serde_json::from_slice(&frame[4..])?;
    response.validate()?;
    Ok(response)
}

/// Encode one length-prefixed JSON request for a future private broker channel.
///
/// The frame is bounded and contains no command string, executable path, or arbitrary
/// kernel operation. This codec does not open IPC sockets or execute a helper.
#[cfg(target_os = "linux")]
pub fn encode_socket_mark_request(request: &SocketMarkBrokerRequest) -> Result<Vec<u8>> {
    request.validate()?;
    let payload = serde_json::to_vec(request)?;
    ensure!(
        !payload.is_empty() && payload.len() <= MAX_SOCKET_MARK_REQUEST_BYTES,
        "socket-mark broker request exceeds the frame limit"
    );
    let length = u32::try_from(payload.len())?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode exactly one complete request frame; trailing bytes and oversized frames fail closed.
#[cfg(target_os = "linux")]
pub fn decode_socket_mark_request(frame: &[u8]) -> Result<SocketMarkBrokerRequest> {
    ensure!(
        frame.len() >= 4,
        "socket-mark broker frame header is truncated"
    );
    let length = u32::from_le_bytes(frame[..4].try_into()?) as usize;
    ensure!(
        length > 0 && length <= MAX_SOCKET_MARK_REQUEST_BYTES,
        "socket-mark broker frame length is invalid"
    );
    ensure!(
        frame.len() == 4 + length,
        "socket-mark broker frame length does not match its payload"
    );
    let request: SocketMarkBrokerRequest = serde_json::from_slice(&frame[4..])?;
    request.validate()?;
    Ok(request)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerAction {
    ApplyPreparedManifest,
    CleanupManifest,
}

/// The only request shape a future privileged helper may accept.
///
/// The helper must reopen and validate the private manifest, verify activation/generation,
/// and derive every kernel operation from its exact resource records. No arbitrary argv,
/// shell text, executable path, interface command, route string, or firewall operation exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerRequest {
    pub version: u32,
    pub activation_id: String,
    pub generation: u64,
    pub manifest_path: PathBuf,
    pub action: BrokerAction,
}

impl BrokerRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == BROKER_REQUEST_VERSION,
            "unsupported privilege-broker request version"
        );
        ensure!(
            valid_activation_id(&self.activation_id),
            "invalid privilege-broker activation identity"
        );
        ensure!(
            self.generation > 0,
            "privilege-broker generation must be non-zero"
        );
        ensure!(
            self.manifest_path.is_absolute(),
            "privilege-broker manifest path must be absolute"
        );
        ensure!(
            self.manifest_path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
            "privilege-broker manifest path contains an unsafe component"
        );
        ensure!(
            self.manifest_path.file_name().and_then(OsStr::to_str) == Some("tun-manifest.json"),
            "privilege-broker request does not reference a TUN manifest"
        );
        Ok(())
    }

    /// Bind a request to the exact durable snapshot before a helper may act.
    /// The helper must still reopen the file and repeat this check itself.
    pub fn validate_snapshot(&self, snapshot: &ManifestSnapshot) -> Result<()> {
        self.validate()?;
        snapshot.validate()?;
        ensure!(
            self.activation_id == snapshot.manifest.activation_id
                && self.generation == snapshot.generation,
            "privilege-broker request does not match the durable activation"
        );
        match (self.action, snapshot.phase) {
            (BrokerAction::ApplyPreparedManifest, SupervisorPhase::Prepared)
            | (BrokerAction::CleanupManifest, SupervisorPhase::CleanupPending) => Ok(()),
            _ => {
                anyhow::bail!("privilege-broker action is invalid for the manifest lifecycle phase")
            }
        }
    }
}

fn valid_activation_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{ffi::OsString, fs};

    #[cfg(target_os = "linux")]
    #[test]
    fn private_broker_listener_requires_private_directory_and_creates_mode_0600_socket() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        // Make the test's security precondition explicit instead of relying on the
        // temporary-directory implementation's default mode.
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("broker.sock");
        let listener = bind_private_broker_listener(&socket).unwrap();
        let metadata = fs::symlink_metadata(&socket).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert!(bind_private_broker_listener(&socket).is_err());
        drop(listener);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_broker_listener_rejects_group_accessible_or_symlink_parent() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(bind_private_broker_listener(&directory.path().join("broker.sock")).is_err());

        let target = tempfile::tempdir().unwrap();
        let link = target.path().join("linked");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        assert!(bind_private_broker_listener(&link.join("broker.sock")).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn broker_peer_credentials_come_from_kernel_socket_metadata() {
        use std::os::unix::net::UnixStream;

        let (client, server) = UnixStream::pair().unwrap();
        let expected_uid = unsafe { libc::getuid() };
        let expected_gid = unsafe { libc::getgid() };
        let expected_pid = std::process::id();
        let credentials = read_broker_peer_credentials(&server).unwrap();
        assert_eq!(credentials.uid, expected_uid);
        assert_eq!(credentials.gid, expected_gid);
        assert_eq!(credentials.pid, expected_pid);
        drop(client);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn broker_authorization_allows_only_same_user_processes() {
        let request = socket_mark_request();
        let peer = BrokerPeerCredentials {
            pid: 100,
            uid: 1000,
            gid: 1000,
        };
        assert!(authorize_socket_mark_request(&request, peer, 1000).is_ok());
        assert!(authorize_socket_mark_request(&request, peer, 1001).is_err());
        let invalid_peer = BrokerPeerCredentials { pid: 0, ..peer };
        assert!(authorize_socket_mark_request(&request, invalid_peer, 1000).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn request_authorization_is_bound_to_the_exact_pidfd_target() {
        use super::super::process::{ProcessHandle, ProcessIdentity};

        let identity = ProcessIdentity::capture(std::process::id()).unwrap();
        let target = ProcessHandle::open(identity.clone()).unwrap();
        let mut request = socket_mark_request();
        request.process = identity;
        let peer = BrokerPeerCredentials {
            pid: std::process::id(),
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        authorize_socket_mark_request_for_process(&request, peer, &target).unwrap();

        let mut mismatched = request.clone();
        mismatched.process.start_ticks += 1;
        assert!(authorize_socket_mark_request_for_process(&mismatched, peer, &target).is_err());

        let other_user = BrokerPeerCredentials { uid: peer.uid.wrapping_add(1), ..peer };
        assert!(authorize_socket_mark_request_for_process(&request, other_user, &target).is_err());
    }

    #[cfg(target_os = "linux")]
    fn socket_mark_request() -> SocketMarkBrokerRequest {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        SocketMarkBrokerRequest {
            version: BROKER_REQUEST_VERSION,
            process: ProcessIdentity {
                pid: 4242,
                start_ticks: 987654,
                executable: "/opt/proxyctl/cores/sing-box".into(),
            },
            expected_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)), 443),
            transport: BrokerSocketTransport::Tcp,
            expected_mark: 0x142,
            mark_mask: 0xffff,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stream_reader_accepts_one_complete_bounded_request() {
        use std::{io::Write, os::unix::net::UnixStream, thread};

        let request = socket_mark_request();
        let frame = encode_socket_mark_request(&request).unwrap();
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || writer.write_all(&frame).unwrap());
        let decoded =
            read_socket_mark_request(&mut reader, std::time::Duration::from_secs(1)).unwrap();
        sender.join().unwrap();
        assert_eq!(decoded, request);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stream_reader_rejects_partial_and_oversized_frames() {
        use std::{io::Write, os::unix::net::UnixStream, thread};

        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&[8, 0]).unwrap();
        drop(writer);
        assert!(read_socket_mark_request(&mut reader, std::time::Duration::from_secs(1),).is_err());

        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let oversized = (MAX_SOCKET_MARK_REQUEST_BYTES as u32 + 1).to_le_bytes();
        writer.write_all(&oversized).unwrap();
        let _sender = thread::spawn(move || drop(writer));
        assert!(read_socket_mark_request(&mut reader, std::time::Duration::from_secs(1),).is_err());
    }

    #[cfg(target_os = "linux")]
    fn socket_mark_response() -> SocketMarkBrokerResponse {
        use super::super::socket_diag_records::{SocketAddressFamily, SocketDiagnosticRecord};
        SocketMarkBrokerResponse {
            version: BROKER_REQUEST_VERSION,
            expected_peer: socket_mark_request().expected_peer,
            transport: BrokerSocketTransport::Tcp,
            expected_mark: 0x142,
            mark_mask: 0xffff,
            records: vec![SocketDiagnosticRecord {
                family: SocketAddressFamily::Ipv4,
                state: 1,
                local_address: "192.0.2.2".parse().unwrap(),
                local_port: 40000,
                remote_address: "198.51.100.8".parse().unwrap(),
                remote_port: 443,
                inode: 77,
                mark: 0x142,
            }],
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_mark_response_round_trips_and_rejects_out_of_scope_records() {
        let response = socket_mark_response();
        let frame = encode_socket_mark_response(&response).unwrap();
        assert_eq!(decode_socket_mark_response(&frame).unwrap(), response);

        let mut invalid = response.clone();
        invalid.records[0].remote_port = 8443;
        assert!(encode_socket_mark_response(&invalid).is_err());

        let mut invalid = response.clone();
        invalid.records[0].mark = 0x242;
        assert!(encode_socket_mark_response(&invalid).is_err());

        let mut trailing = frame;
        trailing.push(0);
        assert!(decode_socket_mark_response(&trailing).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_mark_request_round_trips_in_one_bounded_frame() {
        let request = socket_mark_request();
        let frame = encode_socket_mark_request(&request).unwrap();
        assert_eq!(decode_socket_mark_request(&frame).unwrap(), request);
        assert_eq!(
            u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize,
            frame.len() - 4
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_mark_request_rejects_invalid_identity_peer_and_mark_policy() {
        let mut invalid = socket_mark_request();
        invalid.process.pid = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = socket_mark_request();
        invalid.expected_peer.set_port(0);
        assert!(invalid.validate().is_err());

        let mut invalid = socket_mark_request();
        invalid.expected_mark = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = socket_mark_request();
        invalid.expected_mark = 0x100;
        invalid.mark_mask = 0x0f;
        assert!(invalid.validate().is_err());

        let mut invalid = socket_mark_request();
        invalid.expected_mark = i32::MAX as u32 + 1;
        assert!(invalid.validate().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_mark_frame_rejects_truncation_oversize_and_trailing_data() {
        let frame = encode_socket_mark_request(&socket_mark_request()).unwrap();
        assert!(decode_socket_mark_request(&frame[..3]).is_err());

        let mut truncated = frame.clone();
        truncated.pop();
        assert!(decode_socket_mark_request(&truncated).is_err());

        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(decode_socket_mark_request(&trailing).is_err());

        let oversized = (MAX_SOCKET_MARK_REQUEST_BYTES as u32 + 1).to_le_bytes();
        assert!(decode_socket_mark_request(&oversized).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn socket_mark_frame_rejects_unknown_request_fields() {
        let payload = br#"{"version":1,"process":{"pid":4242,"start_ticks":987654,"executable":"/opt/proxyctl/cores/sing-box"},"expected_peer":"198.51.100.8:443","transport":"tcp","expected_mark":322,"mark_mask":65535,"command":"ip route add"}"#;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(payload);
        assert!(decode_socket_mark_request(&frame).is_err());
    }

    fn request() -> BrokerRequest {
        BrokerRequest {
            version: BROKER_REQUEST_VERSION,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 4,
            manifest_path: "/run/user/1000/proxyctl/tun-manifest.json".into(),
            action: BrokerAction::CleanupManifest,
        }
    }

    #[test]
    fn request_accepts_only_versioned_generation_scoped_manifest_actions() {
        request().validate().unwrap();
        let mut invalid = request();
        invalid.generation = 0;
        assert!(invalid.validate().is_err());
        let mut invalid = request();
        invalid.version += 1;
        assert!(invalid.validate().is_err());
        let mut invalid = request();
        invalid.activation_id = "not-an-activation".into();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn request_must_match_snapshot_generation_activation_and_phase() {
        use crate::tun::ownership::{MANIFEST_VERSION, OwnedResource, RouteManifest};
        let mut snapshot = ManifestSnapshot {
            schema_version: 1,
            generation: 4,
            phase: SupervisorPhase::CleanupPending,
            #[cfg(target_os = "linux")]
            core_process: None,
            manifest: RouteManifest {
                version: MANIFEST_VERSION,
                activation_id: "12345678-1234-4234-8234-123456789abc".into(),
                table_id: 42420,
                rule_priority: 42420,
                interface_name: "tun-proxyctl".into(),
                interface_index: 77,
                resources: vec![OwnedResource {
                    key: "route:v4-default".into(),
                    fingerprint: "route-fp".into(),
                }],
            },
        };
        request().validate_snapshot(&snapshot).unwrap();

        let mut invalid = request();
        invalid.generation += 1;
        assert!(invalid.validate_snapshot(&snapshot).is_err());

        snapshot.phase = SupervisorPhase::Running;
        assert!(request().validate_snapshot(&snapshot).is_err());

        snapshot.phase = SupervisorPhase::CleanupPending;
        snapshot.manifest.activation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
        assert!(request().validate_snapshot(&snapshot).is_err());
    }

    #[test]
    fn request_rejects_relative_traversal_and_non_manifest_paths() {
        for path in [
            PathBuf::from("run/tun-manifest.json"),
            PathBuf::from("/run/user/../etc/tun-manifest.json"),
            PathBuf::from("/run/user/1000/proxyctl/other.json"),
        ] {
            let mut invalid = request();
            invalid.manifest_path = path;
            assert!(invalid.validate().is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn discovers_only_executable_candidates_without_running_them() {
        let directory = tempfile::tempdir().unwrap();
        let sudo = directory.path().join("sudo");
        let doas = directory.path().join("doas");
        fs::write(&sudo, "not executed").unwrap();
        fs::write(&doas, "not executed").unwrap();
        fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&doas, fs::Permissions::from_mode(0o600)).unwrap();

        let candidates = discover_candidates(Some(directory.path().as_os_str()));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, PrivilegeBrokerKind::Sudo);
        assert_eq!(candidates[0].executable, sudo);
        assert!(discover_candidates(None).is_empty());
        let _unused: OsString = directory.path().as_os_str().to_owned();
    }
}
