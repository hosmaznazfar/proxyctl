//! Persistent typed Linux mutation-broker service.
//!
//! This protocol is intentionally separate from the read-only socket-mark diagnostic broker.
//! Requests describe complete typed policy operations; raw netlink bytes, command strings,
//! executable paths, and arbitrary ioctl requests are not representable.
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    journal_recovery_executor::recover,
    kernel_inventory,
    kernel_transaction::{self, KernelTransaction},
    linux_journal_backend::LinuxJournalBackend,
    manifest_store::ManifestStore,
    privilege_broker::read_broker_peer_credentials,
    route_policy::RoutingPolicyPlan,
};

const VERSION: u32 = 1;
const MAX_FRAME: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum MutationRequest {
    Ping {
        version: u32,
    },
    Activate {
        version: u32,
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
    },
    ActivateNative {
        version: u32,
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
    },
    Recover {
        version: u32,
        activation_id: String,
        generation: u64,
    },
    AttachDescriptor {
        version: u32,
        activation_id: String,
        generation: u64,
    },
}

impl MutationRequest {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Ping { version } => {
                ensure!(
                    *version == VERSION,
                    "unsupported mutation broker protocol version"
                );
            }
            Self::Activate {
                version,
                activation_id,
                generation,
                interface_name,
                table_id,
                bypass_priority,
                proxy_priority,
                core_mark,
                core_mark_mask,
                ..
            } => {
                ensure!(
                    *version == VERSION,
                    "unsupported mutation broker protocol version"
                );
                validate_identity(activation_id, *generation)?;
                let plan = RoutingPolicyPlan::new(
                    *table_id,
                    *bypass_priority,
                    *proxy_priority,
                    *core_mark,
                    *core_mark_mask,
                    interface_name,
                    1,
                );
                plan.validate()?;
            }
            Self::ActivateNative {
                version,
                activation_id,
                generation,
                interface_name,
                table_id,
                bypass_priority,
                proxy_priority,
                core_mark,
                core_mark_mask,
                ..
            } => {
                ensure!(
                    *version == VERSION,
                    "unsupported mutation broker protocol version"
                );
                validate_identity(activation_id, *generation)?;
                RoutingPolicyPlan::new(
                    *table_id,
                    *bypass_priority,
                    *proxy_priority,
                    *core_mark,
                    *core_mark_mask,
                    interface_name,
                    1,
                )
                .validate()?;
            }
            Self::Recover {
                version,
                activation_id,
                generation,
            }
            | Self::AttachDescriptor {
                version,
                activation_id,
                generation,
            } => {
                ensure!(
                    *version == VERSION,
                    "unsupported mutation broker protocol version"
                );
                validate_identity(activation_id, *generation)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationResponse {
    pub version: u32,
    pub success: bool,
    pub message: String,
}

impl MutationResponse {
    fn success(message: impl Into<String>) -> Self {
        Self {
            version: VERSION,
            success: true,
            message: message.into(),
        }
    }
    fn failure(error: impl std::fmt::Display) -> Self {
        let mut message = error.to_string();
        // Keep error envelopes bounded even when an error chain contains attacker-controlled
        // strings (interface names, paths, or protocol input).
        const MAX_MESSAGE_BYTES: usize = 8 * 1024;
        if message.len() > MAX_MESSAGE_BYTES {
            let mut boundary = MAX_MESSAGE_BYTES;
            while !message.is_char_boundary(boundary) {
                boundary -= 1;
            }
            message.truncate(boundary);
            message.push('…');
        }
        Self {
            version: VERSION,
            success: false,
            message,
        }
    }
}

/// Run until the service is stopped. The backend map is deliberately process-lifetime state:
/// it retains descriptor-backed devices or native persistent-device ownership bookkeeping
/// between independent client connections; the journal remains authoritative after restart.
pub fn serve(listener: &UnixListener, runtime_directory: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(runtime_directory)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() },
        "mutation broker runtime directory must be a real caller-owned directory"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0
            && metadata.permissions().mode() & 0o700 == 0o700,
        "mutation broker runtime directory must be private and owner-accessible"
    );
    let mut backends: BTreeMap<(String, u64), LinuxJournalBackend> = BTreeMap::new();
    loop {
        let (mut stream, _) = listener
            .accept()
            .context("cannot accept mutation broker client")?;
        // A malformed or unauthorized client must not terminate the persistent privileged
        // service. Close that connection and continue accepting authenticated peers.
        let handled = (|| -> Result<()> {
            stream.set_read_timeout(Some(IO_TIMEOUT))?;
            stream.set_write_timeout(Some(IO_TIMEOUT))?;
            let peer = read_broker_peer_credentials(&stream)?;
            ensure!(
                peer.uid == unsafe { libc::geteuid() },
                "mutation broker accepts requests only from its owning user"
            );
            let request = read_request(&mut stream)?;
            if let MutationRequest::AttachDescriptor {
                version: _,
                activation_id,
                generation,
            } = &request
            {
                request.validate()?;
                let backend = backends
                    .get(&(activation_id.clone(), *generation))
                    .context(
                        "no live broker-owned TUN descriptor exists for this activation generation",
                    )?;
                let descriptor = backend.tun_descriptor(activation_id, *generation)?;
                let response = MutationResponse::success("generation-bound TUN descriptor follows");
                write_response(&mut stream, &response)?;
                super::descriptor_transfer::send_descriptor(&stream, descriptor)?;
                return Ok(());
            }
            let response = match request.validate().and_then(|()| {
                if let MutationRequest::Activate {
                    owner_uid,
                    owner_gid,
                    ..
                }
                | MutationRequest::ActivateNative {
                    owner_uid,
                    owner_gid,
                    ..
                } = &request
                {
                    ensure!(
                        *owner_uid == peer.uid && *owner_gid == peer.gid,
                        "TUN owner IDs must match the authenticated broker peer"
                    );
                }
                Ok(())
            }) {
                Ok(()) => match execute(request, runtime_directory, &mut backends) {
                    Ok(message) => MutationResponse::success(message),
                    Err(error) => MutationResponse::failure(format!("{error:#}")),
                },
                Err(error) => MutationResponse::failure(format!("{error:#}")),
            };
            write_response(&mut stream, &response)
        })();
        handled.unwrap_or(());
    }
}

/// Refuse privileged resource recovery while the manifest-bound core process is live.
fn ensure_managed_core_stopped(
    process: Option<&super::process::ProcessIdentity>,
) -> Result<()> {
    if let Some(process) = process {
        ensure!(
            !process.verify()?,
            "refusing TUN resource recovery while the manifest-bound core process is still live"
        );
    }
    Ok(())
}

fn execute(
    request: MutationRequest,
    directory: &Path,
    backends: &mut BTreeMap<(String, u64), LinuxJournalBackend>,
) -> Result<String> {
    match request {
        MutationRequest::Ping { .. } => inspect_broker_readiness(directory, backends),
        MutationRequest::Activate {
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
            ..
        } => {
            // The kernel policy and attachment owner are process-lifetime resources.
            // A second generation must not coexist with them: replacement first recovers the
            // previous journal, then starts a fresh activation under the same broker.
            ensure!(
                backends.is_empty(),
                "another TUN activation still has a live broker backend; recover it before activating a replacement"
            );
            let key = (activation_id.clone(), generation);
            ensure!(
                !backends.contains_key(&key),
                "activation generation already has a live broker backend"
            );
            let policy = RoutingPolicyPlan::new(
                table_id,
                bypass_priority,
                proxy_priority,
                core_mark,
                core_mark_mask,
                interface_name,
                1,
            );
            // Refuse occupied tables/priorities before the write-ahead transaction begins.
            // The typed add operations still use create-exclusive ACKs to close the race.
            let inventory = kernel_inventory::inspect_snapshot()?;
            policy.validate_against(&inventory.inventory)?;
            let store = ManifestStore::open(directory)?;
            let backend = LinuxJournalBackend::new(store.clone(), &activation_id, generation)?;
            let transaction = KernelTransaction {
                activation_id: activation_id.clone(),
                policy,
                owner_uid,
                owner_gid,
            };
            let mut backend = backend;
            let result = kernel_transaction::apply(&transaction, &mut backend);
            match result {
                Ok(_) => {
                    backends.insert(key, backend);
                    Ok(format!(
                        "activation {activation_id} generation {generation} committed"
                    ))
                }
                Err(error) => {
                    // A fully successful rollback removes the journal and never creates an
                    // active manifest. In that case the retained TUN descriptor has already
                    // been released and this generation must not poison the broker's next
                    // activation. If either durable record remains, preserve the backend so
                    // unresolved ownership and its descriptor remain available for recovery.
                    let fully_rolled_back = matches!(
                        (store.load_transaction_journal(), store.load()),
                        (Ok(None), Ok(None))
                    );
                    if !fully_rolled_back {
                        backends.insert(key, backend);
                    }
                    Err(error)
                }
            }
        }
        MutationRequest::AttachDescriptor { .. } => {
            anyhow::bail!(
                "descriptor attachment requests must use the authenticated SCM_RIGHTS response path"
            )
        }
        MutationRequest::ActivateNative {
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
            ..
        } => {
            ensure!(
                backends.is_empty(),
                "another TUN activation still has a live broker backend; recover it first"
            );
            let key = (activation_id.clone(), generation);
            ensure!(
                !backends.contains_key(&key),
                "activation generation already has a live broker backend"
            );
            let policy = RoutingPolicyPlan::new(
                table_id,
                bypass_priority,
                proxy_priority,
                core_mark,
                core_mark_mask,
                interface_name,
                1,
            );
            let inventory = kernel_inventory::inspect_snapshot()?;
            policy.validate_against(&inventory.inventory)?;
            let store = ManifestStore::open(directory)?;
            let mut backend =
                LinuxJournalBackend::new_native(store.clone(), &activation_id, generation)?;
            let transaction = KernelTransaction {
                activation_id: activation_id.clone(),
                policy,
                owner_uid,
                owner_gid,
            };
            match kernel_transaction::apply_native(&transaction, &mut backend) {
                Ok(_) => {
                    backends.insert(key, backend);
                    Ok(format!(
                        "native activation {activation_id} generation {generation} committed"
                    ))
                }
                Err(error) => {
                    let fully_rolled_back = matches!(
                        (store.load_transaction_journal(), store.load()),
                        (Ok(None), Ok(None))
                    );
                    if !fully_rolled_back {
                        backends.insert(key, backend);
                    }
                    Err(error)
                }
            }
        }
        MutationRequest::Recover {
            activation_id,
            generation,
            ..
        } => {
            let key = (activation_id.clone(), generation);
            let store = ManifestStore::open(directory)?;
            // Bind both durable records to the requested identity before any kernel mutation.
            let manifest = store.load()?;
            if let Some(snapshot) = &manifest {
                ensure!(
                    snapshot.manifest.activation_id == activation_id
                        && snapshot.generation == generation,
                    "recovery identity does not match the durable TUN manifest"
                );
            }
            let journal = store.load_transaction_journal()?;
            ensure_managed_core_stopped(
                manifest.as_ref().and_then(|snapshot| snapshot.core_process.as_ref()),
            )?;
            if let Some(journal) = &journal {
                ensure!(
                    journal.activation_id == activation_id && journal.generation == generation,
                    "recovery identity does not match the durable TUN transaction journal"
                );
            }

            // A crash may occur after journal removal but before manifest retirement. Finish
            // that idempotent finalization without trying to reopen a now-absent journal.
            if journal.is_none() {
                let Some(mut snapshot) = manifest else {
                    anyhow::bail!("no matching TUN manifest or transaction journal exists");
                };
                snapshot.phase = super::recovery::SupervisorPhase::Cleaned;
                store.write(&snapshot)?;
                store.remove_cleaned(&activation_id, generation)?;
                backends.remove(&key);
                return Ok("recovery complete: ownership manifest finalized".to_owned());
            }

            let mut backend = match backends.remove(&key) {
                Some(backend) => backend,
                None => LinuxJournalBackend::open_for_recovery(
                    store.clone(),
                    &activation_id,
                    generation,
                )?,
            };
            match recover(&store, &mut backend) {
                Ok(report) => {
                    // Journal cleanup is already durable at this point. Keep the backend
                    // registered if manifest retirement fails so the broker remains exclusive
                    // and a retry can finish the manifest-only finalization path.
                    let finalization = (|| -> Result<String> {
                        if let Some(mut snapshot) = manifest {
                            snapshot.phase = super::recovery::SupervisorPhase::Cleaned;
                            store.write(&snapshot)?;
                            store.remove_cleaned(&activation_id, generation)?;
                        }
                        Ok(format!(
                            "recovery complete: {} removed, {} already absent, {} intents resolved",
                            report.removed.len(),
                            report.already_absent.len(),
                            report.resolved_intents.len()
                        ))
                    })();
                    match finalization {
                        Ok(message) => Ok(message),
                        Err(error) => {
                            backends.insert(key, backend);
                            Err(error).context(
                                "kernel recovery completed but ownership-manifest finalization failed; retry the same generation",
                            )
                        }
                    }
                }
                Err(error) => {
                    backends.insert(key, backend);
                    Err(error)
                }
            }
        }
    }
}

/// Verify that the persistent broker can safely resume any durable generation.
///
/// This is deliberately read-only: a restarted helper may have durable records but no
/// in-memory descriptor, in which case generation-matched recovery remains available.
fn inspect_broker_readiness(
    directory: &Path,
    backends: &BTreeMap<(String, u64), LinuxJournalBackend>,
) -> Result<String> {
    ensure!(
        backends.len() <= 1,
        "mutation broker retained more than one activation backend"
    );
    let store = ManifestStore::open(directory)?;
    let manifest = store.load()?;
    let journal = store.load_transaction_journal()?;

    let manifest_identity = manifest
        .as_ref()
        .map(|snapshot| (snapshot.manifest.activation_id.clone(), snapshot.generation));
    let journal_identity = journal
        .as_ref()
        .map(|entry| (entry.activation_id.clone(), entry.generation));

    if let (Some(manifest_id), Some(journal_id)) = (&manifest_identity, &journal_identity) {
        ensure!(
            manifest_id == journal_id,
            "durable TUN manifest and transaction journal identities disagree"
        );
    }

    let durable_identity = manifest_identity.or(journal_identity);
    if let Some((backend_id, backend_generation)) = backends.keys().next() {
        ensure!(
            durable_identity.as_ref() == Some(&(backend_id.clone(), *backend_generation)),
            "retained mutation backend has no matching durable manifest or journal"
        );
    }

    match durable_identity {
        Some((activation_id, generation)) => Ok(format!(
            "mutation broker ready; durable activation {activation_id} generation {generation} is available for supervision or recovery"
        )),
        None => Ok("mutation broker ready; no durable activation is pending".to_owned()),
    }
}

fn read_request(stream: &mut UnixStream) -> Result<MutationRequest> {
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    let mut header = [0u8; 4];
    read_exact_deadline(stream, &mut header, deadline)?;
    let length = u32::from_le_bytes(header) as usize;
    ensure!(
        length > 0 && length <= MAX_FRAME,
        "mutation request frame length is invalid"
    );
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(length)
        .context("cannot reserve bounded mutation request payload")?;
    payload.resize(length, 0);
    read_exact_deadline(stream, &mut payload, deadline)?;
    serde_json::from_slice(&payload).context("mutation request JSON is malformed")
}

fn read_exact_deadline(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: std::time::Instant,
) -> Result<()> {
    use std::io::ErrorKind;
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        ensure!(
            !remaining.is_zero(),
            "mutation request exceeded its frame deadline"
        );
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(bytes) {
            Ok(0) => anyhow::bail!("mutation request ended before the frame was complete"),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                anyhow::bail!("mutation request exceeded its frame deadline")
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_exact_deadline(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: std::time::Instant,
) -> Result<()> {
    use std::io::ErrorKind;
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        ensure!(
            !remaining.is_zero(),
            "mutation response exceeded its frame deadline"
        );
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(bytes) {
            Ok(0) => anyhow::bail!("mutation response socket closed during frame write"),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                anyhow::bail!("mutation response exceeded its frame deadline")
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_response(stream: &mut UnixStream, response: &MutationResponse) -> Result<()> {
    let payload = serde_json::to_vec(response)?;
    ensure!(
        !payload.is_empty() && payload.len() <= MAX_FRAME,
        "mutation response exceeds frame limit"
    );
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    write_exact_deadline(stream, &(payload.len() as u32).to_le_bytes(), deadline)?;
    write_exact_deadline(stream, &payload, deadline)?;
    stream.flush()?;
    Ok(())
}

fn read_response_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    let mut header = [0u8; 4];
    read_exact_deadline(stream, &mut header, deadline)?;
    let length = u32::from_le_bytes(header) as usize;
    ensure!(
        (2..=MAX_FRAME).contains(&length),
        "mutation response frame length is invalid"
    );
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .context("cannot reserve bounded mutation response payload")?;
    bytes.resize(length, 0);
    read_exact_deadline(stream, &mut bytes, deadline)?;
    Ok(bytes)
}

fn validate_response_envelope(response: &MutationResponse) -> Result<()> {
    ensure!(
        response.version == VERSION,
        "mutation broker response version mismatch"
    );
    ensure!(
        response.message.len() <= 8 * 1024,
        "mutation response message exceeds limit"
    );
    ensure!(
        !response.message.is_empty(),
        "mutation broker response message is empty"
    );
    Ok(())
}

fn validate_identity(id: &str, generation: u64) -> Result<()> {
    ensure!(
        id.len() == 36
            && id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                }
            }),
        "activation ID must be a canonical lowercase UUID"
    );
    ensure!(generation > 0, "activation generation must be non-zero");
    Ok(())
}

/// Send one typed request to an already-running mutation helper.
pub fn call(socket_path: &Path, request: &MutationRequest) -> Result<MutationResponse> {
    request.validate()?;
    let payload = serde_json::to_vec(request)?;
    ensure!(
        !payload.is_empty() && payload.len() <= MAX_FRAME,
        "mutation request exceeds frame limit"
    );
    let mut stream =
        UnixStream::connect(socket_path).context("cannot connect to mutation broker")?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    write_exact_deadline(&mut stream, &(payload.len() as u32).to_le_bytes(), deadline)?;
    write_exact_deadline(&mut stream, &payload, deadline)?;
    stream.flush()?;
    let bytes = read_response_frame(&mut stream)?;
    let response: MutationResponse =
        serde_json::from_slice(&bytes).context("mutation broker response is malformed")?;
    validate_response_envelope(&response)?;
    ensure!(
        response.success,
        "mutation broker rejected request: {}",
        response.message
    );
    Ok(response)
}

/// Request the descriptor retained by one exact activation generation.
/// The broker authenticates the peer, sends a positive envelope, then transfers one fd.
pub fn attach_descriptor(
    socket_path: &Path,
    activation_id: &str,
    generation: u64,
) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    let request = MutationRequest::AttachDescriptor {
        version: VERSION,
        activation_id: activation_id.to_owned(),
        generation,
    };
    request.validate()?;
    let payload = serde_json::to_vec(&request)?;
    ensure!(
        !payload.is_empty() && payload.len() <= MAX_FRAME,
        "mutation request exceeds frame limit"
    );
    let mut stream = UnixStream::connect(socket_path)
        .context("cannot connect to mutation broker for TUN descriptor attachment")?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    write_exact_deadline(&mut stream, &(payload.len() as u32).to_le_bytes(), deadline)?;
    write_exact_deadline(&mut stream, &payload, deadline)?;
    stream.flush()?;
    let bytes = read_response_frame(&mut stream)?;
    let response: MutationResponse =
        serde_json::from_slice(&bytes).context("mutation broker response is malformed")?;
    validate_response_envelope(&response)?;
    ensure!(
        response.success,
        "mutation broker rejected descriptor attachment: {}",
        response.message
    );
    let descriptor = super::descriptor_transfer::receive_descriptor(&stream)?;
    ensure!(
        unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } >= 0,
        "received TUN descriptor is not valid"
    );
    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn activation() -> MutationRequest {
        MutationRequest::Activate {
            version: VERSION,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 8,
            interface_name: "tun-proxyctl".into(),
            owner_uid: 1000,
            owner_gid: 1000,
            table_id: 42420,
            bypass_priority: 42410,
            proxy_priority: 42420,
            core_mark: 0x42,
            core_mark_mask: 0xff,
        }
    }

    #[test]
    fn broker_recovery_refuses_to_mutate_while_manifest_core_is_live() {
        use std::process::{Command, Stdio};

        let mut child = Command::new("tail")
            .args(["-f", "/dev/null"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let identity = loop {
            assert!(std::time::Instant::now() < deadline);
            if let Ok(identity) = super::super::process::ProcessIdentity::capture(child.id())
                && identity.verify().unwrap_or(false)
            {
                break identity;
            }
            std::thread::sleep(Duration::from_millis(5));
        };

        assert!(ensure_managed_core_stopped(Some(&identity)).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(ensure_managed_core_stopped(Some(&identity)).is_ok());
        assert!(ensure_managed_core_stopped(None).is_ok());
    }

    #[test]
    fn refuses_symlinked_runtime_directory() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("runtime-link");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let socket = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(serve(&listener, &link).is_err());
    }

    #[test]
    fn refuses_runtime_directory_without_owner_write_access() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("broker.sock");
        // Create the socket while writable, then restrict the directory. This ensures the
        // test exercises broker validation rather than failing during socket creation.
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(serve(&listener, directory.path()).is_err());
        // Restore cleanup permissions for TempDir and its socket.
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn refuses_group_accessible_runtime_directory_before_accepting_clients() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let socket = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(serve(&listener, directory.path()).is_err());
    }

    #[test]
    fn rejects_oversized_request_frame_before_allocating_payload() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender
            .write_all(&((MAX_FRAME as u32) + 1).to_le_bytes())
            .unwrap();
        assert!(read_request(&mut receiver).is_err());
    }

    #[test]
    fn rejects_malformed_request_json_after_bounded_frame_read() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let payload = b"{not-json";
        sender
            .write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        sender.write_all(payload).unwrap();
        assert!(read_request(&mut receiver).is_err());
    }

    #[test]
    fn rejects_zero_length_request_frame() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&0u32.to_le_bytes()).unwrap();
        assert!(read_request(&mut receiver).is_err());
    }

    #[test]
    fn rejects_truncated_response_frame_payload() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&8u32.to_le_bytes()).unwrap();
        sender.write_all(b"short").unwrap();
        drop(sender);
        assert!(read_response_frame(&mut receiver).is_err());
    }

    #[test]
    fn rejects_truncated_response_frame_header() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&[1, 2]).unwrap();
        drop(sender);
        assert!(read_response_frame(&mut receiver).is_err());
    }

    #[test]
    fn rejects_response_frame_length_below_minimum() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&1u32.to_le_bytes()).unwrap();
        sender.write_all(b"x").unwrap();
        assert!(read_response_frame(&mut receiver).is_err());
    }

    #[test]
    fn rejects_response_frame_length_over_limit() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender
            .write_all(&((MAX_FRAME as u32) + 1).to_le_bytes())
            .unwrap();
        assert!(read_response_frame(&mut receiver).is_err());
    }

    #[test]
    fn rejects_malformed_response_json_from_frame() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let bytes = b"not-json";
        sender
            .write_all(&(bytes.len() as u32).to_le_bytes())
            .unwrap();
        sender.write_all(bytes).unwrap();
        let frame = read_response_frame(&mut receiver).unwrap();
        assert!(serde_json::from_slice::<MutationResponse>(&frame).is_err());
    }

    #[test]
    fn rejects_response_with_unknown_fields() {
        let malformed = br#"{"version":1,"success":true,"message":"ok","extra":true}"#;
        assert!(serde_json::from_slice::<MutationResponse>(malformed).is_err());
    }

    #[test]
    fn rejects_oversized_response_message_after_decode() {
        let response = MutationResponse {
            version: VERSION,
            success: true,
            message: "x".repeat(8 * 1024 + 1),
        };
        assert!(validate_response_envelope(&response).is_err());
    }

    #[test]
    fn rejects_response_message_above_envelope_bound() {
        let response = MutationResponse {
            version: VERSION,
            success: false,
            message: "x".repeat(8 * 1024 + 1),
        };
        assert!(validate_response_envelope(&response).is_err());
    }

    #[test]
    fn accepts_bounded_failure_response_envelope() {
        let response = MutationResponse {
            version: VERSION,
            success: false,
            message: "denied".into(),
        };
        assert!(validate_response_envelope(&response).is_ok());
    }

    #[test]
    fn accepts_valid_response_envelope() {
        let response = MutationResponse {
            version: VERSION,
            success: true,
            message: "ok".into(),
        };
        assert!(validate_response_envelope(&response).is_ok());
    }

    #[test]
    fn rejects_empty_response_message() {
        let response = MutationResponse {
            version: VERSION,
            success: true,
            message: String::new(),
        };
        assert!(validate_response_envelope(&response).is_err());
    }

    #[test]
    fn rejects_response_with_empty_failure_message() {
        let response = MutationResponse {
            version: VERSION,
            success: false,
            message: String::new(),
        };
        assert!(validate_response_envelope(&response).is_err());
    }

    #[test]
    fn rejects_response_version_mismatch() {
        let response = MutationResponse {
            version: VERSION + 1,
            success: true,
            message: "ok".into(),
        };
        assert!(validate_response_envelope(&response).is_err());
    }

    #[test]
    fn rejects_ping_protocol_version_mismatch() {
        assert!(
            MutationRequest::Ping {
                version: VERSION + 1
            }
            .validate()
            .is_err()
        );
        assert!(
            MutationRequest::Ping { version: VERSION }
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn validates_generation_bound_typed_activation_envelope() {
        assert!(activation().validate().is_ok());
        let mut invalid = activation();
        if let MutationRequest::Activate { generation, .. } = &mut invalid {
            *generation = 0;
        }
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rejects_unknown_or_oversized_protocol_payloads() {
        assert!(serde_json::from_slice::<MutationRequest>(br#"{"operation":"activate","version":1,"activation_id":"12345678-1234-4234-8234-123456789abc","generation":1,"interface_name":"tun0","owner_uid":1,"owner_gid":1,"table_id":42420,"bypass_priority":42410,"proxy_priority":42420,"core_mark":66,"core_mark_mask":255,"raw_netlink":"AA"}"#).is_err());
        const { assert!(MAX_FRAME < 64 * 1024) };
    }

    #[test]
    fn descriptor_export_envelope_is_generation_bound() {
        let request = MutationRequest::AttachDescriptor {
            version: VERSION,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 8,
        };
        assert!(request.validate().is_ok());
        let stale = MutationRequest::AttachDescriptor {
            version: VERSION,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 0,
        };
        assert!(stale.validate().is_err());
    }

    #[test]
    fn failure_envelope_truncates_long_messages_on_utf8_boundary() {
        let response = MutationResponse::failure("界".repeat(10_000));
        assert!(response.message.len() <= 8 * 1024 + 3);
        assert!(response.message.is_char_boundary(response.message.len()));
        assert!(response.message.ends_with("…"));
    }

    #[test]
    fn recovery_envelope_requires_canonical_activation_identity() {
        let request = MutationRequest::Recover {
            version: VERSION,
            activation_id: "12345678-1234-4234-8234-123456789ABC".into(),
            generation: 8,
        };
        assert!(request.validate().is_err());
    }
}

#[test]
fn native_activation_envelope_is_generation_and_policy_validated() {
    let request = MutationRequest::ActivateNative {
        version: VERSION,
        activation_id: "12345678-1234-4234-8234-123456789abc".into(),
        generation: 8,
        interface_name: "tun-proxyctl".into(),
        owner_uid: 1000,
        owner_gid: 1000,
        table_id: 42420,
        bypass_priority: 42410,
        proxy_priority: 42420,
        core_mark: 0x42,
        core_mark_mask: 0xff,
    };
    assert!(request.validate().is_ok());
    let mut stale = request.clone();
    if let MutationRequest::ActivateNative { generation, .. } = &mut stale {
        *generation = 0;
    }
    assert!(stale.validate().is_err());
    let mut invalid_name = request;
    if let MutationRequest::ActivateNative { interface_name, .. } = &mut invalid_name {
        *interface_name = "bad/name".into();
    }
    assert!(invalid_name.validate().is_err());
}

#[test]
fn native_activation_wire_operation_is_distinct_from_descriptor_activation() {
    let native = MutationRequest::ActivateNative {
        version: VERSION,
        activation_id: "12345678-1234-4234-8234-123456789abc".into(),
        generation: 8,
        interface_name: "tun-proxyctl".into(),
        owner_uid: 1000,
        owner_gid: 1000,
        table_id: 42420,
        bypass_priority: 42410,
        proxy_priority: 42420,
        core_mark: 0x42,
        core_mark_mask: 0xff,
    };
    let encoded = serde_json::to_value(&native).unwrap();
    assert_eq!(
        encoded.get("operation").and_then(serde_json::Value::as_str),
        Some("activate_native")
    );
    assert!(
        serde_json::from_value::<MutationRequest>(encoded)
            .unwrap()
            .validate()
            .is_ok()
    );
}
