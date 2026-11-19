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
        fs::MetadataExt,
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
    Recover {
        version: u32,
        activation_id: String,
        generation: u64,
    },
}

impl MutationRequest {
    fn validate(&self) -> Result<()> {
        match self {
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
            Self::Recover {
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
        Self {
            version: VERSION,
            success: false,
            message: error.to_string(),
        }
    }
}

/// Run until the service is stopped. The backend map is deliberately process-lifetime state:
/// it retains each active TUN descriptor between independent client connections.
pub fn serve(listener: &UnixListener, runtime_directory: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(runtime_directory)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() },
        "mutation broker runtime directory must be a real caller-owned directory"
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
            let response = match request.validate().and_then(|()| {
                if let MutationRequest::Activate {
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

fn execute(
    request: MutationRequest,
    directory: &Path,
    backends: &mut BTreeMap<(String, u64), LinuxJournalBackend>,
) -> Result<String> {
    match request {
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
            // The kernel policy and persistent TUN owner are process-lifetime resources.
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
            let backend = LinuxJournalBackend::new(store, &activation_id, generation)?;
            let transaction = KernelTransaction {
                activation_id: activation_id.clone(),
                policy,
                owner_uid,
                owner_gid,
            };
            // Keep the backend even when apply fails: an error can follow an acknowledged
            // mutation or an unresolved write-ahead intent, and its descriptor must stay owned.
            let mut backend = backend;
            let result = kernel_transaction::apply(&transaction, &mut backend);
            backends.insert(key, backend);
            result.map(|_| format!("activation {activation_id} generation {generation} committed"))
        }
        MutationRequest::Recover {
            activation_id,
            generation,
            ..
        } => {
            let key = (activation_id.clone(), generation);
            let mut backend = match backends.remove(&key) {
                Some(backend) => backend,
                None => LinuxJournalBackend::open_for_recovery(
                    ManifestStore::open(directory)?,
                    &activation_id,
                    generation,
                )?,
            };
            let result = recover(&ManifestStore::open(directory)?, &mut backend);
            if result.is_err() {
                backends.insert(key, backend);
            }
            result.map(|report| {
                format!(
                    "recovery complete: {} removed, {} already absent, {} intents resolved",
                    report.removed.len(),
                    report.already_absent.len(),
                    report.resolved_intents.len()
                )
            })
        }
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
    let mut payload = vec![0u8; length];
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

fn write_response(stream: &mut UnixStream, response: &MutationResponse) -> Result<()> {
    let payload = serde_json::to_vec(response)?;
    ensure!(
        payload.len() <= MAX_FRAME,
        "mutation response exceeds frame limit"
    );
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
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
        payload.len() <= MAX_FRAME,
        "mutation request exceeds frame limit"
    );
    let mut stream =
        UnixStream::connect(socket_path).context("cannot connect to mutation broker")?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    ensure!(
        length > 0 && length <= MAX_FRAME,
        "mutation response frame length is invalid"
    );
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes)?;
    let response: MutationResponse =
        serde_json::from_slice(&bytes).context("mutation broker response is malformed")?;
    ensure!(
        response.version == VERSION,
        "mutation broker response version mismatch"
    );
    ensure!(
        response.success,
        "mutation broker rejected request: {}",
        response.message
    );
    Ok(response)
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
    fn recovery_envelope_requires_canonical_activation_identity() {
        let request = MutationRequest::Recover {
            version: VERSION,
            activation_id: "12345678-1234-4234-8234-123456789ABC".into(),
            generation: 8,
        };
        assert!(request.validate().is_err());
    }
}
