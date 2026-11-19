//! Persistent typed Linux mutation-broker service.
//!
//! This protocol is intentionally separate from the read-only socket-mark diagnostic broker.
//! Requests describe complete typed policy operations; raw netlink bytes, command strings,
//! executable paths, and arbitrary ioctl requests are not representable.
#![cfg(target_os = "linux")]

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::{UnixListener, UnixStream}},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    journal_recovery_executor::recover,
    kernel_transaction::{self, KernelTransaction},
    linux_journal_backend::LinuxJournalBackend,
    manifest_store::ManifestStore,
    route_policy::RoutingPolicyPlan,
    privilege_broker::read_broker_peer_credentials,
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
            Self::Activate { version, activation_id, generation, interface_name, table_id,
                bypass_priority, proxy_priority, core_mark, core_mark_mask, .. } => {
                ensure!(*version == VERSION, "unsupported mutation broker protocol version");
                validate_identity(activation_id, *generation)?;
                let plan = RoutingPolicyPlan::new(*table_id, *bypass_priority, *proxy_priority,
                    *core_mark, *core_mark_mask, interface_name, 1);
                plan.validate()?;
            }
            Self::Recover { version, activation_id, generation } => {
                ensure!(*version == VERSION, "unsupported mutation broker protocol version");
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
        Self { version: VERSION, success: true, message: message.into() }
    }
    fn failure(error: impl std::fmt::Display) -> Self {
        Self { version: VERSION, success: false, message: error.to_string() }
    }
}

/// Run until the service is stopped. The backend map is deliberately process-lifetime state:
/// it retains each active TUN descriptor between independent client connections.
pub fn serve(listener: &UnixListener, runtime_directory: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(runtime_directory)?;
    ensure!(metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() },
        "mutation broker runtime directory must be a real caller-owned directory");
    let mut backends: BTreeMap<(String, u64), LinuxJournalBackend> = BTreeMap::new();
    loop {
        let (mut stream, _) = listener.accept().context("cannot accept mutation broker client")?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        let peer = read_broker_peer_credentials(&stream)?;
        ensure!(peer.uid == unsafe { libc::geteuid() },
            "mutation broker accepts requests only from its owning user");
        let request = read_request(&mut stream)?;
        let response = match request.validate() {
            Ok(()) => match execute(request, runtime_directory, &mut backends) {
                Ok(message) => MutationResponse::success(message),
                Err(error) => MutationResponse::failure(format!("{error:#}")),
            },
            Err(error) => MutationResponse::failure(format!("{error:#}")),
        };
        write_response(&mut stream, &response)?;
    }
}

fn execute(request: MutationRequest, directory: &Path,
    backends: &mut BTreeMap<(String, u64), LinuxJournalBackend>) -> Result<String> {
    match request {
        MutationRequest::Activate { activation_id, generation, interface_name, owner_uid, owner_gid,
            table_id, bypass_priority, proxy_priority, core_mark, core_mark_mask, .. } => {
            let key = (activation_id.clone(), generation);
            ensure!(!backends.contains_key(&key), "activation generation already has a live broker backend");
            let store = ManifestStore::open(directory)?;
            let backend = LinuxJournalBackend::new(store, &activation_id, generation)?;
            let policy = RoutingPolicyPlan::new(table_id, bypass_priority, proxy_priority,
                core_mark, core_mark_mask, interface_name, 1);
            let transaction = KernelTransaction { activation_id: activation_id.clone(), policy,
                owner_uid, owner_gid };
            // Keep the backend even when apply fails: an error can follow an acknowledged
            // mutation or an unresolved write-ahead intent, and its descriptor must stay owned.
            let mut backend = backend;
            let result = kernel_transaction::apply(&transaction, &mut backend);
            backends.insert(key, backend);
            result.map(|_| format!("activation {activation_id} generation {generation} committed"))
        }
        MutationRequest::Recover { activation_id, generation, .. } => {
            let key = (activation_id.clone(), generation);
            let mut backend = match backends.remove(&key) {
                Some(backend) => backend,
                None => LinuxJournalBackend::open_for_recovery(
                    ManifestStore::open(directory)?, &activation_id, generation)?,
            };
            let result = recover(&ManifestStore::open(directory)?, &mut backend);
            if result.is_err() {
                backends.insert(key, backend);
            }
            result.map(|report| format!("recovery complete: {} removed, {} already absent, {} intents resolved",
                report.removed.len(), report.already_absent.len(), report.resolved_intents.len()))
        }
    }
}

fn read_request(stream: &mut UnixStream) -> Result<MutationRequest> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    ensure!(length > 0 && length <= MAX_FRAME, "mutation request frame length is invalid");
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).context("mutation request JSON is malformed")
}

fn write_response(stream: &mut UnixStream, response: &MutationResponse) -> Result<()> {
    let payload = serde_json::to_vec(response)?;
    ensure!(payload.len() <= MAX_FRAME, "mutation response exceeds frame limit");
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn validate_identity(id: &str, generation: u64) -> Result<()> {
    ensure!(id.len() == 36 && id.bytes().enumerate().all(|(i, b)| {
        if [8, 13, 18, 23].contains(&i) { b == b'-' }
        else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() }
    }), "activation ID must be a canonical lowercase UUID");
    ensure!(generation > 0, "activation generation must be non-zero");
    Ok(())
}
