//! Durable, private storage for TUN ownership manifests.
//!
//! This module only writes Proxyctl runtime files. It does not inspect or mutate kernel state.
//! The caller must serialize lifecycle operations; this store prevents stale activations from
//! overwriting or deleting a different activation's recovery record.

#[cfg(target_os = "linux")]
use super::process::ProcessIdentity;
use super::{
    ownership::RouteManifest,
    recovery::{RecoveryAction, SupervisorEvent, SupervisorPhase, transition},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const STORE_FILE: &str = "tun-manifest.json";
const JOURNAL_FILE: &str = "tun-transaction-journal.json";
const STORE_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024;
const MAX_JOURNAL_OPERATIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSnapshot {
    pub schema_version: u32,
    pub generation: u64,
    pub phase: SupervisorPhase,
    pub manifest: RouteManifest,
    #[cfg(target_os = "linux")]
    #[serde(default)]
    pub core_process: Option<ProcessIdentity>,
}

impl ManifestSnapshot {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == STORE_VERSION,
            "unsupported TUN manifest store version"
        );
        ensure!(
            self.generation > 0,
            "TUN manifest generation must be non-zero"
        );
        self.manifest.validate()?;
        #[cfg(target_os = "linux")]
        if let Some(process) = &self.core_process {
            process.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalOperationKind {
    CreateInterface,
    AddRoute,
    AddRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalOperationState {
    Intent,
    Applied,
    Removed,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalOperation {
    pub sequence: u32,
    pub kind: JournalOperationKind,
    pub resource_key: String,
    pub state: JournalOperationState,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionJournal {
    pub schema_version: u32,
    pub activation_id: String,
    pub generation: u64,
    pub operations: Vec<JournalOperation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalRecoveryAction {
    /// Kernel state must be inspected; no deletion is authorized by an intent alone.
    InspectAmbiguousIntent,
    /// Compare the live resource's full fingerprint before attempting deletion.
    CompareAndDelete,
    /// Cleanup was durably recorded; do not repeat the mutation.
    SkipAlreadyRemoved,
}

pub fn recovery_action(operation: &JournalOperation) -> JournalRecoveryAction {
    match operation.state {
        JournalOperationState::Intent => JournalRecoveryAction::InspectAmbiguousIntent,
        JournalOperationState::Applied => JournalRecoveryAction::CompareAndDelete,
        JournalOperationState::Removed | JournalOperationState::Absent => {
            JournalRecoveryAction::SkipAlreadyRemoved
        }
    }
}

/// A fail-closed recovery decision derived from one journal operation and a fresh exact
/// kernel fingerprint lookup. This planner never performs a mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecoveryDecision {
    MarkAbsent,
    CompareAndDelete { expected_fingerprint: String },
    MarkRemoved,
    PreserveAndReportConflict,
    Skip,
}

/// Plan recovery in reverse creation order. The observed map must come from a fresh exact
/// kernel inventory; None means the exact resource identity is absent.
pub fn plan_journal_recovery(
    journal: &TransactionJournal,
    observed: &std::collections::BTreeMap<String, Option<String>>,
) -> Result<Vec<(String, JournalRecoveryDecision)>> {
    journal.validate()?;
    let mut decisions = Vec::with_capacity(journal.operations.len());
    for operation in journal.operations.iter().rev() {
        let current = observed.get(&operation.resource_key).cloned().flatten();
        let decision = match operation.state {
            JournalOperationState::Intent => {
                if observed.contains_key(&operation.resource_key) && current.is_none() {
                    JournalRecoveryDecision::MarkAbsent
                } else {
                    JournalRecoveryDecision::PreserveAndReportConflict
                }
            }
            JournalOperationState::Applied => {
                if !observed.contains_key(&operation.resource_key) {
                    JournalRecoveryDecision::PreserveAndReportConflict
                } else {
                    match (operation.fingerprint.as_ref(), current) {
                        (Some(_), None) => JournalRecoveryDecision::MarkRemoved,
                        (Some(expected), Some(actual)) if *expected == actual => {
                            JournalRecoveryDecision::CompareAndDelete {
                                expected_fingerprint: expected.clone(),
                            }
                        }
                        _ => JournalRecoveryDecision::PreserveAndReportConflict,
                    }
                }
            }
            JournalOperationState::Removed | JournalOperationState::Absent => {
                JournalRecoveryDecision::Skip
            }
        };
        decisions.push((operation.resource_key.clone(), decision));
    }
    Ok(decisions)
}

impl TransactionJournal {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported TUN transaction journal version"
        );
        ensure!(
            valid_journal_activation_id(&self.activation_id),
            "invalid journal activation identity"
        );
        ensure!(self.generation > 0, "journal generation must be non-zero");
        ensure!(
            self.operations.len() <= MAX_JOURNAL_OPERATIONS,
            "too many journal operations"
        );
        let mut keys = std::collections::BTreeSet::new();
        for (index, operation) in self.operations.iter().enumerate() {
            ensure!(
                operation.sequence as usize == index,
                "journal operation sequence is not contiguous"
            );
            ensure!(
                !operation.resource_key.is_empty() && operation.resource_key.len() <= 512,
                "invalid journal resource key"
            );
            ensure!(
                !operation.resource_key.chars().any(char::is_control),
                "journal resource key contains control characters"
            );
            ensure!(
                keys.insert(operation.resource_key.as_str()),
                "duplicate journal resource key"
            );
            match operation.state {
                JournalOperationState::Intent => ensure!(
                    operation.fingerprint.is_none(),
                    "intent cannot contain a fingerprint"
                ),
                JournalOperationState::Applied | JournalOperationState::Removed => ensure!(
                    operation
                        .fingerprint
                        .as_ref()
                        .is_some_and(|value| !value.is_empty()
                            && value.len() <= 16 * 1024
                            && !value.chars().any(char::is_control)),
                    "applied journal operation requires a valid fingerprint"
                ),
                JournalOperationState::Absent => ensure!(
                    operation.fingerprint.is_none(),
                    "absent journal operation cannot contain a fingerprint"
                ),
            }
        }
        Ok(())
    }
}

fn valid_journal_activation_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

/// Private manifest storage rooted in Proxyctl's runtime directory.
#[derive(Debug, Clone)]
pub struct ManifestStore {
    directory: PathBuf,
}

impl ManifestStore {
    /// Create or validate a private runtime directory. Existing directories are tightened to 0700
    /// only when owned by the current user; symlink directories are always rejected.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self> {
        let directory = directory.into();
        fs::create_dir_all(&directory).with_context(|| {
            format!(
                "cannot create TUN runtime directory {}",
                directory.display()
            )
        })?;
        let metadata = fs::symlink_metadata(&directory).with_context(|| {
            format!(
                "cannot inspect TUN runtime directory {}",
                directory.display()
            )
        })?;
        ensure!(
            metadata.file_type().is_dir(),
            "TUN runtime path is not a real directory"
        );
        verify_owner(&metadata)?;
        set_private_directory(&directory)?;
        let metadata = fs::metadata(&directory)?;
        verify_private_directory(&metadata)?;
        Ok(Self { directory })
    }

    pub fn path(&self) -> PathBuf {
        self.directory.join(STORE_FILE)
    }

    /// Create the first durable record for a new activation.
    ///
    /// Callers must hold the process-wide lifecycle lock while creating or transitioning a
    /// manifest. This method refuses to replace an existing recovery record.
    pub fn create_prepared(&self, snapshot: &ManifestSnapshot) -> Result<()> {
        ensure!(
            snapshot.phase == SupervisorPhase::Prepared,
            "new TUN manifest must begin in the prepared phase"
        );
        #[cfg(target_os = "linux")]
        ensure!(
            snapshot.core_process.is_none(),
            "new TUN manifest cannot begin with a pre-bound core process"
        );
        ensure!(
            self.load()?.is_none(),
            "an existing TUN recovery manifest must be recovered before a new activation"
        );
        self.write(snapshot)
    }

    /// Apply one generation-scoped lifecycle event and persist its phase before returning.
    ///
    /// Cleanup completion is durable before the manifest is removed. If removal fails, the
    /// remaining Cleaned record is safe to remove on the next recovery pass.
    pub fn apply_event(&self, event: SupervisorEvent, generation: u64) -> Result<RecoveryAction> {
        let mut snapshot = self
            .load()?
            .ok_or_else(|| anyhow::anyhow!("no TUN recovery manifest exists"))?;
        let next = transition(snapshot.phase, event, generation, snapshot.generation);
        if next.action == RecoveryAction::IgnoreStaleEvent {
            return Ok(next.action);
        }
        if next.phase != snapshot.phase {
            snapshot.phase = next.phase;
            self.write(&snapshot)?;
        }
        if next.action == RecoveryAction::RemoveManifest {
            self.remove_cleaned(&snapshot.manifest.activation_id, snapshot.generation)?;
        }
        Ok(next.action)
    }

    /// Persist a snapshot atomically. A different activation/generation cannot be overwritten.
    pub fn write(&self, snapshot: &ManifestSnapshot) -> Result<()> {
        snapshot.validate()?;
        let destination = self.path();
        if let Some(existing) = self.load()? {
            ensure!(
                existing.generation == snapshot.generation
                    && existing.manifest.activation_id == snapshot.manifest.activation_id,
                "refusing to overwrite a different TUN activation manifest"
            );
        }
        if let Ok(metadata) = fs::symlink_metadata(&destination) {
            ensure!(
                metadata.file_type().is_file(),
                "TUN manifest path is not a regular file"
            );
            verify_owner(&metadata)?;
            verify_private_file(&metadata)?;
        }

        let bytes = serde_json::to_vec_pretty(snapshot)?;
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST_BYTES,
            "TUN manifest exceeds size limit"
        );
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)
            .context("cannot create private temporary TUN manifest")?;
        set_private_file(temporary.as_file())?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&destination)
            .context("cannot atomically replace TUN manifest")?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    /// Read and validate the manifest without following symlinks or accepting permissive files.
    pub fn load(&self) -> Result<Option<ManifestSnapshot>> {
        let path = self.path();
        let file = match open_private_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("cannot securely open TUN manifest"),
        };
        let metadata = file.metadata()?;
        ensure!(
            metadata.len() <= MAX_MANIFEST_BYTES,
            "TUN manifest exceeds size limit"
        );
        ensure!(
            metadata.file_type().is_file(),
            "TUN manifest is not a regular file"
        );
        verify_owner(&metadata)?;
        verify_private_file(&metadata)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST_BYTES,
            "TUN manifest exceeds size limit"
        );
        let snapshot: ManifestSnapshot =
            serde_json::from_slice(&bytes).context("TUN manifest is malformed")?;
        snapshot.validate()?;
        Ok(Some(snapshot))
    }

    pub fn journal_path(&self) -> PathBuf {
        self.directory.join(JOURNAL_FILE)
    }

    /// Create the write-ahead journal before the first kernel mutation.
    ///
    /// The caller must hold the process-wide lifecycle lock across journal creation and every
    /// subsequent update. This store deliberately does not acquire a second lock internally.
    pub fn create_transaction_journal(&self, activation_id: &str, generation: u64) -> Result<()> {
        let journal = TransactionJournal {
            schema_version: 1,
            activation_id: activation_id.to_owned(),
            generation,
            operations: Vec::new(),
        };
        journal.validate()?;
        ensure!(
            self.load_transaction_journal()?.is_none(),
            "an existing TUN transaction journal must be recovered first"
        );
        self.write_journal(&journal)
    }

    /// Persist an operation intent before attempting its kernel mutation.
    pub fn record_operation_intent(
        &self,
        activation_id: &str,
        generation: u64,
        kind: JournalOperationKind,
        resource_key: &str,
    ) -> Result<()> {
        let mut journal = self
            .load_transaction_journal()?
            .ok_or_else(|| anyhow::anyhow!("no TUN transaction journal exists"))?;
        ensure!(
            journal.activation_id == activation_id && journal.generation == generation,
            "journal activation or generation mismatch"
        );
        ensure!(
            journal.operations.len() < MAX_JOURNAL_OPERATIONS,
            "too many journal operations"
        );
        ensure!(
            !resource_key.is_empty()
                && resource_key.len() <= 512
                && !resource_key.chars().any(char::is_control),
            "invalid journal resource key"
        );
        ensure!(
            !journal
                .operations
                .iter()
                .any(|operation| operation.resource_key == resource_key),
            "journal resource already exists"
        );
        journal.operations.push(JournalOperation {
            sequence: journal.operations.len() as u32,
            kind,
            resource_key: resource_key.to_owned(),
            state: JournalOperationState::Intent,
            fingerprint: None,
        });
        self.write_journal(&journal)
    }

    pub fn mark_operation_applied(
        &self,
        activation_id: &str,
        generation: u64,
        resource_key: &str,
        fingerprint: &str,
    ) -> Result<()> {
        ensure!(
            !fingerprint.is_empty()
                && fingerprint.len() <= 16 * 1024
                && !fingerprint.chars().any(char::is_control),
            "invalid journal fingerprint"
        );
        self.update_journal_operation(activation_id, generation, resource_key, |operation| {
            ensure!(
                operation.state == JournalOperationState::Intent,
                "only an intended operation can become applied"
            );
            operation.state = JournalOperationState::Applied;
            operation.fingerprint = Some(fingerprint.to_owned());
            Ok(())
        })
    }

    /// Mark cleanup only after compare-and-delete confirms removal or absence.
    pub fn mark_operation_removed(
        &self,
        activation_id: &str,
        generation: u64,
        resource_key: &str,
    ) -> Result<()> {
        self.update_journal_operation(activation_id, generation, resource_key, |operation| {
            ensure!(
                operation.state == JournalOperationState::Applied,
                "only an applied operation can become removed"
            );
            operation.state = JournalOperationState::Removed;
            Ok(())
        })
    }

    fn update_journal_operation(
        &self,
        activation_id: &str,
        generation: u64,
        resource_key: &str,
        update: impl FnOnce(&mut JournalOperation) -> Result<()>,
    ) -> Result<()> {
        let mut journal = self
            .load_transaction_journal()?
            .ok_or_else(|| anyhow::anyhow!("no TUN transaction journal exists"))?;
        ensure!(
            journal.activation_id == activation_id && journal.generation == generation,
            "journal activation or generation mismatch"
        );
        let operation = journal
            .operations
            .iter_mut()
            .find(|operation| operation.resource_key == resource_key)
            .ok_or_else(|| anyhow::anyhow!("journal operation does not exist"))?;
        update(operation)?;
        self.write_journal(&journal)
    }

    pub fn load_transaction_journal(&self) -> Result<Option<TransactionJournal>> {
        let file = match open_private_file(&self.journal_path()) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).context("cannot securely open TUN transaction journal");
            }
        };
        let metadata = file.metadata()?;
        ensure!(
            metadata.len() <= MAX_JOURNAL_BYTES,
            "TUN transaction journal exceeds size limit"
        );
        ensure!(
            metadata.file_type().is_file(),
            "TUN transaction journal is not a regular file"
        );
        verify_owner(&metadata)?;
        verify_private_file(&metadata)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_JOURNAL_BYTES,
            "TUN transaction journal exceeds size limit"
        );
        let journal: TransactionJournal =
            serde_json::from_slice(&bytes).context("TUN transaction journal is malformed")?;
        journal.validate()?;
        Ok(Some(journal))
    }

    /// Resolve an intent as absent only after exact kernel inspection proves no resource exists.
    pub fn mark_intent_absent(
        &self,
        activation_id: &str,
        generation: u64,
        resource_key: &str,
    ) -> Result<()> {
        self.update_journal_operation(activation_id, generation, resource_key, |operation| {
            ensure!(
                operation.state == JournalOperationState::Intent,
                "only an unresolved intent can be confirmed absent"
            );
            operation.state = JournalOperationState::Absent;
            Ok(())
        })
    }

    pub fn remove_completed_transaction_journal(
        &self,
        activation_id: &str,
        generation: u64,
    ) -> Result<()> {
        let Some(journal) = self.load_transaction_journal()? else {
            return Ok(());
        };
        ensure!(
            journal.activation_id == activation_id && journal.generation == generation,
            "refusing to remove another transaction journal"
        );
        ensure!(
            journal.operations.iter().all(|operation| matches!(
                operation.state,
                JournalOperationState::Removed | JournalOperationState::Absent
            )),
            "refusing to remove an incomplete transaction journal"
        );
        match fs::remove_file(self.journal_path()) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn write_journal(&self, journal: &TransactionJournal) -> Result<()> {
        journal.validate()?;
        let destination = self.journal_path();
        if let Ok(metadata) = fs::symlink_metadata(&destination) {
            ensure!(
                metadata.file_type().is_file(),
                "TUN transaction journal path is not a regular file"
            );
            verify_owner(&metadata)?;
            verify_private_file(&metadata)?;
        }
        let bytes = serde_json::to_vec_pretty(journal)?;
        ensure!(
            bytes.len() as u64 <= MAX_JOURNAL_BYTES,
            "TUN transaction journal exceeds size limit"
        );
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)
            .context("cannot create private TUN transaction journal")?;
        set_private_file(temporary.as_file())?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(&destination)
            .context("cannot atomically replace TUN transaction journal")?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    /// Remove only the exact activation after its cleanup phase has completed.
    pub fn remove_cleaned(&self, activation_id: &str, generation: u64) -> Result<()> {
        let Some(snapshot) = self.load()? else {
            return Ok(());
        };
        ensure!(
            snapshot.manifest.activation_id == activation_id && snapshot.generation == generation,
            "refusing to remove a different TUN activation manifest"
        );
        ensure!(
            snapshot.phase == SupervisorPhase::Cleaned,
            "refusing to remove a TUN manifest before cleanup is complete"
        );
        match fs::remove_file(self.path()) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(unix)]
fn verify_owner(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "TUN runtime file has a foreign owner"
    );
    Ok(())
}

#[cfg(not(unix))]
fn verify_owner(_metadata: &fs::Metadata) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage requires Unix file ownership support")
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage is supported only on Unix")
}

#[cfg(unix)]
fn verify_private_directory(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "TUN runtime directory permissions are not private"
    );
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_directory(_metadata: &fs::Metadata) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage is supported only on Unix")
}

#[cfg(unix)]
fn set_private_file(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_file: &File) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage is supported only on Unix")
}

#[cfg(unix)]
fn verify_private_file(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "TUN manifest permissions are not private"
    );
    ensure!(
        metadata.nlink() == 1,
        "TUN manifest must not have external hard links"
    );
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_file(_metadata: &fs::Metadata) -> Result<()> {
    anyhow::bail!("secure TUN manifest storage is supported only on Unix")
}

#[cfg(unix)]
fn open_private_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_private_file(_path: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure TUN manifest storage is supported only on Unix",
    ))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::ownership::{MANIFEST_VERSION, OwnedResource};

    fn snapshot() -> ManifestSnapshot {
        ManifestSnapshot {
            schema_version: STORE_VERSION,
            generation: 9,
            phase: SupervisorPhase::Prepared,
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
                    fingerprint: "sha256:fixture".into(),
                }],
            },
        }
    }

    #[cfg(unix)]
    #[test]
    fn persists_atomically_with_private_permissions_and_round_trips() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let original = snapshot();
        store.write(&original).unwrap();
        assert_eq!(store.load().unwrap(), Some(original));
        assert_eq!(
            fs::metadata(store.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(directory.path().join("runtime"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_overwrite_or_remove_another_activation() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let original = snapshot();
        store.write(&original).unwrap();
        let mut other = original.clone();
        other.generation += 1;
        assert!(store.write(&other).is_err());
        assert!(
            store
                .remove_cleaned("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 9)
                .is_err()
        );
        assert_eq!(store.load().unwrap(), Some(original));
    }

    #[cfg(unix)]
    #[test]
    fn manifest_is_removed_only_after_matching_generation_is_cleaned() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let mut value = snapshot();
        store.write(&value).unwrap();
        assert!(
            store
                .remove_cleaned(&value.manifest.activation_id, value.generation)
                .is_err()
        );
        value.phase = SupervisorPhase::Cleaned;
        store.write(&value).unwrap();
        store
            .remove_cleaned(&value.manifest.activation_id, value.generation)
            .unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_events_are_generation_checked_and_durably_transitioned() {
        use super::super::recovery::{RecoveryAction, SupervisorEvent};

        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let original = snapshot();
        store.create_prepared(&original).unwrap();
        assert_eq!(
            store
                .apply_event(SupervisorEvent::StartCommitted, 9)
                .unwrap(),
            RecoveryAction::StartManagedCore
        );
        assert_eq!(
            store.load().unwrap().unwrap().phase,
            SupervisorPhase::Running
        );

        assert_eq!(
            store.apply_event(SupervisorEvent::CoreExited, 8).unwrap(),
            RecoveryAction::IgnoreStaleEvent
        );
        assert_eq!(
            store.load().unwrap().unwrap().phase,
            SupervisorPhase::Running
        );

        assert_eq!(
            store.apply_event(SupervisorEvent::CoreExited, 9).unwrap(),
            RecoveryAction::CleanupManifestResources
        );
        assert_eq!(
            store.load().unwrap().unwrap().phase,
            SupervisorPhase::CleanupPending
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_conflict_preserves_manifest_and_success_removes_it() {
        use super::super::recovery::{RecoveryAction, SupervisorEvent};

        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        store.create_prepared(&snapshot()).unwrap();
        store
            .apply_event(SupervisorEvent::StartCommitted, 9)
            .unwrap();
        store.apply_event(SupervisorEvent::CoreExited, 9).unwrap();

        assert_eq!(
            store
                .apply_event(SupervisorEvent::CleanupConflicted, 9)
                .unwrap(),
            RecoveryAction::PreserveManifestAndReportConflict
        );
        assert_eq!(
            store.load().unwrap().unwrap().phase,
            SupervisorPhase::CleanupPending
        );

        assert_eq!(
            store
                .apply_event(SupervisorEvent::CleanupCompleted, 9)
                .unwrap(),
            RecoveryAction::RemoveManifest
        );
        assert!(store.load().unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_create_over_an_existing_recovery_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let original = snapshot();
        store.create_prepared(&original).unwrap();
        let mut another = original.clone();
        another.generation += 1;
        another.manifest.activation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
        assert!(store.create_prepared(&another).is_err());
        assert_eq!(store.load().unwrap(), Some(original));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_manifest_symlink_and_permissive_file() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let target = directory.path().join("outside.json");
        fs::write(&target, serde_json::to_vec(&snapshot()).unwrap()).unwrap();
        symlink(&target, store.path()).unwrap();
        assert!(store.load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_manifest_with_external_hard_link() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        store.write(&snapshot()).unwrap();
        let external = directory.path().join("linked-manifest.json");
        fs::hard_link(store.path(), external).unwrap();
        assert!(store.load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_planner_reverses_order_and_never_deletes_unresolved_intents() {
        let journal = TransactionJournal {
            schema_version: 1,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 7,
            operations: vec![
                JournalOperation {
                    sequence: 0,
                    kind: JournalOperationKind::CreateInterface,
                    resource_key: "interface:tun-proxyctl".into(),
                    state: JournalOperationState::Intent,
                    fingerprint: None,
                },
                JournalOperation {
                    sequence: 1,
                    kind: JournalOperationKind::AddRoute,
                    resource_key: "route:v4:42420:default".into(),
                    state: JournalOperationState::Applied,
                    fingerprint: Some("route-fp".into()),
                },
                JournalOperation {
                    sequence: 2,
                    kind: JournalOperationKind::AddRule,
                    resource_key: "rule:v4:42420".into(),
                    state: JournalOperationState::Applied,
                    fingerprint: Some("rule-fp".into()),
                },
            ],
        };
        let observed = std::collections::BTreeMap::from([
            ("interface:tun-proxyctl".into(), None),
            ("route:v4:42420:default".into(), Some("route-fp".into())),
            ("rule:v4:42420".into(), None),
        ]);
        let plan = plan_journal_recovery(&journal, &observed).unwrap();
        assert_eq!(plan[0].0, "rule:v4:42420");
        assert_eq!(plan[0].1, JournalRecoveryDecision::MarkRemoved);
        assert_eq!(
            plan[1].1,
            JournalRecoveryDecision::CompareAndDelete {
                expected_fingerprint: "route-fp".into()
            }
        );
        assert_eq!(plan[2].1, JournalRecoveryDecision::MarkAbsent);
    }

    #[test]
    fn recovery_planner_preserves_unobserved_or_changed_resources() {
        let journal = TransactionJournal {
            schema_version: 1,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 7,
            operations: vec![
                JournalOperation {
                    sequence: 0,
                    kind: JournalOperationKind::AddRoute,
                    resource_key: "route:a".into(),
                    state: JournalOperationState::Intent,
                    fingerprint: None,
                },
                JournalOperation {
                    sequence: 1,
                    kind: JournalOperationKind::AddRule,
                    resource_key: "rule:b".into(),
                    state: JournalOperationState::Applied,
                    fingerprint: Some("expected".into()),
                },
            ],
        };
        let observed = std::collections::BTreeMap::from([
            ("route:a".into(), Some("possibly-foreign".into())),
            ("rule:b".into(), Some("changed".into())),
        ]);
        let plan = plan_journal_recovery(&journal, &observed).unwrap();
        assert!(
            plan.iter().all(
                |(_, decision)| *decision == JournalRecoveryDecision::PreserveAndReportConflict
            )
        );
    }

    #[test]
    fn recovery_planner_does_not_treat_missing_inventory_as_absence_for_applied_resource() {
        let journal = TransactionJournal {
            schema_version: 1,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 7,
            operations: vec![JournalOperation {
                sequence: 0,
                kind: JournalOperationKind::AddRoute,
                resource_key: "route:v4:42420:default".into(),
                state: JournalOperationState::Applied,
                fingerprint: Some("route-fp".into()),
            }],
        };
        let plan = plan_journal_recovery(&journal, &std::collections::BTreeMap::new()).unwrap();
        assert_eq!(
            plan[0].1,
            JournalRecoveryDecision::PreserveAndReportConflict
        );
    }

    #[test]
    fn recovery_planner_requires_explicit_inventory_entry_for_intent_absence() {
        let journal = TransactionJournal {
            schema_version: 1,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 7,
            operations: vec![JournalOperation {
                sequence: 0,
                kind: JournalOperationKind::CreateInterface,
                resource_key: "interface:tun-proxyctl".into(),
                state: JournalOperationState::Intent,
                fingerprint: None,
            }],
        };
        let plan = plan_journal_recovery(&journal, &std::collections::BTreeMap::new()).unwrap();
        assert_eq!(
            plan[0].1,
            JournalRecoveryDecision::PreserveAndReportConflict
        );
    }

    #[test]
    fn write_ahead_journal_persists_intent_before_applied_fingerprint() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let id = "12345678-1234-4234-8234-123456789abc";
        store.create_transaction_journal(id, 17).unwrap();
        store
            .record_operation_intent(
                id,
                17,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl:pending",
            )
            .unwrap();
        let intent = store.load_transaction_journal().unwrap().unwrap();
        assert_eq!(intent.operations[0].state, JournalOperationState::Intent);
        assert_eq!(intent.operations[0].fingerprint, None);

        store
            .mark_operation_applied(id, 17, "interface:tun-proxyctl:pending", "sha256:interface")
            .unwrap();
        let applied = store.load_transaction_journal().unwrap().unwrap();
        assert_eq!(applied.operations[0].state, JournalOperationState::Applied);
        assert_eq!(
            applied.operations[0].fingerprint.as_deref(),
            Some("sha256:interface")
        );
    }

    #[test]
    fn journal_recovery_never_authorizes_delete_from_an_unresolved_intent() {
        let intent = JournalOperation {
            sequence: 0,
            kind: JournalOperationKind::CreateInterface,
            resource_key: "interface:tun-proxyctl:pending".into(),
            state: JournalOperationState::Intent,
            fingerprint: None,
        };
        assert_eq!(
            recovery_action(&intent),
            JournalRecoveryAction::InspectAmbiguousIntent
        );
        let mut applied = intent.clone();
        applied.state = JournalOperationState::Applied;
        applied.fingerprint = Some("sha256:exact-resource".into());
        assert_eq!(
            recovery_action(&applied),
            JournalRecoveryAction::CompareAndDelete
        );
        applied.state = JournalOperationState::Removed;
        assert_eq!(
            recovery_action(&applied),
            JournalRecoveryAction::SkipAlreadyRemoved
        );
    }

    #[cfg(unix)]
    #[test]
    fn unresolved_intent_can_be_closed_only_by_explicit_absence_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let id = "12345678-1234-4234-8234-123456789abc";
        store.create_transaction_journal(id, 21).unwrap();
        store
            .record_operation_intent(id, 21, JournalOperationKind::AddRule, "rule:v6:42420")
            .unwrap();
        assert!(store.remove_completed_transaction_journal(id, 21).is_err());
        store.mark_intent_absent(id, 21, "rule:v6:42420").unwrap();
        let journal = store.load_transaction_journal().unwrap().unwrap();
        assert_eq!(journal.operations[0].state, JournalOperationState::Absent);
        assert_eq!(
            recovery_action(&journal.operations[0]),
            JournalRecoveryAction::SkipAlreadyRemoved
        );
        store.remove_completed_transaction_journal(id, 21).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journal_cleanup_requires_every_operation_to_be_removed() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let id = "12345678-1234-4234-8234-123456789abc";
        store.create_transaction_journal(id, 18).unwrap();
        store
            .record_operation_intent(
                id,
                18,
                JournalOperationKind::AddRoute,
                "route:v4:42420:default",
            )
            .unwrap();
        store
            .mark_operation_applied(id, 18, "route:v4:42420:default", "sha256:route")
            .unwrap();
        assert!(store.remove_completed_transaction_journal(id, 18).is_err());
        store
            .mark_operation_removed(id, 18, "route:v4:42420:default")
            .unwrap();
        store.remove_completed_transaction_journal(id, 18).unwrap();
        assert!(store.load_transaction_journal().unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn journal_rejects_wrong_generation_duplicate_keys_and_invalid_transitions() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let id = "12345678-1234-4234-8234-123456789abc";
        store.create_transaction_journal(id, 19).unwrap();
        store
            .record_operation_intent(id, 19, JournalOperationKind::AddRule, "rule:v4:42410")
            .unwrap();
        assert!(
            store
                .mark_operation_applied(id, 20, "rule:v4:42410", "sha256:rule")
                .is_err()
        );
        assert!(
            store
                .mark_operation_removed(id, 19, "rule:v4:42410")
                .is_err()
        );
        assert!(
            store
                .record_operation_intent(id, 19, JournalOperationKind::AddRule, "rule:v4:42410")
                .is_err()
        );
        store
            .mark_operation_applied(id, 19, "rule:v4:42410", "sha256:rule")
            .unwrap();
        assert!(
            store
                .mark_operation_applied(id, 19, "rule:v4:42410", "sha256:again")
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn journal_file_uses_private_permissions_and_is_bounded() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let id = "12345678-1234-4234-8234-123456789abc";
        store.create_transaction_journal(id, 22).unwrap();
        assert_eq!(
            fs::metadata(store.journal_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut journal = store.load_transaction_journal().unwrap().unwrap();
        journal.operations = (0..=MAX_JOURNAL_OPERATIONS)
            .map(|index| JournalOperation {
                sequence: index as u32,
                kind: JournalOperationKind::AddRule,
                resource_key: format!("rule:v4:{index}"),
                state: JournalOperationState::Intent,
                fingerprint: None,
            })
            .collect();
        assert!(journal.validate().is_err());
    }

    #[test]
    fn journal_validation_rejects_duplicate_keys_and_non_contiguous_sequences() {
        let mut journal = TransactionJournal {
            schema_version: 1,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 23,
            operations: vec![
                JournalOperation {
                    sequence: 0,
                    kind: JournalOperationKind::AddRoute,
                    resource_key: "route:v4:42420:default".into(),
                    state: JournalOperationState::Intent,
                    fingerprint: None,
                },
                JournalOperation {
                    sequence: 1,
                    kind: JournalOperationKind::AddRule,
                    resource_key: "route:v4:42420:default".into(),
                    state: JournalOperationState::Intent,
                    fingerprint: None,
                },
            ],
        };
        assert!(journal.validate().is_err());
        journal.operations[1].resource_key = "rule:v4:42410".into();
        journal.operations[1].sequence = 4;
        assert!(journal.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_refuses_symlink_and_external_hard_link() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let id = "12345678-1234-4234-8234-123456789abc";
        store.create_transaction_journal(id, 20).unwrap();
        let outside = directory.path().join("outside");
        fs::write(&outside, "{}").unwrap();
        fs::remove_file(store.journal_path()).unwrap();
        symlink(&outside, store.journal_path()).unwrap();
        assert!(store.load_transaction_journal().is_err());

        fs::remove_file(store.journal_path()).unwrap();
        store.create_transaction_journal(id, 20).unwrap();
        fs::hard_link(store.journal_path(), directory.path().join("journal-link")).unwrap();
        assert!(store.load_transaction_journal().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_runtime_directory() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = directory.path().join("runtime");
        symlink(&target, &link).unwrap();
        assert!(ManifestStore::open(link).is_err());
    }
}
