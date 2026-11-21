//! Durable write-ahead journal persistence, separate from lifecycle manifest storage.
//!
//! This store shares the private filesystem primitives with ManifestStore, but owns only the
//! generation-scoped kernel-operation journal. It never inspects or mutates kernel state.

use super::{
    journal::{
        JournalOperation, JournalOperationKind, JournalOperationState, MAX_JOURNAL_OPERATIONS,
        TransactionJournal,
    },
    manifest_fs::{
        open_private_file, set_private_file, sync_directory, verify_owner, verify_private_file,
    },
};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

const JOURNAL_FILE: &str = "tun-transaction-journal.json";
const MAX_JOURNAL_BYTES: u64 = 256 * 1024;

struct BoundedJournalWriter<'a> {
    file: &'a mut tempfile::NamedTempFile,
    written: u64,
}

impl Write for BoundedJournalWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let remaining = MAX_JOURNAL_BYTES.saturating_sub(self.written);
        if buffer.len() as u64 > remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "TUN transaction journal exceeds size limit",
            ));
        }
        let written = self.file.write(buffer)?;
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

/// Private persistence for the write-ahead kernel transaction journal.
#[derive(Debug, Clone)]
pub struct JournalStore {
    directory: PathBuf,
}

impl JournalStore {
    /// Construct a journal store inside an already-validated private runtime directory.
    ///
    /// The directory is validated by ManifestStore::open; keeping this constructor crate-private
    /// prevents callers from bypassing that shared ownership/permission boundary.
    pub(crate) fn from_directory(directory: PathBuf) -> Self {
        Self { directory }
    }

    pub fn path(&self) -> PathBuf {
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
        journal.operations.try_reserve(1)
            .context("cannot reserve transaction journal operation capacity")?;
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
        self.update_operation(activation_id, generation, resource_key, |operation| {
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
        self.update_operation(activation_id, generation, resource_key, |operation| {
            ensure!(
                operation.state == JournalOperationState::Applied,
                "only an applied operation can become removed"
            );
            operation.state = JournalOperationState::Removed;
            Ok(())
        })
    }

    /// Resolve an intent as absent only after exact kernel inspection proves no resource exists.
    pub fn mark_intent_absent(
        &self,
        activation_id: &str,
        generation: u64,
        resource_key: &str,
    ) -> Result<()> {
        self.update_operation(activation_id, generation, resource_key, |operation| {
            ensure!(
                operation.state == JournalOperationState::Intent,
                "only an unresolved intent can be confirmed absent"
            );
            operation.state = JournalOperationState::Absent;
            Ok(())
        })
    }

    fn update_operation(
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
        let file = match open_private_file(&self.path()) {
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
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(metadata.len() as usize)
            .context("cannot reserve bounded TUN journal read buffer")?;
        (&file).take(MAX_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_JOURNAL_BYTES,
            "TUN transaction journal exceeds size limit"
        );
        let after_read = file.metadata()?;
        ensure!(
            bytes.len() as u64 == metadata.len() && after_read.len() == metadata.len(),
            "TUN transaction journal changed size while it was being read"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                metadata.dev() == after_read.dev()
                    && metadata.ino() == after_read.ino()
                    && metadata.mtime() == after_read.mtime()
                    && metadata.mtime_nsec() == after_read.mtime_nsec()
                    && metadata.ctime() == after_read.ctime()
                    && metadata.ctime_nsec() == after_read.ctime_nsec(),
                "TUN transaction journal changed while it was being read"
            );
        }
        ensure!(!bytes.is_empty(), "TUN transaction journal file is empty");
        let journal: TransactionJournal =
            serde_json::from_slice(&bytes).context("TUN transaction journal is malformed")?;
        journal.validate()?;
        Ok(Some(journal))
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
        match fs::remove_file(self.path()) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn write_journal(&self, journal: &TransactionJournal) -> Result<()> {
        journal.validate()?;
        let destination = self.path();
        if let Ok(metadata) = fs::symlink_metadata(&destination) {
            ensure!(
                metadata.file_type().is_file(),
                "TUN transaction journal path is not a regular file"
            );
            verify_owner(&metadata)?;
            verify_private_file(&metadata)?;
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)
            .context("cannot create private TUN transaction journal")?;
        set_private_file(temporary.as_file())?;
        let temporary_metadata = temporary.as_file().metadata()?;
        verify_owner(&temporary_metadata)?;
        verify_private_file(&temporary_metadata)?;
        let mut bounded = BoundedJournalWriter {
            file: &mut temporary,
            written: 0,
        };
        serde_json::to_writer_pretty(&mut bounded, journal)
            .context("cannot serialize bounded TUN transaction journal")?;
        drop(bounded);
        temporary.as_file().sync_all()?;
        temporary
            .persist(&destination)
            .context("cannot atomically replace TUN transaction journal")?;
        sync_directory(&self.directory)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn journal_store_round_trips_intent_and_applied_state() {
        let directory = tempdir().unwrap();
        let store = JournalStore::from_directory(directory.path().to_path_buf());
        let activation = "12345678-1234-4234-8234-123456789abc";
        store.create_transaction_journal(activation, 7).unwrap();
        store
            .record_operation_intent(
                activation,
                7,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            )
            .unwrap();
        let intent = store.load_transaction_journal().unwrap().unwrap();
        assert_eq!(intent.operations[0].state, JournalOperationState::Intent);
        store
            .mark_operation_applied(
                activation,
                7,
                "interface:tun-proxyctl",
                "ifindex=77;kind=tun",
            )
            .unwrap();
        let applied = store.load_transaction_journal().unwrap().unwrap();
        assert_eq!(applied.operations[0].state, JournalOperationState::Applied);
        assert_eq!(
            applied.operations[0].fingerprint.as_deref(),
            Some("ifindex=77;kind=tun")
        );
    }

    #[test]
    fn journal_recovery_boundaries_survive_store_reopen_and_never_delete_unresolved_intents() {
        use super::super::journal::{
            JournalRecoveryAction, JournalRecoveryDecision, plan_journal_recovery, recovery_action,
        };
        use std::collections::BTreeMap;

        let directory = tempdir().unwrap();
        let activation = "12345678-1234-4234-8234-123456789abc";
        let store = JournalStore::from_directory(directory.path().to_path_buf());
        store.create_transaction_journal(activation, 19).unwrap();
        store
            .record_operation_intent(
                activation,
                19,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            )
            .unwrap();
        drop(store); // Simulate controller termination after durable intent.

        let store = JournalStore::from_directory(directory.path().to_path_buf());
        let intent = store.load_transaction_journal().unwrap().unwrap();
        assert_eq!(
            recovery_action(&intent.operations[0]),
            JournalRecoveryAction::InspectAmbiguousIntent
        );
        let no_inventory = BTreeMap::new();
        assert_eq!(
            plan_journal_recovery(&intent, &no_inventory).unwrap()[0].1,
            JournalRecoveryDecision::PreserveAndReportConflict,
        );
        let proven_absent = BTreeMap::from([("interface:tun-proxyctl".to_owned(), None)]);
        assert_eq!(
            plan_journal_recovery(&intent, &proven_absent).unwrap()[0].1,
            JournalRecoveryDecision::MarkAbsent,
        );
        store
            .mark_intent_absent(activation, 19, "interface:tun-proxyctl")
            .unwrap();
        store
            .remove_completed_transaction_journal(activation, 19)
            .unwrap();
        drop(store); // The absent interface transaction is complete and removed.

        let store = JournalStore::from_directory(directory.path().to_path_buf());
        store.create_transaction_journal(activation, 20).unwrap();
        store
            .record_operation_intent(
                activation,
                20,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            )
            .unwrap();
        store
            .mark_operation_applied(
                activation,
                20,
                "interface:tun-proxyctl",
                "interface-fingerprint",
            )
            .unwrap();
        store
            .record_operation_intent(
                activation,
                20,
                JournalOperationKind::AddRoute,
                "route:v4:42420:0.0.0.0/0",
            )
            .unwrap();
        store
            .mark_operation_applied(
                activation,
                20,
                "route:v4:42420:0.0.0.0/0",
                "canonical-route-fingerprint",
            )
            .unwrap();
        drop(store); // Simulate termination after the kernel mutation and durable fingerprint.

        let store = JournalStore::from_directory(directory.path().to_path_buf());
        let applied = store.load_transaction_journal().unwrap().unwrap();
        let exact = BTreeMap::from([
            (
                "interface:tun-proxyctl".to_owned(),
                Some("interface-fingerprint".to_owned()),
            ),
            (
                "route:v4:42420:0.0.0.0/0".to_owned(),
                Some("canonical-route-fingerprint".to_owned()),
            ),
        ]);
        assert_eq!(
            plan_journal_recovery(&applied, &exact).unwrap()[0].1,
            JournalRecoveryDecision::CompareAndDelete {
                expected_fingerprint: "canonical-route-fingerprint".into(),
            },
        );
        let changed = BTreeMap::from([
            (
                "interface:tun-proxyctl".to_owned(),
                Some("interface-fingerprint".to_owned()),
            ),
            (
                "route:v4:42420:0.0.0.0/0".to_owned(),
                Some("foreign-route-fingerprint".to_owned()),
            ),
        ]);
        assert_eq!(
            plan_journal_recovery(&applied, &changed).unwrap()[0].1,
            JournalRecoveryDecision::PreserveAndReportConflict,
        );
        store
            .mark_operation_removed(activation, 20, "route:v4:42420:0.0.0.0/0")
            .unwrap();
        store
            .mark_operation_removed(activation, 20, "interface:tun-proxyctl")
            .unwrap();
        store
            .remove_completed_transaction_journal(activation, 20)
            .unwrap();
        assert!(store.load_transaction_journal().unwrap().is_none());
    }

    #[test]
    fn journal_store_refuses_incomplete_removal_and_wrong_generation() {
        let directory = tempdir().unwrap();
        let store = JournalStore::from_directory(directory.path().to_path_buf());
        let activation = "12345678-1234-4234-8234-123456789abc";
        store.create_transaction_journal(activation, 3).unwrap();
        store
            .record_operation_intent(
                activation,
                3,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            )
            .unwrap();
        assert!(
            store
                .remove_completed_transaction_journal(activation, 3)
                .is_err()
        );
        assert!(
            store
                .remove_completed_transaction_journal(activation, 4)
                .is_err()
        );
    }
}
