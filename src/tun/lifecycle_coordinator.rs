#[cfg(target_os = "linux")]
use super::process::{ProcessHandle, ProcessIdentity, read_process_owner_uid};
#[cfg(target_os = "linux")]
use super::session_record::{SessionRecord, SessionStore};
use super::{
    manifest_store::{JournalOperationState, ManifestSnapshot, ManifestStore},
    recovery::{RecoveryAction, SupervisorEvent, SupervisorPhase},
};
use anyhow::{Context, Result, ensure};
use std::{fs::File, path::PathBuf, time::Duration};
#[cfg(unix)]
use std::{fs::OpenOptions, thread, time::Instant};

const LOCK_FILE: &str = "tun-lifecycle.lock";
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationToken {
    activation_id: String,
    generation: u64,
}

impl ActivationToken {
    pub fn from_snapshot(snapshot: &ManifestSnapshot) -> Result<Self> {
        snapshot.validate()?;
        Ok(Self {
            activation_id: snapshot.manifest.activation_id.clone(),
            generation: snapshot.generation,
        })
    }

    pub fn activation_id(&self) -> &str {
        &self.activation_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatedSnapshot {
    pub snapshot: ManifestSnapshot,
    pub token: ActivationToken,
}

/// Read-only classification of the two root-owned durable startup records.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionReconciliation {
    Idle,
    PreparedWithoutReceipt {
        activation_id: String,
        generation: u64,
    },
    ReceiptCommittedBeforeManifest(SessionRecord),
    Running(SessionRecord),
    CleanupPending(Option<SessionRecord>),
    CleanedAwaitingReceiptRemoval(SessionRecord),
    CleanedWithoutReceipt,
    OrphanReceipt(SessionRecord),
    Inconsistent(String),
}

#[derive(Debug, Clone)]
pub struct LifecycleCoordinator {
    store: ManifestStore,
    lock_path: PathBuf,
}

impl LifecycleCoordinator {
    pub fn new(store: ManifestStore) -> Result<Self> {
        let lock_path = store
            .path()
            .parent()
            .context("TUN manifest path has no parent directory")?
            .join(LOCK_FILE);
        Ok(Self { store, lock_path })
    }

    pub fn create_prepared(&self, snapshot: &ManifestSnapshot) -> Result<ActivationToken> {
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        self.store.create_prepared(snapshot)?;
        ActivationToken::from_snapshot(snapshot)
    }

    /// Adopt the Prepared manifest committed by the privileged mutation broker.
    ///
    /// The broker owns kernel transaction creation; the unprivileged lifecycle coordinator
    /// must not create a competing manifest. Adoption is allowed only for the exact
    /// activation generation and only before a core process has been bound.
    pub fn adopt_prepared(&self, activation_id: &str, generation: u64) -> Result<ActivationToken> {
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        let snapshot = self
            .store
            .load()?
            .context("mutation broker did not commit an ownership manifest")?;
        ensure!(
            snapshot.manifest.activation_id == activation_id && snapshot.generation == generation,
            "broker manifest identity does not match the requested activation generation"
        );
        ensure!(
            snapshot.phase == SupervisorPhase::Prepared,
            "only a newly prepared broker manifest can be adopted"
        );
        #[cfg(target_os = "linux")]
        ensure!(
            snapshot.core_process.is_none(),
            "broker manifest unexpectedly already contains a core process identity"
        );
        ActivationToken::from_snapshot(&snapshot)
    }

    /// Return the private directory containing this coordinator's durable manifest.
    pub fn runtime_directory(&self) -> Result<PathBuf> {
        self.store
            .path()
            .parent()
            .map(std::path::Path::to_path_buf)
            .context("TUN manifest path has no parent directory")
    }

    pub fn load_current(&self) -> Result<Option<CoordinatedSnapshot>> {
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        self.store
            .load()?
            .map(|snapshot| {
                let token = ActivationToken::from_snapshot(&snapshot)?;
                Ok(CoordinatedSnapshot { snapshot, token })
            })
            .transpose()
    }

    /// Atomically claim an orphaned Prepared activation for cleanup.
    ///
    /// The lifecycle lock makes this transition mutually exclusive with bind_core_process:
    /// once CleanupPending is durable, a concurrent startup commit can no longer succeed.
    #[cfg(target_os = "linux")]
    pub fn claim_prepared_cleanup(&self, token: &ActivationToken) -> Result<()> {
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        let mut snapshot = self
            .store
            .load()?
            .context("no TUN recovery manifest exists")?;
        ensure!(
            snapshot.manifest.activation_id == token.activation_id
                && snapshot.generation == token.generation,
            "stale TUN lifecycle token does not match the active activation"
        );
        ensure!(
            snapshot.phase == SupervisorPhase::Prepared,
            "only a Prepared activation can be claimed for orphan cleanup"
        );
        ensure!(
            snapshot.core_process.is_none(),
            "Prepared activation unexpectedly contains a core process identity"
        );
        snapshot.phase = SupervisorPhase::CleanupPending;
        self.store.write(&snapshot)
    }

    /// Bind the exact launched core process to a prepared activation before committing startup.
    /// A pidfd pins the process instance throughout the durable write, preventing PID reuse from
    /// redirecting the identity check. If the process exits after the final liveness check, the
    /// supervisor observes that exact exit and recovers the prepared manifest.
    #[cfg(target_os = "linux")]
    pub fn bind_core_process(
        &self,
        token: &ActivationToken,
        process: ProcessIdentity,
    ) -> Result<()> {
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        process.validate()?;
        let process_handle = ProcessHandle::open(process.clone())?;
        ensure!(
            !process_handle.is_exited()?,
            "managed core process exited before its identity could be bound"
        );
        let mut snapshot = self
            .store
            .load()?
            .context("no TUN recovery manifest exists")?;
        ensure!(
            snapshot.manifest.activation_id == token.activation_id
                && snapshot.generation == token.generation,
            "stale TUN lifecycle token does not match the active activation"
        );
        ensure!(
            snapshot.phase == SupervisorPhase::Prepared && snapshot.core_process.is_none(),
            "core process can only be bound once to a prepared TUN activation"
        );
        ensure!(
            !process_handle.is_exited()?,
            "managed core process exited before its identity could be persisted"
        );
        snapshot.core_process = Some(process);
        snapshot.phase = SupervisorPhase::Running;
        self.store.write(&snapshot)
    }

    /// Inspect the root-owned manifest and session receipt under one lifecycle lock.
    /// This is deliberately read-only: classification never signals a process or removes evidence.
    #[cfg(target_os = "linux")]
    pub fn reconcile_session_records(
        &self,
        sessions: &SessionStore,
    ) -> Result<SessionReconciliation> {
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        ensure!(
            sessions.path().parent() == self.store.path().parent(),
            "privileged session receipt and lifecycle manifest must share one runtime directory"
        );
        let manifest = self.store.load()?;
        let receipt = sessions.load()?;
        reconcile_session_records(manifest.as_ref(), receipt.as_ref())
    }

    /// Stop only the exact root-owned core process recorded for this activation.
    ///
    /// The manifest is durably moved to CleanupPending before any signal is sent. pidfd
    /// operations pin the process instance, so PID reuse cannot redirect TERM or KILL.
    #[cfg(target_os = "linux")]
    pub fn stop_session_core(
        &self,
        token: &ActivationToken,
        sessions: &SessionStore,
        term_grace: Duration,
        kill_grace: Duration,
    ) -> Result<bool> {
        ensure!(
            !term_grace.is_zero()
                && term_grace <= Duration::from_secs(30)
                && !kill_grace.is_zero()
                && kill_grace <= Duration::from_secs(30),
            "TUN process stop grace periods must be between 1ms and 30s"
        );
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        ensure!(
            sessions.path().parent() == self.store.path().parent(),
            "privileged session receipt and lifecycle manifest must share one runtime directory"
        );
        let mut snapshot = self.store.load()?.context("no TUN recovery manifest exists")?;
        let record = sessions.load()?.context("no privileged TUN session receipt exists")?;
        ensure!(
            snapshot.manifest.activation_id == token.activation_id
                && snapshot.generation == token.generation
                && record.activation_id == token.activation_id
                && record.generation == token.generation,
            "TUN stop request does not match the active session generation"
        );
        ensure!(
            matches!(
                reconcile_session_records(Some(&snapshot), Some(&record))?,
                SessionReconciliation::Running(_)
                    | SessionReconciliation::ReceiptCommittedBeforeManifest(_)
                    | SessionReconciliation::CleanupPending(Some(_))
            ),
            "refusing to stop a process from inconsistent TUN session records"
        );

        if snapshot.phase != SupervisorPhase::CleanupPending {
            ensure!(
                matches!(snapshot.phase, SupervisorPhase::Prepared | SupervisorPhase::Running),
                "TUN session is not in a stoppable lifecycle phase"
            );
            snapshot.phase = SupervisorPhase::CleanupPending;
            self.store.write(&snapshot)?;
        }

        // If the recorded instance has exited or its PID has been reused, the original
        // process is already gone. Never signal a replacement process.
        if !record.process.verify()? {
            return Ok(true);
        }
        let process = match ProcessHandle::open(record.process.clone()) {
            Ok(process) => process,
            Err(_error) if !record.process.verify()? => return Ok(true),
            Err(error) => return Err(error).context("cannot pin recorded TUN core process"),
        };
        if process.is_exited()? {
            return Ok(true);
        }
        ensure!(
            read_process_owner_uid(&process)? == unsafe { libc::geteuid() },
            "recorded TUN core process credentials do not match the privileged supervisor"
        );

        process.signal(libc::SIGTERM)?;
        if process.wait_exit(term_grace)? {
            return Ok(true);
        }
        process.signal(libc::SIGKILL)?;
        ensure!(
            process.wait_exit(kill_grace)?,
            "recorded TUN core did not exit after SIGKILL; preserving cleanup state"
        );
        Ok(true)
    }

    /// Finish durable record cleanup after the caller has removed and journaled every
    /// kernel resource. This method performs no kernel networking operation.
    #[cfg(target_os = "linux")]
    pub fn finalize_session_cleanup(
        &self,
        token: &ActivationToken,
        sessions: &SessionStore,
    ) -> Result<()> {
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        ensure!(
            sessions.path().parent() == self.store.path().parent(),
            "privileged session receipt and lifecycle manifest must share one runtime directory"
        );
        let mut snapshot = self.store.load()?.context("no TUN recovery manifest exists")?;
        ensure!(
            snapshot.manifest.activation_id == token.activation_id
                && snapshot.generation == token.generation,
            "stale TUN lifecycle token does not match the active activation"
        );
        ensure!(
            matches!(
                snapshot.phase,
                SupervisorPhase::CleanupPending | SupervisorPhase::Cleaned
            ),
            "TUN activation must be cleanup-pending or already cleaned"
        );

        let receipt = sessions.load()?;
        if let Some(record) = receipt.as_ref() {
            ensure!(
                record.activation_id == token.activation_id
                    && record.generation == token.generation,
                "privileged session receipt belongs to another activation"
            );
            ensure!(
                !record.process.verify()?,
                "refusing to finalize TUN cleanup while the recorded core is still alive"
            );
            ensure!(
                snapshot.core_process.as_ref().is_none_or(|identity| identity == &record.process),
                "manifest process identity conflicts with the privileged session receipt"
            );
        } else {
            ensure!(
                snapshot.core_process.is_none(),
                "refusing to finalize without the receipt for a manifest-bound core process"
            );
        }

        if let Some(journal) = self.store.load_transaction_journal()? {
            ensure!(
                journal.activation_id == token.activation_id
                    && journal.generation == token.generation,
                "TUN transaction journal belongs to another activation"
            );
            ensure!(
                journal.operations.iter().all(|operation| matches!(
                    operation.state,
                    JournalOperationState::Removed | JournalOperationState::Absent
                )),
                "refusing to finalize while kernel resource journal contains unresolved operations"
            );
            for resource in &snapshot.manifest.resources {
                let operation = journal
                    .operations
                    .iter()
                    .find(|operation| operation.resource_key == resource.key)
                    .context("owned resource is missing from the transaction journal")?;
                ensure!(
                    operation.state == JournalOperationState::Removed
                        && operation.fingerprint.as_deref() == Some(resource.fingerprint.as_str()),
                    "owned resource does not have a matching durable removal record"
                );
            }
        } else {
            ensure!(
                snapshot.phase == SupervisorPhase::Cleaned
                    || snapshot.manifest.resources.is_empty(),
                "TUN resource manifest exists but its transaction journal is missing"
            );
        }

        // Persist the terminal phase before removing either durable identity. If the
        // process crashes after this write, recovery can safely finish receipt/journal removal.
        if snapshot.phase != SupervisorPhase::Cleaned || snapshot.core_process.is_some() {
            snapshot.phase = SupervisorPhase::Cleaned;
            snapshot.core_process = None;
            self.store.write(&snapshot)?;
        }
        self.store.remove_completed_transaction_journal(
            &token.activation_id,
            token.generation,
        )?;
        if let Some(record) = receipt {
            sessions.remove(&record)?;
        }
        self.store
            .remove_cleaned(&token.activation_id, token.generation)
    }

    /// Persist the root-owned process receipt before binding the same identity to the
    /// lifecycle manifest. If the second durable write fails, the receipt is deliberately
    /// retained as recovery evidence; callers must not delete it as a rollback shortcut.
    #[cfg(target_os = "linux")]
    pub fn bind_core_session(
        &self,
        token: &ActivationToken,
        sessions: &SessionStore,
        record: &SessionRecord,
    ) -> Result<()> {
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        record.validate()?;
        ensure!(
            record.activation_id == token.activation_id && record.generation == token.generation,
            "privileged session receipt does not match the activation token"
        );
        ensure!(
            sessions.path().parent() == self.store.path().parent(),
            "privileged session receipt and lifecycle manifest must share one runtime directory"
        );

        let process_handle = ProcessHandle::open(record.process.clone())?;
        ensure!(
            !process_handle.is_exited()?,
            "managed core exited before its session receipt could be committed"
        );
        ensure!(
            read_process_owner_uid(&process_handle)? == unsafe { libc::geteuid() },
            "managed core process credentials do not match the privileged supervisor"
        );

        let mut snapshot = self
            .store
            .load()?
            .context("no TUN recovery manifest exists")?;
        ensure!(
            snapshot.manifest.activation_id == token.activation_id
                && snapshot.generation == token.generation,
            "stale TUN lifecycle token does not match the active activation"
        );
        ensure!(
            snapshot.phase == SupervisorPhase::Prepared && snapshot.core_process.is_none(),
            "core session can only be committed once to a prepared TUN activation"
        );

        // This is the first commit point. A crash after it leaves a root-owned session
        // receipt plus a Prepared manifest, which recovery can reconcile without trusting
        // the user's database or a user-owned manifest.
        sessions.create(record)?;

        ensure!(
            !process_handle.is_exited()?,
            "managed core exited before its lifecycle manifest could be committed"
        );
        snapshot.core_process = Some(record.process.clone());
        snapshot.phase = SupervisorPhase::Running;
        self.store.write(&snapshot).context(
            "session receipt is durable but lifecycle manifest commit failed; preserve the receipt for recovery",
        )?;
        Ok(())
    }

    pub fn apply_event(
        &self,
        token: &ActivationToken,
        event: SupervisorEvent,
    ) -> Result<RecoveryAction> {
        let _lock = LifecycleLock::acquire(&self.lock_path, LOCK_TIMEOUT)?;
        let snapshot = self
            .store
            .load()?
            .context("no TUN recovery manifest exists")?;
        ensure!(
            snapshot.manifest.activation_id == token.activation_id
                && snapshot.generation == token.generation,
            "stale TUN lifecycle token does not match the active activation"
        );
        self.store.apply_event(event, token.generation)
    }
}

/// Classify partial durable commits without taking any destructive recovery action.
#[cfg(target_os = "linux")]
pub fn reconcile_session_records(
    manifest: Option<&ManifestSnapshot>,
    receipt: Option<&SessionRecord>,
) -> Result<SessionReconciliation> {
    if let Some(snapshot) = manifest {
        snapshot.validate()?;
    }
    if let Some(record) = receipt {
        record.validate()?;
    }

    let (Some(snapshot), Some(record)) = (manifest, receipt) else {
        return Ok(match (manifest, receipt) {
            (None, None) => SessionReconciliation::Idle,
            (None, Some(record)) => SessionReconciliation::OrphanReceipt(record.clone()),
            (Some(snapshot), None) => match snapshot.phase {
                SupervisorPhase::Prepared => SessionReconciliation::PreparedWithoutReceipt {
                    activation_id: snapshot.manifest.activation_id.clone(),
                    generation: snapshot.generation,
                },
                SupervisorPhase::Running => SessionReconciliation::Inconsistent(
                    "Running manifest has no privileged session receipt".into(),
                ),
                SupervisorPhase::CleanupPending if snapshot.core_process.is_none() => {
                    SessionReconciliation::CleanupPending(None)
                }
                SupervisorPhase::CleanupPending => SessionReconciliation::Inconsistent(
                    "cleanup-pending manifest still binds a core process but has no session receipt"
                        .into(),
                ),
                SupervisorPhase::Cleaned if snapshot.core_process.is_none() => {
                    SessionReconciliation::CleanedWithoutReceipt
                }
                SupervisorPhase::Cleaned => SessionReconciliation::Inconsistent(
                    "cleaned manifest still binds a core process but has no session receipt".into(),
                ),
            },
            (Some(_), Some(_)) => unreachable!("both records were handled above"),
        });
    };

    if snapshot.manifest.activation_id != record.activation_id
        || snapshot.generation != record.generation
    {
        return Ok(SessionReconciliation::Inconsistent(
            "manifest and session receipt refer to different activation generations".into(),
        ));
    }

    match snapshot.phase {
        SupervisorPhase::Prepared if snapshot.core_process.is_none() => Ok(
            SessionReconciliation::ReceiptCommittedBeforeManifest(record.clone()),
        ),
        SupervisorPhase::Running if snapshot.core_process.as_ref() == Some(&record.process) => {
            Ok(SessionReconciliation::Running(record.clone()))
        }
        SupervisorPhase::CleanupPending
            if snapshot.core_process.is_none()
                || snapshot.core_process.as_ref() == Some(&record.process) =>
        {
            Ok(SessionReconciliation::CleanupPending(Some(record.clone())))
        }
        SupervisorPhase::Cleaned
            if snapshot.core_process.is_none()
                || snapshot.core_process.as_ref() == Some(&record.process) =>
        {
            Ok(SessionReconciliation::CleanedAwaitingReceiptRemoval(record.clone()))
        },
        _ => Ok(SessionReconciliation::Inconsistent(
            "manifest phase or process identity conflicts with the session receipt".into(),
        )),
    }
}

struct LifecycleLock {
    file: File,
}

impl LifecycleLock {
    fn acquire(path: &std::path::Path, timeout: Duration) -> Result<Self> {
        acquire_platform_lock(path, timeout).map(|file| Self { file })
    }
}

impl Drop for LifecycleLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: this guard owns the open descriptor until after the unlock call.
            unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
        #[cfg(not(unix))]
        let _ = &self.file;
    }
}

#[cfg(unix)]
fn acquire_platform_lock(path: &std::path::Path, timeout: Duration) -> Result<File> {
    ensure!(
        path.is_absolute() && path.as_os_str().len() <= 4096,
        "TUN lifecycle lock path must be a bounded absolute path"
    );
    ensure!(
        !timeout.is_zero() && timeout <= Duration::from_secs(60),
        "TUN lifecycle lock timeout must be between 1ms and 60s"
    );
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("cannot securely open TUN lifecycle lock {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file(),
        "TUN lifecycle lock is not a regular file"
    );
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "TUN lifecycle lock has a foreign owner"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "TUN lifecycle lock permissions are not private"
    );
    ensure!(
        metadata.permissions().mode() & 0o7000 == 0,
        "TUN lifecycle lock must not have special permission bits"
    );
    ensure!(
        metadata.permissions().mode() & 0o700 == 0o600,
        "TUN lifecycle lock must be owner-readable and writable"
    );
    ensure!(
        metadata.nlink() == 1,
        "TUN lifecycle lock must not have external hard links"
    );

    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: flock operates on the valid descriptor owned by file.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            ensure!(
                Instant::now() < deadline,
                "timed out waiting for another Proxyctl TUN lifecycle operation"
            );
            continue;
        }
        if !matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK)) {
            return Err(error).context("cannot acquire TUN lifecycle lock");
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for another Proxyctl TUN lifecycle operation"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(not(unix))]
fn acquire_platform_lock(_path: &std::path::Path, _timeout: Duration) -> Result<File> {
    anyhow::bail!("cross-process TUN lifecycle locking is supported only on Unix")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::{
        ownership::{MANIFEST_VERSION, OwnedResource, RouteManifest},
        recovery::SupervisorPhase,
    };

    #[cfg(target_os = "linux")]
    fn bind_fake_core(
        coordinator: &LifecycleCoordinator,
        token: &ActivationToken,
    ) -> std::process::Child {
        use crate::tun::process::ProcessIdentity;
        use std::process::{Command, Stdio};

        let executable = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join("sleep"))
            .find(|path| path.is_file())
            .and_then(|path| std::fs::canonicalize(path).ok())
            .expect("sleep utility is required for lifecycle process tests");
        let child = Command::new(&executable)
            .arg("3600")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let identity = loop {
            assert!(
                Instant::now() < deadline,
                "fake child did not reach its expected executable identity"
            );
            if let Ok(identity) = ProcessIdentity::capture(child.id())
                && identity.executable == executable
                && identity.verify().unwrap_or(false)
            {
                break identity;
            }
            thread::sleep(Duration::from_millis(5));
        };
        coordinator.bind_core_process(token, identity).unwrap();
        child
    }

    fn snapshot(activation_id: &str) -> ManifestSnapshot {
        ManifestSnapshot {
            schema_version: 1,
            generation: 17,
            phase: SupervisorPhase::Prepared,
            #[cfg(target_os = "linux")]
            core_process: None,
            manifest: RouteManifest {
                version: MANIFEST_VERSION,
                activation_id: activation_id.into(),
                table_id: 42420,
                rule_priority: 42420,
                interface_name: "tun-proxyctl".into(),
                interface_index: 77,
                resources: vec![OwnedResource {
                    key: "route:v4-default".into(),
                    fingerprint: "route-fingerprint".into(),
                }],
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn fixture_session(activation_id: &str, generation: u64) -> SessionRecord {
        SessionRecord {
            schema_version: 1,
            invoking_uid: 1000,
            session_nonce: "12345678-1234-4234-8234-123456789abc".into(),
            activation_id: activation_id.into(),
            generation,
            core: super::super::launch_spec::CoreKind::Xray,
            process: ProcessIdentity {
                pid: 4242,
                start_ticks: 991,
                executable: PathBuf::from("/home/user/.local/share/proxyctl/cores/xray/xray"),
            },
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn classifies_session_receipt_and_manifest_crash_states() {
        let activation_id = "12345678-1234-4234-8234-123456789abc";
        let prepared = snapshot(activation_id);
        let receipt = fixture_session(activation_id, prepared.generation);

        assert_eq!(
            reconcile_session_records(None, None).unwrap(),
            SessionReconciliation::Idle
        );
        assert!(matches!(
            reconcile_session_records(Some(&prepared), None).unwrap(),
            SessionReconciliation::PreparedWithoutReceipt { .. }
        ));
        assert_eq!(
            reconcile_session_records(Some(&prepared), Some(&receipt)).unwrap(),
            SessionReconciliation::ReceiptCommittedBeforeManifest(receipt.clone())
        );
        assert_eq!(
            reconcile_session_records(None, Some(&receipt)).unwrap(),
            SessionReconciliation::OrphanReceipt(receipt.clone())
        );

        let mut running = prepared.clone();
        running.phase = SupervisorPhase::Running;
        running.core_process = Some(receipt.process.clone());
        assert_eq!(
            reconcile_session_records(Some(&running), Some(&receipt)).unwrap(),
            SessionReconciliation::Running(receipt.clone())
        );
        assert!(matches!(
            reconcile_session_records(Some(&running), None).unwrap(),
            SessionReconciliation::Inconsistent(_)
        ));

        let mut cleanup = running.clone();
        cleanup.phase = SupervisorPhase::CleanupPending;
        assert_eq!(
            reconcile_session_records(Some(&cleanup), Some(&receipt)).unwrap(),
            SessionReconciliation::CleanupPending(Some(receipt.clone()))
        );

        let mut cleaned = running.clone();
        cleaned.phase = SupervisorPhase::Cleaned;
        assert_eq!(
            reconcile_session_records(Some(&cleaned), Some(&receipt)).unwrap(),
            SessionReconciliation::CleanedAwaitingReceiptRemoval(receipt)
        );

        let mismatched =
            fixture_session("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", prepared.generation);
        assert!(matches!(
            reconcile_session_records(Some(&prepared), Some(&mismatched)).unwrap(),
            SessionReconciliation::Inconsistent(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lock_excludes_another_open_file_description_and_releases_on_drop() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LOCK_FILE);
        let first = LifecycleLock::acquire(&path, Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        assert!(LifecycleLock::acquire(&path, Duration::from_millis(60)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(first);
        assert!(LifecycleLock::acquire(&path, Duration::from_secs(1)).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_lifecycle_lock_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let path = directory.path().join(LOCK_FILE);
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(LifecycleLock::acquire(&path, Duration::from_millis(50)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_lifecycle_lock_with_external_hard_link() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LOCK_FILE);
        let external = directory.path().join("linked-lock");
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&path, &external).unwrap();
        assert!(LifecycleLock::acquire(&path, Duration::from_millis(50)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_lifecycle_lock_without_owner_read_write_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LOCK_FILE);
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(LifecycleLock::acquire(&path, Duration::from_millis(50)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn claiming_prepared_cleanup_prevents_a_late_core_commit() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let coordinator = LifecycleCoordinator::new(store).unwrap();
        let token = coordinator
            .create_prepared(&snapshot("12345678-1234-4234-8234-123456789abc"))
            .unwrap();

        use std::process::{Command, Stdio};

        let mut child = Command::new("tail")
            .args(["-f", "/dev/null"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let identity = loop {
            assert!(
                Instant::now() < deadline,
                "fake child did not become inspectable"
            );
            if let Ok(identity) = ProcessIdentity::capture(child.id())
                && identity.verify().unwrap_or(false)
            {
                break identity;
            }
            thread::sleep(Duration::from_millis(5));
        };

        coordinator.claim_prepared_cleanup(&token).unwrap();
        let current = coordinator.load_current().unwrap().unwrap();
        assert_eq!(current.snapshot.phase, SupervisorPhase::CleanupPending);
        assert!(coordinator.bind_core_process(&token, identity).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn binds_only_a_live_process_to_the_prepared_activation() {
        use crate::tun::process::ProcessIdentity;
        use std::process::{Command, Stdio};

        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let coordinator = LifecycleCoordinator::new(store).unwrap();
        let token = coordinator
            .create_prepared(&snapshot("12345678-1234-4234-8234-123456789abc"))
            .unwrap();
        let mut child = Command::new("tail")
            .args(["-f", "/dev/null"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let identity = loop {
            assert!(
                Instant::now() < deadline,
                "fake child did not remain available long enough to capture its identity"
            );
            if let Ok(identity) = ProcessIdentity::capture(child.id())
                && identity.verify().unwrap_or(false)
            {
                break identity;
            }
            thread::sleep(Duration::from_millis(5));
        };
        coordinator
            .bind_core_process(&token, identity.clone())
            .unwrap();
        assert_eq!(
            coordinator
                .load_current()
                .unwrap()
                .unwrap()
                .snapshot
                .core_process,
            Some(identity)
        );
        assert!(
            coordinator
                .bind_core_process(
                    &token,
                    ProcessIdentity {
                        pid: 0,
                        start_ticks: 1,
                        executable: "/bin/sleep".into(),
                    }
                )
                .is_err()
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn commits_session_receipt_before_running_manifest_identity() {
        use std::{
            os::unix::fs::PermissionsExt,
            process::{Command, Stdio},
        };

        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("runtime");
        let store = ManifestStore::open(&runtime).unwrap();
        let sessions = SessionStore::open_for_owner(runtime, unsafe { libc::geteuid() }, unsafe {
            libc::getuid()
        })
        .unwrap();
        let coordinator = LifecycleCoordinator::new(store).unwrap();
        let token = coordinator
            .create_prepared(&snapshot("12345678-1234-4234-8234-123456789abc"))
            .unwrap();

        let source = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join("sleep"))
            .find(|path| path.is_file())
            .expect("sleep utility is required for lifecycle session tests");
        let executable = directory.path().join("xray");
        std::fs::copy(source, &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut child = Command::new(&executable)
            .arg("3600")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let identity = loop {
            assert!(
                Instant::now() < deadline,
                "fake xray process did not reach its expected executable identity"
            );
            if let Ok(identity) = ProcessIdentity::capture(child.id())
                && identity.executable == executable
                && identity.verify().unwrap_or(false)
            {
                break identity;
            }
            thread::sleep(Duration::from_millis(5));
        };
        let record = SessionRecord::new(
            unsafe { libc::getuid() },
            token.activation_id().to_owned(),
            token.generation(),
            super::super::launch_spec::CoreKind::Xray,
            identity.clone(),
        )
        .unwrap();

        coordinator
            .bind_core_session(&token, &sessions, &record)
            .unwrap();
        let committed = coordinator.load_current().unwrap().unwrap();
        assert_eq!(committed.snapshot.phase, SupervisorPhase::Running);
        assert_eq!(committed.snapshot.core_process, Some(identity));
        assert_eq!(sessions.load().unwrap(), Some(record));

        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stops_only_the_recorded_core_and_keeps_cleanup_evidence() {
        use std::{
            os::unix::fs::PermissionsExt,
            process::{Command, Stdio},
        };

        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("runtime");
        let store = ManifestStore::open(&runtime).unwrap();
        let sessions = SessionStore::open_for_owner(
            runtime,
            unsafe { libc::geteuid() },
            unsafe { libc::getuid() },
        )
        .unwrap();
        let coordinator = LifecycleCoordinator::new(store).unwrap();
        let token = coordinator
            .create_prepared(&snapshot("12345678-1234-4234-8234-123456789abc"))
            .unwrap();

        let source = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|directory| directory.join("sleep"))
            .find(|path| path.is_file())
            .expect("sleep utility is required for lifecycle session tests");
        let executable = directory.path().join("xray");
        std::fs::copy(source, &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut child = Command::new(&executable)
            .arg("3600")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let identity = loop {
            assert!(Instant::now() < deadline, "fake core did not become inspectable");
            if let Ok(identity) = ProcessIdentity::capture(child.id())
                && identity.executable == executable
                && identity.verify().unwrap_or(false)
            {
                break identity;
            }
            thread::sleep(Duration::from_millis(5));
        };
        let record = SessionRecord::new(
            unsafe { libc::getuid() },
            token.activation_id().to_owned(),
            token.generation(),
            super::super::launch_spec::CoreKind::Xray,
            identity.clone(),
        )
        .unwrap();
        coordinator
            .bind_core_session(&token, &sessions, &record)
            .unwrap();

        assert!(
            coordinator
                .stop_session_core(
                    &token,
                    &sessions,
                    Duration::from_millis(500),
                    Duration::from_secs(2),
                )
                .unwrap()
        );
        assert!(identity.verify().is_ok_and(|alive| !alive));
        let current = coordinator.load_current().unwrap().unwrap();
        assert_eq!(current.snapshot.phase, SupervisorPhase::CleanupPending);
        assert_eq!(current.snapshot.core_process, Some(identity));
        assert_eq!(sessions.load().unwrap(), Some(record));
        assert!(
            coordinator
                .finalize_session_cleanup(&token, &sessions)
                .is_err(),
            "resource-bearing manifest without its completed transaction journal must be retained"
        );
        assert_eq!(sessions.load().unwrap(), Some(record));
        assert_eq!(
            coordinator.load_current().unwrap().unwrap().snapshot.phase,
            SupervisorPhase::CleanupPending
        );
        child.wait().unwrap();
    }

    #[test]
    fn coordinator_serializes_manifest_creation_and_event_transitions() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let coordinator = LifecycleCoordinator::new(store).unwrap();
        let token = coordinator
            .create_prepared(&snapshot("12345678-1234-4234-8234-123456789abc"))
            .unwrap();

        #[cfg(target_os = "linux")]
        let mut child = bind_fake_core(&coordinator, &token);
        assert_eq!(
            coordinator
                .apply_event(&token, SupervisorEvent::StartCommitted)
                .unwrap(),
            RecoveryAction::StartManagedCore
        );
        assert_eq!(
            coordinator
                .apply_event(&token, SupervisorEvent::CoreExited)
                .unwrap(),
            RecoveryAction::CleanupManifestResources
        );
        assert_eq!(
            coordinator
                .apply_event(&token, SupervisorEvent::CleanupConflicted)
                .unwrap(),
            RecoveryAction::PreserveManifestAndReportConflict
        );
        let current = coordinator.load_current().unwrap().unwrap();
        assert_eq!(current.snapshot.phase, SupervisorPhase::CleanupPending);
        assert_eq!(current.token, token);
        #[cfg(target_os = "linux")]
        {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    #[test]
    fn old_activation_token_cannot_change_a_new_activation_with_reused_generation() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let coordinator = LifecycleCoordinator::new(store).unwrap();
        let old_token = coordinator
            .create_prepared(&snapshot("12345678-1234-4234-8234-123456789abc"))
            .unwrap();

        #[cfg(target_os = "linux")]
        let mut child = bind_fake_core(&coordinator, &old_token);
        coordinator
            .apply_event(&old_token, SupervisorEvent::StartCommitted)
            .unwrap();
        coordinator
            .apply_event(&old_token, SupervisorEvent::CoreExited)
            .unwrap();
        coordinator
            .apply_event(&old_token, SupervisorEvent::CleanupCompleted)
            .unwrap();

        let new_token = coordinator
            .create_prepared(&snapshot("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
            .unwrap();
        assert_eq!(old_token.generation(), new_token.generation());
        assert!(
            coordinator
                .apply_event(&old_token, SupervisorEvent::CoreExited)
                .is_err()
        );
        assert_eq!(
            coordinator.load_current().unwrap().unwrap().token,
            new_token
        );
        #[cfg(target_os = "linux")]
        {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    #[test]
    fn concurrent_activation_claims_are_serialized_across_coordinator_instances() {
        use std::sync::{Arc, Barrier};

        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("runtime");
        let barrier = Arc::new(Barrier::new(2));
        let activation_ids = [
            "12345678-1234-4234-8234-123456789abc",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        ];

        let outcomes = std::thread::scope(|scope| {
            let handles = activation_ids.map(|activation_id| {
                let runtime = runtime.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let store = ManifestStore::open(runtime).unwrap();
                    let coordinator = LifecycleCoordinator::new(store).unwrap();
                    barrier.wait();
                    coordinator.create_prepared(&snapshot(activation_id))
                })
            });
            handles.map(|handle| handle.join().unwrap())
        });

        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_ok()).count(),
            1,
            "exactly one competing activation may claim the empty manifest slot"
        );
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1,
            "the losing activation must fail instead of overwriting the winner"
        );

        let store = ManifestStore::open(runtime).unwrap();
        let current = store.load().unwrap().expect("winning manifest is durable");
        let winning_id = &current.manifest.activation_id;
        assert!(activation_ids.contains(&winning_id.as_str()));
        assert_eq!(current.phase, SupervisorPhase::Prepared);
        assert_eq!(current.generation, 17);
    }
}
