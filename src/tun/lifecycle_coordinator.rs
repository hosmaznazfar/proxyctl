use super::{
    manifest_store::{ManifestSnapshot, ManifestStore},
    recovery::{RecoveryAction, SupervisorEvent},
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

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatedSnapshot {
    pub snapshot: ManifestSnapshot,
    pub token: ActivationToken,
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

    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: flock operates on the valid descriptor owned by file.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(file);
        }
        let error = std::io::Error::last_os_error();
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

    fn snapshot(activation_id: &str) -> ManifestSnapshot {
        ManifestSnapshot {
            schema_version: 1,
            generation: 17,
            phase: SupervisorPhase::Prepared,
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

    #[test]
    fn coordinator_serializes_manifest_creation_and_event_transitions() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let coordinator = LifecycleCoordinator::new(store).unwrap();
        let token = coordinator
            .create_prepared(&snapshot("12345678-1234-4234-8234-123456789abc"))
            .unwrap();

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
    }

    #[test]
    fn old_activation_token_cannot_change_a_new_activation_with_reused_generation() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let coordinator = LifecycleCoordinator::new(store).unwrap();
        let old_token = coordinator
            .create_prepared(&snapshot("12345678-1234-4234-8234-123456789abc"))
            .unwrap();

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
    }
}
