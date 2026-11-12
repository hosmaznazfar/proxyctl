//! Durable, private storage for TUN ownership manifests.
//!
//! This module only writes Proxyctl runtime files. It does not inspect or mutate kernel state.
//! The caller must serialize lifecycle operations; this store prevents stale activations from
//! overwriting or deleting a different activation's recovery record.

use super::{
    ownership::RouteManifest,
    #[cfg(target_os = "linux")] process::ProcessIdentity,
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
const STORE_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

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
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "TUN manifest permissions are not private"
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
