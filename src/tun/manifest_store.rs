//! Durable, private storage for TUN ownership manifests.
//!
//! This module only writes Proxyctl runtime files. It does not inspect or mutate kernel state.
//! The caller must serialize lifecycle operations; this store prevents stale activations from
//! overwriting or deleting a different activation's recovery record.

use super::{
    ownership::RouteManifest,
    recovery::SupervisorPhase,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::fs::OpenOptions;

const STORE_FILE: &str = "tun-manifest.json";
const STORE_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSnapshot {
    pub schema_version: u32,
    pub generation: u64,
    pub phase: SupervisorPhase,
    pub manifest: RouteManifest,
}

impl ManifestSnapshot {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == STORE_VERSION, "unsupported TUN manifest store version");
        ensure!(self.generation > 0, "TUN manifest generation must be non-zero");
        self.manifest.validate()
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
        fs::create_dir_all(&directory)
            .with_context(|| format!("cannot create TUN runtime directory {}", directory.display()))?;
        let metadata = fs::symlink_metadata(&directory)
            .with_context(|| format!("cannot inspect TUN runtime directory {}", directory.display()))?;
        ensure!(metadata.file_type().is_dir(), "TUN runtime path is not a real directory");
        verify_owner(&metadata)?;
        set_private_directory(&directory)?;
        let metadata = fs::metadata(&directory)?;
        verify_private_directory(&metadata)?;
        Ok(Self { directory })
    }

    pub fn path(&self) -> PathBuf {
        self.directory.join(STORE_FILE)
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
        ensure!(bytes.len() as u64 <= MAX_MANIFEST_BYTES, "TUN manifest exceeds size limit");
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
        ensure!(metadata.len() <= MAX_MANIFEST_BYTES, "TUN manifest exceeds size limit");
        ensure!(metadata.file_type().is_file(), "TUN manifest is not a regular file");
        verify_owner(&metadata)?;
        verify_private_file(&metadata)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 <= MAX_MANIFEST_BYTES, "TUN manifest exceeds size limit");
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
            snapshot.manifest.activation_id == activation_id
                && snapshot.generation == generation,
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
    ensure!(metadata.uid() == unsafe { libc::geteuid() }, "TUN runtime file has a foreign owner");
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
    ensure!(metadata.permissions().mode() & 0o077 == 0, "TUN runtime directory permissions are not private");
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
    ensure!(metadata.permissions().mode() & 0o077 == 0, "TUN manifest permissions are not private");
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
        assert_eq!(fs::metadata(store.path()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(directory.path().join("runtime")).unwrap().permissions().mode() & 0o777, 0o700);
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
        assert!(store.remove_cleaned("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", 9).is_err());
        assert_eq!(store.load().unwrap(), Some(original));
    }

    #[cfg(unix)]
    #[test]
    fn manifest_is_removed_only_after_matching_generation_is_cleaned() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let mut value = snapshot();
        store.write(&value).unwrap();
        assert!(store.remove_cleaned(&value.manifest.activation_id, value.generation).is_err());
        value.phase = SupervisorPhase::Cleaned;
        store.write(&value).unwrap();
        store.remove_cleaned(&value.manifest.activation_id, value.generation).unwrap();
        assert!(store.load().unwrap().is_none());
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
