//! Root-owned durable identity for one privileged TUN core session.
//!
//! This record is separate from the user-owned lifecycle manifest. It binds the invoking
//! UID and selected core to one activation generation and one exact Linux process instance.
//! It does not launch, signal, or clean up a process and does not mutate host networking.

use super::{launch_spec::CoreKind, process::ProcessIdentity};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const SESSION_FILE: &str = "tun-session.json";
const MAX_SESSION_BYTES: u64 = 16 * 1024;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    pub schema_version: u32,
    pub invoking_uid: u32,
    pub session_nonce: String,
    pub activation_id: String,
    pub generation: u64,
    pub core: CoreKind,
    pub process: ProcessIdentity,
}

impl SessionRecord {
    /// Construct a record with a kernel-generated session nonce.
    pub fn new(
        invoking_uid: u32,
        activation_id: String,
        generation: u64,
        core: CoreKind,
        process: ProcessIdentity,
    ) -> Result<Self> {
        let session_nonce = fs::read_to_string("/proc/sys/kernel/random/uuid")
            .context("cannot obtain a kernel-generated TUN session nonce")?
            .trim()
            .to_owned();
        let record = Self {
            schema_version: 1,
            invoking_uid,
            session_nonce,
            activation_id,
            generation,
            core,
            process,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported TUN session record version"
        );
        ensure!(
            self.invoking_uid != 0,
            "TUN session owner UID must be non-zero"
        );
        ensure!(
            canonical_uuid(&self.session_nonce),
            "TUN session nonce must be a canonical lowercase UUID"
        );
        ensure!(
            canonical_uuid(&self.activation_id),
            "TUN activation ID must be a canonical lowercase UUID"
        );
        ensure!(
            self.generation > 0,
            "TUN session generation must be non-zero"
        );
        self.process.validate()?;
        ensure!(
            self.process
                .executable
                .file_name()
                .is_some_and(|name| name == self.core.as_str()),
            "recorded process executable name does not match the selected core kind"
        );
        Ok(())
    }
}

/// Durable session metadata stored only below the root-owned per-user runtime directory.
#[derive(Debug, Clone)]
pub struct SessionStore {
    directory: PathBuf,
    owner_uid: u32,
    invoking_uid: u32,
}

impl SessionStore {
    /// Open the root-owned runtime directory created by the privileged runtime bootstrap.
    pub fn open_root_owned(directory: impl Into<PathBuf>, invoking_uid: u32) -> Result<Self> {
        let directory = directory.into();
        ensure!(invoking_uid != 0, "TUN session owner UID must be non-zero");
        let expected_directory = PathBuf::from("/run/proxyctl").join(invoking_uid.to_string());
        ensure!(
            directory == expected_directory,
            "privileged runtime directory does not match the invoking UID"
        );
        Self::open_for_owner(directory, 0, invoking_uid)
    }

    pub(crate) fn open_for_owner(
        directory: PathBuf,
        expected_owner_uid: u32,
        invoking_uid: u32,
    ) -> Result<Self> {
        ensure!(invoking_uid != 0, "TUN session owner UID must be non-zero");
        verify_directory(&directory, expected_owner_uid)?;
        Ok(Self {
            directory: fs::canonicalize(&directory)
                .context("cannot canonicalize privileged TUN session directory")?,
            owner_uid: expected_owner_uid,
            invoking_uid,
        })
    }

    /// Persist the first session record without replacing any existing recovery evidence.
    pub fn create(&self, record: &SessionRecord) -> Result<()> {
        record.validate()?;
        ensure!(
            record.invoking_uid == self.invoking_uid,
            "TUN session record UID does not match its privileged runtime directory"
        );
        ensure!(
            self.load()?.is_none(),
            "an existing privileged TUN session must be recovered before starting another"
        );

        let destination = self.path();
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)
            .context("cannot create temporary privileged TUN session record")?;
        set_private_file(temporary.as_file())?;
        verify_file(&temporary.as_file().metadata()?, self.owner_uid)?;
        serde_json::to_writer(&mut temporary, record)
            .context("cannot serialize privileged TUN session record")?;
        ensure!(
            temporary.as_file().metadata()?.len() <= MAX_SESSION_BYTES,
            "privileged TUN session record exceeds its size limit"
        );
        temporary.as_file().sync_all()?;
        temporary
            .persist_noclobber(&destination)
            .context("cannot atomically create privileged TUN session record")?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    /// Load a bounded record without following symlinks or accepting mutable file metadata.
    pub fn load(&self) -> Result<Option<SessionRecord>> {
        let file = match open_private_file(&self.path()) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).context("cannot securely open privileged TUN session record");
            }
        };
        let before = file.metadata()?;
        verify_file(&before, self.owner_uid)?;
        ensure!(
            before.len() <= MAX_SESSION_BYTES,
            "privileged TUN session record exceeds its size limit"
        );

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(before.len() as usize)
            .context("cannot reserve bounded privileged session read buffer")?;
        (&file)
            .take(MAX_SESSION_BYTES + 1)
            .read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        ensure!(
            bytes.len() as u64 == before.len() && after.len() == before.len(),
            "privileged TUN session record changed size while being read"
        );
        ensure!(
            before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.mtime() == after.mtime()
                && before.mtime_nsec() == after.mtime_nsec()
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec(),
            "privileged TUN session record changed while being read"
        );
        ensure!(!bytes.is_empty(), "privileged TUN session record is empty");
        let record: SessionRecord =
            serde_json::from_slice(&bytes).context("privileged TUN session record is malformed")?;
        record.validate()?;
        ensure!(
            record.invoking_uid == self.invoking_uid,
            "TUN session record UID does not match its privileged runtime directory"
        );
        Ok(Some(record))
    }

    /// Remove only the exact session record supplied by the caller.
    pub fn remove(&self, expected: &SessionRecord) -> Result<()> {
        expected.validate()?;
        let current = self
            .load()?
            .context("no privileged TUN session record exists")?;
        ensure!(
            current == *expected,
            "refusing to remove a different privileged TUN session record"
        );
        fs::remove_file(self.path())
            .context("cannot remove completed privileged TUN session record")?;
        sync_directory(&self.directory)?;
        Ok(())
    }

    pub fn path(&self) -> PathBuf {
        self.directory.join(SESSION_FILE)
    }
}

fn canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn verify_directory(path: &Path, expected_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "cannot inspect privileged session directory {}",
            path.display()
        )
    })?;
    ensure!(
        metadata.file_type().is_dir(),
        "privileged session path is not a real directory"
    );
    ensure!(
        metadata.uid() == expected_uid,
        "privileged session directory has an unexpected owner"
    );
    ensure!(
        metadata.permissions().mode() & 0o7777 == PRIVATE_DIRECTORY_MODE,
        "privileged session directory must be owned by the expected UID with mode 0700"
    );
    Ok(())
}

fn set_private_file(file: &File) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .context("cannot secure privileged TUN session record")
}

fn verify_file(metadata: &fs::Metadata, expected_uid: u32) -> Result<()> {
    ensure!(
        metadata.file_type().is_file(),
        "privileged TUN session record is not a regular file"
    );
    ensure!(
        metadata.uid() == expected_uid,
        "privileged TUN session record has an unexpected owner"
    );
    ensure!(
        metadata.permissions().mode() & 0o7777 == PRIVATE_FILE_MODE,
        "privileged TUN session record must have mode 0600"
    );
    ensure!(
        metadata.nlink() == 1,
        "privileged TUN session record must not have hard links"
    );
    Ok(())
}

fn open_private_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .with_context(|| {
            format!(
                "cannot open privileged runtime directory {}",
                directory.display()
            )
        })?
        .sync_all()
        .context("cannot sync privileged runtime directory")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
    };

    fn record() -> SessionRecord {
        SessionRecord {
            schema_version: 1,
            invoking_uid: 1000,
            session_nonce: "12345678-1234-4234-8234-123456789abc".into(),
            activation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            generation: 7,
            core: CoreKind::Xray,
            process: ProcessIdentity {
                pid: 42,
                start_ticks: 99,
                executable: PathBuf::from("/home/user/.local/share/proxyctl/cores/xray/xray"),
            },
        }
    }

    #[test]
    fn constructs_record_with_kernel_generated_session_nonce() {
        let source = record();
        let generated = SessionRecord::new(
            unsafe { libc::getuid() },
            source.activation_id,
            source.generation,
            source.core,
            source.process,
        )
        .unwrap();
        assert!(canonical_uuid(&generated.session_nonce));
    }

    #[test]
    fn validates_complete_session_identity() {
        assert!(record().validate().is_ok());
        let mut invalid = record();
        invalid.invoking_uid = 0;
        assert!(invalid.validate().is_err());
        let mut invalid = record();
        invalid.session_nonce = "not-a-uuid".into();
        assert!(invalid.validate().is_err());
        let mut invalid = record();
        invalid.generation = 0;
        assert!(invalid.validate().is_err());
        let mut invalid = record();
        invalid.process.executable = PathBuf::from("/usr/bin/not-xray");
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rejects_unknown_session_record_fields() {
        let bytes = br#"{"schema_version":1,"invoking_uid":1000,"session_nonce":"12345678-1234-4234-8234-123456789abc","activation_id":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","generation":7,"core":"xray","process":{"pid":42,"start_ticks":99,"executable":"/bin/xray"},"extra":true}"#;
        assert!(serde_json::from_slice::<SessionRecord>(bytes).is_err());
    }

    #[test]
    fn rejects_symlinked_session_directory() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, &link).unwrap();
        assert!(
            SessionStore::open_for_owner(link, unsafe { libc::geteuid() }, unsafe {
                libc::getuid()
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_session_directory_with_permissive_mode() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            SessionStore::open_for_owner(
                directory.path().to_path_buf(),
                unsafe { libc::geteuid() },
                unsafe { libc::getuid() }
            )
            .is_err()
        );
    }

    #[test]
    fn creates_loads_and_removes_only_the_matching_record() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = SessionStore::open_for_owner(
            directory.path().to_path_buf(),
            unsafe { libc::geteuid() },
            unsafe { libc::getuid() },
        )
        .unwrap();
        let mut expected = record();
        expected.invoking_uid = unsafe { libc::getuid() };
        store.create(&expected).unwrap();
        assert_eq!(store.load().unwrap(), Some(expected.clone()));
        let mut other = expected.clone();
        other.session_nonce = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into();
        assert!(store.remove(&other).is_err());
        assert_eq!(store.load().unwrap(), Some(expected.clone()));
        store.remove(&expected).unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn refuses_to_replace_an_existing_session_record() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = SessionStore::open_for_owner(
            directory.path().to_path_buf(),
            unsafe { libc::geteuid() },
            unsafe { libc::getuid() },
        )
        .unwrap();
        let mut expected = record();
        expected.invoking_uid = unsafe { libc::getuid() };
        store.create(&expected).unwrap();
        let mut replacement = expected.clone();
        replacement.session_nonce = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into();
        assert!(store.create(&replacement).is_err());
    }
}
