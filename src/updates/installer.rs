//! Staging, validating, and installing executable artifacts.
use anyhow::{Context, ensure};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn replace_executable(
    destination: &Path,
    bytes: &[u8],
    expected_version: &str,
    version_argument: &str,
) -> anyhow::Result<()> {
    let parent = destination
        .parent()
        .context("executable destination has no parent")?;
    fs::create_dir_all(parent).context("could not create executable directory")?;
    let parent = fs::canonicalize(parent).context("could not resolve executable directory")?;
    let file_name = destination
        .file_name()
        .context("executable destination has no filename")?;
    let destination = parent.join(file_name);
    let staged = staged_path(&parent);

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .with_context(|| format!("cannot stage executable beside {}", destination.display()))?;
        file.write_all(bytes)
            .context("could not write staged executable")?;
        file.sync_all()
            .context("could not sync staged executable")?;
        set_executable_permissions(&staged)?;

        // Linux returns ETXTBSY when an executable is launched while a writable
        // file descriptor for it remains open. Close it before version validation.
        drop(file);

        let output = Command::new(&staged)
            .arg(version_argument)
            .output()
            .context("could not validate staged executable")?;
        ensure!(
            output.status.success(),
            "staged executable failed its version check"
        );
        let version_output = String::from_utf8_lossy(&output.stdout);
        ensure!(
            version_output.contains(expected_version),
            "staged executable version does not match expected release {expected_version}"
        );
        fs::rename(&staged, &destination).with_context(|| {
            format!(
                "could not safely install {}; previous executable was preserved",
                destination.display()
            )
        })?;
        if let Ok(directory) = OpenOptions::new().read(true).open(&parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

fn staged_path(parent: &Path) -> PathBuf {
    let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".proxyctl-install-{}-{sequence}.tmp",
        std::process::id()
    ))
}

#[cfg(unix)]
fn set_executable_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .context("could not set executable permissions")
}

#[cfg(not(unix))]
fn set_executable_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn closes_staged_file_before_executing_version_check() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("managed-core");
        let script = b"#!/bin/sh\nprintf 'core version 1.2.3\\n'\n";

        replace_executable(&destination, script, "1.2.3", "--version")
            .expect("staged executable should run and install");

        let output = Command::new(&destination)
            .arg("--version")
            .output()
            .expect("installed executable should run");
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("1.2.3"));
    }

    #[cfg(unix)]
    #[test]
    fn removes_staged_file_when_version_validation_fails() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destination = directory.path().join("managed-core");
        let script = b"#!/bin/sh\nprintf 'wrong version\\n'\n";

        assert!(replace_executable(&destination, script, "1.2.3", "--version").is_err());
        assert!(!destination.exists());
        let remaining = fs::read_dir(directory.path())
            .expect("read staging directory")
            .count();
        assert_eq!(remaining, 0);
    }
}
