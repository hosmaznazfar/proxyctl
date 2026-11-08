//! Safe staging, validation, and replacement of executable artifacts.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, ensure};

/// Stage a verified executable beside its destination, validate its reported version, then
/// atomically replace the destination. The previous binary is untouched until the final rename.
pub fn replace_executable(
    destination: &Path,
    bytes: &[u8],
    expected_version: &str,
    version_argument: &str,
) -> anyhow::Result<()> {
    let destination = fs::canonicalize(destination)
        .context("could not resolve installed executable path")?;
    let parent = destination
        .parent()
        .context("installed executable has no parent directory")?;
    let staged = staged_path(parent);

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .with_context(|| format!("cannot stage executable beside {}", destination.display()))?;
        file.write_all(bytes).context("could not write staged executable")?;
        file.sync_all().context("could not sync staged executable")?;
        set_executable_permissions(&staged)?;

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
                "could not safely replace {}; existing executable was preserved",
                destination.display()
            )
        })?;
        if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
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
    parent.join(format!(
        ".proxyctl-install-{}-{}.tmp",
        std::process::id(),
        std::thread::current().name().unwrap_or("worker")
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
