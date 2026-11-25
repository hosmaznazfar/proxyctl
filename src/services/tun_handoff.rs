//! Direct, shell-free privilege handoff for the internal TUN supervisor.
//!
//! This transports a bounded generated request only. The supervisor still fails closed
//! after validation until the root-owned lifecycle and recovery backend is implemented.
use anyhow::{Context, Result, ensure};
use std::{
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

use crate::tun::launch_spec::LaunchSpec;

/// Resolve sudo only from conventional system locations, never from the caller's PATH.
///
/// A PATH lookup would allow a user-controlled executable to impersonate sudo before
/// authorization. The resolved executable must be a root-owned, non-writable regular file.
fn find_sudo() -> Result<PathBuf> {
    for candidate in ["/usr/bin/sudo", "/bin/sudo"] {
        let candidate = Path::new(candidate);
        if !candidate.exists() {
            continue;
        }
        let executable = std::fs::canonicalize(candidate)
            .with_context(|| format!("cannot resolve sudo at {}", candidate.display()))?;
        let metadata = std::fs::metadata(&executable)
            .with_context(|| format!("cannot inspect sudo at {}", executable.display()))?;
        validate_sudo_metadata(&metadata, 0)
            .with_context(|| format!("sudo at {} is not trusted", executable.display()))?;
        return Ok(executable);
    }
    anyhow::bail!("sudo is required for TUN mode but was not found in a system location")
}

fn validate_sudo_metadata(metadata: &std::fs::Metadata, expected_uid: u32) -> Result<()> {
    let mode = metadata.permissions().mode() & 0o7777;
    ensure!(metadata.is_file(), "sudo executable is not a regular file");
    ensure!(
        metadata.uid() == expected_uid,
        "sudo executable is not owned by root"
    );
    ensure!(mode & 0o111 != 0, "sudo executable has no execute bit");
    ensure!(
        mode & 0o022 == 0,
        "sudo executable is writable by group or other users"
    );
    Ok(())
}

/// Terminate and reap a child when request delivery fails, avoiding an orphaned sudo process.
fn abort_child(child: &mut Child) -> String {
    let kill = child.kill();
    let wait = child.wait();
    format!("child kill result: {kill:?}; child reap result: {wait:?}")
}

/// Request root validation through sudo, with config delivered exclusively on stdin.
///
/// No shell is involved; sudo's password prompt is handled via its terminal, not stdin.
/// A failed request write always triggers a best-effort kill and reap of the sudo child.
pub fn validate_supervisor_handoff(spec: &LaunchSpec) -> Result<()> {
    let encoded = spec
        .encode_bounded()
        .context("cannot encode bounded TUN request")?;
    let sudo = find_sudo()?;
    let executable =
        std::env::current_exe().context("cannot resolve current Proxyctl executable")?;
    let mut child = Command::new(sudo)
        .arg("--")
        .arg(executable)
        .arg("__tun-supervisor")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("cannot launch privileged Proxyctl supervisor via sudo")?;

    let write_result = match child.stdin.take() {
        Some(stdin) => {
            let mut stdin = stdin;
            stdin.write_all(&encoded)
        }
        None => Err(std::io::Error::other("sudo request stdin was not created")),
    };
    // Closing the pipe delimits the complete bounded request for the supervisor.
    if let Err(error) = write_result {
        let cleanup = abort_child(&mut child);
        return Err(error).context(format!(
            "cannot deliver TUN launch request to supervisor; {cleanup}"
        ));
    }

    let status = child
        .wait()
        .context("cannot wait for supervisor validation")?;
    ensure!(
        status.success(),
        "privileged TUN supervisor validation exited with {status}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn rejects_sudo_metadata_with_wrong_owner() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("sudo");
        fs::write(&executable, b"not executed").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let metadata = fs::metadata(&executable).unwrap();
        assert!(validate_sudo_metadata(&metadata, u32::MAX).is_err());
    }

    #[test]
    fn rejects_non_executable_sudo_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("sudo");
        fs::write(&executable, b"not executed").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o644)).unwrap();
        let metadata = fs::metadata(&executable).unwrap();
        assert!(validate_sudo_metadata(&metadata, unsafe { libc::getuid() }).is_err());
    }

    #[test]
    fn rejects_group_or_world_writable_sudo_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("sudo");
        fs::write(&executable, b"not executed").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o757)).unwrap();
        let metadata = fs::metadata(&executable).unwrap();
        assert!(validate_sudo_metadata(&metadata, unsafe { libc::getuid() }).is_err());
    }

    #[test]
    fn abort_child_terminates_and_reaps_the_handoff_process() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let _cleanup = abort_child(&mut child);
        assert!(child.try_wait().unwrap().is_some());
    }
}
