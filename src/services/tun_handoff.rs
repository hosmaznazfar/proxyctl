//! Direct, shell-free privilege handoff for the internal TUN supervisor.
//!
//! This transports a bounded generated request to the single-executable privileged supervisor.
//! The supervisor owns native core startup, readiness, durable session commit, monitoring,
//! and generation-scoped journal recovery.
use anyhow::{Context, Result, ensure};
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

use super::activation::TunHandoffGuard;
use crate::tun::{
    launch_spec::LaunchSpec,
    session_record::SessionRecord,
    supervisor_protocol::{self, SupervisorOutcome},
};

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
const STARTUP_ACK_TIMEOUT: Duration = Duration::from_secs(60);

/// Request a privileged TUN session and return only after its one-shot startup acknowledgement.
///
/// The supervisor closes stdout after its reply and remains alive to monitor the core and
/// recover its generation on exit. A Started reply is accepted only while the supervisor is
/// still alive. Foreground requests wait for that supervisor to finish.
/// Ask the single Proxyctl executable to recover and stop the current privileged TUN session.
///
/// Sudo keeps its terminal attached for authentication. The request carries no caller-controlled
/// paths or arguments beyond the fixed hidden command; the supervisor derives the runtime owner
/// from sudo credentials and loads only root-owned durable records.
pub fn request_supervisor_recovery() -> Result<()> {
    let sudo = find_sudo()?;
    let executable =
        std::env::current_exe().context("cannot resolve current Proxyctl executable")?;
    let status = Command::new(sudo)
        .arg("--")
        .arg(executable)
        .arg("__tun-recover")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("cannot launch privileged Proxyctl TUN recovery via sudo")?;
    ensure!(
        status.success(),
        "privileged TUN recovery exited with {status}"
    );
    Ok(())
}

pub fn request_supervisor_session(
    spec: &LaunchSpec,
    handoff_guard: TunHandoffGuard,
) -> Result<SessionRecord> {
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
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("cannot launch privileged Proxyctl supervisor via sudo")?;

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let cleanup = abort_child(&mut child);
            anyhow::bail!("supervisor acknowledgement pipe was not created; {cleanup}");
        }
    };
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .take(supervisor_protocol::MAX_REPLY_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });

    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(&encoded),
        None => Err(std::io::Error::other("sudo request stdin was not created")),
    };
    // Dropping the request pipe delimits the complete bounded request.
    if let Err(error) = write_result {
        let cleanup = abort_child(&mut child);
        let _ = reader.join();
        return Err(error).context(format!(
            "cannot deliver TUN launch request to supervisor; {cleanup}"
        ));
    }

    let response = match receiver.recv_timeout(STARTUP_ACK_TIMEOUT) {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            let cleanup = abort_child(&mut child);
            let _ = reader.join();
            return Err(error)
                .context(format!("cannot read supervisor acknowledgement; {cleanup}"));
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let cleanup = abort_child(&mut child);
            let _ = reader.join();
            anyhow::bail!(
                "privileged TUN supervisor did not acknowledge startup within {} seconds; {cleanup}",
                STARTUP_ACK_TIMEOUT.as_secs()
            );
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let cleanup = abort_child(&mut child);
            let _ = reader.join();
            anyhow::bail!("supervisor acknowledgement channel closed unexpectedly; {cleanup}");
        }
    };
    if reader.join().is_err() {
        let cleanup = abort_child(&mut child);
        anyhow::bail!("supervisor acknowledgement reader panicked; {cleanup}");
    }

    let reply = match supervisor_protocol::read_reply(response.as_slice()) {
        Ok(reply) => reply,
        Err(error) => {
            let cleanup = abort_child(&mut child);
            return Err(error).context(format!(
                "invalid privileged supervisor acknowledgement; {cleanup}"
            ));
        }
    };

    match reply.outcome {
        SupervisorOutcome::Started { session } => {
            // Release the activation lock only after a durable Started reply is accepted.
            // A concurrent stop can now safely recover this exact session.
            drop(handoff_guard);
            if spec.foreground {
                let status = match child.wait() {
                    Ok(status) => status,
                    Err(error) => {
                        let cleanup = abort_child(&mut child);
                        return Err(error).context(format!(
                            "cannot wait for the foreground TUN supervisor; {cleanup}"
                        ));
                    }
                };
                ensure!(
                    status.success(),
                    "foreground TUN supervisor exited with {status}"
                );
                Ok(session)
            } else {
                match child.try_wait() {
                    Ok(None) => {
                        // The supervisor has closed the acknowledgement channel and remains
                        // alive to own the background session. Dropping Child does not kill it.
                        drop(child);
                        Ok(session)
                    }
                    Ok(Some(status)) => anyhow::bail!(
                        "supervisor exited with {status} immediately after reporting a started session"
                    ),
                    Err(error) => {
                        let cleanup = abort_child(&mut child);
                        Err(error).context(format!(
                            "cannot verify supervisor survived its startup acknowledgement; {cleanup}"
                        ))
                    }
                }
            }
        }
        SupervisorOutcome::NotStarted { reason } => {
            let cleanup = abort_child(&mut child);
            anyhow::bail!("supervisor did not start a TUN session: {reason}; {cleanup}")
        }
        SupervisorOutcome::Failed { reason } => {
            let cleanup = abort_child(&mut child);
            anyhow::bail!("privileged TUN supervisor rejected the request: {reason}; {cleanup}")
        }
    }
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
