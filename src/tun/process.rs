//! Linux process-instance identity and pidfd operations for the TUN supervisor.
//!
//! A PID alone is never an ownership identity. The process start time and canonical executable
//! are checked after opening a pidfd, so PID reuse cannot redirect monitoring or signals.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::PathBuf,
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub executable: PathBuf,
}

impl ProcessIdentity {
    pub fn capture(pid: u32) -> Result<Self> {
        ensure!(pid > 0, "process ID must be non-zero");
        let start_ticks = read_start_ticks(pid)?;
        let executable = fs::canonicalize(format!("/proc/{pid}/exe"))
            .with_context(|| format!("cannot resolve executable for process {pid}"))?;
        ensure!(
            read_start_ticks(pid)? == start_ticks,
            "process identity changed while it was being captured"
        );
        let identity = Self {
            pid,
            start_ticks,
            executable,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.pid > 0 && self.pid <= libc::pid_t::MAX as u32,
            "process ID is outside the Linux pid_t range"
        );
        ensure!(self.start_ticks > 0, "process start time must be non-zero");
        let executable_text = self
            .executable
            .to_str()
            .context("process executable identity is not valid UTF-8")?;
        ensure!(
            self.executable.is_absolute()
                && self.executable.file_name().is_some()
                && !executable_text
                    .bytes()
                    .any(|byte| byte == 0 || byte.is_ascii_control())
                && executable_text
                    .split('/')
                    .skip(1)
                    .all(|component| !component.is_empty()
                        && component != "."
                        && component != "..")
                && self.executable.components().all(|component| {
                    matches!(
                        component,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                }),
            "process executable identity must be a normalized absolute file path"
        );
        Ok(())
    }

    pub fn verify(&self) -> Result<bool> {
        self.validate()?;
        let start_ticks = match read_start_ticks(self.pid) {
            Ok(value) => value,
            Err(error) if is_process_gone(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        if start_ticks != self.start_ticks {
            return Ok(false);
        }
        let executable = match fs::canonicalize(format!("/proc/{}/exe", self.pid)) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        Ok(executable == self.executable)
    }
}

/// A pidfd pins one process instance and remains safe if its numeric PID is later reused.
pub struct ProcessHandle {
    identity: ProcessIdentity,
    pidfd: OwnedFd,
}

impl ProcessHandle {
    pub fn open(identity: ProcessIdentity) -> Result<Self> {
        identity.validate()?;
        let raw = loop {
            let result = unsafe {
                libc::syscall(libc::SYS_pidfd_open, identity.pid as libc::pid_t, 0u32)
                    as libc::c_int
            };
            if result >= 0 {
                break result;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("pidfd_open is unavailable or process cannot be opened");
        };
        // SAFETY: successful pidfd_open returns a new owned file descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let handle = Self { identity, pidfd };
        // The process may exit after pidfd_open but before /proc identity verification.
        // A readable pidfd proves that the pinned instance has exited, so monitoring can
        // safely treat it as dead without consulting a possibly vanished or reused PID.
        if handle.wait_exit(Duration::ZERO)? {
            return Ok(handle);
        }
        if !handle.identity.verify()? {
            // Close the race where the process exits after the first pidfd poll but before
            // /proc identity verification. A now-readable pidfd proves the pinned instance
            // exited; a live replacement PID remains unreadable and is rejected.
            ensure!(
                handle.wait_exit(Duration::ZERO)?,
                "process identity changed while opening pidfd"
            );
        }
        Ok(handle)
    }

    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }

    pub fn is_exited(&self) -> Result<bool> {
        self.wait_exit(Duration::ZERO)
    }

    /// Wait for this exact process instance to exit. A false result means timeout.
    pub fn wait_exit(&self, timeout: Duration) -> Result<bool> {
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = loop {
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if result >= 0 {
                break result;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                descriptor.revents = 0;
                continue;
            }
            return Err(error).context("poll on process pidfd failed");
        };
        if result == 0 {
            return Ok(false);
        }
        ensure!(
            descriptor.revents & (libc::POLLIN | libc::POLLHUP) != 0,
            "pidfd returned an unexpected poll event"
        );
        Ok(true)
    }

    /// Signal only the pinned process instance after rechecking its recorded identity.
    pub fn signal(&self, signal: i32) -> Result<()> {
        ensure!(
            (1..=64).contains(&signal),
            "refusing an invalid or signal-zero pidfd operation"
        );
        ensure!(
            self.identity.verify()?,
            "refusing to signal a process whose identity no longer matches"
        );
        loop {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                ) as libc::c_int
            };
            if result == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("pidfd_send_signal failed");
        }
        Ok(())
    }
}

/// Read the pinned process's real/effective/saved/filesystem UIDs from procfs.
///
/// All four values must agree: a setuid or otherwise credential-divergent target is
/// deliberately rejected by the broker's same-user policy.
pub fn read_process_owner_uid(handle: &ProcessHandle) -> Result<u32> {
    let identity = handle.identity();
    ensure!(
        identity.verify()?,
        "process identity changed before owner inspection"
    );
    ensure!(
        !handle.is_exited()?,
        "process exited before owner inspection"
    );
    let status = fs::read_to_string(format!("/proc/{}/status", identity.pid))
        .context("cannot inspect pinned process credentials")?;
    let uid_line = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .context("process status is missing UID credentials")?;
    let values = uid_line
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("process status contains invalid UID credentials")?;
    ensure!(
        values.len() == 4,
        "process status has an unexpected UID field count"
    );
    ensure!(
        values.iter().all(|uid| *uid == values[0]),
        "process has divergent real/effective/saved/filesystem UIDs"
    );
    ensure!(
        identity.verify()?,
        "process identity changed during owner inspection"
    );
    ensure!(
        !handle.is_exited()?,
        "process exited during owner inspection"
    );
    Ok(values[0])
}

fn is_process_gone(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

fn read_start_ticks(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("cannot read process identity for PID {pid}"))?;
    let close = stat
        .rfind(')')
        .context("process stat has no closing command delimiter")?;
    stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .context("process stat is missing start-time field")?
        .parse()
        .context("process stat has an invalid start-time field")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::{Child, Command, Stdio},
        time::Instant,
    };

    fn child() -> Child {
        Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep must be available for process identity tests")
    }

    #[test]
    fn reads_owner_uid_only_from_a_live_pinned_process() {
        let child = child();
        let (_identity, handle) = pin_live_child(&child);
        assert_eq!(read_process_owner_uid(&handle).unwrap(), unsafe {
            libc::getuid()
        });
        drop(handle);
        drop(child);
    }

    #[test]
    fn captures_and_verifies_exact_process_identity() {
        let mut child = child();
        let identity = ProcessIdentity::capture(child.id()).unwrap();
        assert!(identity.verify().unwrap());
        assert!(identity.executable.is_absolute());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!identity.verify().unwrap());
    }

    #[test]
    fn rejects_pid_values_outside_linux_pid_t_range() {
        let mut invalid = ProcessIdentity {
            pid: u32::MAX,
            start_ticks: 1,
            executable: PathBuf::from("/usr/bin/sleep"),
        };
        assert!(invalid.validate().is_err());
        invalid.pid = 1;
        invalid.executable = PathBuf::from("/usr/bin/./sleep");
        assert!(invalid.validate().is_err());
        invalid.executable = PathBuf::from("/usr/bin/../bin/sleep");
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rejects_changed_start_time_and_executable() {
        let mut child = child();
        let identity = ProcessIdentity::capture(child.id()).unwrap();
        let mut changed = identity.clone();
        changed.start_ticks += 1;
        assert!(!changed.verify().unwrap());
        let mut changed = identity;
        changed.executable = PathBuf::from("/bin/false");
        assert!(!changed.verify().unwrap());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn pidfd_signal_rejects_zero_and_out_of_range_signals() {
        let child = child();
        let (_identity, handle) = pin_live_child(&child);
        assert!(handle.signal(0).is_err());
        assert!(handle.signal(65).is_err());
        drop(handle);
        drop(child);
    }

    #[test]
    fn pidfd_wait_observes_only_the_pinned_child_exit() {
        let mut child = child();
        let (_identity, handle) = pin_live_child(&child);
        assert!(!handle.is_exited().unwrap());
        child.kill().unwrap();
        child.wait().unwrap();
        let started = Instant::now();
        assert!(handle.wait_exit(Duration::from_secs(1)).unwrap());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    fn pin_live_child(child: &Child) -> (ProcessIdentity, ProcessHandle) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(
                Instant::now() < deadline,
                "fake child did not remain available long enough to pin its pidfd"
            );
            if let Ok(identity) = ProcessIdentity::capture(child.id()) {
                // Command::spawn can return while the child is still completing exec.
                // Require the executable and start-time identity to remain stable before
                // pinning the pidfd, then verify it once more before returning the handle.
                std::thread::sleep(Duration::from_millis(10));
                if identity.verify().unwrap_or(false)
                    && let Ok(handle) = ProcessHandle::open(identity.clone())
                {
                    std::thread::sleep(Duration::from_millis(10));
                    if handle.identity().verify().unwrap_or(false) {
                        return (identity, handle);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_until_unreaped_child_exits(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
                .expect("unreaped child must remain visible in procfs");
            let close = stat
                .rfind(')')
                .expect("process stat must close command name");
            let state = stat[close + 1..]
                .split_whitespace()
                .next()
                .expect("process stat must include state");
            if matches!(state, "Z" | "X") {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "child did not exit after SIGKILL"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn pidfd_open_accepts_an_already_exited_but_unreaped_child() {
        let mut child = child();
        let identity = ProcessIdentity::capture(child.id()).unwrap();
        child.kill().unwrap();
        // kill() only queues the signal; wait for the zombie state without reaping the child.
        wait_until_unreaped_child_exits(child.id());

        let handle = ProcessHandle::open(identity).unwrap();
        assert!(handle.is_exited().unwrap());
        child.wait().unwrap();
    }

    #[test]
    fn pidfd_signal_targets_the_verified_fake_child() {
        let mut child = child();
        let (_identity, handle) = pin_live_child(&child);
        handle.signal(libc::SIGTERM).unwrap();
        assert!(handle.wait_exit(Duration::from_secs(2)).unwrap());
        child.wait().unwrap();
    }

    #[test]
    fn rejects_non_normalized_executable_identity_paths() {
        for executable in [PathBuf::from("/bin/../bin/sleep"), PathBuf::from("/")] {
            let identity = ProcessIdentity {
                pid: 1,
                start_ticks: 1,
                executable,
            };
            assert!(identity.validate().is_err());
        }
    }

    #[test]
    fn invalid_or_unavailable_process_identity_fails_closed() {
        let invalid = ProcessIdentity {
            pid: 0,
            start_ticks: 1,
            executable: PathBuf::from("/bin/sleep"),
        };
        assert!(ProcessHandle::open(invalid).is_err());
        let missing = ProcessIdentity {
            pid: u32::MAX,
            start_ticks: 1,
            executable: PathBuf::from("/bin/sleep"),
        };
        assert!(ProcessHandle::open(missing).is_err());
    }
}
