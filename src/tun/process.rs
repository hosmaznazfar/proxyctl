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
        let identity = Self {
            pid,
            start_ticks,
            executable,
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.pid > 0, "process ID must be non-zero");
        ensure!(self.start_ticks > 0, "process start time must be non-zero");
        ensure!(
            self.executable.is_absolute(),
            "process executable identity must be an absolute path"
        );
        Ok(())
    }

    pub fn verify(&self) -> Result<bool> {
        self.validate()?;
        let start_ticks = match read_start_ticks(self.pid) {
            Ok(value) => value,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(false);
            }
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
        let raw = unsafe {
            libc::syscall(libc::SYS_pidfd_open, identity.pid as libc::pid_t, 0u32) as libc::c_int
        };
        ensure!(
            raw >= 0,
            "pidfd_open is unavailable or process cannot be opened"
        );
        // SAFETY: successful pidfd_open returns a new owned file descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let handle = Self { identity, pidfd };
        ensure!(
            handle.identity.verify()?,
            "process identity changed while opening pidfd"
        );
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
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        ensure!(result >= 0, "poll on process pidfd failed");
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
            self.identity.verify()?,
            "refusing to signal a process whose identity no longer matches"
        );
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            ) as libc::c_int
        };
        ensure!(result == 0, "pidfd_send_signal failed");
        Ok(())
    }
}

fn read_start_ticks(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .with_context(|| format!("cannot read process identity for PID {pid}"))?;
    let close = stat
        .rfind(')')
        .context("process stat has no closing command delimiter")?;
    let fields = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
    fields
        .get(19)
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
    fn pidfd_wait_observes_only_the_pinned_child_exit() {
        let mut child = child();
        let identity = ProcessIdentity::capture(child.id()).unwrap();
        let handle = ProcessHandle::open(identity).unwrap();
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
            if let Ok(identity) = ProcessIdentity::capture(child.id())
                && let Ok(handle) = ProcessHandle::open(identity.clone())
            {
                return (identity, handle);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
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
