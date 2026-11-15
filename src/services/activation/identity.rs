//! Exact managed-process identity checks and pidfd signaling.
use std::{
    fs,
    net::TcpStream,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use anyhow::ensure;

use super::POLL;

#[cfg(target_os = "linux")]
pub(super) fn start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.get(stat.rfind(')')? + 2..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
#[cfg(target_os = "linux")]
pub(super) fn executable(pid: u32) -> Option<PathBuf> {
    fs::canonicalize(format!("/proc/{pid}/exe")).ok()
}
#[cfg(target_os = "linux")]
pub(super) fn matches_process(pid: u32, expected: &Path, ticks: u64) -> bool {
    start_ticks(pid) == Some(ticks) && executable(pid).as_deref() == Some(expected)
}
#[cfg(target_os = "linux")]
pub(super) fn await_identity(pid: u32, expected: &Path, timeout: Duration) -> anyhow::Result<u64> {
    let start = Instant::now();
    loop {
        if let (Some(ticks), Some(actual)) = (start_ticks(pid), executable(pid))
            && actual == expected
        {
            return Ok(ticks);
        }
        ensure!(
            start.elapsed() < timeout,
            "could not verify the managed process identity"
        );
        thread::sleep(POLL);
    }
}
#[cfg(target_os = "linux")]
pub(super) fn await_listener(pid: u32, ticks: u64, port: u16, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        ensure!(
            start_ticks(pid) == Some(ticks),
            "managed core exited before listener readiness"
        );
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        ensure!(
            start.elapsed() < timeout,
            "managed core did not open its loopback listener"
        );
        thread::sleep(POLL);
    }
}
#[cfg(target_os = "linux")]
pub(super) fn wait_exit(pid: u32, ticks: u64, timeout: Duration) {
    let start = Instant::now();
    while start_ticks(pid) == Some(ticks) && start.elapsed() < timeout {
        thread::sleep(POLL);
    }
}
#[cfg(target_os = "linux")]
pub(super) fn signal_verified(pid: u32, expected: &Path, ticks: u64, signal: i32) -> anyhow::Result<()> {
    ensure!(
        matches_process(pid, expected, ticks),
        "process identity changed; refusing signal"
    );
    // pidfd pins the signal target to this process instance and prevents PID-reuse races.
    // SAFETY: scalar PID/flags; successful result is an owned descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) as i32 };
    ensure!(fd >= 0, "could not obtain pidfd; refusing to signal by PID");
    // The PID could have been reused between the first identity check and pidfd_open.
    // Recheck while holding the pidfd; after this, signalling the pidfd cannot target a
    // later process that reuses the numeric PID.
    if !matches_process(pid, expected, ticks) {
        // SAFETY: fd was opened above and is owned here.
        unsafe {
            libc::close(fd);
        }
        anyhow::bail!("process identity changed after pidfd acquisition; refusing signal");
    }
    // SAFETY: fd is a valid pidfd and siginfo is unused for this syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    // SAFETY: fd was opened above and is owned here.
    unsafe {
        libc::close(fd);
    }
    ensure!(result == 0, "could not signal tracked process");
    Ok(())
}

