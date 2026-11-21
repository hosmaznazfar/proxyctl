//! Linux launch support for Xray's documented externally supplied TUN descriptor.
//!
//! Xray reads XRAY_TUN_FD during startup. The descriptor is duplicated with CLOEXEC set in
//! the parent, then CLOEXEC is cleared only in the forked child immediately before exec.
//! Keep this guard alive until Command::spawn returns.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    os::unix::process::CommandExt,
    process::Command,
};

/// Owns a private duplicate of the broker-exported TUN descriptor for one Xray spawn.
#[derive(Debug)]
pub struct XrayTunDescriptor {
    descriptor: OwnedFd,
}

impl XrayTunDescriptor {
    /// Duplicate a broker-exported TUN descriptor above the standard I/O range.
    pub fn duplicate(source: BorrowedFd<'_>) -> Result<Self> {
        let raw = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(
            raw >= 3,
            "cannot duplicate broker-owned TUN descriptor for Xray: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: F_DUPFD_CLOEXEC returned a new descriptor owned by this value.
        Ok(Self { descriptor: unsafe { OwnedFd::from_raw_fd(raw) } })
    }

    /// Configure a Command so only its child inherits the descriptor and Xray receives
    /// the documented XRAY_TUN_FD environment variable.
    ///
    /// The caller must keep self alive through Command::spawn. The parent descriptor remains
    /// close-on-exec; only the forked child clears FD_CLOEXEC in the pre-exec hook.
    pub fn configure_command(&self, command: &mut Command) -> Result<()> {
        let raw = self.descriptor.as_raw_fd();
        ensure!(raw >= 3, "Xray TUN descriptor overlaps standard I/O");
        command.env(super::XRAY_TUN_FD_ENV, raw.to_string());
        // SAFETY: the pre-exec closure performs only async-signal-safe fcntl operations.
        // The descriptor is owned by self and must remain alive until spawn returns.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(raw, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }

    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.descriptor.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, os::fd::AsFd};

    #[test]
    fn duplicates_descriptor_without_disabling_parent_close_on_exec() {
        let source = File::open("/dev/null").unwrap();
        let duplicate = XrayTunDescriptor::duplicate(source.as_fd()).unwrap();
        let flags = unsafe { libc::fcntl(duplicate.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn configures_only_the_xray_fd_environment_contract() {
        let source = File::open("/dev/null").unwrap();
        let duplicate = XrayTunDescriptor::duplicate(source.as_fd()).unwrap();
        let mut command = Command::new("xray");
        duplicate.configure_command(&mut command).unwrap();
        let configured = command.get_envs().find(|(key, _)| *key == "XRAY_TUN_FD")
            .and_then(|(_, value)| value)
            .and_then(|value| value.to_str())
            .unwrap();
        assert_eq!(configured, duplicate.as_raw_fd().to_string());
    }
}
