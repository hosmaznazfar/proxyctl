//! Concrete, non-persistent Linux TUN descriptor allocation via ioctl.
#![cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
use std::{
    fs::OpenOptions,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::fs::{FileTypeExt, OpenOptionsExt},
    },
};
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETOWNER: libc::c_ulong = 0x4004_54cc;
const TUNSETGROUP: libc::c_ulong = 0x4004_54ce;
const IFF_TUN: u16 = 1;
const IFF_NO_PI: u16 = 0x1000;
const IFF_TUN_EXCL: u16 = 0x8000;
const IFNAMSIZ: usize = 16;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
const IFF_UP: libc::c_short = 0x1;
#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 6],
}
/// Owns a non-persistent TUN attachment. Closing this fd removes the device.
#[derive(Debug)]
pub struct TunDevice {
    fd: OwnedFd,
    name: String,
}
impl TunDevice {
    /// Allocates an exclusive TUN interface, assigns owner/group, and brings its link up.
    /// Does not install routes/rules or alter DNS/firewall.
    pub fn create(name: &str, uid: u32, gid: u32) -> Result<Self> {
        validate_name(name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open("/dev/net/tun")
            .context("securely open /dev/net/tun")?;
        ensure!(
            file.metadata()?.file_type().is_char_device(),
            "/dev/net/tun is not a character device"
        );
        let fd: OwnedFd = file.into();
        // SAFETY: fcntl reads descriptor flags for the live descriptor owned by fd.
        ensure!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC != 0,
            "TUN descriptor is not close-on-exec"
        );
        let mut req = IfReq {
            name: [0; IFNAMSIZ],
            flags: (IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL) as libc::c_short,
            padding: [0; 6],
        };
        for (dst, src) in req.name.iter_mut().zip(name.bytes()) {
            *dst = src as libc::c_char;
        }
        // SAFETY: fd is a TUN fd and req follows Linux ifreq layout.
        let rc = ioctl_retry(fd.as_raw_fd(), TUNSETIFF, (&mut req as *mut IfReq) as usize)?;
        ensure!(
            rc == 0,
            "TUNSETIFF failed: {}",
            std::io::Error::last_os_error()
        );
        let bytes = req
            .name
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect::<Vec<_>>();
        let actual = String::from_utf8(bytes).context("kernel returned invalid interface name")?;
        ensure!(
            actual == name,
            "kernel allocated unexpected interface identity"
        );
        // SAFETY: TUNSETOWNER/GROUP accept scalar uid/gid on the attached fd.
        let rc = ioctl_retry(fd.as_raw_fd(), TUNSETOWNER, uid as usize)?;
        ensure!(
            rc == 0,
            "TUNSETOWNER failed: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: scalar gid argument is valid for TUNSETGROUP.
        let rc = ioctl_retry(fd.as_raw_fd(), TUNSETGROUP, gid as usize)?;
        ensure!(
            rc == 0,
            "TUNSETGROUP failed: {}",
            std::io::Error::last_os_error()
        );
        set_link_up(&actual)?;
        Ok(Self { fd, name: actual })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

fn ioctl_retry(fd: std::os::fd::RawFd, request: libc::c_ulong, argument: usize) -> Result<libc::c_int> {
    loop {
        // SAFETY: callers provide the argument shape required by the specific ioctl request.
        let result = unsafe { libc::ioctl(fd, request, argument) };
        if result >= 0 {
            return Ok(result);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn set_link_up(name: &str) -> Result<()> {
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    ensure!(
        socket >= 0,
        "cannot open link-control socket: {}",
        std::io::Error::last_os_error()
    );
    let fd = unsafe { OwnedFd::from_raw_fd(socket) };
    let mut req = IfReq {
        name: [0; IFNAMSIZ],
        flags: 0,
        padding: [0; 6],
    };
    for (dst, src) in req.name.iter_mut().zip(name.bytes()) {
        *dst = src as libc::c_char;
    }
    let rc = ioctl_retry(fd.as_raw_fd(), SIOCGIFFLAGS, (&mut req as *mut IfReq) as usize)?;
    ensure!(
        rc == 0,
        "SIOCGIFFLAGS failed: {}",
        std::io::Error::last_os_error()
    );
    req.flags |= IFF_UP;
    let rc = ioctl_retry(fd.as_raw_fd(), SIOCSIFFLAGS, (&req as *const IfReq) as usize)?;
    ensure!(
        rc == 0,
        "SIOCSIFFLAGS failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() < IFNAMSIZ
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')),
        "invalid TUN interface name"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_interface_names() {
        for name in ["", "bad/name", "bad name", "1234567890123456", "bad\\name"] {
            assert!(validate_name(name).is_err());
        }
        for name in ["tun0", "proxyctl-tun", "pctl_1"] {
            assert!(validate_name(name).is_ok());
        }
    }
}
