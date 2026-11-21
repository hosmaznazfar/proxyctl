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
        ensure_tun_character_device(&file)?;
        let fd: OwnedFd = file.into();
        ensure_descriptor_cloexec(fd.as_raw_fd())?;
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
        let returned_name = req.name.iter()
            .take_while(|character| **character != 0)
            .map(|character| *character as u8);
        ensure!(
            returned_name.eq(name.bytes()),
            "kernel allocated unexpected interface identity"
        );
        let actual = name.to_owned();
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

fn ensure_descriptor_cloexec(fd: std::os::fd::RawFd) -> Result<()> {
    // SAFETY: fcntl reads descriptor flags for the caller-owned descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    ensure!(flags >= 0, "cannot inspect TUN descriptor flags: {}", std::io::Error::last_os_error());
    ensure!(flags & libc::FD_CLOEXEC != 0, "TUN descriptor is not close-on-exec");
    Ok(())
}

fn ensure_tun_character_device(file: &std::fs::File) -> Result<()> {
    ensure!(
        file.metadata()?.file_type().is_char_device(),
        "/dev/net/tun is not a character device"
    );
    Ok(())
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
    let socket = loop {
        // SAFETY: socket receives a valid address family, type, and protocol.
        let result = unsafe {
            libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)
        };
        if result >= 0 {
            break result;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("cannot open link-control socket");
        }
    };
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
    fn accepts_close_on_exec_descriptor() {
        use std::os::fd::AsRawFd;

        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(ensure_descriptor_cloexec(file.as_raw_fd()).is_ok());
    }

    #[test]
    fn ioctl_retry_reports_invalid_descriptor_errors() {
        assert!(ioctl_retry(-1, TUNSETIFF, 0).is_err());
    }

    #[test]
    fn rejects_descriptor_without_close_on_exec() {
        use std::os::fd::AsRawFd;

        let file = std::fs::File::open("/dev/null").unwrap();
        // SAFETY: F_GETFD/F_SETFD operate on the live descriptor owned by file.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        assert!(ensure_descriptor_cloexec(file.as_raw_fd()).is_err());
    }

    #[test]
    fn rejects_regular_file_as_tun_device_node() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("not-a-device");
        std::fs::write(&path, "").unwrap();
        let file = std::fs::File::open(path).unwrap();
        assert!(ensure_tun_character_device(&file).is_err());
    }

    #[test]
    fn validates_interface_names() {
        for name in ["", "bad/name", "bad name", "1234567890123456", "bad\\name"] {
            assert!(validate_name(name).is_err());
        }
        for name in ["tun0", "proxyctl-tun", "pctl_1", "123456789012345"] {
            assert!(validate_name(name).is_ok());
        }
    }
}
