//! Concrete, non-persistent Linux TUN descriptor allocation via ioctl.
#![cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
use std::{fs::OpenOptions, os::fd::{AsRawFd, OwnedFd}};
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const TUNSETOWNER: libc::c_ulong = 0x4004_54cc;
const TUNSETGROUP: libc::c_ulong = 0x4004_54ce;
const IFF_TUN: u16 = 1;
const IFF_NO_PI: u16 = 0x1000;
const IFF_TUN_EXCL: u16 = 0x8000;
const IFNAMSIZ: usize = 16;
#[repr(C)]
struct IfReq { name: [libc::c_char; IFNAMSIZ], flags: libc::c_short, padding: [u8; 22] }
/// Owns a non-persistent TUN attachment. Closing this fd removes the device.
#[derive(Debug)]
pub struct TunDevice { fd: OwnedFd, name: String }
impl TunDevice {
    /// Allocates an exclusive TUN interface and assigns its owner and group.
    /// Does not configure link state, routes, DNS, or firewall.
    pub fn create(name: &str, uid: u32, gid: u32) -> Result<Self> {
        validate_name(name)?;
        let file = OpenOptions::new().read(true).write(true).open("/dev/net/tun").context("open /dev/net/tun")?;
        let fd: OwnedFd = file.into();
        let mut req = IfReq { name: [0; IFNAMSIZ], flags: (IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL) as libc::c_short, padding: [0; 22] };
        for (dst, src) in req.name.iter_mut().zip(name.bytes()) { *dst = src as libc::c_char; }
        // SAFETY: fd is a TUN fd and req follows Linux ifreq layout.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut req) };
        ensure!(rc == 0, "TUNSETIFF failed: {}", std::io::Error::last_os_error());
        let bytes = req.name.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect::<Vec<_>>();
        let actual = String::from_utf8(bytes).context("kernel returned invalid interface name")?;
        ensure!(actual == name, "kernel allocated unexpected interface identity");
        // SAFETY: TUNSETOWNER/GROUP accept scalar uid/gid on the attached fd.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETOWNER, uid) };
        ensure!(rc == 0, "TUNSETOWNER failed: {}", std::io::Error::last_os_error());
        // SAFETY: scalar gid argument is valid for TUNSETGROUP.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETGROUP, gid) };
        ensure!(rc == 0, "TUNSETGROUP failed: {}", std::io::Error::last_os_error());
        Ok(Self { fd, name: actual })
    }
    pub fn name(&self) -> &str { &self.name }
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd { self.fd.as_raw_fd() }
}
fn validate_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty() && name.len() < IFNAMSIZ && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')), "invalid TUN interface name");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_interface_names() {
        for name in ["", "bad/name", "bad name", "1234567890123456", "bad\\name"] { assert!(validate_name(name).is_err()); }
        for name in ["tun0", "proxyctl-tun", "pctl_1"] { assert!(validate_name(name).is_ok()); }
    }
}
