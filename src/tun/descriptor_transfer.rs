//! Linux-only, single-descriptor SCM_RIGHTS transfer primitives.
//!
//! This transfers an already-open descriptor over a connected Unix stream. It
//! does not create a TUN device, authenticate the peer, launch a core, or prove
//! that a receiving core adopted the descriptor.
#![cfg(target_os = "linux")]
use anyhow::{Result, ensure};
use std::{mem, os::{fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd}, unix::net::UnixStream}};
const MARKER: u8 = 0xA7;

/// Send one descriptor with a marker byte. Use only on a private authenticated socket.
/// A successful sendmsg confirms queueing, not application-level adoption.
pub fn send_descriptor(stream: &UnixStream, descriptor: BorrowedFd<'_>) -> Result<()> {
    let mut marker = MARKER;
    let mut iov = libc::iovec { iov_base: (&mut marker as *mut u8).cast(), iov_len: 1 };
    const MAX_RECEIVED_DESCRIPTORS: usize = 16;
    let bytes = unsafe { libc::CMSG_SPACE((mem::size_of::<libc::c_int>() * MAX_RECEIVED_DESCRIPTORS) as u32) } as usize;
    let mut control = vec![0usize; bytes.div_ceil(mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov; message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast(); message.msg_controllen = bytes;
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    ensure!(!header.is_null(), "cannot allocate SCM_RIGHTS control header");
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>(), descriptor.as_raw_fd());
    }
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    ensure!(sent == 1, "SCM_RIGHTS sendmsg failed: {}", std::io::Error::last_os_error());
    Ok(())
}

/// Receive one descriptor and atomically set close-on-exec.
pub fn receive_descriptor(stream: &UnixStream) -> Result<OwnedFd> {
    let mut marker = 0u8;
    let mut iov = libc::iovec { iov_base: (&mut marker as *mut u8).cast(), iov_len: 1 };
    let bytes = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut control = vec![0usize; bytes.div_ceil(mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov; message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast(); message.msg_controllen = bytes;
    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    ensure!(received == 1, "SCM_RIGHTS recvmsg failed or peer closed: {}", std::io::Error::last_os_error());
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    ensure!(!header.is_null(), "descriptor transfer omitted SCM_RIGHTS");
    ensure!(unsafe { (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS }, "unexpected ancillary message");
    ensure!(unsafe { (*header).cmsg_len >= libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as usize }, "SCM_RIGHTS message omitted its descriptor");
    let raw = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>()) };
    ensure!(raw >= 0, "kernel returned invalid descriptor");
    // Take ownership before any later validation can fail, so malformed/truncated
    // frames cannot leak the descriptor installed by the kernel.
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    ensure!(marker == MARKER, "descriptor transfer marker is invalid");
    ensure!(message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0, "descriptor control message was truncated");
    ensure!(unsafe { (*header).cmsg_len == libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as usize }, "transfer must contain exactly one descriptor");
    ensure!(unsafe { libc::CMSG_NXTHDR(&message, header).is_null() }, "unexpected additional ancillary data");
    Ok(descriptor)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, os::fd::AsFd, os::unix::net::UnixStream};
    #[test]
    fn transfers_one_descriptor_with_close_on_exec() {
        let (sender, receiver) = UnixStream::pair().unwrap();
        let source = File::open("/dev/null").unwrap();
        send_descriptor(&sender, source.as_fd()).unwrap();
        let received = receive_descriptor(&receiver).unwrap();
        let flags = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
    #[test]
    fn rejects_marker_without_descriptor() {
        use std::io::Write;
        let (sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(&[MARKER]).unwrap();
        assert!(receive_descriptor(&receiver).is_err());
    }
}
