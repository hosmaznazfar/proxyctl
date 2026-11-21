//! Linux-only, single-descriptor SCM_RIGHTS transfer primitives.
//!
//! This transfers an already-open descriptor over a connected Unix stream. It
//! does not create a TUN device, authenticate the peer, launch a core, or prove
//! that a receiving core adopted the descriptor.
#![cfg(target_os = "linux")]
use anyhow::{Result, ensure};
use std::{mem, os::{fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd}, unix::net::UnixStream}, time::Duration};
const MARKER: u8 = 0xA7;

/// Send one descriptor with a marker byte. Use only on a private authenticated socket.
/// A successful sendmsg confirms queueing, not application-level adoption.
pub fn send_descriptor(stream: &UnixStream, descriptor: BorrowedFd<'_>) -> Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
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
    let sent = loop {
        let result = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        if result >= 0 { break result; }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted { continue; }
        return Err(error).context("SCM_RIGHTS sendmsg failed");
    };
    ensure!(sent == 1, "SCM_RIGHTS sendmsg did not transfer its marker byte");
    Ok(())
}

/// Receive one descriptor and atomically set close-on-exec.
pub fn receive_descriptor(stream: &UnixStream) -> Result<OwnedFd> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut marker = 0u8;
    let mut iov = libc::iovec { iov_base: (&mut marker as *mut u8).cast(), iov_len: 1 };
    let bytes = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut control = vec![0usize; bytes.div_ceil(mem::size_of::<usize>())];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut iov; message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast(); message.msg_controllen = bytes;
    let received = loop {
        let result = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if result >= 0 { break result; }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted { continue; }
        return Err(error).context("SCM_RIGHTS recvmsg failed");
    };
    ensure!(received == 1, "SCM_RIGHTS peer closed before transferring its marker byte");
    // Convert every installed SCM_RIGHTS descriptor to RAII ownership before checking
    // the envelope. This guarantees that malformed messages cannot leak extra fds.
    let mut descriptors = Vec::new();
    let mut unexpected_control = false;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let level = unsafe { (*header).cmsg_level };
        let kind = unsafe { (*header).cmsg_type };
        let length = unsafe { (*header).cmsg_len };
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            let base = unsafe { libc::CMSG_LEN(0) as usize };
            if length >= base {
                let data_bytes = length - base;
                if data_bytes % mem::size_of::<libc::c_int>() == 0 {
                    let count = data_bytes / mem::size_of::<libc::c_int>();
                    for index in 0..count {
                        let raw = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>().add(index)) };
                        if raw >= 0 {
                            descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                        } else {
                            unexpected_control = true;
                        }
                    }
                } else {
                    unexpected_control = true;
                }
            } else {
                unexpected_control = true;
            }
        } else {
            unexpected_control = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    ensure!(marker == MARKER, "descriptor transfer marker is invalid");
    ensure!(message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) == 0, "descriptor control message was truncated");
    ensure!(!unexpected_control, "unexpected ancillary message");
    ensure!(descriptors.len() == 1, "transfer must contain exactly one descriptor");
    let descriptor = descriptors.pop().expect("descriptor count was validated");
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    ensure!(flags >= 0 && flags & libc::FD_CLOEXEC != 0, "received descriptor is not marked close-on-exec");
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
    fn rejects_multiple_descriptors_without_leaking_them() {
        use std::os::fd::AsFd;
        let (sender, receiver) = UnixStream::pair().unwrap();
        let first = File::open("/dev/null").unwrap();
        let second = File::open("/dev/null").unwrap();
        let mut marker = MARKER;
        let mut iov = libc::iovec { iov_base: (&mut marker as *mut u8).cast(), iov_len: 1 };
        let bytes = unsafe { libc::CMSG_SPACE((2 * mem::size_of::<libc::c_int>()) as u32) } as usize;
        let mut control = vec![0usize; bytes.div_ceil(mem::size_of::<usize>())];
        let mut message: libc::msghdr = unsafe { mem::zeroed() };
        message.msg_iov = &mut iov; message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast(); message.msg_controllen = bytes;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        assert!(!header.is_null());
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN((2 * mem::size_of::<libc::c_int>()) as u32) as usize;
            let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
            std::ptr::write_unaligned(data, first.as_fd().as_raw_fd());
            std::ptr::write_unaligned(data.add(1), second.as_fd().as_raw_fd());
        }
        assert_eq!(unsafe { libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_NOSIGNAL) }, 1);
        assert!(receive_descriptor(&receiver).is_err());
    }

    #[test]
    fn rejects_marker_without_descriptor() {
        use std::io::Write;
        let (sender, receiver) = UnixStream::pair().unwrap();
        sender.write_all(&[MARKER]).unwrap();
        assert!(receive_descriptor(&receiver).is_err());
    }
}
