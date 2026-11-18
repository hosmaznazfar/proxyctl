//! Read-only Linux NETLINK_SOCK_DIAG transport.
//!
//! This opens a dedicated netlink socket and never changes routes, links, firewall,
//! DNS, or proxy settings. The caller is responsible for running this operation inside
//! the narrowly scoped diagnostic broker when INET_DIAG_MARK requires CAP_NET_ADMIN.
//! The ordinary Proxyctl process must not gain broad privileges.

use std::{
    mem::{size_of, zeroed},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};

use super::socket_diag_collector::{
    ReceivedNetlinkDatagram, SocketDiagnosticIo,
};

const NETLINK_SOCK_DIAG: libc::c_int = 4;
const RECEIVE_BUFFER_BYTES: usize = 64 * 1024;

pub struct LinuxSocketDiagnosticIo {
    socket: OwnedFd,
}

impl LinuxSocketDiagnosticIo {
    /// Open and bind a CLOEXEC NETLINK_SOCK_DIAG socket.
    ///
    /// No capability is requested or acquired. Without CAP_NET_ADMIN, Linux may omit
    /// INET_DIAG_MARK; the strict record parser will then reject the incomplete result.
    pub fn open() -> Result<Self> {
        // SAFETY: socket has no pointer arguments and returns a new owned descriptor.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        ensure!(raw >= 0, "failed to open NETLINK_SOCK_DIAG socket: {}", std::io::Error::last_os_error());
        // SAFETY: raw is a newly-created descriptor and ownership is transferred once.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: zero is a valid initial representation for sockaddr_nl; fields are set below.
        let mut local: libc::sockaddr_nl = unsafe { zeroed() };
        local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        local.nl_pid = 0;
        local.nl_groups = 0;
        // SAFETY: local points to a fully initialized sockaddr_nl of the supplied length.
        let result = unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&local as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        ensure!(result == 0, "failed to bind NETLINK_SOCK_DIAG socket: {}", std::io::Error::last_os_error());
        Ok(Self { socket })
    }
}

impl SocketDiagnosticIo for LinuxSocketDiagnosticIo {
    fn send_request(&mut self, request: &[u8]) -> Result<()> {
        ensure!(!request.is_empty(), "cannot send an empty socket diagnostic request");
        // SAFETY: zero is a valid initial representation for sockaddr_nl; fields are set below.
        let mut kernel: libc::sockaddr_nl = unsafe { zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        kernel.nl_pid = 0;
        kernel.nl_groups = 0;
        loop {
            // SAFETY: request is a valid readable slice and kernel is a valid destination address.
            let sent = unsafe {
                libc::sendto(
                    self.socket.as_raw_fd(),
                    request.as_ptr().cast(),
                    request.len(),
                    0,
                    (&kernel as *const libc::sockaddr_nl).cast(),
                    size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if sent >= 0 {
                ensure!(sent as usize == request.len(), "short NETLINK_SOCK_DIAG request send");
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error).context("failed to send NETLINK_SOCK_DIAG request");
            }
        }
    }

    fn receive(&mut self, timeout: Duration) -> Result<ReceivedNetlinkDatagram> {
        ensure!(!timeout.is_zero(), "netlink receive timeout must be non-zero");
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("netlink receive deadline overflow")?;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(!remaining.is_zero(), "NETLINK_SOCK_DIAG receive timed out");
            let fractional_millisecond = if remaining.subsec_nanos() % 1_000_000 != 0 {
                1u128
            } else {
                0u128
            };
            let millis = remaining
                .as_millis()
                .saturating_add(fractional_millisecond)
                .clamp(1, i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: descriptor points to one initialized pollfd for the duration of poll.
            let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("failed waiting for NETLINK_SOCK_DIAG response");
            }
            ensure!(ready != 0, "NETLINK_SOCK_DIAG receive timed out");
            ensure!(
                descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
                "NETLINK_SOCK_DIAG socket reported a poll error"
            );
            ensure!(
                descriptor.revents & libc::POLLIN != 0,
                "NETLINK_SOCK_DIAG socket became ready without readable data"
            );

            let mut bytes = vec![0u8; RECEIVE_BUFFER_BYTES];
            // SAFETY: zero is a valid initial representation for sockaddr_nl; recvmsg fills it.
            let mut sender: libc::sockaddr_nl = unsafe { zeroed() };
            let mut vector = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: all pointers reference writable buffers valid for the recvmsg call.
            let mut message: libc::msghdr = unsafe { zeroed() };
            message.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
            message.msg_namelen = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;

            // SAFETY: message and its buffers remain alive and writable for the call.
            let received = unsafe { libc::recvmsg(self.socket.as_raw_fd(), &mut message, 0) };
            if received < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("failed receiving NETLINK_SOCK_DIAG response");
            }
            ensure!(received > 0, "NETLINK_SOCK_DIAG returned an empty datagram");
            ensure!(
                message.msg_namelen as usize >= size_of::<libc::sockaddr_nl>(),
                "NETLINK_SOCK_DIAG sender address is truncated"
            );
            ensure!(
                sender.nl_family as libc::c_int == libc::AF_NETLINK,
                "NETLINK_SOCK_DIAG response has a non-netlink sender address"
            );
            ensure!(sender.nl_groups == 0, "NETLINK_SOCK_DIAG response came from a multicast group");

            let truncated = message.msg_flags & libc::MSG_TRUNC != 0
                || received as usize > bytes.len();
            bytes.truncate((received as usize).min(bytes.len()));
            return Ok(ReceivedNetlinkDatagram {
                sender_port_id: sender.nl_pid,
                truncated,
                bytes,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_a_cloexec_netlink_diagnostic_socket_without_network_mutation() {
        let io = LinuxSocketDiagnosticIo::open().unwrap();
        assert!(io.socket.as_raw_fd() >= 0);
        // The descriptor is owned and closed by OwnedFd; this test sends no request.
    }
}
