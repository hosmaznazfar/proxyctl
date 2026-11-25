//! Bounded orchestration for Linux socket-diagnostic dumps.
//!
//! This layer owns no file descriptor and performs no privilege escalation. The privileged
//! Proxyctl supervisor supplies a NETLINK_SOCK_DIAG transport with kernel-origin metadata
//! and bounded receive timeouts. The orchestration independently enforces a monotonic deadline
//! and accumulator bounds; tests use an in-memory transport.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};

use super::socket_diag_netlink::{
    SocketDiagnosticDump, SocketDiagnosticDumpAccumulator, SocketDiagnosticRequest,
    SocketTransport, build_dump_request,
};

pub const MAX_DUMP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedNetlinkDatagram {
    pub sender_port_id: u32,
    pub truncated: bool,
    pub bytes: Vec<u8>,
}

/// Narrow transport contract for a single NETLINK_SOCK_DIAG socket.
///
/// Implementations must send to the kernel netlink address and return sender port ID
/// and MSG_TRUNC status from the same recvmsg call.
pub trait SocketDiagnosticIo {
    fn send_request(&mut self, request: &[u8]) -> Result<()>;
    fn receive(&mut self, timeout: Duration) -> Result<ReceivedNetlinkDatagram>;
}

/// Collect one complete dump with a monotonic wall-clock deadline.
///
/// Any timeout, transport error, foreign sender, truncation, malformed message, or
/// incomplete multipart sequence discards the entire dump.
pub fn collect_dump(
    io: &mut impl SocketDiagnosticIo,
    request: SocketDiagnosticRequest,
    timeout: Duration,
) -> Result<SocketDiagnosticDump> {
    ensure!(
        !timeout.is_zero() && timeout <= MAX_DUMP_TIMEOUT,
        "socket diagnostic timeout must be between zero and five seconds"
    );

    let encoded = build_dump_request(request)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("socket diagnostic deadline overflow")?;
    io.send_request(&encoded)?;

    let mut accumulator = SocketDiagnosticDumpAccumulator::new(request.sequence)?;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "socket diagnostic dump exceeded its deadline"
        );

        let received = io.receive(remaining)?;
        ensure!(
            Instant::now() < deadline,
            "socket diagnostic dump exceeded its deadline"
        );
        accumulator.push_received_datagram(
            received.sender_port_id,
            received.truncated,
            &received.bytes,
        )?;

        if accumulator.is_complete() {
            return accumulator.into_complete_dump();
        }
    }
}

/// Collect IPv4/IPv6 TCP and UDP dumps using four distinct non-zero sequences.
pub fn collect_all(
    io: &mut impl SocketDiagnosticIo,
    first_sequence: u32,
    timeout_per_dump: Duration,
) -> Result<Vec<(u8, SocketTransport, SocketDiagnosticDump)>> {
    ensure!(
        first_sequence != 0,
        "first netlink sequence must be non-zero"
    );
    ensure!(
        first_sequence <= u32::MAX - 3,
        "four netlink sequence identifiers are required"
    );
    let mut dumps = Vec::with_capacity(4);

    for (index, (family, transport)) in [
        (libc::AF_INET as u8, SocketTransport::Tcp),
        (libc::AF_INET as u8, SocketTransport::Udp),
        (libc::AF_INET6 as u8, SocketTransport::Tcp),
        (libc::AF_INET6 as u8, SocketTransport::Udp),
    ]
    .into_iter()
    .enumerate()
    {
        let sequence = first_sequence + index as u32;
        let request = SocketDiagnosticRequest {
            family,
            transport,
            sequence,
        };
        let dump = collect_dump(io, request, timeout_per_dump)
            .with_context(|| format!("failed to collect {family}/{transport:?} diagnostics"))?;
        dumps.push((family, transport, dump));
    }

    Ok(dumps)
}

#[cfg(test)]
mod tests {
    use super::super::socket_diag_netlink::NLMSG_DONE;
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeIo {
        sent: Vec<Vec<u8>>,
        received: VecDeque<ReceivedNetlinkDatagram>,
    }

    impl SocketDiagnosticIo for FakeIo {
        fn send_request(&mut self, request: &[u8]) -> Result<()> {
            self.sent.push(request.to_vec());
            Ok(())
        }

        fn receive(&mut self, _timeout: Duration) -> Result<ReceivedNetlinkDatagram> {
            self.received
                .pop_front()
                .context("fake transport has no queued datagram")
        }
    }

    fn done(sequence: u32) -> ReceivedNetlinkDatagram {
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&16u32.to_ne_bytes());
        bytes[4..6].copy_from_slice(&NLMSG_DONE.to_ne_bytes());
        bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
        ReceivedNetlinkDatagram {
            sender_port_id: 0,
            truncated: false,
            bytes,
        }
    }

    fn request(sequence: u32) -> SocketDiagnosticRequest {
        SocketDiagnosticRequest {
            family: libc::AF_INET as u8,
            transport: SocketTransport::Tcp,
            sequence,
        }
    }

    #[test]
    fn sends_request_and_returns_only_after_kernel_done() {
        let mut io = FakeIo::default();
        io.received.push_back(done(7));
        let dump = collect_dump(&mut io, request(7), Duration::from_secs(1)).unwrap();
        assert!(dump.complete);
        assert_eq!(io.sent.len(), 1);
        assert_eq!(u32::from_ne_bytes(io.sent[0][8..12].try_into().unwrap()), 7);
    }

    #[test]
    fn rejects_invalid_timeout_and_sequence() {
        let mut io = FakeIo::default();
        assert!(collect_dump(&mut io, request(7), Duration::ZERO).is_err());
        assert!(
            collect_dump(
                &mut io,
                request(7),
                MAX_DUMP_TIMEOUT + Duration::from_millis(1)
            )
            .is_err()
        );
        assert!(collect_dump(&mut io, request(0), Duration::from_secs(1)).is_err());
        assert!(io.sent.is_empty());
    }

    #[test]
    fn rejects_foreign_sender_and_truncated_receive_metadata() {
        for (sender_port_id, truncated) in [(5, false), (0, true)] {
            let mut io = FakeIo::default();
            let mut received = done(7);
            received.sender_port_id = sender_port_id;
            received.truncated = truncated;
            io.received.push_back(received);
            assert!(collect_dump(&mut io, request(7), Duration::from_secs(1)).is_err());
        }
    }

    #[test]
    fn rejects_missing_terminal_completion() {
        let mut io = FakeIo::default();
        let mut incomplete = done(7);
        incomplete.bytes[4..6].copy_from_slice(&1u16.to_ne_bytes());
        io.received.push_back(incomplete);
        assert!(collect_dump(&mut io, request(7), Duration::from_secs(1)).is_err());
    }

    #[test]
    fn collects_all_four_family_transport_combinations() {
        let mut io = FakeIo::default();
        for sequence in 20..24 {
            io.received.push_back(done(sequence));
        }
        let dumps = collect_all(&mut io, 20, Duration::from_secs(1)).unwrap();
        assert_eq!(dumps.len(), 4);
        assert_eq!(io.sent.len(), 4);
        assert!(dumps.iter().all(|(_, _, dump)| dump.complete));
    }

    #[test]
    fn refuses_sequence_wrap_before_reusing_an_identifier() {
        let mut io = FakeIo::default();
        assert!(collect_all(&mut io, u32::MAX, Duration::from_secs(1)).is_err());
        assert!(io.sent.is_empty());
    }

    #[test]
    fn transport_exhaustion_is_a_hard_failure() {
        let mut io = FakeIo::default();
        assert!(collect_dump(&mut io, request(7), Duration::from_secs(1)).is_err());
    }
}
