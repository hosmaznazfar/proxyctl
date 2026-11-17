//! Pure Linux NETLINK_SOCK_DIAG request framing and dump decoding.
//!
//! This module performs no socket I/O and grants no privileges. It builds bounded IPv4/IPv6
//! TCP/UDP dump requests and decodes complete netlink datagrams into marked socket records.
//! A future broker owns the actual NETLINK_SOCK_DIAG socket and must enforce time/size limits.

use anyhow::{Context, Result, ensure};

use super::socket_diag_records::{SocketDiagnosticRecord, parse_socket_diagnostic_record};

const NLMSG_HEADER_LEN: usize = 16;
const INET_DIAG_REQUEST_LEN: usize = 56;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;

/// Maximum records accepted from one datagram.
pub const MAX_RECORDS_PER_DATAGRAM: usize = 4096;
/// Maximum aggregate bytes retained for one multipart dump (4 MiB).
pub const MAX_TOTAL_DUMP_BYTES: usize = 4 * 1024 * 1024;
/// Maximum datagrams accepted for one multipart dump.
pub const MAX_DUMP_DATAGRAMS: usize = 1024;
/// Maximum aggregate socket records retained for one multipart dump.
pub const MAX_TOTAL_DUMP_RECORDS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketTransport {
    Tcp,
    Udp,
}

impl SocketTransport {
    fn protocol(self) -> u8 {
        match self {
            Self::Tcp => libc::IPPROTO_TCP as u8,
            Self::Udp => libc::IPPROTO_UDP as u8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketDiagnosticRequest {
    pub family: u8,
    pub transport: SocketTransport,
    pub sequence: u32,
}

/// Build one NETLINK_SOCK_DIAG dump request using native-endian netlink fields.
pub fn build_dump_request(request: SocketDiagnosticRequest) -> Result<Vec<u8>> {
    ensure!(
        request.family == libc::AF_INET as u8 || request.family == libc::AF_INET6 as u8,
        "socket diagnostic request has an unsupported address family"
    );
    ensure!(request.sequence != 0, "netlink sequence must be non-zero");

    let mut bytes = vec![0u8; NLMSG_HEADER_LEN + INET_DIAG_REQUEST_LEN];
    let message_len = bytes.len() as u32;
    put_u32(&mut bytes, 0, message_len)?;
    put_u16(&mut bytes, 4, SOCK_DIAG_BY_FAMILY)?;
    put_u16(&mut bytes, 6, NLM_F_REQUEST | NLM_F_DUMP)?;
    put_u32(&mut bytes, 8, request.sequence)?;

    // struct inet_diag_req_v2: family, protocol, extensions, pad, states, inet_diag_sockid.
    bytes[NLMSG_HEADER_LEN] = request.family;
    bytes[NLMSG_HEADER_LEN + 1] = request.transport.protocol();
    put_u32(&mut bytes, NLMSG_HEADER_LEN + 4, u32::MAX)?;
    // idiag_cookie[2] = INET_DIAG_NOCOOKIE.
    put_u32(&mut bytes, NLMSG_HEADER_LEN + 48, u32::MAX)?;
    put_u32(&mut bytes, NLMSG_HEADER_LEN + 52, u32::MAX)?;
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketDiagnosticDump {
    pub records: Vec<SocketDiagnosticRecord>,
    pub complete: bool,
}

/// Decode one netlink datagram. NLMSG_DONE marks completion; NLMSG_ERROR is always an error.
/// A multipart dump may contain multiple data datagrams before its terminal DONE message.
pub fn decode_datagram(bytes: &[u8], expected_sequence: u32) -> Result<SocketDiagnosticDump> {
    ensure!(
        expected_sequence != 0,
        "expected netlink sequence must be non-zero"
    );
    let mut offset = 0usize;
    let mut records = Vec::new();
    let mut complete = false;

    while offset < bytes.len() {
        ensure!(
            bytes.len() - offset >= NLMSG_HEADER_LEN,
            "netlink message header is truncated"
        );
        let length = read_u32(bytes, offset)? as usize;
        let kind = read_u16(bytes, offset + 4)?;
        let flags = read_u16(bytes, offset + 6)?;
        let sequence = read_u32(bytes, offset + 8)?;
        let sender_port_id = read_u32(bytes, offset + 12)?;
        ensure!(
            sender_port_id == 0,
            "netlink message was not sent by the kernel"
        );
        ensure!(
            length >= NLMSG_HEADER_LEN && length <= bytes.len() - offset,
            "netlink message has an invalid length"
        );
        ensure!(
            flags & NLM_F_DUMP_INTR == 0,
            "kernel reported an interrupted socket diagnostic dump"
        );
        ensure!(
            sequence == expected_sequence,
            "netlink message sequence does not match request"
        );
        let payload = &bytes[offset + NLMSG_HEADER_LEN..offset + length];

        match kind {
            NLMSG_NOOP => {}
            NLMSG_ERROR => {
                ensure!(payload.len() >= 4, "netlink error payload is truncated");
                let error = i32::from_ne_bytes(payload[..4].try_into()?);
                ensure!(
                    error == 0,
                    "kernel rejected socket diagnostic request: errno {}",
                    error.saturating_abs()
                );
            }
            NLMSG_DONE => {
                ensure!(
                    !complete,
                    "netlink dump contains duplicate completion messages"
                );
                if payload.len() >= 4 {
                    let error = i32::from_ne_bytes(payload[..4].try_into()?);
                    ensure!(
                        error == 0,
                        "socket diagnostic dump failed: errno {}",
                        error.saturating_abs()
                    );
                }
                complete = true;
            }
            SOCK_DIAG_BY_FAMILY => {
                ensure!(
                    !complete,
                    "socket diagnostic record appeared after dump completion"
                );
                ensure!(
                    records.len() < MAX_RECORDS_PER_DATAGRAM,
                    "socket diagnostic datagram exceeds the record limit"
                );
                records.push(parse_socket_diagnostic_record(payload)?);
            }
            _ => anyhow::bail!("netlink datagram contains an unexpected message type"),
        }

        let aligned = align_netlink(length)?;
        ensure!(
            aligned <= bytes.len() - offset,
            "netlink message alignment padding is truncated"
        );
        offset += aligned;
    }

    Ok(SocketDiagnosticDump { records, complete })
}


/// Accumulate a multipart dump while enforcing aggregate memory and message bounds.
///
/// The collector must still enforce receive-buffer truncation and elapsed-time limits.
#[derive(Debug, Clone)]
pub struct SocketDiagnosticDumpAccumulator {
    expected_sequence: u32,
    total_bytes: usize,
    datagrams: usize,
    records: Vec<SocketDiagnosticRecord>,
    complete: bool,
}

impl SocketDiagnosticDumpAccumulator {
    pub fn new(expected_sequence: u32) -> Result<Self> {
        ensure!(
            expected_sequence != 0,
            "expected netlink sequence must be non-zero"
        );
        Ok(Self {
            expected_sequence,
            total_bytes: 0,
            datagrams: 0,
            records: Vec::new(),
            complete: false,
        })
    }

    /// Add a datagram together with transport metadata returned by recvmsg.
    ///
    /// The collector must pass the sender port ID from sockaddr_nl and whether MSG_TRUNC
    /// was reported. A truncated or non-kernel datagram is never decoded or retained.
    pub fn push_received_datagram(
        &mut self,
        sender_port_id: u32,
        truncated: bool,
        bytes: &[u8],
    ) -> Result<()> {
        ensure!(
            sender_port_id == 0,
            "socket diagnostic datagram was not received from the kernel"
        );
        ensure!(!truncated, "socket diagnostic datagram was truncated");
        self.push_datagram(bytes)
    }

    /// Add one complete datagram. Any malformed, interrupted, oversized, or post-DONE
    /// input is rejected; callers must discard the accumulator after an error.
    pub fn push_datagram(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(!self.complete, "socket diagnostic dump is already complete");
        ensure!(!bytes.is_empty(), "socket diagnostic datagram is empty");
        ensure!(
            self.datagrams < MAX_DUMP_DATAGRAMS,
            "socket diagnostic dump exceeds the datagram limit"
        );
        let total_bytes = self
            .total_bytes
            .checked_add(bytes.len())
            .context("socket diagnostic dump byte count overflow")?;
        ensure!(
            total_bytes <= MAX_TOTAL_DUMP_BYTES,
            "socket diagnostic dump exceeds the total byte limit"
        );

        let decoded = decode_datagram(bytes, self.expected_sequence)?;
        let total_records = self
            .records
            .len()
            .checked_add(decoded.records.len())
            .context("socket diagnostic dump record count overflow")?;
        ensure!(
            total_records <= MAX_TOTAL_DUMP_RECORDS,
            "socket diagnostic dump exceeds the total record limit"
        );

        self.total_bytes = total_bytes;
        self.datagrams += 1;
        self.records.extend(decoded.records);
        self.complete = decoded.complete;
        Ok(())
    }

    /// Return records only after an uninterrupted terminal NLMSG_DONE was received.
    pub fn into_complete_dump(self) -> Result<SocketDiagnosticDump> {
        ensure!(
            self.complete,
            "socket diagnostic multipart dump has no completion message"
        );
        Ok(SocketDiagnosticDump {
            records: self.records,
            complete: true,
        })
    }
}

fn align_netlink(length: usize) -> Result<usize> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .context("netlink message length overflow")
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let target = bytes
        .get_mut(offset..offset + 2)
        .context("netlink request field is out of bounds")?;
    target.copy_from_slice(&value.to_ne_bytes());
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let target = bytes
        .get_mut(offset..offset + 4)
        .context("netlink request field is out of bounds")?;
    target.copy_from_slice(&value.to_ne_bytes());
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(offset..offset + 2)
            .context("netlink field is truncated")?
            .try_into()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .context("netlink field is truncated")?
            .try_into()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::socket_diag_records::{INET_DIAG_MARK, INET_DIAG_MSG_LEN};

    fn message(kind: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let mut bytes = vec![0u8; length];
        bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
        bytes[NLMSG_HEADER_LEN..].copy_from_slice(payload);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
        bytes
    }

    fn marked_record(inode: u32, mark: u32) -> Vec<u8> {
        let mut payload = vec![0u8; INET_DIAG_MSG_LEN];
        payload[0] = libc::AF_INET as u8;
        payload[68..72].copy_from_slice(&inode.to_ne_bytes());
        payload.extend_from_slice(&8u16.to_ne_bytes());
        payload.extend_from_slice(&INET_DIAG_MARK.to_ne_bytes());
        payload.extend_from_slice(&mark.to_ne_bytes());
        payload
    }

    #[test]
    fn builds_dual_stack_tcp_udp_dump_requests() {
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            for transport in [SocketTransport::Tcp, SocketTransport::Udp] {
                let bytes = build_dump_request(SocketDiagnosticRequest {
                    family,
                    transport,
                    sequence: 9,
                })
                .unwrap();
                assert_eq!(bytes.len(), NLMSG_HEADER_LEN + INET_DIAG_REQUEST_LEN);
                assert_eq!(read_u32(&bytes, 0).unwrap() as usize, bytes.len());
                assert_eq!(read_u16(&bytes, 4).unwrap(), SOCK_DIAG_BY_FAMILY);
                assert_eq!(read_u16(&bytes, 6).unwrap(), NLM_F_REQUEST | NLM_F_DUMP);
                assert_eq!(read_u32(&bytes, 8).unwrap(), 9);
                assert_eq!(bytes[16], family);
                assert_eq!(bytes[17], transport.protocol());
                assert_eq!(read_u32(&bytes, 20).unwrap(), u32::MAX);
            }
        }
    }

    #[test]
    fn rejects_invalid_request_family_and_sequence() {
        assert!(
            build_dump_request(SocketDiagnosticRequest {
                family: 0,
                transport: SocketTransport::Tcp,
                sequence: 1,
            })
            .is_err()
        );
        assert!(
            build_dump_request(SocketDiagnosticRequest {
                family: libc::AF_INET as u8,
                transport: SocketTransport::Tcp,
                sequence: 0,
            })
            .is_err()
        );
    }

    #[test]
    fn decodes_multipart_records_and_completion() {
        let mut datagram = message(SOCK_DIAG_BY_FAMILY, 7, &marked_record(123, 0x142));
        datagram.extend(message(NLMSG_DONE, 7, &[]));
        let decoded = decode_datagram(&datagram, 7).unwrap();
        assert!(decoded.complete);
        assert_eq!(decoded.records.len(), 1);
        assert_eq!(decoded.records[0].inode, 123);
        assert_eq!(decoded.records[0].mark, 0x142);
    }

    #[test]
    fn incomplete_dump_is_not_reported_complete() {
        let datagram = message(SOCK_DIAG_BY_FAMILY, 7, &marked_record(123, 0x142));
        let decoded = decode_datagram(&datagram, 7).unwrap();
        assert!(!decoded.complete);
        assert_eq!(decoded.records.len(), 1);
    }

    #[test]
    fn rejects_wrong_sequence_kernel_errors_and_truncation() {
        let valid = message(SOCK_DIAG_BY_FAMILY, 7, &marked_record(123, 0x142));
        assert!(decode_datagram(&valid, 8).is_err());
        assert!(decode_datagram(&valid[..8], 7).is_err());

        let error = message(NLMSG_ERROR, 7, &(-libc::EPERM).to_ne_bytes());
        assert!(decode_datagram(&error, 7).is_err());
    }

    #[test]
    fn rejects_interrupted_dump_even_when_done_is_present() {
        let mut done = message(NLMSG_DONE, 7, &[]);
        done[6..8].copy_from_slice(&NLM_F_DUMP_INTR.to_ne_bytes());
        assert!(decode_datagram(&done, 7).is_err());

        let mut record = message(SOCK_DIAG_BY_FAMILY, 7, &marked_record(123, 1));
        record[6..8].copy_from_slice(&NLM_F_DUMP_INTR.to_ne_bytes());
        assert!(decode_datagram(&record, 7).is_err());
    }


    #[test]
    fn accumulates_bounded_multipart_dump_until_done() {
        let mut accumulator = SocketDiagnosticDumpAccumulator::new(7).unwrap();
        accumulator
            .push_datagram(&message(
                SOCK_DIAG_BY_FAMILY,
                7,
                &marked_record(123, 0x142),
            ))
            .unwrap();
        assert!(accumulator.clone().into_complete_dump().is_err());

        accumulator
            .push_datagram(&message(NLMSG_DONE, 7, &[]))
            .unwrap();
        let dump = accumulator.into_complete_dump().unwrap();
        assert!(dump.complete);
        assert_eq!(dump.records.len(), 1);
        assert_eq!(dump.records[0].inode, 123);
    }

    #[test]
    fn accumulator_rejects_invalid_sequence_empty_and_post_done_datagrams() {
        assert!(SocketDiagnosticDumpAccumulator::new(0).is_err());
        let mut accumulator = SocketDiagnosticDumpAccumulator::new(7).unwrap();
        assert!(accumulator.push_datagram(&[]).is_err());
        assert!(accumulator
            .push_datagram(&message(NLMSG_DONE, 7, &[]))
            .is_ok());
        assert!(accumulator
            .push_datagram(&message(NLMSG_DONE, 7, &[]))
            .is_err());
    }

    #[test]
    fn rejects_non_kernel_netlink_sender_port_ids() {
        let mut response = message(NLMSG_DONE, 7, &[]);
        response[12..16].copy_from_slice(&42u32.to_ne_bytes());
        assert!(decode_datagram(&response, 7).is_err());
    }

    #[test]
    fn received_datagrams_require_kernel_sender_and_no_truncation() {
        let mut accumulator = SocketDiagnosticDumpAccumulator::new(7).unwrap();
        let done = message(NLMSG_DONE, 7, &[]);
        assert!(accumulator.push_received_datagram(12, false, &done).is_err());
        assert!(accumulator.push_received_datagram(0, true, &done).is_err());
        accumulator
            .push_received_datagram(0, false, &done)
            .unwrap();
        assert!(accumulator.into_complete_dump().unwrap().complete);
    }

    #[test]
    fn accumulator_enforces_datagram_count_limit() {
        let mut accumulator = SocketDiagnosticDumpAccumulator::new(7).unwrap();
        let noop = message(NLMSG_NOOP, 7, &[]);
        for _ in 0..MAX_DUMP_DATAGRAMS {
            accumulator.push_datagram(&noop).unwrap();
        }
        assert!(accumulator.push_datagram(&noop).is_err());
    }

    #[test]
    fn accumulator_enforces_total_byte_limit_before_decoding() {
        let mut accumulator = SocketDiagnosticDumpAccumulator::new(7).unwrap();
        let oversized = vec![0u8; MAX_TOTAL_DUMP_BYTES + 1];
        assert!(accumulator.push_datagram(&oversized).is_err());
    }

    #[test]
    fn accumulator_rejects_incomplete_dump_at_finalization() {
        let mut accumulator = SocketDiagnosticDumpAccumulator::new(7).unwrap();
        accumulator
            .push_datagram(&message(
                SOCK_DIAG_BY_FAMILY,
                7,
                &marked_record(123, 0x142),
            ))
            .unwrap();
        assert!(accumulator.into_complete_dump().is_err());
    }

    #[test]
    fn rejects_records_after_done_and_unexpected_types() {
        let mut datagram = message(NLMSG_DONE, 7, &[]);
        datagram.extend(message(SOCK_DIAG_BY_FAMILY, 7, &marked_record(123, 1)));
        assert!(decode_datagram(&datagram, 7).is_err());

        let unexpected = message(99, 7, &[]);
        assert!(decode_datagram(&unexpected, 7).is_err());
    }
}
