//! Strict parser for Linux INET socket-diagnostic messages.
//!
//! This module parses already-received kernel netlink payloads only. It opens no sockets,
//! sends no netlink requests, and does not provide privilege escalation. Collection remains
//! the responsibility of the future narrow read-only broker.

use anyhow::{Context, Result, ensure};

/// Linux UAPI value of the INET_DIAG_MARK netlink attribute.
pub const INET_DIAG_MARK: u16 = 15;
/// Size of struct inet_diag_msg in the Linux UAPI.
pub const INET_DIAG_MSG_LEN: usize = 72;
/// Netlink attributes are aligned to four bytes.
const NLA_ALIGNTO: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketDiagnosticRecord {
    pub family: SocketAddressFamily,
    pub state: u8,
    pub inode: u32,
    pub mark: u32,
}

/// Parse one complete inet_diag_msg payload, including its aligned netlink attributes.
///
/// Unknown attributes are skipped for forward compatibility. A missing mark is an error:
/// absence must never be interpreted as mark zero or successful policy evidence.
pub fn parse_socket_diagnostic_record(payload: &[u8]) -> Result<SocketDiagnosticRecord> {
    ensure!(
        payload.len() >= INET_DIAG_MSG_LEN,
        "socket diagnostic message is shorter than inet_diag_msg"
    );
    let family = match payload[0] {
        family if family == libc::AF_INET as u8 => SocketAddressFamily::Ipv4,
        family if family == libc::AF_INET6 as u8 => SocketAddressFamily::Ipv6,
        _ => anyhow::bail!("socket diagnostic message has an unsupported address family"),
    };
    let state = payload[1];
    let inode = u32::from_ne_bytes(
        payload[68..72]
            .try_into()
            .context("socket diagnostic inode field is truncated")?,
    );
    ensure!(inode > 0, "socket diagnostic record has a zero inode");

    let mut offset = INET_DIAG_MSG_LEN;
    let mut mark = None;
    while offset < payload.len() {
        ensure!(
            payload.len() - offset >= 4,
            "socket diagnostic attribute header is truncated"
        );
        let length = u16::from_ne_bytes([payload[offset], payload[offset + 1]]) as usize;
        let kind = u16::from_ne_bytes([payload[offset + 2], payload[offset + 3]]) & 0x3fff;
        ensure!(
            length >= 4 && length <= payload.len() - offset,
            "socket diagnostic attribute has an invalid length"
        );
        let value = &payload[offset + 4..offset + length];
        if kind == INET_DIAG_MARK {
            ensure!(mark.is_none(), "socket diagnostic record contains duplicate mark attributes");
            ensure!(value.len() == 4, "socket diagnostic mark attribute must contain exactly four bytes");
            mark = Some(u32::from_ne_bytes(
                value.try_into().context("socket diagnostic mark is truncated")?,
            ));
        }
        let aligned = align_attribute(length)?;
        ensure!(
            aligned <= payload.len() - offset,
            "socket diagnostic attribute padding is truncated"
        );
        offset += aligned;
    }
    let mark = mark.context("socket diagnostic record does not include INET_DIAG_MARK")?;
    Ok(SocketDiagnosticRecord {
        family,
        state,
        inode,
        mark,
    })
}

fn align_attribute(length: usize) -> Result<usize> {
    length
        .checked_add(NLA_ALIGNTO - 1)
        .map(|value| value & !(NLA_ALIGNTO - 1))
        .context("socket diagnostic attribute length overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(family: u8, inode: u32, mark: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; INET_DIAG_MSG_LEN];
        bytes[0] = family;
        bytes[1] = 1;
        bytes[68..72].copy_from_slice(&inode.to_ne_bytes());
        bytes.extend_from_slice(&8u16.to_ne_bytes());
        bytes.extend_from_slice(&INET_DIAG_MARK.to_ne_bytes());
        bytes.extend_from_slice(&mark.to_ne_bytes());
        bytes
    }

    #[test]
    fn parses_ipv4_and_ipv6_marked_socket_records() {
        for (family, expected) in [
            (libc::AF_INET as u8, SocketAddressFamily::Ipv4),
            (libc::AF_INET6 as u8, SocketAddressFamily::Ipv6),
        ] {
            let parsed = parse_socket_diagnostic_record(&record(family, 1234, 0x142)).unwrap();
            assert_eq!(parsed.family, expected);
            assert_eq!(parsed.state, 1);
            assert_eq!(parsed.inode, 1234);
            assert_eq!(parsed.mark, 0x142);
        }
    }

    #[test]
    fn skips_unknown_attributes_before_mark() {
        let mut bytes = vec![0u8; INET_DIAG_MSG_LEN];
        bytes[0] = libc::AF_INET as u8;
        bytes[68..72].copy_from_slice(&55u32.to_ne_bytes());
        bytes.extend_from_slice(&8u16.to_ne_bytes());
        bytes.extend_from_slice(&99u16.to_ne_bytes());
        bytes.extend_from_slice(&[1, 2, 3, 4]);
        bytes.extend_from_slice(&8u16.to_ne_bytes());
        bytes.extend_from_slice(&INET_DIAG_MARK.to_ne_bytes());
        bytes.extend_from_slice(&7u32.to_ne_bytes());
        assert_eq!(parse_socket_diagnostic_record(&bytes).unwrap().mark, 7);
    }

    #[test]
    fn rejects_missing_duplicate_and_malformed_mark_attributes() {
        let mut missing = vec![0u8; INET_DIAG_MSG_LEN];
        missing[0] = libc::AF_INET as u8;
        missing[68..72].copy_from_slice(&1u32.to_ne_bytes());
        assert!(parse_socket_diagnostic_record(&missing).is_err());

        let mut duplicate = record(libc::AF_INET as u8, 1, 7);
        duplicate.extend_from_slice(&8u16.to_ne_bytes());
        duplicate.extend_from_slice(&INET_DIAG_MARK.to_ne_bytes());
        duplicate.extend_from_slice(&7u32.to_ne_bytes());
        assert!(parse_socket_diagnostic_record(&duplicate).is_err());

        let mut short = record(libc::AF_INET as u8, 1, 7);
        short[72..74].copy_from_slice(&7u16.to_ne_bytes());
        assert!(parse_socket_diagnostic_record(&short).is_err());
    }

    #[test]
    fn rejects_truncated_unknown_attributes_and_invalid_identity() {
        let mut truncated = record(libc::AF_INET as u8, 1, 7);
        truncated.push(1);
        assert!(parse_socket_diagnostic_record(&truncated).is_err());

        let mut invalid = record(libc::AF_INET as u8, 0, 7);
        assert!(parse_socket_diagnostic_record(&invalid).is_err());
        invalid[68..72].copy_from_slice(&1u32.to_ne_bytes());
        invalid[0] = 0;
        assert!(parse_socket_diagnostic_record(&invalid).is_err());
    }
}
