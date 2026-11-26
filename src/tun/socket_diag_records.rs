//! Strict parser for Linux INET socket-diagnostic messages.
//!
//! This module parses already-received kernel netlink payloads only. It opens no sockets,
//! sends no netlink requests, and does not provide privilege escalation. Collection remains
//! the responsibility of the future narrow read-only broker.

use anyhow::{Context, Result, ensure};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Linux UAPI value of the INET_DIAG_MARK netlink attribute.
pub const INET_DIAG_MARK: u16 = 15;
/// Size of struct inet_diag_msg in the Linux UAPI.
pub const INET_DIAG_MSG_LEN: usize = 72;
/// Netlink attributes are aligned to four bytes.
const NLA_ALIGNTO: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketAddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocketDiagnosticRecord {
    pub family: SocketAddressFamily,
    pub state: u8,
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
    pub inode: u32,
    pub mark: u32,
}

/// Parse one complete inet_diag_msg payload, including its aligned netlink attributes.
///
/// Unknown attributes are skipped for forward compatibility. A missing mark is an error for
/// inode-bearing records; inode-less kernel entries are validated and omitted because they
/// cannot identify a live process-owned socket.
pub fn parse_socket_diagnostic_record(payload: &[u8]) -> Result<Option<SocketDiagnosticRecord>> {
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
    let local_port = u16::from_be_bytes(payload[4..6].try_into()?);
    let remote_port = u16::from_be_bytes(payload[6..8].try_into()?);
    let local_address = parse_address(family, &payload[8..24])?;
    let remote_address = parse_address(family, &payload[24..40])?;
    let inode = u32::from_ne_bytes(
        payload[68..72]
            .try_into()
            .context("socket diagnostic inode field is truncated")?,
    );
    // Kernel socket dumps can include entries without a userspace socket inode
    // (for example, TCP time-wait records). Parse their attributes for structural
    // validity, then omit them: they cannot identify a live process-owned socket.
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
            ensure!(
                mark.is_none(),
                "socket diagnostic record contains duplicate mark attributes"
            );
            ensure!(
                value.len() == 4,
                "socket diagnostic mark attribute must contain exactly four bytes"
            );
            mark = Some(u32::from_ne_bytes(
                value
                    .try_into()
                    .context("socket diagnostic mark is truncated")?,
            ));
        }
        let aligned = align_attribute(length)?;
        ensure!(
            aligned <= payload.len() - offset,
            "socket diagnostic attribute padding is truncated"
        );
        offset += aligned;
    }
    if inode == 0 {
        return Ok(None);
    }
    let mark = mark.context("socket diagnostic record does not include INET_DIAG_MARK")?;
    Ok(Some(SocketDiagnosticRecord {
        family,
        state,
        local_address,
        local_port,
        remote_address,
        remote_port,
        inode,
        mark,
    }))
}

fn parse_address(family: SocketAddressFamily, bytes: &[u8]) -> Result<IpAddr> {
    ensure!(
        bytes.len() == 16,
        "socket diagnostic address has an invalid length"
    );
    Ok(match family {
        SocketAddressFamily::Ipv4 => {
            ensure!(
                bytes[4..].iter().all(|byte| *byte == 0),
                "IPv4 socket address contains non-zero padding"
            );
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
        }
        SocketAddressFamily::Ipv6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes)?)),
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
        bytes[4..6].copy_from_slice(&443u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&8443u16.to_be_bytes());
        bytes[8..12].copy_from_slice(&[192, 0, 2, 10]);
        bytes[24..28].copy_from_slice(&[198, 51, 100, 20]);
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
            let parsed = parse_socket_diagnostic_record(&record(family, 1234, 0x142))
                .unwrap()
                .unwrap();
            assert_eq!(parsed.family, expected);
            assert_eq!(parsed.state, 1);
            assert_eq!(parsed.inode, 1234);
            assert_eq!(parsed.mark, 0x142);
            assert_eq!(parsed.local_port, 443);
            assert_eq!(parsed.remote_port, 8443);
            assert_eq!(
                parsed.local_address,
                if expected == SocketAddressFamily::Ipv4 {
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
                } else {
                    IpAddr::V6(Ipv6Addr::from([
                        192, 0, 2, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]))
                }
            );
            assert_eq!(
                parsed.remote_address,
                if expected == SocketAddressFamily::Ipv4 {
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20))
                } else {
                    IpAddr::V6(Ipv6Addr::from([
                        198, 51, 100, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    ]))
                }
            );
        }
    }

    #[test]
    fn rejects_ipv4_address_padding_that_is_not_zero() {
        let mut bytes = record(libc::AF_INET as u8, 55, 7);
        bytes[12] = 1;
        assert!(parse_socket_diagnostic_record(&bytes).is_err());
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
        assert_eq!(parse_socket_diagnostic_record(&bytes).unwrap().unwrap().mark, 7);
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

        let without_inode = record(libc::AF_INET as u8, 0, 7);
        assert!(parse_socket_diagnostic_record(&without_inode).unwrap().is_none());

        let mut invalid = record(libc::AF_INET as u8, 1, 7);
        invalid[0] = 0;
        assert!(parse_socket_diagnostic_record(&invalid).is_err());
    }

    #[test]
    fn zero_inode_records_are_skipped_after_attribute_validation() {
        let mut without_mark = vec![0u8; INET_DIAG_MSG_LEN];
        without_mark[0] = libc::AF_INET as u8;
        assert!(parse_socket_diagnostic_record(&without_mark).unwrap().is_none());

        let mut malformed = record(libc::AF_INET as u8, 0, 7);
        malformed[72..74].copy_from_slice(&3u16.to_ne_bytes());
        assert!(parse_socket_diagnostic_record(&malformed).is_err());
    }
}
