//! Bounded Linux NETLINK_ROUTE transport primitives.
//!
//! This module owns no policy and exposes no public mutation API. Higher-level operations
//! must build and validate typed requests, journal intent before calling this transport, and
//! verify kernel acknowledgements plus a fresh exact inventory afterwards.

#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::Duration,
};

const NETLINK_HEADER_LEN: usize = 16;
const MAX_NETLINK_DATAGRAM: usize = 1024 * 1024;
const MAX_NETLINK_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_NETLINK_RESPONSE_MESSAGES: usize = 16_384;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_F_NESTED: u16 = 1 << 15;
const RTATTR_HEADER_LEN: usize = 4;
const IFINFO_MESSAGE_LEN: usize = 16;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;

#[derive(Debug)]
pub(crate) struct RouteNetlink {
    fd: OwnedFd,
    sequence: u32,
}

impl RouteNetlink {
    pub(crate) fn open() -> Result<Self> {
        // SAFETY: socket has no pointer arguments and returns a new owned descriptor.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        ensure!(
            raw >= 0,
            "cannot open NETLINK_ROUTE socket: {}",
            io::Error::last_os_error()
        );
        // SAFETY: raw is a newly-created descriptor and ownership is transferred exactly once.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zero is a valid initial representation for sockaddr_nl.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: address is initialized and the pointer/length match sockaddr_nl.
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        ensure!(
            result == 0,
            "cannot bind NETLINK_ROUTE socket: {}",
            io::Error::last_os_error()
        );
        Ok(Self { fd, sequence: 0 })
    }

    /// Send one already-encoded request and collect its matching multipart response.
    /// Callers must not expose arbitrary caller-provided bytes across the privilege boundary.
    pub(crate) fn transact(&mut self, request: &[u8], timeout: Duration) -> Result<Vec<Vec<u8>>> {
        validate_request(request)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("netlink sequence exhausted")?;
        let sequence = self.sequence;
        let mut request = request.to_vec();
        request[8..12].copy_from_slice(&sequence.to_ne_bytes());

        // SAFETY: zero is a valid initial representation for sockaddr_nl.
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: request and destination remain alive for the duration of sendto.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&kernel as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        ensure!(
            sent == request.len() as isize,
            "short NETLINK_ROUTE send: {}",
            io::Error::last_os_error()
        );

        let deadline = std::time::Instant::now() + timeout.min(DEFAULT_TIMEOUT);
        let mut messages = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            ensure!(!remaining.is_zero(), "NETLINK_ROUTE response timed out");
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pollfd points to one initialized poll descriptor.
            let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
            if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            ensure!(
                ready >= 0,
                "NETLINK_ROUTE poll failed: {}",
                io::Error::last_os_error()
            );
            ensure!(ready > 0, "NETLINK_ROUTE response timed out");
            ensure!(
                pollfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) == 0,
                "NETLINK_ROUTE socket reported an error"
            );

            let mut buffer = vec![0u8; MAX_NETLINK_DATAGRAM];
            // SAFETY: buffer and sender storage are writable for their declared lengths.
            let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut sender_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            let received = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_TRUNC,
                    (&mut sender as *mut libc::sockaddr_nl).cast(),
                    &mut sender_len,
                )
            };
            if received < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            ensure!(
                received >= 0,
                "NETLINK_ROUTE receive failed: {}",
                io::Error::last_os_error()
            );
            ensure!(
                sender_len as usize >= std::mem::size_of::<libc::sockaddr_nl>()
                    && sender.nl_family == libc::AF_NETLINK as u16
                    && sender.nl_pid == 0,
                "NETLINK_ROUTE response did not originate from the kernel"
            );
            ensure!(
                received as usize <= buffer.len(),
                "NETLINK_ROUTE datagram exceeded the size limit"
            );
            buffer.truncate(received as usize);
            let (batch, terminal) = parse_datagram(&buffer, sequence)?;
            validate_response_budget(&messages, &batch)?;
            messages.extend(batch);
            if terminal {
                return Ok(messages);
            }
        }
    }
}

/// Perform a bounded, read-only NETLINK_ROUTE link dump and return its record count.
/// This diagnostic is safe without privileges and never changes interface state.
pub fn inspect_link_count() -> Result<usize> {
    let mut request = vec![0u8; NETLINK_HEADER_LEN + 16];
    let request_len = request.len() as u32;
    request[0..4].copy_from_slice(&request_len.to_ne_bytes());
    request[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    // ifinfomsg is zeroed: AF_UNSPEC, all interfaces, no filters.
    let mut socket = RouteNetlink::open()?;
    let messages = socket.transact(&request, DEFAULT_TIMEOUT)?;
    let mut count = 0usize;
    for message in messages {
        ensure!(
            u16::from_ne_bytes(message[4..6].try_into()?) == RTM_NEWLINK,
            "unexpected message in NETLINK_ROUTE link dump"
        );
        ensure!(
            message.len() >= NETLINK_HEADER_LEN + 16,
            "truncated link record"
        );
        count = count
            .checked_add(1)
            .context("link inventory count overflow")?;
    }
    Ok(count)
}

/// Exact link identity decoded from a kernel RTM_GETLINK dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetlinkLinkRecord {
    pub name: String,
    pub index: u32,
    pub kind: Option<String>,
}

/// Capture and decode every link using a bounded, read-only RTM_GETLINK dump.
pub fn inspect_links() -> Result<Vec<NetlinkLinkRecord>> {
    let mut request = vec![0u8; NETLINK_HEADER_LEN + IFINFO_MESSAGE_LEN];
    let request_len = request.len() as u32;
    request[0..4].copy_from_slice(&request_len.to_ne_bytes());
    request[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());

    let mut socket = RouteNetlink::open()?;
    let messages = socket.transact(&request, DEFAULT_TIMEOUT)?;
    let mut links = Vec::with_capacity(messages.len());
    let mut names = std::collections::BTreeSet::new();
    let mut indices = std::collections::BTreeSet::new();
    for message in messages {
        ensure!(
            u16::from_ne_bytes(message[4..6].try_into()?) == RTM_NEWLINK,
            "unexpected message in NETLINK_ROUTE link dump"
        );
        let link = parse_link_message(&message)?;
        ensure!(
            names.insert(link.name.clone()) && indices.insert(link.index),
            "NETLINK_ROUTE link dump contains duplicate names or indices"
        );
        links.push(link);
    }
    links.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(links)
}

fn parse_link_message(message: &[u8]) -> Result<NetlinkLinkRecord> {
    ensure!(
        message.len() >= NETLINK_HEADER_LEN + IFINFO_MESSAGE_LEN,
        "truncated RTM_NEWLINK ifinfomsg"
    );
    let declared_length = u32::from_ne_bytes(message[0..4].try_into()?) as usize;
    ensure!(
        declared_length == message.len()
            && u16::from_ne_bytes(message[4..6].try_into()?) == RTM_NEWLINK,
        "RTM_NEWLINK header length or type is inconsistent"
    );
    let payload = &message[NETLINK_HEADER_LEN..];
    let raw_index = i32::from_ne_bytes(payload[4..8].try_into()?);
    ensure!(raw_index > 0, "RTM_NEWLINK has a non-positive interface index");
    let index = u32::try_from(raw_index).context("interface index exceeds u32")?;
    let attributes = &payload[IFINFO_MESSAGE_LEN..];
    let mut name = None;
    let mut kind = None;
    let mut link_info_seen = false;
    let mut offset = 0usize;
    while offset < attributes.len() {
        ensure!(
            attributes.len() - offset >= RTATTR_HEADER_LEN,
            "truncated RTM_NEWLINK attribute header"
        );
        let length = u16::from_ne_bytes(attributes[offset..offset + 2].try_into()?) as usize;
        let raw_kind = u16::from_ne_bytes(attributes[offset + 2..offset + 4].try_into()?);
        let attribute_kind = raw_kind & !IFLA_F_NESTED;
        ensure!(
            length >= RTATTR_HEADER_LEN && length <= attributes.len() - offset,
            "invalid RTM_NEWLINK attribute length"
        );
        let value = &attributes[offset + RTATTR_HEADER_LEN..offset + length];
        match attribute_kind {
            IFLA_IFNAME => {
                ensure!(name.is_none(), "duplicate IFLA_IFNAME attribute");
                let nul = value
                    .iter()
                    .position(|byte| *byte == 0)
                    .context("IFLA_IFNAME is not NUL terminated")?;
                ensure!(
                    nul > 0 && nul + 1 == value.len(),
                    "invalid IFLA_IFNAME payload"
                );
                let parsed = std::str::from_utf8(&value[..nul])
                    .context("interface name is not valid UTF-8")?;
                ensure!(
                    parsed.len() <= 15
                        && parsed.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
                        }),
                    "kernel returned an invalid interface name"
                );
                name = Some(parsed.to_owned());
            }
            IFLA_LINKINFO => {
                ensure!(!link_info_seen, "duplicate IFLA_LINKINFO attribute");
                link_info_seen = true;
                kind = parse_link_kind(value)?;
            }
            _ => {}
        }
        let aligned = length
            .checked_add(3)
            .map(|value| value & !3)
            .context("RTM_NEWLINK attribute alignment overflow")?;
        let remaining = attributes.len() - offset;
        ensure!(
            aligned <= remaining || length == remaining,
            "truncated RTM_NEWLINK attribute padding"
        );
        if aligned <= remaining {
            ensure!(
                attributes[offset + length..offset + aligned]
                    .iter()
                    .all(|byte| *byte == 0),
                "non-zero RTM_NEWLINK attribute padding"
            );
        }
        offset = offset
            .checked_add(if aligned <= remaining { aligned } else { length })
            .context("RTM_NEWLINK attribute offset overflow")?;
    }
    let name = name.context("RTM_NEWLINK is missing IFLA_IFNAME")?;
    Ok(NetlinkLinkRecord { name, index, kind })
}

fn parse_link_kind(attributes: &[u8]) -> Result<Option<String>> {
    let mut kind = None;
    let mut offset = 0usize;
    while offset < attributes.len() {
        ensure!(
            attributes.len() - offset >= RTATTR_HEADER_LEN,
            "truncated IFLA_LINKINFO attribute header"
        );
        let length = u16::from_ne_bytes(attributes[offset..offset + 2].try_into()?) as usize;
        let attribute_kind =
            u16::from_ne_bytes(attributes[offset + 2..offset + 4].try_into()?) & !IFLA_F_NESTED;
        ensure!(
            length >= RTATTR_HEADER_LEN && length <= attributes.len() - offset,
            "invalid IFLA_LINKINFO attribute length"
        );
        if attribute_kind == IFLA_INFO_KIND {
            ensure!(kind.is_none(), "duplicate IFLA_INFO_KIND attribute");
            let value = &attributes[offset + RTATTR_HEADER_LEN..offset + length];
            let nul = value
                .iter()
                .position(|byte| *byte == 0)
                .context("IFLA_INFO_KIND is not NUL terminated")?;
            ensure!(
                nul > 0 && nul + 1 == value.len(),
                "invalid IFLA_INFO_KIND payload"
            );
            let parsed = std::str::from_utf8(&value[..nul])
                .context("link kind is not valid UTF-8")?;
            ensure!(
                parsed.len() <= 32
                    && parsed.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "invalid kernel link kind"
            );
            kind = Some(parsed.to_owned());
        }
        let aligned = length
            .checked_add(3)
            .map(|value| value & !3)
            .context("IFLA_LINKINFO alignment overflow")?;
        let remaining = attributes.len() - offset;
        ensure!(
            aligned <= remaining || length == remaining,
            "truncated IFLA_LINKINFO padding"
        );
        if aligned <= remaining {
            ensure!(
                attributes[offset + length..offset + aligned]
                    .iter()
                    .all(|byte| *byte == 0),
                "non-zero IFLA_LINKINFO padding"
            );
        }
        offset = offset
            .checked_add(if aligned <= remaining { aligned } else { length })
            .context("IFLA_LINKINFO offset overflow")?;
    }
    Ok(kind)
}

fn validate_alignment_padding(
    datagram: &[u8],
    offset: usize,
    message_length: usize,
    aligned_length: usize,
    remaining: usize,
) -> Result<()> {
    if aligned_length > remaining {
        ensure!(
            message_length == remaining,
            "truncated netlink alignment padding"
        );
        return Ok(());
    }

    let padding_start = offset
        .checked_add(message_length)
        .context("netlink padding offset overflow")?;
    let padding_end = offset
        .checked_add(aligned_length)
        .context("netlink padding end overflow")?;
    ensure!(
        datagram[padding_start..padding_end]
            .iter()
            .all(|byte| *byte == 0),
        "non-zero netlink alignment padding"
    );
    Ok(())
}

fn validate_response_budget(current: &[Vec<u8>], incoming: &[Vec<u8>]) -> Result<()> {
    let current_bytes = current
        .iter()
        .try_fold(0usize, |total, item| total.checked_add(item.len()))
        .context("NETLINK_ROUTE response size overflow")?;
    let incoming_bytes = incoming
        .iter()
        .try_fold(0usize, |total, item| total.checked_add(item.len()))
        .context("NETLINK_ROUTE response size overflow")?;
    ensure!(
        current_bytes
            .checked_add(incoming_bytes)
            .is_some_and(|size| size <= MAX_NETLINK_RESPONSE_BYTES),
        "NETLINK_ROUTE response exceeds the aggregate size limit"
    );
    ensure!(
        current
            .len()
            .checked_add(incoming.len())
            .is_some_and(|count| count <= MAX_NETLINK_RESPONSE_MESSAGES),
        "NETLINK_ROUTE response contains too many messages"
    );
    Ok(())
}

fn validate_request(bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() >= NETLINK_HEADER_LEN && bytes.len() <= MAX_NETLINK_DATAGRAM,
        "invalid netlink request length"
    );
    let declared = u32::from_ne_bytes(bytes[0..4].try_into()?);
    ensure!(
        declared as usize == bytes.len(),
        "netlink request length does not match its header"
    );
    Ok(())
}

fn parse_datagram(bytes: &[u8], expected_sequence: u32) -> Result<(Vec<Vec<u8>>, bool)> {
    let mut offset = 0usize;
    let mut messages = Vec::new();
    let mut terminal = false;
    while offset < bytes.len() {
        ensure!(
            !terminal,
            "netlink datagram contains data after a terminal message"
        );
        ensure!(
            bytes.len() - offset >= NETLINK_HEADER_LEN,
            "truncated netlink message header"
        );
        let header = &bytes[offset..offset + NETLINK_HEADER_LEN];
        let length = u32::from_ne_bytes(header[0..4].try_into()?) as usize;
        let kind = u16::from_ne_bytes(header[4..6].try_into()?);
        let sequence = u32::from_ne_bytes(header[8..12].try_into()?);
        ensure!(
            length >= NETLINK_HEADER_LEN && length <= bytes.len() - offset,
            "invalid netlink message length"
        );
        ensure!(
            sequence == expected_sequence,
            "unexpected NETLINK_ROUTE sequence"
        );
        let message = &bytes[offset..offset + length];
        if kind == NLMSG_ERROR {
            ensure!(
                length >= NETLINK_HEADER_LEN + 4,
                "truncated netlink acknowledgement"
            );
            let error =
                i32::from_ne_bytes(message[NETLINK_HEADER_LEN..NETLINK_HEADER_LEN + 4].try_into()?);
            if error != 0 {
                let errno = error
                    .checked_neg()
                    .context("invalid positive or overflowing netlink error code")?;
                ensure!(errno > 0, "invalid netlink error code");
                anyhow::bail!(
                    "kernel rejected NETLINK_ROUTE request: {}",
                    io::Error::from_raw_os_error(errno)
                );
            }
            terminal = true;
        } else if kind == NLMSG_DONE {
            terminal = true;
        } else {
            messages.push(message.to_vec());
        }
        let aligned_length = length
            .checked_add(3)
            .map(|value| value & !3)
            .context("netlink message alignment overflow")?;
        let remaining = bytes.len() - offset;
        ensure!(
            aligned_length <= remaining || length == remaining,
            "truncated netlink alignment padding"
        );
        validate_alignment_padding(bytes, offset, length, aligned_length, remaining)?;
        offset = offset
            .checked_add(if aligned_length <= remaining {
                aligned_length
            } else {
                length
            })
            .context("netlink offset overflow")?;
    }
    ensure!(
        offset == bytes.len() || bytes[offset..].iter().all(|byte| *byte == 0),
        "invalid netlink alignment padding"
    );
    Ok((messages, terminal))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = NETLINK_HEADER_LEN + payload.len();
        let mut bytes = vec![0; (length + 3) & !3];
        bytes[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
        bytes[NETLINK_HEADER_LEN..length].copy_from_slice(payload);
        bytes
    }

    fn rtattr(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = RTATTR_HEADER_LEN + value.len();
        let mut bytes = vec![0u8; (length + 3) & !3];
        bytes[..2].copy_from_slice(&(length as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&kind.to_ne_bytes());
        bytes[4..length].copy_from_slice(value);
        bytes
    }

    fn link_message(index: i32, name: &[u8], kind: Option<&[u8]>) -> Vec<u8> {
        let mut payload = vec![0u8; IFINFO_MESSAGE_LEN];
        payload[4..8].copy_from_slice(&index.to_ne_bytes());
        let mut name_value = name.to_vec();
        name_value.push(0);
        let mut attributes = rtattr(IFLA_IFNAME, &name_value);
        if let Some(kind) = kind {
            let kind_attr = rtattr(IFLA_INFO_KIND, kind);
            let link_info = rtattr(IFLA_LINKINFO, &kind_attr);
            attributes.extend(link_info);
        }
        payload.extend(attributes);
        message(RTM_NEWLINK, 7, &payload)
    }

    #[test]
    fn decodes_exact_link_name_index_and_tun_kind() {
        let bytes = link_message(77, b"tun-proxyctl", Some(b"tun"));
        let parsed = parse_link_message(&bytes).unwrap();
        assert_eq!(
            parsed,
            NetlinkLinkRecord {
                name: "tun-proxyctl".into(),
                index: 77,
                kind: Some("tun".into())
            }
        );
    }

    #[test]
    fn rejects_inconsistent_link_headers_and_string_terminators() {
        let mut wrong_type = link_message(2, b"eth0", None);
        wrong_type[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
        assert!(parse_link_message(&wrong_type).is_err());

        let mut wrong_length = link_message(2, b"eth0", None);
        wrong_length[0..4].copy_from_slice(&1u32.to_ne_bytes());
        assert!(parse_link_message(&wrong_length).is_err());

        let mut extra_nul = link_message(2, b"eth0", None);
        let name_attr = NETLINK_HEADER_LEN + IFINFO_MESSAGE_LEN;
        let attr_length = u16::from_ne_bytes(extra_nul[name_attr..name_attr + 2].try_into().unwrap()) as usize;
        extra_nul[name_attr + attr_length - 1] = 0;
        // Extend the declared attribute payload by one byte and preserve alignment.
        extra_nul[name_attr..name_attr + 2]
            .copy_from_slice(&((attr_length + 1) as u16).to_ne_bytes());
        extra_nul.insert(name_attr + attr_length, 0);
        let message_length = extra_nul.len() as u32;
        extra_nul[0..4].copy_from_slice(&message_length.to_ne_bytes());
        assert!(parse_link_message(&extra_nul).is_err());
    }

    #[test]
    fn rejects_malformed_link_identity_attributes() {
        assert!(parse_link_message(&link_message(0, b"eth0", None)).is_err());
        assert!(parse_link_message(&link_message(2, b"", None)).is_err());
        assert!(parse_link_message(&link_message(2, &[0xff], None)).is_err());
        assert!(parse_link_message(&link_message(2, b"bad/name", None)).is_err());

        let mut missing_name = vec![0u8; NETLINK_HEADER_LEN + IFINFO_MESSAGE_LEN];
        missing_name[0..4].copy_from_slice(&(missing_name.len() as u32).to_ne_bytes());
        missing_name[4..6].copy_from_slice(&RTM_NEWLINK.to_ne_bytes());
        assert!(parse_link_message(&missing_name).is_err());
    }

    #[test]
    fn accepts_matching_ack_as_terminal() {
        let bytes = message(NLMSG_ERROR, 7, &0i32.to_ne_bytes());
        let (messages, terminal) = parse_datagram(&bytes, 7).unwrap();
        assert!(messages.is_empty());
        assert!(terminal);
    }

    #[test]
    fn rejects_unrepresentable_netlink_error_code_without_panicking() {
        for error in [i32::MIN, 1] {
            let bytes = message(NLMSG_ERROR, 7, &error.to_ne_bytes());
            assert!(parse_datagram(&bytes, 7).is_err());
        }
    }

    #[test]
    fn rejects_kernel_error_ack() {
        let bytes = message(NLMSG_ERROR, 7, &(-libc::EPERM).to_ne_bytes());
        assert!(parse_datagram(&bytes, 7).is_err());
    }

    #[test]
    fn rejects_messages_after_terminal_acknowledgement() {
        let mut bytes = message(NLMSG_DONE, 7, &[]);
        bytes.extend(message(99, 7, &[1]));
        assert!(parse_datagram(&bytes, 7).is_err());
    }

    #[test]
    fn rejects_wrong_sequence_and_truncated_headers() {
        assert!(parse_datagram(&message(NLMSG_DONE, 8, &[]), 7).is_err());
        assert!(parse_datagram(&[1, 2, 3], 7).is_err());
    }

    #[test]
    fn validates_request_declared_length() {
        let mut bytes = message(16, 1, &[]);
        bytes[0..4].copy_from_slice(&99u32.to_ne_bytes());
        assert!(validate_request(&bytes).is_err());
    }
    #[test]
    fn accepts_final_unpadded_non_aligned_netlink_message() {
        let mut bytes = message(99, 7, &[1]);
        bytes.truncate(NETLINK_HEADER_LEN + 1);
        assert_eq!(parse_datagram(&bytes, 7).unwrap(), (vec![bytes], false));
    }

    #[test]
    fn accepts_final_unpadded_netlink_message_without_out_of_bounds_access() {
        let mut bytes = message(NLMSG_DONE, 7, &[]);
        bytes.truncate(NETLINK_HEADER_LEN);
        assert_eq!(parse_datagram(&bytes, 7).unwrap(), (Vec::new(), true));
    }

    #[test]
    fn rejects_nonzero_alignment_padding_and_truncated_padding() {
        let mut padded = message(NLMSG_DONE, 7, &[1]);
        *padded.last_mut().unwrap() = 0x7f;
        assert!(parse_datagram(&padded, 7).is_err());
        let mut truncated = message(NLMSG_DONE, 7, &[1]);
        truncated.pop();
        assert!(parse_datagram(&truncated, 7).is_err());
    }

    #[test]
    fn aggregate_response_budget_rejects_byte_and_record_overflow() {
        let oversized = vec![vec![0u8; MAX_NETLINK_RESPONSE_BYTES + 1]];
        assert!(validate_response_budget(&[], &oversized).is_err());
        let too_many = vec![Vec::new(); MAX_NETLINK_RESPONSE_MESSAGES + 1];
        assert!(validate_response_budget(&[], &too_many).is_err());
        let within_limit = vec![vec![0u8; 64], vec![0u8; 64]];
        validate_response_budget(&[], &within_limit).unwrap();
    }

    #[test]
    fn read_only_link_probe_request_uses_dump_flags() {
        let mut request = vec![0u8; NETLINK_HEADER_LEN + 16];
        let length = request.len() as u32;
        request[0..4].copy_from_slice(&length.to_ne_bytes());
        request[4..6].copy_from_slice(&RTM_GETLINK.to_ne_bytes());
        request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        validate_request(&request).unwrap();
        assert_eq!(
            u16::from_ne_bytes(request[4..6].try_into().unwrap()),
            RTM_GETLINK
        );
    }
}
