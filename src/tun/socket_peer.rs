//! Conservative classification of marked sockets connected to the configured proxy peer.
//!
//! A matching mark alone is not directional evidence. This classifier additionally requires
//! exact process-owned inode attribution and an exact configured remote IP/port. It still
//! produces candidates only; the live collector must bind the records to a stable pidfd snapshot.

use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};

use anyhow::{Result, ensure};

const TCP_STATE_ESTABLISHED: u8 = 1;

use super::{
    socket_diag_netlink::SocketTransport,
    socket_diag_records::{SocketAddressFamily, SocketDiagnosticRecord},
};

/// Select process-owned sockets whose remote endpoint is the configured upstream proxy.
///
/// TCP candidates must be ESTABLISHED. UDP candidates must have a concrete connected peer.
/// The expected peer must be a resolved address from the selected node's validated config;
/// hostname resolution and DNS policy are deliberately outside this pure classifier.
pub fn classify_proxy_peer_sockets(
    records: &[SocketDiagnosticRecord],
    owned_inodes: &BTreeSet<u64>,
    expected_peer: SocketAddr,
    transport: SocketTransport,
    expected_mark: u32,
    mark_mask: u32,
) -> Result<Vec<SocketDiagnosticRecord>> {
    ensure!(
        !expected_peer.ip().is_unspecified()
            && !expected_peer.ip().is_multicast()
            && expected_peer.port() != 0,
        "expected proxy peer endpoint is not a usable unicast socket address"
    );
    ensure!(
        expected_mark != 0 && mark_mask != 0 && expected_mark & !mark_mask == 0,
        "expected proxy socket mark policy is invalid"
    );

    let expected_family = match expected_peer.ip() {
        IpAddr::V4(_) => SocketAddressFamily::Ipv4,
        IpAddr::V6(_) => SocketAddressFamily::Ipv6,
    };
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();

    for record in records {
        ensure!(
            seen.insert(record.inode),
            "socket diagnostics contain duplicate inode records"
        );
        if !owned_inodes.contains(&(record.inode as u64))
            || record.family != expected_family
            || record.remote_address != expected_peer.ip()
            || record.remote_port != expected_peer.port()
            || record.mark & mark_mask != expected_mark
        {
            continue;
        }

        match transport {
            SocketTransport::Tcp if record.state != TCP_STATE_ESTABLISHED => continue,
            SocketTransport::Udp if record.remote_port == 0 => continue,
            _ => {}
        }
        candidates.push(record.clone());
    }

    ensure!(
        !candidates.is_empty(),
        "no process-owned socket matches the configured proxy peer and mark policy"
    );
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn record(inode: u32, mark: u32, remote_port: u16, state: u8) -> SocketDiagnosticRecord {
        SocketDiagnosticRecord {
            family: SocketAddressFamily::Ipv4,
            state,
            local_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            local_port: 40000,
            remote_address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)),
            remote_port,
            inode,
            mark,
        }
    }

    fn peer() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 8), 443))
    }

    #[test]
    fn selects_only_owned_established_tcp_socket_to_exact_proxy_peer() {
        let records = [
            record(10, 0x142, 443, TCP_STATE_ESTABLISHED),
            record(11, 0x142, 8443, TCP_STATE_ESTABLISHED),
            record(12, 0x142, 443, 10),
            record(13, 0x242, 443, TCP_STATE_ESTABLISHED),
        ];
        let owned = [10, 11, 12, 13].into_iter().collect();
        let found = classify_proxy_peer_sockets(
            &records, &owned, peer(), SocketTransport::Tcp, 0x142, 0xffff,
        ).unwrap();
        assert_eq!(found.iter().map(|item| item.inode).collect::<Vec<_>>(), [10]);
    }

    #[test]
    fn rejects_matching_peer_when_inode_is_not_owned_by_core() {
        let records = [record(10, 0x142, 443, TCP_STATE_ESTABLISHED)];
        let owned = BTreeSet::new();
        assert!(classify_proxy_peer_sockets(
            &records, &owned, peer(), SocketTransport::Tcp, 0x142, 0xffff,
        ).is_err());
    }

    #[test]
    fn rejects_duplicate_inode_records_and_invalid_mark_policy() {
        let duplicate = [
            record(10, 0x142, 443, TCP_STATE_ESTABLISHED),
            record(10, 0x142, 443, TCP_STATE_ESTABLISHED),
        ];
        let owned = [10].into_iter().collect();
        assert!(classify_proxy_peer_sockets(
            &duplicate, &owned, peer(), SocketTransport::Tcp, 0x142, 0xffff,
        ).is_err());
        let one = [record(10, 0x142, 443, TCP_STATE_ESTABLISHED)];
        assert!(classify_proxy_peer_sockets(
            &one, &owned, peer(), SocketTransport::Tcp, 0x100, 0x0f,
        ).is_err());
    }

    #[test]
    fn accepts_connected_udp_peer_without_assuming_tcp_state_semantics() {
        let records = [record(10, 0x142, 443, 0)];
        let owned = [10].into_iter().collect();
        assert_eq!(classify_proxy_peer_sockets(
            &records, &owned, peer(), SocketTransport::Udp, 0x142, 0xffff,
        ).unwrap().len(), 1);
    }
}
