//! In-process, read-only collection of outbound socket-mark evidence.
//!
//! The privileged Proxyctl supervisor collects NETLINK_SOCK_DIAG records directly. No
//! installed helper executable, socket pathname, IPC listener, or additional package is used.

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use super::{
    privilege_broker::{
        BROKER_REQUEST_VERSION, BrokerSocketTransport, SocketMarkBrokerRequest,
        SocketMarkBrokerResponse, build_socket_mark_broker_response,
    },
    process::{ProcessHandle, ProcessIdentity},
    socket_diag_collector,
    socket_diag_linux::LinuxSocketDiagnosticIo,
    socket_diag_netlink::{SocketDiagnosticRequest, SocketTransport},
    socket_ownership,
};

/// Collect one exact-peer socket-mark observation inside the already privileged supervisor.
#[cfg(target_os = "linux")]
pub fn observe_proxy_outbound_mark(
    process: ProcessIdentity,
    expected_peers: &[std::net::SocketAddr],
    transport: BrokerSocketTransport,
    expected_mark: u32,
    mark_mask: u32,
) -> Result<SocketMarkBrokerResponse> {
    ensure!(
        unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0,
        "direct socket-mark diagnostics must run inside the privileged TUN supervisor"
    );
    ensure!(
        !expected_peers.is_empty() && expected_peers.len() <= 8,
        "socket-mark diagnostics require one to eight expected proxy peers"
    );
    let mut unique_peers = std::collections::BTreeSet::new();
    for peer in expected_peers {
        ensure!(unique_peers.insert(*peer), "duplicate expected proxy peer");
        SocketMarkBrokerRequest {
            version: BROKER_REQUEST_VERSION,
            process: process.clone(),
            expected_peer: *peer,
            transport,
            expected_mark,
            mark_mask,
        }
        .validate()?;
    }

    let handle = ProcessHandle::open(process.clone())
        .context("cannot pin the exact managed core for socket diagnostics")?;
    let before = socket_ownership::inspect_process_sockets(&handle)
        .context("cannot snapshot managed core socket ownership before diagnostics")?;

    // One bounded dump per address family covers every resolved peer in that family.
    // This avoids repeating the same kernel query for each DNS candidate.
    let mut ipv4_records = None;
    let mut ipv6_records = None;
    for (family, peers) in [
        (libc::AF_INET as u8, expected_peers.iter().filter(|peer| peer.is_ipv4()).count()),
        (libc::AF_INET6 as u8, expected_peers.iter().filter(|peer| peer.is_ipv6()).count()),
    ] {
        if peers == 0 {
            continue;
        }
        let request = SocketDiagnosticRequest {
            family,
            transport: match transport {
                BrokerSocketTransport::Tcp => SocketTransport::Tcp,
                BrokerSocketTransport::Udp => SocketTransport::Udp,
            },
            sequence: 1,
        };
        let mut io = LinuxSocketDiagnosticIo::open()
            .context("cannot open the in-process NETLINK_SOCK_DIAG transport")?;
        let dump = socket_diag_collector::collect_dump(&mut io, request, Duration::from_secs(3))
            .context("cannot collect bounded kernel socket-mark diagnostics")?;
        if family == libc::AF_INET as u8 {
            ipv4_records = Some(dump.records);
        } else {
            ipv6_records = Some(dump.records);
        }
    }

    let after = socket_ownership::inspect_process_sockets(&handle)
        .context("cannot snapshot managed core socket ownership after diagnostics")?;

    let mut last_error = None;
    for peer in expected_peers {
        let records = if peer.is_ipv4() {
            ipv4_records.as_deref()
        } else {
            ipv6_records.as_deref()
        }
        .context("socket diagnostics did not collect the peer address family")?;
        let request = SocketMarkBrokerRequest {
            version: BROKER_REQUEST_VERSION,
            process: process.clone(),
            expected_peer: *peer,
            transport,
            expected_mark,
            mark_mask,
        };
        match build_socket_mark_broker_response(&request, &before, &after, records) {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!(
        "no exact marked proxy-peer socket was found in the kernel diagnostic records"
    )))
}

/// Validate a direct socket-mark observation against the expected routing policy.
#[cfg(target_os = "linux")]
pub fn observed_proxy_outbound_mark(
    response: &SocketMarkBrokerResponse,
    expected_mark: u32,
    mark_mask: u32,
) -> Result<u32> {
    response.validate()?;
    ensure!(
        response.expected_mark == expected_mark && response.mark_mask == mark_mask,
        "socket-mark observation does not match the requested mark policy"
    );
    let observed = response
        .records
        .first()
        .map(|record| record.mark)
        .context("socket-mark observation contains no matching records")?;
    ensure!(
        observed & mark_mask == expected_mark,
        "observed proxy outbound socket mark does not match the requested policy"
    );
    Ok(observed)
}

#[cfg(not(target_os = "linux"))]
pub fn observe_proxy_outbound_mark(
    _process: (),
    _expected_peers: &[std::net::SocketAddr],
    _transport: (),
    _expected_mark: u32,
    _mark_mask: u32,
) -> anyhow::Result<()> {
    anyhow::bail!("socket-mark observation is supported only on Linux");
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn readiness_mark_requires_a_matching_nonempty_consistent_observation() {
        use crate::tun::{
            privilege_broker::{
                BROKER_REQUEST_VERSION, BrokerSocketTransport, SocketMarkBrokerResponse,
            },
            socket_diag_records::{SocketAddressFamily, SocketDiagnosticRecord},
        };
        use std::net::{IpAddr, Ipv4Addr};
        let response = SocketMarkBrokerResponse {
            version: BROKER_REQUEST_VERSION,
            expected_peer: "198.51.100.8:443".parse().unwrap(),
            transport: BrokerSocketTransport::Tcp,
            expected_mark: 0x42,
            mark_mask: 0xff,
            records: vec![SocketDiagnosticRecord {
                family: SocketAddressFamily::Ipv4,
                state: 1,
                local_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                local_port: 40000,
                remote_address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)),
                remote_port: 443,
                inode: 7,
                mark: 0x42,
            }],
        };
        assert_eq!(
            observed_proxy_outbound_mark(&response, 0x42, 0xff).unwrap(),
            0x42
        );
        assert!(observed_proxy_outbound_mark(&response, 0x43, 0xff).is_err());
        assert!(observed_proxy_outbound_mark(&response, 0, 0xff).is_err());
        let mut empty = response.clone();
        empty.records.clear();
        assert!(observed_proxy_outbound_mark(&empty, 0x42, 0xff).is_err());
    }

}
