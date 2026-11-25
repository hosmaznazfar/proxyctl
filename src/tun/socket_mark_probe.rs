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
    expected_peer: std::net::SocketAddr,
    transport: BrokerSocketTransport,
    expected_mark: u32,
    mark_mask: u32,
) -> Result<SocketMarkBrokerResponse> {
    ensure!(
        unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0,
        "direct socket-mark diagnostics must run inside the privileged TUN supervisor"
    );
    let broker_request = SocketMarkBrokerRequest {
        version: BROKER_REQUEST_VERSION,
        process: process.clone(),
        expected_peer,
        transport,
        expected_mark,
        mark_mask,
    };
    broker_request.validate()?;

    let handle = ProcessHandle::open(process)
        .context("cannot pin the exact managed core for socket diagnostics")?;
    let before = socket_ownership::inspect_process_sockets(&handle)
        .context("cannot snapshot managed core socket ownership before diagnostics")?;

    let socket_transport = match transport {
        BrokerSocketTransport::Tcp => SocketTransport::Tcp,
        BrokerSocketTransport::Udp => SocketTransport::Udp,
    };
    let diagnostic_request = SocketDiagnosticRequest {
        family: if expected_peer.is_ipv4() {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        },
        transport: socket_transport,
        // Every observation uses a fresh netlink socket and one request, so sequence 1
        // cannot collide with an outstanding dump.
        sequence: 1,
    };
    let mut io = LinuxSocketDiagnosticIo::open()
        .context("cannot open the in-process NETLINK_SOCK_DIAG transport")?;
    let dump = socket_diag_collector::collect_dump(&mut io, diagnostic_request, Duration::from_secs(3))
        .context("cannot collect bounded kernel socket-mark diagnostics")?;

    let after = socket_ownership::inspect_process_sockets(&handle)
        .context("cannot snapshot managed core socket ownership after diagnostics")?;
    let response = build_socket_mark_broker_response(
        &broker_request,
        &before,
        &after,
        &dump.records,
    )
    .context("kernel socket diagnostics did not prove an exact marked proxy-peer socket")?;
    response.validate()?;
    Ok(response)
}

#[cfg(target_os = "linux")]
pub fn observed_proxy_outbound_mark(
    response: &SocketMarkBrokerResponse,
    expected_mark: u32,
    mark_mask: u32,
) -> Result<u32> {
    ensure!(
        expected_mark != 0
            && expected_mark <= i32::MAX as u32
            && mark_mask != 0
            && expected_mark & !mark_mask == 0,
        "expected proxy outbound mark policy is invalid"
    );
    response.validate()?;
    ensure!(
        response.expected_mark == expected_mark && response.mark_mask == mark_mask,
        "socket-mark response policy does not match the requested readiness policy"
    );
    ensure!(
        !response.records.is_empty(),
        "no process-owned proxy outbound socket with the expected peer and mark was observed"
    );
    let mut observed = None;
    for record in &response.records {
        ensure!(
            record.mark & mark_mask == expected_mark,
            "observed proxy outbound socket mark does not match the configured policy"
        );
        if let Some(previous) = observed {
            ensure!(
                previous == record.mark,
                "proxy outbound sockets have inconsistent observed marks"
            );
        } else {
            observed = Some(record.mark);
        }
    }
    observed.context("socket-mark response did not contain a mark")
}

#[cfg(not(target_os = "linux"))]
pub fn observe_proxy_outbound_mark(
    _process: (),
    _expected_peer: std::net::SocketAddr,
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
