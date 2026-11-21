//! Fail-closed evidence model and active local-listener probe for TUN readiness.
//!
//! The listener probe verifies the persisted core process identity around a bounded loopback
//! TCP connection. Other dataplane evidence remains independently supplied and fail-closed.

use anyhow::{Context, Result, ensure};
use std::{
    net::{SocketAddr, TcpStream},
    time::Duration,
};

/// Actively verify a loopback listener while the exact managed core process remains alive.
///
/// A successful TCP connection is not by itself proof that the listener belongs to the core;
/// callers must use a dedicated, manifest-bound listener endpoint and retain the process
/// identity evidence. The identity is checked both before and after connecting to narrow PID
/// replacement races.
#[cfg(target_os = "linux")]
pub fn probe_core_listener(
    process: &super::process::ProcessIdentity,
    listener: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr> {
    ensure!(
        listener.ip().is_loopback() && listener.port() != 0,
        "core readiness listener must be a non-zero loopback socket"
    );
    ensure!(
        !timeout.is_zero() && timeout <= Duration::from_secs(5),
        "core listener probe timeout must be between zero and five seconds"
    );
    ensure!(
        process.verify()?,
        "managed core process identity is no longer present before listener probe"
    );
    verify_listener_process_ownership(process, listener)?;
    let stream = TcpStream::connect_timeout(&listener, timeout)
        .context("managed core local proxy listener did not accept a connection")?;
    ensure!(
        stream.peer_addr()? == listener,
        "connected local listener does not match the requested endpoint"
    );
    ensure!(
        process.verify()?,
        "managed core process identity changed during listener probe"
    );
    verify_listener_process_ownership(process, listener)?;
    Ok(listener)
}

#[cfg(target_os = "linux")]
fn verify_listener_process_ownership(
    identity: &super::process::ProcessIdentity,
    listener: SocketAddr,
) -> Result<()> {
    use std::{collections::BTreeSet, fs};

    let handle = super::process::ProcessHandle::open(identity.clone())
        .context("cannot pin managed core while verifying listener ownership")?;
    let before = super::socket_ownership::inspect_process_sockets(&handle)?;
    let mut listener_inodes = BTreeSet::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let contents = fs::read_to_string(table)
            .with_context(|| format!("cannot inspect kernel listener table {table}"))?;
        for line in contents.lines().skip(1) {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 10 || fields[3] != "0A" {
                continue;
            }
            let Some((address, port)) = parse_proc_tcp_endpoint(fields[1], table.ends_with("tcp6")) else {
                continue;
            };
            if address == listener.ip() && port == listener.port() {
                if let Ok(inode) = fields[9].parse::<u64>() {
                    if inode > 0 {
                        listener_inodes.insert(inode);
                    }
                }
            }
        }
    }
    ensure!(
        !listener_inodes.is_disjoint(&before.socket_inodes),
        "loopback listener socket is not owned by the managed core process"
    );
    let after = super::socket_ownership::inspect_process_sockets(&handle)?;
    ensure!(
        before == after && identity.verify()? && !handle.is_exited()?,
        "managed core socket ownership changed during listener verification"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_proc_tcp_endpoint(value: &str, ipv6: bool) -> Option<(std::net::IpAddr, u16)> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if ipv6 {
        if address.len() != 32 { return None; }
        let mut bytes = [0u8; 16];
        for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
    } else {
        if address.len() != 8 { return None; }
        let word = u32::from_str_radix(address, 16).ok()?;
        Some((IpAddr::V4(Ipv4Addr::from(word.to_le_bytes())), port))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe_core_listener(
    _process: &(),
    _listener: SocketAddr,
    _timeout: Duration,
) -> Result<SocketAddr> {
    anyhow::bail!("managed-core listener probing is supported only on Linux");
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEvidence {
    pub name: String,
    pub index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessEvidence {
    pub core_process_verified: bool,
    pub local_listener: Option<SocketAddr>,
    pub tun_interface: Option<InterfaceEvidence>,
    pub route_policy_verified: bool,
    pub core_outbound_socket_mark: Option<u32>,
    pub physical_egress_bypass_verified: bool,
    pub proxied_traffic_verified: bool,
    pub dns_unchanged: bool,
    pub firewall_unchanged: bool,
}

/// The expected resources are taken from the persisted activation manifest, never guessed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessExpectation<'a> {
    pub interface_name: &'a str,
    pub interface_index: u32,
    pub core_mark: u32,
    pub core_mark_mask: u32,
}

/// Compare pre-activation and current host DNS/firewall snapshots.
///
/// Route and interface fields are intentionally excluded because the activation owns those
/// changes. DNS configuration and the complete read-only firewall summary must remain equal.
/// Both snapshots must contain usable inspection evidence; unavailable DNS/firewall data is
/// never treated as proof that the host configuration stayed unchanged.
pub fn verify_host_network_unchanged(
    baseline: &super::NetworkStatus,
    current: &super::NetworkStatus,
) -> Result<()> {
    ensure!(baseline.dns_inspected && current.dns_inspected,
        "DNS state must be successfully inspected in both host snapshots");
    ensure!(baseline.firewall.backend != "not available"
        && current.firewall.backend != "not available"
        && !baseline.firewall.detail.contains("failed")
        && !current.firewall.detail.contains("failed")
        && !baseline.firewall.detail.contains("unrecognized")
        && !current.firewall.detail.contains("unrecognized")
        && !baseline.firewall.detail.contains("not permitted")
        && !current.firewall.detail.contains("not permitted")
        && (baseline.firewall.backend != "iptables"
            || baseline.firewall.detail.contains("2 address family commands"))
        && (current.firewall.backend != "iptables"
            || current.firewall.detail.contains("2 address family commands")),
        "firewall state is unavailable or incomplete in a host snapshot");
    ensure!(
        baseline.dns_servers == current.dns_servers
            && baseline.resolv_conf_target == current.resolv_conf_target
            && baseline.systemd_resolved_runtime == current.systemd_resolved_runtime
            && baseline.network_manager_runtime == current.network_manager_runtime,
        "host DNS configuration changed during TUN activation"
    );
    ensure!(baseline.firewall == current.firewall,
        "host firewall snapshot changed during TUN activation");
    Ok(())
}



/// Hard defaults for a conservative diagnostic traffic observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyTrafficProbeLimits {
    pub timeout: Duration,
    pub maximum_response_bytes: usize,
}

impl ProxyTrafficProbeLimits {
    /// Construct validated limits; no timeout above thirty seconds or body above one MiB.
    pub fn new(timeout: Duration, maximum_response_bytes: usize) -> Result<Self> {
        ensure!(!timeout.is_zero() && timeout <= Duration::from_secs(30),
            "proxy traffic timeout must be between zero and thirty seconds");
        ensure!(maximum_response_bytes > 0 && maximum_response_bytes <= 1024 * 1024,
            "proxy traffic response bound must be within one MiB");
        Ok(Self { timeout, maximum_response_bytes })
    }

    /// Conservative default bounds for a future explicit diagnostic probe.
    pub fn conservative() -> Self {
        Self { timeout: Duration::from_secs(5), maximum_response_bytes: 64 * 1024 }
    }
}

/// Evidence from a bounded, externally executed end-to-end proxy traffic probe.
///
/// This record intentionally does not execute traffic itself. The caller must use a verifier
/// that binds the request to the proxy process and activation generation; validation here
/// prevents incomplete or unbounded probe results from being promoted to readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTrafficObservation {
    pub activation_id: String,
    pub generation: u64,
    pub process: super::process::ProcessIdentity,
    pub destination: SocketAddr,
    pub completed: bool,
    pub elapsed: Duration,
    pub response_bytes: usize,
    pub expected_response_verified: bool,
}

/// An explicit, numeric-address HTTP target for a bounded probe through Xray's local HTTP proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectProbeTarget {
    pub destination: SocketAddr,
    pub host_header: String,
    pub path: String,
    pub expected_status: u16,
    /// Optional response marker. When non-empty it must occur in the HTTP response body.
    pub expected_body_marker: Vec<u8>,
}

impl HttpConnectProbeTarget {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.destination.ip().is_unspecified()
            && !self.destination.ip().is_multicast()
            && self.destination.port() != 0,
            "HTTP probe destination must be a concrete unicast endpoint");
        ensure!(!self.host_header.is_empty() && self.host_header.len() <= 253
            && self.host_header.bytes().all(|byte| byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')),
            "HTTP probe Host header contains invalid characters");
        ensure!(self.path.starts_with('/') && self.path.len() <= 2048
            && !self.path.bytes().any(|byte| byte.is_ascii_control() || byte == b' '),
            "HTTP probe path must be an absolute-path without control characters");
        ensure!((100..=599).contains(&self.expected_status),
            "HTTP probe expected status is outside the valid range");
        ensure!(self.expected_body_marker.len() <= 1024
            && !self.expected_body_marker.iter().any(|byte| *byte == b'\r' || *byte == b'\n'),
            "HTTP probe body marker exceeds its bound or contains line breaks");
        Ok(())
    }
}

/// Execute a bounded HTTP CONNECT request through the process-owned local proxy listener.
///
/// The destination is numeric to avoid resolving names outside the proxy. The expected Host
/// header remains caller-controlled and is validated against header injection. This returns
/// generation-bound evidence only after the local listener, CONNECT tunnel, HTTP status, and
/// optional body marker have all been checked.
#[cfg(target_os = "linux")]
pub fn probe_http_connect_traffic(
    process: &super::process::ProcessIdentity,
    listener: SocketAddr,
    target: &HttpConnectProbeTarget,
    activation_id: &str,
    generation: u64,
    timeout: Duration,
    maximum_response_bytes: usize,
) -> Result<ProxyTrafficObservation> {
    use std::{io::{Read, Write}, net::TcpStream, time::Instant};

    target.validate()?;
    ensure!(!activation_id.is_empty() && generation > 0,
        "HTTP probe activation identity is invalid");
    ensure!(!timeout.is_zero() && timeout <= Duration::from_secs(30),
        "HTTP CONNECT probe timeout must be between zero and thirty seconds");
    ensure!(maximum_response_bytes > 0 && maximum_response_bytes <= 1024 * 1024,
        "HTTP CONNECT response bound must be within one MiB");
    ensure!(process.verify()?, "managed core identity is not live before HTTP CONNECT probe");
    let started = Instant::now();
    probe_core_listener(process, listener, timeout.min(Duration::from_secs(5)))?;

    let mut stream = TcpStream::connect_timeout(&listener, timeout.min(Duration::from_secs(5)))
        .context("cannot connect to the managed core HTTP proxy listener")?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let authority = format!("{}:{}", target.destination.ip(), target.destination.port());
    let connect = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
        target.host_header
    );
    stream.write_all(connect.as_bytes()).context("cannot send bounded HTTP CONNECT request")?;
    let connect_headers = read_http_header_block(&mut stream, 16 * 1024)
        .context("cannot read HTTP CONNECT response headers")?;
    let connect_status = parse_http_status(&connect_headers)?;
    ensure!(connect_status == 200,
        "managed core proxy did not establish the requested HTTP CONNECT tunnel");

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        target.path, target.host_header
    );
    stream.write_all(request.as_bytes()).context("cannot send HTTP request through the proxy tunnel")?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let count = stream.read(&mut chunk).context("cannot read HTTP response through proxy tunnel")?;
        if count == 0 { break; }
        ensure!(response.len().saturating_add(count) <= maximum_response_bytes,
            "HTTP CONNECT probe response exceeded its configured bound");
        response.try_reserve(count).context("cannot reserve bounded HTTP probe response")?;
        response.extend_from_slice(&chunk[..count]);
    }
    let status = parse_http_status(&response)?;
    ensure!(status == target.expected_status,
        "HTTP CONNECT probe returned an unexpected HTTP status");
    let body = http_response_body(&response)?;
    ensure!(target.expected_body_marker.is_empty()
        || contains_bytes(body, &target.expected_body_marker),
        "HTTP CONNECT probe response did not contain its expected body marker");
    ensure!(process.verify()?, "managed core identity changed during HTTP CONNECT probe");

    Ok(ProxyTrafficObservation {
        activation_id: activation_id.to_owned(),
        generation,
        process: process.clone(),
        destination: target.destination,
        completed: true,
        elapsed: started.elapsed(),
        response_bytes: response.len(),
        expected_response_verified: true,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn probe_http_connect_traffic(
    _process: &(),
    _listener: SocketAddr,
    _target: &HttpConnectProbeTarget,
    _activation_id: &str,
    _generation: u64,
    _timeout: Duration,
    _maximum_response_bytes: usize,
) -> Result<ProxyTrafficObservation> {
    anyhow::bail!("HTTP CONNECT TUN traffic probing is supported only on Linux");
}

#[cfg(target_os = "linux")]
fn read_http_header_block(stream: &mut std::net::TcpStream, maximum: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while headers.len() < maximum {
        stream.read_exact(&mut byte).context("HTTP response ended before its header terminator")?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            return Ok(headers);
        }
    }
    anyhow::bail!("HTTP response headers exceeded their configured bound")
}

#[cfg(target_os = "linux")]
fn parse_http_status(response: &[u8]) -> Result<u16> {
    let line_end = response.windows(2).position(|window| window == b"\r\n")
        .context("HTTP response has no complete status line")?;
    let line = std::str::from_utf8(&response[..line_end])
        .context("HTTP response status line is not valid ASCII")?;
    let mut fields = line.split_ascii_whitespace();
    ensure!(matches!(fields.next(), Some("HTTP/1.0" | "HTTP/1.1")),
        "HTTP response uses an unsupported protocol version");
    let status = fields.next().context("HTTP response has no status code")?
        .parse::<u16>().context("HTTP response status code is invalid")?;
    ensure!((100..=599).contains(&status), "HTTP response status code is outside the valid range");
    Ok(status)
}

#[cfg(target_os = "linux")]
fn http_response_body(response: &[u8]) -> Result<&[u8]> {
    let offset = response.windows(4).position(|window| window == b"\r\n\r\n")
        .context("HTTP response has no complete header block")?;
    Ok(&response[offset + 4..])
}

#[cfg(target_os = "linux")]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

/// Validate bounded traffic-probe evidence against the activation identity and limits.
///
/// The API requires a non-zero generation, a concrete destination, positive bounded duration,
/// and response-size ceiling. It does not infer that traffic was proxied from metadata alone;
/// callers must set `expected_response_verified` only after the probe independently confirms
/// the expected response through the proxy path.
#[cfg(target_os = "linux")]
pub fn validate_proxy_traffic_observation(
    observation: &ProxyTrafficObservation,
    activation_id: &str,
    generation: u64,
    process: &super::process::ProcessIdentity,
    maximum_duration: Duration,
    maximum_response_bytes: usize,
) -> Result<()> {
    ensure!(!activation_id.is_empty(), "activation identity must not be empty");
    ensure!(generation > 0, "activation generation must be non-zero");
    ensure!(observation.activation_id == activation_id && observation.generation == generation,
        "traffic observation belongs to a different activation generation");
    ensure!(observation.process == *process && process.verify()?,
        "traffic observation process identity is mismatched or no longer live");
    ensure!(!observation.destination.ip().is_unspecified() && observation.destination.port() != 0,
        "traffic observation destination is invalid");
    ensure!(!maximum_duration.is_zero() && maximum_duration <= Duration::from_secs(30),
        "traffic observation duration bound must be within thirty seconds");
    ensure!(observation.completed && !observation.elapsed.is_zero() && observation.elapsed <= maximum_duration,
        "traffic probe did not complete within its duration bound");
    ensure!(maximum_response_bytes > 0 && maximum_response_bytes <= 1024 * 1024,
        "traffic response bound must be within one MiB");
    ensure!(observation.response_bytes <= maximum_response_bytes,
        "traffic probe exceeded its response size bound");
    ensure!(observation.expected_response_verified,
        "traffic probe did not independently verify its expected response");
    ensure!(process.verify()?, "managed core identity changed after traffic probe");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn validate_proxy_traffic_observation(
    _observation: &ProxyTrafficObservation,
    _activation_id: &str,
    _generation: u64,
    _process: &(),
    _maximum_duration: Duration,
    _maximum_response_bytes: usize,
) -> Result<()> {
    anyhow::bail!("managed proxy traffic observation validation is supported only on Linux");
}


/// Promote a validated traffic observation into complete readiness evidence.
///
/// This validates the observation's generation/process binding and then runs the common
/// readiness gate over the supplied evidence. The supplied evidence must already contain
/// all other independently collected signals.
#[cfg(target_os = "linux")]
pub fn verify_readiness_with_traffic_observation(
    expected: &ReadinessExpectation<'_>,
    evidence: &ReadinessEvidence,
    observation: &ProxyTrafficObservation,
    activation_id: &str,
    generation: u64,
    process: &super::process::ProcessIdentity,
    maximum_duration: Duration,
    maximum_response_bytes: usize,
) -> Result<()> {
    validate_proxy_traffic_observation(
        observation, activation_id, generation, process, maximum_duration, maximum_response_bytes,
    )?;
    ensure!(evidence.core_process_verified, "readiness process evidence is missing");
    ensure!(evidence.local_listener.is_some(), "readiness listener evidence is missing");
    let mut promoted = evidence.clone();
    promoted.proxied_traffic_verified = true;
    verify_readiness(expected, &promoted)
}

/// Complete preflight evidence plus the exact helper response needed by the final readiness gate.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPreflight {
    pub evidence: ReadinessEvidence,
    pub socket_mark_response: super::privilege_broker::SocketMarkBrokerResponse,
}

/// Collect all locally observable readiness evidence after a real proxy traffic probe.
///
/// This is deliberately separate from the traffic probe: the caller must first generate traffic
/// through the local listener so the core has an attributable outbound socket to inspect.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn collect_managed_preflight_with_response(
    runtime_directory: &std::path::Path,
    activation_id: &str,
    process: &super::process::ProcessIdentity,
    listener: SocketAddr,
    listener_timeout: Duration,
    plan: &super::route_policy::RoutingPolicyPlan,
    expected_peer: SocketAddr,
    transport: super::privilege_broker::BrokerSocketTransport,
    baseline_host: &super::NetworkStatus,
    current_host: &super::NetworkStatus,
) -> Result<ManagedPreflight> {
    ensure!(process.verify()?, "managed core identity is not live at preflight start");
    let listener = probe_core_listener(process, listener, listener_timeout)?;
    let interface = probe_tun_interface(&plan.interface_name, plan.interface_index)?;
    probe_routing_policy(plan)?;
    let egress = super::egress_probe::inspect_marked_egress(plan)?;
    ensure!(egress.mark == plan.core_mark && egress.mask == plan.core_mark_mask,
        "marked physical-egress evidence is bound to a different mark policy");
    let response = super::socket_mark_probe::observe_proxy_outbound_mark(
        runtime_directory, activation_id, process.clone(), expected_peer, transport,
        plan.core_mark, plan.core_mark_mask,
    ).context("cannot obtain live core outbound socket-mark evidence")?;
    ensure!(response.expected_peer == expected_peer && response.transport == transport,
        "socket-mark helper response does not match the requested outbound peer and transport");
    let mark = super::socket_mark_probe::observed_proxy_outbound_mark(
        &response, plan.core_mark, plan.core_mark_mask,
    )?;
    verify_host_network_unchanged(baseline_host, current_host)?;
    ensure!(process.verify()?, "managed core identity changed during preflight");
    Ok(ManagedPreflight {
        evidence: ReadinessEvidence {
            core_process_verified: true,
            local_listener: Some(listener),
            tun_interface: Some(interface),
            route_policy_verified: true,
            core_outbound_socket_mark: Some(mark),
            physical_egress_bypass_verified: true,
            proxied_traffic_verified: false,
            dns_unchanged: true,
            firewall_unchanged: true,
        },
        socket_mark_response: response,
    })
}

/// Collect independent read-only evidence for a managed activation preflight.
///
/// This composes process/listener, TUN identity, routing-policy, marked physical-egress,
/// socket-mark, and host DNS/firewall checks. End-to-end proxied traffic remains an explicit
/// external evidence requirement and is not inferred from these observations.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn collect_managed_preflight(
    runtime_directory: &std::path::Path,
    activation_id: &str,
    process: &super::process::ProcessIdentity,
    listener: SocketAddr,
    listener_timeout: Duration,
    plan: &super::route_policy::RoutingPolicyPlan,
    expected_peer: SocketAddr,
    transport: super::privilege_broker::BrokerSocketTransport,
    baseline_host: &super::NetworkStatus,
    current_host: &super::NetworkStatus,
) -> Result<ReadinessEvidence> {
    ensure!(process.verify()?, "managed core identity is not live at preflight start");
    let listener = probe_core_listener(process, listener, listener_timeout)?;
    let interface = probe_tun_interface(&plan.interface_name, plan.interface_index)?;
    probe_routing_policy(plan)?;
    let egress = super::egress_probe::inspect_marked_egress(plan)?;
    ensure!(egress.mark == plan.core_mark && egress.mask == plan.core_mark_mask,
        "marked physical-egress evidence is bound to a different mark policy");
    let mark = probe_core_outbound_socket_mark(
        runtime_directory, activation_id, process, expected_peer, transport,
        plan.core_mark, plan.core_mark_mask,
    )?;
    verify_host_network_unchanged(baseline_host, current_host)?;
    ensure!(process.verify()?, "managed core identity changed during preflight");
    Ok(ReadinessEvidence {
        core_process_verified: true,
        local_listener: Some(listener),
        tun_interface: Some(interface),
        route_policy_verified: true,
        core_outbound_socket_mark: Some(mark),
        physical_egress_bypass_verified: true,
        // This collection does not synthesize or initiate an application-level proxy test.
        proxied_traffic_verified: false,
        dns_unchanged: true,
        firewall_unchanged: true,
    })
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub fn collect_managed_preflight(
    _runtime_directory: &std::path::Path,
    _activation_id: &str,
    _process: &(),
    _listener: SocketAddr,
    _listener_timeout: Duration,
    _plan: &super::route_policy::RoutingPolicyPlan,
    _expected_peer: SocketAddr,
    _transport: (),
    _baseline_host: &super::NetworkStatus,
    _current_host: &super::NetworkStatus,
) -> Result<ReadinessEvidence> {
    anyhow::bail!("managed TUN preflight evidence collection is supported only on Linux");
}

/// Collect and validate live marked outbound-socket evidence for the managed core.
///
/// The dedicated helper performs read-only INET_DIAG collection. The process identity is
/// checked around the helper round trip, and the response must match the exact peer,
/// transport, mark, and mask requested by the activation manifest.
#[cfg(target_os = "linux")]
pub fn probe_core_outbound_socket_mark(
    runtime_directory: &std::path::Path,
    activation_id: &str,
    process: &super::process::ProcessIdentity,
    expected_peer: SocketAddr,
    transport: super::privilege_broker::BrokerSocketTransport,
    expected_mark: u32,
    mark_mask: u32,
) -> Result<u32> {
    ensure!(process.verify()?, "managed core identity changed before socket-mark probe");
    let response = super::socket_mark_probe::observe_proxy_outbound_mark(
        runtime_directory,
        activation_id,
        process.clone(),
        expected_peer,
        transport,
        expected_mark,
        mark_mask,
    )?;
    ensure!(process.verify()?, "managed core identity changed during socket-mark probe");
    ensure!(
        response.expected_peer == expected_peer && response.transport == transport,
        "socket-mark helper response does not match the requested outbound peer and transport"
    );
    super::socket_mark_probe::observed_proxy_outbound_mark(
        &response,
        expected_mark,
        mark_mask,
    )
}

#[cfg(not(target_os = "linux"))]
pub fn probe_core_outbound_socket_mark(
    _runtime_directory: &std::path::Path,
    _activation_id: &str,
    _process: &(),
    _expected_peer: SocketAddr,
    _transport: (),
    _expected_mark: u32,
    _mark_mask: u32,
) -> Result<u32> {
    anyhow::bail!("managed-core socket-mark probing is supported only on Linux");
}

/// Verify readiness using the actual broker response rather than a caller-supplied mark.
///
/// The remaining evidence fields must come from independent live probes. This function
/// binds the diagnostic result to the expected mark policy before invoking the common gate.
#[cfg(target_os = "linux")]
pub fn verify_readiness_with_socket_mark(
    expected: &ReadinessExpectation<'_>,
    evidence: &ReadinessEvidence,
    response: &super::privilege_broker::SocketMarkBrokerResponse,
    expected_peer: SocketAddr,
    expected_transport: super::privilege_broker::BrokerSocketTransport,
) -> Result<()> {
    ensure!(
        response.expected_peer == expected_peer && response.transport == expected_transport,
        "socket-mark response peer or transport does not match the readiness target"
    );
    let observed_mark = super::socket_mark_probe::observed_proxy_outbound_mark(
        response,
        expected.core_mark,
        expected.core_mark_mask,
    )?;
    let mut complete_evidence = evidence.clone();
    complete_evidence.core_outbound_socket_mark = Some(observed_mark);
    verify_readiness(expected, &complete_evidence)
}

/// Verify the manifest-bound TUN interface against a fresh sysfs and NETLINK_ROUTE snapshot.
///
/// Both inventories must agree before this returns evidence. A matching name alone is never
/// sufficient because Linux may reuse an interface name after the original link disappears.
#[cfg(target_os = "linux")]
pub fn probe_tun_interface(interface_name: &str, interface_index: u32) -> Result<InterfaceEvidence> {
    ensure!(
        !interface_name.is_empty()
            && interface_name.len() <= 15
            && interface_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            && interface_index > 0,
        "expected TUN interface identity is invalid"
    );
    let snapshot = super::kernel_inventory::inspect_snapshot()
        .context("cannot capture live interface identity for TUN readiness")?;
    let matches = snapshot.interfaces.iter()
        .filter(|interface| interface.name == interface_name)
        .collect::<Vec<_>>();
    ensure!(matches.len() == 1, "manifest-bound TUN interface is missing or ambiguous");
    let interface = matches[0];
    ensure!(
        interface.index == interface_index && interface.is_tun,
        "live interface name, ifindex, or link kind does not match the activation manifest"
    );
    Ok(InterfaceEvidence { name: interface.name.clone(), index: interface.index })
}

#[cfg(not(target_os = "linux"))]
pub fn probe_tun_interface(_interface_name: &str, _interface_index: u32) -> Result<InterfaceEvidence> {
    anyhow::bail!("live TUN interface probing is supported only on Linux");
}

/// Compare the live kernel routes and policy rules with the exact activation plan.
///
/// This is a read-only snapshot probe. It requires one matching default route and both
/// expected rules for each address family; ambiguous duplicates or missing attributes fail
/// closed. It does not prove that the core actually applies its socket mark or that traffic
/// traverses the proxy; those remain separate readiness checks.
#[cfg(target_os = "linux")]
pub fn probe_routing_policy(plan: &super::route_policy::RoutingPolicyPlan) -> Result<()> {
    use super::route_policy::{RulePurpose, RT_TABLE_MAIN};
    plan.validate()?;
    let snapshot = super::kernel_inventory::inspect_snapshot()
        .context("cannot capture live routing policy for TUN readiness")?;

    for family in [
        super::route_policy::AddressFamily::Ipv4,
        super::route_policy::AddressFamily::Ipv6,
    ] {
        let route_matches = snapshot.routes.iter().filter(|record| {
            if record.family != family || record.table_id != plan.table_id { return false; }
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&record.canonical_attributes) else { return false; };
            value.get("dst").and_then(serde_json::Value::as_str).map_or(true, |destination| destination == "default" || destination == family.default_prefix())
                && value.get("dev").and_then(serde_json::Value::as_str) == Some(plan.interface_name.as_str())
                && value.get("type").and_then(serde_json::Value::as_str).map_or(true, |kind| kind == "unicast")
        }).count();
        ensure!(route_matches == 1, "live {family:?} Proxyctl default route is missing, duplicated, or mismatched");

        for purpose in [RulePurpose::CoreTrafficBypass, RulePurpose::ProxyTraffic] {
            let expected = plan.rules.iter().find(|rule| rule.family == family && rule.purpose == purpose)
                .ok_or_else(|| anyhow::anyhow!("routing plan is missing a {family:?} {purpose:?} rule"))?;
            let matches = snapshot.rules.iter().filter(|record| {
                if record.family != family || record.priority != expected.priority || record.table_id != Some(expected.lookup_table) { return false; }
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&record.canonical_attributes) else { return false; };
                match expected.mark {
                    Some(mark) => parse_rule_mark(value.get("fwmark")) == Some((mark.value, mark.mask)),
                    None => value.get("fwmark").is_none(),
                }
            }).count();
            ensure!(matches == 1, "live {family:?} {purpose:?} policy rule is missing, duplicated, or mismatched");
            if purpose == RulePurpose::CoreTrafficBypass {
                ensure!(expected.lookup_table == RT_TABLE_MAIN, "core bypass rule does not use the main table");
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn probe_routing_policy(_plan: &super::route_policy::RoutingPolicyPlan) -> Result<()> {
    anyhow::bail!("live routing-policy probing is supported only on Linux");
}

fn parse_rule_mark(value: Option<&serde_json::Value>) -> Option<(u32, u32)> {
    let value = value?;
    if let Some(number) = value.as_u64().and_then(|number| u32::try_from(number).ok()) {
        return Some((number, u32::MAX));
    }
    let text = value.as_str()?;
    let (mark, mask) = text.split_once('/')?;
    let parse = |part: &str| {
        let part = part.strip_prefix("0x").unwrap_or(part);
        u32::from_str_radix(part, if text.contains("0x") { 16 } else { 10 }).ok()
    };
    Some((parse(mark)?, parse(mask)?))
}

pub fn verify_readiness(
    expected: &ReadinessExpectation<'_>,
    evidence: &ReadinessEvidence,
) -> Result<()> {
    ensure!(
        !expected.interface_name.is_empty()
            && expected.interface_name.len() <= 15
            && expected
                .interface_name
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.') })
            && expected.interface_index > 0,
        "expected TUN interface identity is invalid"
    );
    ensure!(
        evidence.core_process_verified,
        "TUN core process identity is not verified"
    );
    let listener = evidence
        .local_listener
        .ok_or_else(|| anyhow::anyhow!("TUN core local proxy listener is not ready"))?;
    ensure!(
        listener.ip().is_loopback() && listener.port() != 0,
        "TUN core proxy listener must use a non-zero port bound to loopback"
    );
    let interface = evidence
        .tun_interface
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("manifest-owned TUN interface is not present"))?;
    ensure!(
        interface.name == expected.interface_name
            && interface.index == expected.interface_index
            && interface.index > 0,
        "TUN interface identity does not match the activation manifest"
    );
    ensure!(
        evidence.route_policy_verified,
        "TUN routing policy does not match the activation plan"
    );
    ensure!(
        expected.core_mark != 0
            && expected.core_mark <= i32::MAX as u32
            && expected.core_mark_mask != 0
            && expected.core_mark & !expected.core_mark_mask == 0,
        "expected core socket mark or mask is invalid"
    );
    let observed_mark = evidence
        .core_outbound_socket_mark
        .ok_or_else(|| anyhow::anyhow!("core proxy outbound socket mark is not observed"))?;
    ensure!(
        observed_mark & expected.core_mark_mask == expected.core_mark,
        "observed core proxy outbound socket mark does not match the routing-policy selector"
    );
    ensure!(
        evidence.physical_egress_bypass_verified,
        "core physical-egress bypass is not verified"
    );
    ensure!(
        evidence.proxied_traffic_verified,
        "end-to-end proxied traffic probe failed"
    );
    ensure!(
        evidence.dns_unchanged,
        "TUN readiness probe detected DNS changes"
    );
    ensure!(
        evidence.firewall_unchanged,
        "TUN readiness probe detected firewall changes"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> ReadinessExpectation<'static> {
        ReadinessExpectation {
            interface_name: "tun-proxyctl",
            interface_index: 77,
            core_mark: 0x42,
            core_mark_mask: 0xff,
        }
    }

    fn healthy() -> ReadinessEvidence {
        ReadinessEvidence {
            core_process_verified: true,
            local_listener: Some("127.0.0.1:1080".parse().unwrap()),
            tun_interface: Some(InterfaceEvidence {
                name: "tun-proxyctl".into(),
                index: 77,
            }),
            route_policy_verified: true,
            core_outbound_socket_mark: Some(0x42),
            physical_egress_bypass_verified: true,
            proxied_traffic_verified: true,
            dns_unchanged: true,
            firewall_unchanged: true,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_tcp_ipv4_and_ipv6_endpoints() {
        assert_eq!(
            parse_proc_tcp_endpoint("0100007F:0438", false),
            Some(("127.0.0.1".parse().unwrap(), 1080))
        );
        assert_eq!(
            parse_proc_tcp_endpoint("00000000000000000000000001000000:0438", true),
            Some(("::1".parse().unwrap(), 1080))
        );
        assert_eq!(parse_proc_tcp_endpoint("bad:0438", false), None);
        assert_eq!(parse_proc_tcp_endpoint("0100007F:0438", true), None);
    }

    #[test]
    fn parses_kernel_rule_mark_and_mask_without_guessing() {
        assert_eq!(parse_rule_mark(Some(&serde_json::json!("0x42/0xff"))), Some((0x42, 0xff)));
        assert_eq!(parse_rule_mark(Some(&serde_json::json!("66/255"))), Some((66, 255)));
        assert_eq!(parse_rule_mark(Some(&serde_json::json!("0x42"))), None);
        assert_eq!(parse_rule_mark(Some(&serde_json::json!("invalid/0xff"))), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn readiness_can_only_accept_a_mark_from_a_valid_broker_response() {
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
                inode: 9,
                mark: 0x42,
            }],
        };
        let mut evidence = healthy();
        evidence.core_outbound_socket_mark = None;
        verify_readiness_with_socket_mark(
            &expected(),
            &evidence,
            &response,
            "198.51.100.8:443".parse().unwrap(),
            BrokerSocketTransport::Tcp,
        )
        .unwrap();
        assert!(
            verify_readiness_with_socket_mark(
                &expected(),
                &evidence,
                &response,
                "198.51.100.9:443".parse().unwrap(),
                BrokerSocketTransport::Tcp,
            )
            .is_err()
        );
        let mut empty = response;
        empty.records.clear();
        assert!(
            verify_readiness_with_socket_mark(
                &expected(),
                &evidence,
                &empty,
                "198.51.100.8:443".parse().unwrap(),
                BrokerSocketTransport::Tcp,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_expected_interface_identity_before_evaluating_evidence() {
        let mut expected = expected();
        expected.interface_name = "bad/name";
        assert!(verify_readiness(&expected, &healthy()).is_err());
        expected.interface_name = "tun-proxyctl";
        expected.interface_index = 0;
        assert!(verify_readiness(&expected, &healthy()).is_err());
    }

    #[test]
    fn accepts_only_complete_end_to_end_readiness_evidence() {
        verify_readiness(&expected(), &healthy()).unwrap();
    }

    #[test]
    fn process_and_listener_alone_are_not_dataplane_readiness() {
        let mut evidence = healthy();
        evidence.route_policy_verified = false;
        assert!(verify_readiness(&expected(), &evidence).is_err());
        evidence.route_policy_verified = true;
        evidence.physical_egress_bypass_verified = false;
        assert!(verify_readiness(&expected(), &evidence).is_err());
        evidence.physical_egress_bypass_verified = true;
        evidence.proxied_traffic_verified = false;
        assert!(verify_readiness(&expected(), &evidence).is_err());
    }

    #[test]
    fn requires_the_observed_proxy_outbound_mark_to_match_the_policy() {
        let mut evidence = healthy();
        evidence.core_outbound_socket_mark = None;
        assert!(verify_readiness(&expected(), &evidence).is_err());

        evidence.core_outbound_socket_mark = Some(0x41);
        assert!(verify_readiness(&expected(), &evidence).is_err());

        evidence.core_outbound_socket_mark = Some(0x142);
        evidence.physical_egress_bypass_verified = false;
        assert!(
            verify_readiness(&expected(), &evidence)
                .unwrap_err()
                .to_string()
                .contains("physical-egress")
        );
    }

    #[test]
    fn rejects_invalid_expected_core_mark_policy() {
        let mut expected = expected();
        expected.core_mark = 0;
        assert!(verify_readiness(&expected, &healthy()).is_err());
        expected.core_mark = 0x100;
        expected.core_mark_mask = 0xff;
        assert!(verify_readiness(&expected, &healthy()).is_err());
        expected.core_mark = 0x8000_0000;
        expected.core_mark_mask = u32::MAX;
        assert!(verify_readiness(&expected, &healthy()).is_err());
    }

    #[test]
    fn rejects_wildcard_and_non_loopback_proxy_listeners() {
        for address in [
            "0.0.0.0:1080",
            "192.0.2.10:1080",
            "[::]:1080",
            "127.0.0.1:0",
        ] {
            let mut evidence = healthy();
            evidence.local_listener = Some(address.parse().unwrap());
            assert!(
                verify_readiness(&expected(), &evidence).is_err(),
                "accepted non-loopback listener {address}"
            );
        }
        let mut evidence = healthy();
        evidence.local_listener = Some("[::1]:1080".parse().unwrap());
        verify_readiness(&expected(), &evidence).unwrap();
    }

    #[test]
    fn rejects_foreign_or_replaced_tun_interfaces() {
        for interface in [
            InterfaceEvidence {
                name: "tun-foreign".into(),
                index: 77,
            },
            InterfaceEvidence {
                name: "tun-proxyctl".into(),
                index: 78,
            },
        ] {
            let mut evidence = healthy();
            evidence.tun_interface = Some(interface);
            assert!(verify_readiness(&expected(), &evidence).is_err());
        }
    }

    #[test]
    fn rejects_missing_listener_interface_or_system_isolation() {
        let mut evidence = healthy();
        evidence.local_listener = None;
        assert!(verify_readiness(&expected(), &evidence).is_err());
        let mut evidence = healthy();
        evidence.tun_interface = None;
        assert!(verify_readiness(&expected(), &evidence).is_err());
        let mut evidence = healthy();
        evidence.dns_unchanged = false;
        assert!(verify_readiness(&expected(), &evidence).is_err());
        let mut evidence = healthy();
        evidence.firewall_unchanged = false;
        assert!(verify_readiness(&expected(), &evidence).is_err());
    }
}


/// Perform a bounded SOCKS5 CONNECT probe through the manifest-bound core listener.
/// This establishes a TCP tunnel to the explicit IP destination without DNS resolution,
/// credentials, host-network mutation, or application payload transmission.
#[cfg(target_os = "linux")]
pub fn probe_socks5_connect(
    process: &super::process::ProcessIdentity,
    listener: SocketAddr,
    destination: SocketAddr,
    timeout: Duration,
) -> Result<()> {
    use std::io::{Read, Write};
    ensure!(destination.port() != 0 && !destination.ip().is_unspecified(), "probe destination must be a concrete IP endpoint");
    ensure!(!destination.ip().is_loopback() && !destination.ip().is_multicast() && !destination.ip().is_link_local(), "probe destination must not be loopback, multicast, or link-local");
    ensure!(!timeout.is_zero() && timeout <= Duration::from_secs(5), "SOCKS5 probe timeout must be between zero and five seconds");
    probe_core_listener(process, listener, timeout)?;
    let mut stream = TcpStream::connect_timeout(&listener, timeout).context("could not connect to managed SOCKS5 listener")?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(&[0x05, 0x01, 0x00]).context("failed sending SOCKS5 greeting")?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).context("failed reading SOCKS5 greeting response")?;
    ensure!(greeting == [0x05, 0x00], "listener did not accept unauthenticated SOCKS5 probe");
    let mut request = vec![0x05, 0x01, 0x00];
    match destination.ip() {
        std::net::IpAddr::V4(ip) => { request.push(0x01); request.extend_from_slice(&ip.octets()); }
        std::net::IpAddr::V6(ip) => { request.push(0x04); request.extend_from_slice(&ip.octets()); }
    }
    request.extend_from_slice(&destination.port().to_be_bytes());
    stream.write_all(&request).context("failed sending SOCKS5 CONNECT request")?;
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).context("failed reading SOCKS5 CONNECT response")?;
    ensure!(response[0] == 0x05 && response[1] == 0x00 && response[2] == 0x00,
        "SOCKS5 CONNECT failed or returned an invalid protocol response");
    let tail_len = match response[3] { 0x01 => 6, 0x04 => 18, 0x03 => { let mut length=[0u8;1]; stream.read_exact(&mut length)?; usize::from(length[0])+2 }, _ => anyhow::bail!("SOCKS5 response contained an invalid address type") };
    let mut tail=vec![0u8;tail_len]; stream.read_exact(&mut tail).context("failed reading SOCKS5 bound address")?;
    ensure!(process.verify()?, "managed core process identity changed during SOCKS5 probe");
    verify_listener_process_ownership(process, listener)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn probe_socks5_connect(_process: &(), _listener: SocketAddr, _destination: SocketAddr, _timeout: Duration) -> Result<()> {
    anyhow::bail!("managed SOCKS5 probing is supported only on Linux");
}


/// Structured result from a SOCKS5 CONNECT-only diagnostic (no payload sent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5ConnectProbeResult {
    pub listener: SocketAddr,
    pub destination: SocketAddr,
    pub elapsed: Duration,
    /// Bytes exchanged for SOCKS negotiation and CONNECT response only.
    pub request_protocol_bytes: usize,
}

#[cfg(target_os = "linux")]
pub fn probe_socks5_connect_detailed(
    process: &super::process::ProcessIdentity,
    listener: SocketAddr,
    destination: SocketAddr,
    timeout: Duration,
) -> Result<Socks5ConnectProbeResult> {
    let started = std::time::Instant::now();
    probe_socks5_connect(process, listener, destination, timeout)?;
    let elapsed = started.elapsed();
    ensure!(elapsed <= timeout.saturating_mul(4), "SOCKS5 probe exceeded its aggregate time bound");
    Ok(Socks5ConnectProbeResult { listener, destination, elapsed, request_protocol_bytes: 3 + 3 + match destination.ip() { std::net::IpAddr::V4(_) => 4, std::net::IpAddr::V6(_) => 16 } + 2 })
}

#[cfg(not(target_os = "linux"))]
pub fn probe_socks5_connect_detailed(_process: &(), _listener: SocketAddr, _destination: SocketAddr, _timeout: Duration) -> Result<Socks5ConnectProbeResult> {
    anyhow::bail!("managed SOCKS5 probing is supported only on Linux");
}


#[cfg(all(test, target_os = "linux"))]
mod http_connect_probe_tests {
    use super::*;

    fn target() -> HttpConnectProbeTarget {
        HttpConnectProbeTarget {
            destination: "192.0.2.80:80".parse().unwrap(),
            host_header: "probe.example".into(),
            path: "/health".into(),
            expected_status: 200,
            expected_body_marker: b"proxyctl-ok".to_vec(),
        }
    }

    #[test]
    fn validates_explicit_numeric_http_probe_target() {
        assert!(target().validate().is_ok());
    }

    #[test]
    fn rejects_http_probe_header_and_request_injection() {
        let mut value = target();
        value.host_header = "probe.example\\r\\nX-Injected: yes".into();
        assert!(value.validate().is_err());
        value = target();
        value.path = "/health\\r\\nHost: attacker.example".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_unsafe_http_probe_destinations_and_unbounded_markers() {
        let mut value = target();
        value.destination = "0.0.0.0:80".parse().unwrap();
        assert!(value.validate().is_err());
        value = target();
        value.expected_body_marker = vec![b'x'; 1025];
        assert!(value.validate().is_err());
    }

    #[test]
    fn parses_http_status_and_body_without_accepting_malformed_responses() {
        let response = b"HTTP/1.1 200 OK\\r\\nContent-Length: 11\\r\\n\\r\\nproxyctl-ok";
        assert_eq!(parse_http_status(response).unwrap(), 200);
        assert_eq!(http_response_body(response).unwrap(), b"proxyctl-ok");
        assert!(contains_bytes(http_response_body(response).unwrap(), b"proxyctl"));
        assert!(parse_http_status(b"not-http\\r\\n").is_err());
        assert!(http_response_body(b"HTTP/1.1 200 OK\\r\\n").is_err());
    }

    #[test]
    fn parser_requires_complete_supported_status_line() {
        assert!(parse_http_status(b"HTTP/2 200 OK\\r\\n").is_err());
        assert!(parse_http_status(b"HTTP/1.1 700 Bad\\r\\n").is_err());
        assert!(parse_http_status(b"HTTP/1.1 nope Bad\\r\\n").is_err());
    }
}
