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

/// An explicit, numeric-address HTTP target for a bounded application probe through the host TUN route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpProbeTarget {
    pub destination: SocketAddr,
    pub host_header: String,
    pub path: String,
    pub expected_status: u16,
}

impl HttpProbeTarget {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.destination.ip().is_unspecified()
            && !self.destination.ip().is_multicast()
            && !self.destination.ip().is_loopback()
            && !self.destination.ip().is_link_local()
            && self.destination.port() != 0,
            "HTTP probe destination must be a concrete non-local unicast endpoint");
        ensure!(!self.host_header.is_empty() && self.host_header.len() <= 253
            && self.host_header.bytes().all(|byte| byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')),
            "HTTP probe Host header contains invalid characters");
        ensure!(self.path.starts_with('/') && self.path.len() <= 2048
            && !self.path.bytes().any(|byte| byte.is_ascii_control() || byte == b' '),
            "HTTP probe path must be an absolute-path without control characters");
        ensure!((200..=599).contains(&self.expected_status),
            "HTTP probe expected status must be a final 2xx–5xx response");
        Ok(())
    }
}

/// Ask the kernel how an unmarked application packet to this destination will route.
#[cfg(target_os = "linux")]
pub fn probe_unmarked_route_to_tun(
    plan: &super::route_policy::RoutingPolicyPlan,
    destination: std::net::IpAddr,
) -> Result<()> {
    plan.validate()?;
    ensure!(!destination.is_unspecified() && !destination.is_multicast()
        && !destination.is_loopback() && !destination.is_link_local(),
        "TUN route probe destination must be a concrete non-local unicast address");
    let family = if destination.is_ipv4() { "-4" } else { "-6" };
    let destination = destination.to_string();
    let output = super::kernel_inventory::run_ip(&[
        "-j", family, "route", "get", &destination, "mark", "0",
    ]).context("cannot query the kernel route for an unmarked application flow")?;
    let value: serde_json::Value = serde_json::from_slice(&output)
        .context("kernel returned invalid JSON for the unmarked route lookup")?;
    let records = value.as_array().context("unmarked route lookup did not return an array")?;
    ensure!(records.len() == 1, "unmarked route lookup is missing or ambiguous");
    validate_unmarked_route_record(&records[0], plan)
}

#[cfg(not(target_os = "linux"))]
pub fn probe_unmarked_route_to_tun(
    _plan: &super::route_policy::RoutingPolicyPlan,
    _destination: std::net::IpAddr,
) -> Result<()> {
    anyhow::bail!("unmarked TUN route probing is supported only on Linux");
}

#[cfg(target_os = "linux")]
fn validate_unmarked_route_record(
    record: &serde_json::Value,
    plan: &super::route_policy::RoutingPolicyPlan,
) -> Result<()> {
    ensure!(record.get("dev").and_then(serde_json::Value::as_str)
        == Some(plan.interface_name.as_str()),
        "kernel would not route the unmarked application flow through the owned TUN interface");
    let table = record.get("table").and_then(|value| {
        value.as_u64().or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
    });
    ensure!(table == Some(u64::from(plan.table_id)),
        "kernel selected a different routing table for the unmarked application flow");
    Ok(())
}

/// A verified TUN-routed HTTP response whose TCP stream remains open while socket marks are inspected.
pub struct TunTrafficProbe {
    pub observation: ProxyTrafficObservation,
    _stream: TcpStream,
}

/// Send a direct application HTTP request through the host's unmarked TUN route.
#[cfg(target_os = "linux")]
pub fn probe_tun_routed_http_traffic(
    process: &super::process::ProcessIdentity,
    target: &HttpProbeTarget,
    activation_id: &str,
    generation: u64,
    timeout: Duration,
    maximum_response_bytes: usize,
) -> Result<TunTrafficProbe> {
    use std::{io::Write, net::TcpStream, time::Instant};

    target.validate()?;
    ensure!(!activation_id.is_empty() && generation > 0,
        "TUN HTTP probe activation identity is invalid");
    ensure!(!timeout.is_zero() && timeout <= Duration::from_secs(30),
        "TUN HTTP probe timeout must be between zero and thirty seconds");
    ensure!(maximum_response_bytes > 0 && maximum_response_bytes <= 16 * 1024,
        "TUN HTTP response-header bound must be within sixteen KiB");
    ensure!(process.verify()?, "managed core identity is not live before TUN traffic probe");
    let started = Instant::now();
    let deadline = started + timeout;
    let connect_timeout = timeout.min(Duration::from_secs(5));
    let mut stream = TcpStream::connect_timeout(&target.destination, connect_timeout)
        .context("cannot establish the direct application TCP flow through the TUN route")?;
    ensure!(stream.peer_addr()? == target.destination,
        "direct TUN probe connected to a different destination endpoint");
    let remaining = deadline.saturating_duration_since(Instant::now());
    ensure!(!remaining.is_zero(), "TUN HTTP probe deadline expired during TCP connection");
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))?;
    let authority = if target.destination.port() == 80 {
        target.host_header.clone()
    } else {
        format!("{}:{}", target.host_header, target.destination.port())
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
        target.path, authority
    );
    stream.write_all(request.as_bytes())
        .context("cannot send HTTP request through the host TUN route")?;
    let response_headers = read_http_header_block(&mut stream, maximum_response_bytes, deadline)
        .context("cannot read HTTP response headers from the TUN-routed application flow")?;
    let status = parse_http_status(&response_headers)?;
    ensure!(status == target.expected_status,
        "TUN-routed HTTP probe returned an unexpected status");
    ensure!(http_response_allows_keepalive(&response_headers)?,
        "TUN readiness endpoint requested connection closure before outbound socket-mark inspection");
    ensure!(Instant::now() <= deadline, "TUN HTTP probe exceeded its aggregate deadline");
    ensure!(process.verify()?, "managed core identity changed during TUN traffic probe");
    Ok(TunTrafficProbe {
        observation: ProxyTrafficObservation {
            activation_id: activation_id.to_owned(),
            generation,
            process: process.clone(),
            destination: target.destination,
            completed: true,
            elapsed: started.elapsed(),
            response_bytes: response_headers.len(),
            expected_response_verified: true,
        },
        _stream: stream,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn probe_tun_routed_http_traffic(
    _process: &(),
    _target: &HttpProbeTarget,
    _activation_id: &str,
    _generation: u64,
    _timeout: Duration,
    _maximum_response_bytes: usize,
) -> Result<TunTrafficProbe> {
    anyhow::bail!("direct TUN-routed HTTP probing is supported only on Linux");
}

#[cfg(target_os = "linux")]
fn read_http_header_block(
    stream: &mut TcpStream,
    maximum: usize,
    deadline: std::time::Instant,
) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while headers.len() < maximum {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        ensure!(!remaining.is_zero(), "HTTP response headers exceeded the TUN probe deadline");
        stream.set_read_timeout(Some(remaining))?;
        stream.read_exact(&mut byte).context("HTTP response ended before its header terminator")?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            return Ok(headers);
        }
    }
    anyhow::bail!("HTTP response headers exceeded their configured bound")
}

#[cfg(target_os = "linux")]
fn http_response_allows_keepalive(response: &[u8]) -> Result<bool> {
    let end = response.windows(4).position(|window| window == b"\r\n\r\n")
        .context("HTTP response has no complete header block")?;
    let headers = std::str::from_utf8(&response[..end])
        .context("HTTP response headers are not valid ASCII")?;
    Ok(!headers.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("connection")
                && value.split(',').any(|token| token.trim().eq_ignore_ascii_case("close"))
        })
    }))
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

/// Validate bounded traffic-probe evidence against the activation identity and limits.
///
/// The API requires a non-zero generation, a concrete destination, bounded duration,
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
    ensure!(observation.completed && observation.elapsed <= maximum_duration,
        "traffic probe did not complete within its duration bound");
    ensure!(maximum_response_bytes > 0 && maximum_response_bytes <= 1024 * 1024,
        "traffic response bound must be within one MiB");
    ensure!(observation.response_bytes > 0 && observation.response_bytes <= maximum_response_bytes,
        "traffic probe response size is empty or exceeded its configured bound");
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
    expected_peers: &[SocketAddr],
    transport: super::privilege_broker::BrokerSocketTransport,
    baseline_host: &super::NetworkStatus,
    current_host: &super::NetworkStatus,
) -> Result<ManagedPreflight> {
    ensure!(process.verify()?, "managed core identity is not live at preflight start");
    ensure!(!expected_peers.is_empty() && expected_peers.len() <= 8,
        "Xray outbound peer candidate list must contain one to eight addresses");
    let listener = probe_core_listener(process, listener, listener_timeout)?;
    let interface = probe_tun_interface(&plan.interface_name, plan.interface_index)?;
    probe_routing_policy(plan)?;
    let egress = super::egress_probe::inspect_marked_egress(plan)?;
    ensure!(egress.mark == plan.core_mark && egress.mask == plan.core_mark_mask,
        "marked physical-egress evidence is bound to a different mark policy");

    let mut matched = None;
    let mut last_error = None;
    for peer in expected_peers {
        if peer.ip().is_unspecified() || peer.ip().is_multicast() || peer.port() == 0 {
            last_error = Some(anyhow::anyhow!("Xray outbound peer candidate is not a valid unicast endpoint"));
            continue;
        }
        match super::socket_mark_probe::observe_proxy_outbound_mark(
            runtime_directory, activation_id, process.clone(), *peer, transport,
            plan.core_mark, plan.core_mark_mask,
        ) {
            Ok(response) if response.expected_peer == *peer && response.transport == transport => {
                match super::socket_mark_probe::observed_proxy_outbound_mark(
                    &response, plan.core_mark, plan.core_mark_mask,
                ) {
                    Ok(mark) => { matched = Some((response, mark)); break; }
                    Err(error) => last_error = Some(error),
                }
            }
            Ok(_) => last_error = Some(anyhow::anyhow!(
                "socket-mark helper response did not match the requested Xray peer and transport"
            )),
            Err(error) => last_error = Some(error),
        }
    }
    let (response, mark) = matched.ok_or_else(|| last_error.unwrap_or_else(||
        anyhow::anyhow!("no Xray outbound socket matched any resolved node address")))?;
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
    Ok(collect_managed_preflight_with_response(
        runtime_directory, activation_id, process, listener, listener_timeout, plan,
        &[expected_peer], transport, baseline_host, current_host,
    )?.evidence)
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

/// Verify the interface address and MTU contract emitted by the Xray TUN adapter.
#[cfg(target_os = "linux")]
pub fn probe_xray_tun_addressing(interface_name: &str, interface_index: u32) -> Result<()> {
    ensure!(!interface_name.is_empty() && interface_name.len() <= 15 && interface_index > 0,
        "Xray TUN interface identity is invalid");
    let output = super::kernel_inventory::run_ip(&[
        "-j", "address", "show", "dev", interface_name,
    ]).context("cannot inspect Xray TUN interface addresses")?;
    let value: serde_json::Value = serde_json::from_slice(&output)
        .context("kernel returned invalid JSON for Xray TUN address inspection")?;
    let records = value.as_array().context("Xray TUN address inspection did not return an array")?;
    ensure!(records.len() == 1, "Xray TUN address record is missing or ambiguous");
    validate_xray_tun_address_record(&records[0], interface_name, interface_index)
}

#[cfg(not(target_os = "linux"))]
pub fn probe_xray_tun_addressing(_interface_name: &str, _interface_index: u32) -> Result<()> {
    anyhow::bail!("Xray TUN address verification is supported only on Linux");
}

#[cfg(target_os = "linux")]
fn validate_xray_tun_address_record(
    record: &serde_json::Value,
    interface_name: &str,
    interface_index: u32,
) -> Result<()> {
    ensure!(record.get("ifname").and_then(serde_json::Value::as_str) == Some(interface_name)
        && record.get("ifindex").and_then(serde_json::Value::as_u64) == Some(u64::from(interface_index)),
        "Xray TUN address record does not match the manifest-bound interface identity");
    ensure!(record.get("mtu").and_then(serde_json::Value::as_u64) == Some(1500),
        "Xray TUN interface MTU differs from the generated adapter contract");
    ensure!(record.get("flags").and_then(serde_json::Value::as_array)
        .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UP"))),
        "Xray TUN interface is not administratively up");
    let addresses = record.get("addr_info").and_then(serde_json::Value::as_array)
        .context("Xray TUN interface has no address inventory")?;
    let ipv4 = addresses.iter().any(|address| {
        address.get("family").and_then(serde_json::Value::as_str) == Some("inet")
            && address.get("local").and_then(serde_json::Value::as_str) == Some("198.18.0.1")
            && address.get("prefixlen").and_then(serde_json::Value::as_u64) == Some(30)
    });
    let ipv6 = addresses.iter().any(|address| {
        address.get("family").and_then(serde_json::Value::as_str) == Some("inet6")
            && address.get("local").and_then(serde_json::Value::as_str) == Some("fdfe:dcba:9876::1")
            && address.get("prefixlen").and_then(serde_json::Value::as_u64) == Some(126)
    });
    ensure!(ipv4 && ipv6,
        "Xray TUN interface is missing one or more configured dual-stack gateway addresses");
    Ok(())
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
mod http_tun_probe_tests {
    #[test]
    fn validates_xray_tun_link_mtu_and_dual_stack_gateway_addresses() {
        let record = serde_json::json!({
            "ifname": "tun-proxyctl",
            "ifindex": 42,
            "mtu": 1500,
            "flags": ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"],
            "addr_info": [
                {"family":"inet","local":"198.18.0.1","prefixlen":30},
                {"family":"inet6","local":"fdfe:dcba:9876::1","prefixlen":126}
            ]
        });
        assert!(super::validate_xray_tun_address_record(&record, "tun-proxyctl", 42).is_ok());
        assert!(super::validate_xray_tun_address_record(&record, "tun-proxyctl", 43).is_err());
        let mut wrong_mtu = record.clone();
        wrong_mtu["mtu"] = serde_json::json!(9000);
        assert!(super::validate_xray_tun_address_record(&wrong_mtu, "tun-proxyctl", 42).is_err());
        let mut missing_ipv6 = record.clone();
        missing_ipv6["addr_info"].as_array_mut().unwrap().pop();
        assert!(super::validate_xray_tun_address_record(&missing_ipv6, "tun-proxyctl", 42).is_err());
    }

    #[test]
    fn validates_the_exact_unmarked_kernel_route_result() {
        let plan = super::super::route_policy::RoutingPolicyPlan::new(
            10001, 10002, 10003, 0x4123_4567, 0x7fff_ffff, "tun-proxyctl", 42,
        );
        let accepted: serde_json::Value = serde_json::json!({
            "dev": "tun-proxyctl",
            "table": 10001
        });
        assert!(super::validate_unmarked_route_record(&accepted, &plan).is_ok());
        let wrong_device = serde_json::json!({"dev":"eth0","table":10001});
        assert!(super::validate_unmarked_route_record(&wrong_device, &plan).is_err());
        let wrong_table = serde_json::json!({"dev":"tun-proxyctl","table":254});
        assert!(super::validate_unmarked_route_record(&wrong_table, &plan).is_err());
        let incomplete = serde_json::json!({"dev":"tun-proxyctl"});
        assert!(super::validate_unmarked_route_record(&incomplete, &plan).is_err());
    }

    use super::*;

    fn target() -> HttpProbeTarget {
        HttpProbeTarget {
            destination: "192.0.2.80:80".parse().unwrap(),
            host_header: "probe.example".into(),
            path: "/health".into(),
            expected_status: 200,
        }
    }

    #[test]
    fn validates_explicit_numeric_http_probe_target() {
        assert!(target().validate().is_ok());
    }

    #[test]
    fn rejects_http_probe_header_and_request_injection() {
        let mut value = target();
        value.host_header = "probe.example\r\nX-Injected: yes".into();
        assert!(value.validate().is_err());
        value = target();
        value.path = "/health\r\nHost: attacker.example".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn rejects_unsafe_http_probe_destinations_and_unbounded_markers() {
        let mut value = target();
        value.destination = "0.0.0.0:80".parse().unwrap();
        assert!(value.validate().is_err());
        value = target();
    }

    #[test]
    fn parses_http_status_and_body_without_accepting_malformed_responses() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n";
        assert_eq!(parse_http_status(response).unwrap(), 200);
        assert!(parse_http_status(b"not-http\r\n").is_err());
    }

    #[test]
    fn persistent_readiness_response_rejects_connection_close() {
        assert!(super::http_response_allows_keepalive(
            b"HTTP/1.1 204 No Content\r\n\r\n"
        ).unwrap());
        assert!(!super::http_response_allows_keepalive(
            b"HTTP/1.1 204 No Content\r\nConnection: keep-alive, close\r\n\r\n"
        ).unwrap());
    }

    #[test]
    fn parser_requires_complete_supported_status_line() {
        assert!(parse_http_status(b"HTTP/2 200 OK\r\n").is_err());
        assert!(parse_http_status(b"HTTP/1.1 700 Bad\r\n").is_err());
        assert!(parse_http_status(b"HTTP/1.1 nope Bad\r\n").is_err());
    }
}
