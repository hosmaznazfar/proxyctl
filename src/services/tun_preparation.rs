//! Side-effect-limited preparation of a native TUN supervisor launch request.
//!
//! Resolves user-owned node state and validates/generates the config in the unprivileged
//! process. It deliberately does not acquire privileged runtime state or mutate networking.
use anyhow::{Context, ensure};
use std::net::ToSocketAddrs;

use crate::{
    cores::{CoreId, adapters, core_binary_path, managed_cores_path},
    database::{NodeDatabase, default_database_path},
    tun::launch_spec::{CoreKind, LaunchSpec, from_generated_config},
};

/// Resolve a stored node and construct a bounded supervisor request, without launching it.
pub fn prepare_launch_spec(
    node_id: u64,
    core: CoreId,
    port: u16,
    probe_url: &str,
    expected_status: u16,
) -> anyhow::Result<LaunchSpec> {
    ensure!(node_id != 0, "node ID must be non-zero");
    ensure!(port >= 1024, "listener port must be between 1024 and 65535");

    let db = NodeDatabase::open(default_database_path()?)?;
    let record = db
        .get_node(node_id)?
        .with_context(|| format!("node #{node_id} not found"))?;
    ensure!(
        !record.is_deleted(),
        "node #{node_id} is deleted; restore it first"
    );
    let node = record.node;
    drop(db);

    ensure!(
        matches!(core, CoreId::SingBox | CoreId::Mihomo),
        "the native persistent-device supervisor currently supports sing-box and Mihomo; Xray requires its separate descriptor-backed lifecycle"
    );
    ensure!(
        (200..=299).contains(&expected_status),
        "TUN readiness HTTP status must be within 200..=299"
    );

    let adapter = adapters::adapter(core);
    let compatibility = adapter.compatibility(&node);
    ensure!(
        compatibility.is_supported(),
        "selected core does not support this node: {}",
        compatibility
            .reason
            .as_deref()
            .unwrap_or("unsupported configuration")
    );

    let managed_root = managed_cores_path()?;
    let executable = core_binary_path(core)?;
    ensure!(
        executable.is_file(),
        "selected core is not installed by Proxyctl; run setup for the selected core"
    );
    let executable = std::fs::canonicalize(executable)?;
    let canonical_managed_root = std::fs::canonicalize(&managed_root)?;
    ensure!(
        executable.starts_with(canonical_managed_root),
        "refusing to validate a core outside Proxyctl's managed-core directory"
    );

    let activation_id = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .context("cannot obtain a kernel-generated activation UUID")?
        .trim()
        .to_ascii_lowercase();
    let (mark, mask) = crate::tun::route_policy::mark_for_activation_id(&activation_id)?;
    let outbound_mark = adapters::TunOutboundMark::new(mark, mask)?;
    ensure!(
        adapter.tun_attachment_mode() != adapters::TunAttachmentMode::Unsupported,
        "selected core does not expose a supported TUN attachment contract"
    );
    let generated = adapter
        .generate_tun_activation_config(&node, port, outbound_mark)
        .with_context(|| format!("could not generate {core} TUN configuration"))?;
    adapters::validation::validate_generated_config(core, &generated, &executable)
        .with_context(|| format!("{core} rejected the prepared TUN configuration"))?;

    let expected_peers = (node.server.as_str(), node.port)
        .to_socket_addrs()
        .context("cannot resolve the selected proxy node endpoint before privilege escalation")?
        .filter(|peer| !peer.ip().is_unspecified() && !peer.ip().is_multicast())
        .take(8)
        .collect::<Vec<_>>();
    ensure!(
        !expected_peers.is_empty(),
        "selected node did not resolve to a usable endpoint"
    );

    let probe = url::Url::parse(probe_url).context("TUN readiness probe URL is invalid")?;
    ensure!(
        probe.scheme() == "http"
            && probe.username().is_empty()
            && probe.password().is_none()
            && probe.query().is_none()
            && probe.fragment().is_none(),
        "TUN readiness probe must be a plain HTTP URL without credentials, query, or fragment"
    );
    let probe_host = probe.host().context("TUN readiness probe URL has no host")?;
    let probe_port = probe
        .port_or_known_default()
        .context("TUN readiness probe URL has no usable port")?;
    let probe_addresses = match probe_host {
        url::Host::Ipv4(address) => vec![std::net::SocketAddr::from((address, probe_port))],
        url::Host::Ipv6(address) => vec![std::net::SocketAddr::from((address, probe_port))],
        url::Host::Domain(domain) => (domain, probe_port)
            .to_socket_addrs()
            .context("cannot resolve TUN readiness endpoint before privilege escalation")?
            .take(16)
            .collect::<Vec<_>>,
    };
    let traffic_targets =
        build_dual_stack_probe_targets(&probe, probe_addresses, expected_status)?;
    let generation = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    )
    .context("system clock produced an unsupported TUN generation")?;

    let kind = match core {
        CoreId::SingBox => CoreKind::SingBox,
        CoreId::Xray => CoreKind::Xray,
        CoreId::Mihomo => CoreKind::Mihomo,
    };
    from_generated_config(
        node_id,
        kind,
        port,
        activation_id,
        managed_root,
        &generated.content,
        generation,
        expected_peers,
        traffic_targets,
    )
}

fn build_dual_stack_probe_targets(
    probe: &url::Url,
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
    expected_status: u16,
) -> anyhow::Result<Vec<crate::tun::readiness::HttpProbeTarget>> {
    let host_header = probe
        .host_str()
        .context("TUN readiness URL has no host")?
        .to_owned();
    let path = if probe.path().is_empty() {
        "/".to_owned()
    } else {
        probe.path().to_owned()
    };
    let mut ipv4 = None;
    let mut ipv6 = None;
    for address in addresses {
        let ip = address.ip();
        let link_local = match ip {
            std::net::IpAddr::V4(ip) => ip.is_link_local(),
            std::net::IpAddr::V6(ip) => ip.is_unicast_link_local(),
        };
        if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() || link_local {
            continue;
        }
        if address.is_ipv4() && ipv4.is_none() {
            ipv4 = Some(address);
        } else if address.is_ipv6() && ipv6.is_none() {
            ipv6 = Some(address);
        }
    }
    let targets = vec![
        crate::tun::readiness::HttpProbeTarget {
            destination: ipv4.context("TUN readiness endpoint must resolve to IPv4")?,
            host_header: host_header.clone(),
            path: path.clone(),
            expected_status,
        },
        crate::tun::readiness::HttpProbeTarget {
            destination: ipv6.context("TUN readiness endpoint must resolve to IPv6")?,
            host_header,
            path,
            expected_status,
        },
    ];
    crate::tun::readiness::validate_dual_stack_probe_targets(&targets)?;
    Ok(targets)
}
