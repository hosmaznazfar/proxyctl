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
    Ok(listener)
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
