//! Fail-closed evidence model for TUN dataplane readiness.
//!
//! This module evaluates probe results supplied by a future Linux probe backend. It performs
//! no socket, route, interface, DNS, firewall, or process operation itself.

use anyhow::{Result, ensure};
use std::net::SocketAddr;

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

pub fn verify_readiness(
    expected: &ReadinessExpectation<'_>,
    evidence: &ReadinessEvidence,
) -> Result<()> {
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
