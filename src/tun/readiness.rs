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
}

pub fn verify_readiness(
    expected: &ReadinessExpectation<'_>,
    evidence: &ReadinessEvidence,
) -> Result<()> {
    ensure!(
        evidence.core_process_verified,
        "TUN core process identity is not verified"
    );
    ensure!(
        evidence.local_listener.is_some(),
        "TUN core local proxy listener is not ready"
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
        evidence.physical_egress_bypass_verified,
        "core physical-egress bypass is not verified"
    );
    ensure!(
        evidence.proxied_traffic_verified,
        "end-to-end proxied traffic probe failed"
    );
    ensure!(evidence.dns_unchanged, "TUN readiness probe detected DNS changes");
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
