//! Fixed-argument Linux iproute2 operation planning.
//!
//! This module produces a deterministic command plan only. It never executes iproute2,
//! acquires privileges, opens /dev/net/tun, or changes kernel state. A future privileged
//! backend must compare exact live resource fingerprints before every apply/delete operation.

use anyhow::Result;

use super::{
    kernel_inventory::{KernelInterfaceRecord, KernelSnapshot},
    route_policy::{
        AddressFamily, PlannedRoute, PlannedRule, RouteType, RoutingPolicyPlan, RulePurpose,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCommand {
    pub arguments: Vec<String>,
}

impl IpCommand {
    fn new(arguments: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            arguments: arguments.into_iter().map(Into::into).collect(),
        }
    }
}

/// Exact interface identity required by a future rtnetlink delete operation.
///
/// A name-only `ip link delete dev NAME` is deliberately not emitted: the name may
/// have been reused by another application after the manifest was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDeleteGuard {
    pub interface_name: String,
    pub interface_index: u32,
}

impl InterfaceDeleteGuard {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.interface_name.is_empty()
                && self.interface_name.len() <= 15
                && self.interface_name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                }),
            "invalid interface cleanup name"
        );
        anyhow::ensure!(
            self.interface_index > 0,
            "interface cleanup requires a non-zero ifindex"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupTarget {
    Rule(PlannedRule),
    Route(PlannedRoute),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelCommandPlan {
    pub apply: Vec<IpCommand>,
    /// Typed cleanup identities in reverse creation order. No destructive command
    /// strings are emitted; a privileged backend must compare full fingerprints first.
    pub cleanup: Vec<CleanupTarget>,
    /// Interface removal is separate and requires an atomic name+ifindex ownership check.
    pub interface_cleanup: InterfaceDeleteGuard,
}

impl KernelCommandPlan {
    /// Build a fixed-argument plan from a validated policy. Commands are not executed.
    pub fn from_policy(policy: &RoutingPolicyPlan, owner_uid: u32, owner_gid: u32) -> Result<Self> {
        policy.validate()?;
        let mut apply = vec![
            IpCommand::new(vec![
                "tuntap".into(),
                "add".into(),
                "dev".into(),
                policy.interface_name.clone(),
                "mode".into(),
                "tun".into(),
                "user".into(),
                owner_uid.to_string(),
                "group".into(),
                owner_gid.to_string(),
            ]),
            IpCommand::new(["link", "set", "dev", policy.interface_name.as_str(), "up"]),
        ];

        for route in &policy.routes {
            apply.push(route_add(route)?);
        }
        for rule in &policy.rules {
            apply.push(rule_add(rule));
        }

        let mut cleanup = Vec::with_capacity(policy.rules.len() + policy.routes.len());
        for rule in policy.rules.iter().rev() {
            cleanup.push(CleanupTarget::Rule(rule.clone()));
        }
        for route in policy.routes.iter().rev() {
            anyhow::ensure!(
                route.route_type == RouteType::Unicast,
                "only unicast routes may be planned"
            );
            cleanup.push(CleanupTarget::Route(route.clone()));
        }
        let interface_cleanup = InterfaceDeleteGuard {
            interface_name: policy.interface_name.clone(),
            interface_index: policy.interface_index,
        };
        interface_cleanup.validate()?;

        Ok(Self {
            apply,
            cleanup,
            interface_cleanup,
        })
    }
}

fn family_args(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::Ipv4 => "-4",
        AddressFamily::Ipv6 => "-6",
    }
}

fn route_add(route: &PlannedRoute) -> Result<IpCommand> {
    anyhow::ensure!(
        route.route_type == RouteType::Unicast,
        "only unicast routes may be planned"
    );
    Ok(IpCommand::new(vec![
        family_args(route.family).into(),
        "route".into(),
        "add".into(),
        route.destination.clone(),
        "dev".into(),
        route.interface_name.clone(),
        "table".into(),
        route.table_id.to_string(),
    ]))
}

/// Validate that a planned TUN interface name and the expected ifindex are both free
/// before creating the interface. Route/rule table and priority collisions are checked
/// against the same read-only snapshot. This is a preflight only; callers must re-inspect
/// after creation and verify the kernel-assigned identity before installing routes.
pub fn validate_interface_preflight(
    policy: &RoutingPolicyPlan,
    snapshot: &KernelSnapshot,
) -> Result<()> {
    policy.validate_against(&snapshot.inventory)?;
    anyhow::ensure!(
        !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.name == policy.interface_name),
        "TUN interface name is already present"
    );
    anyhow::ensure!(
        !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.index == policy.interface_index),
        "planned TUN interface index is already occupied"
    );
    Ok(())
}

/// Verify the interface identity assigned by the kernel before route installation.
/// Both name and ifindex must match exactly, and the interface must be a TUN device.
pub fn verify_created_interface(
    policy: &RoutingPolicyPlan,
    interfaces: &[KernelInterfaceRecord],
) -> Result<()> {
    policy.validate()?;
    let by_name = interfaces
        .iter()
        .filter(|interface| interface.name == policy.interface_name)
        .collect::<Vec<_>>();
    let by_index = interfaces
        .iter()
        .filter(|interface| interface.index == policy.interface_index)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        by_name.len() == 1 && by_index.len() == 1,
        "created TUN interface identity is missing, duplicated, or reused"
    );
    let interface = by_name[0];
    anyhow::ensure!(
        interface.index == policy.interface_index && interface.is_tun,
        "created interface does not match the expected TUN identity"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::route_policy::RoutingPolicyPlan;

    fn policy() -> RoutingPolicyPlan {
        RoutingPolicyPlan::new(42_420, 42_410, 42_420, 0x42, 0xff, "tun-proxyctl", 77)
    }

    fn snapshot(interfaces: Vec<KernelInterfaceRecord>) -> KernelSnapshot {
        KernelSnapshot {
            inventory: Default::default(),
            routes: Vec::new(),
            rules: Vec::new(),
            interfaces,
        }
    }

    #[test]
    fn preflight_refuses_existing_interface_name_or_index() {
        let policy = policy();
        let existing_name = snapshot(vec![KernelInterfaceRecord {
            name: "tun-proxyctl".into(),
            index: 90,
            is_tun: true,
        }]);
        assert!(validate_interface_preflight(&policy, &existing_name).is_err());

        let existing_index = snapshot(vec![KernelInterfaceRecord {
            name: "other0".into(),
            index: 77,
            is_tun: false,
        }]);
        assert!(validate_interface_preflight(&policy, &existing_index).is_err());
    }

    #[test]
    fn preflight_accepts_free_interface_and_policy_resources() {
        let policy = policy();
        let inventory = snapshot(vec![KernelInterfaceRecord {
            name: "wlan0".into(),
            index: 2,
            is_tun: false,
        }]);
        validate_interface_preflight(&policy, &inventory).unwrap();
    }

    #[test]
    fn created_interface_must_match_exact_name_index_and_tun_kind() {
        let policy = policy();
        verify_created_interface(
            &policy,
            &[KernelInterfaceRecord {
                name: "tun-proxyctl".into(),
                index: 77,
                is_tun: true,
            }],
        )
        .unwrap();

        for invalid in [
            vec![KernelInterfaceRecord {
                name: "tun-proxyctl".into(),
                index: 78,
                is_tun: true,
            }],
            vec![KernelInterfaceRecord {
                name: "tun-proxyctl".into(),
                index: 77,
                is_tun: false,
            }],
            vec![
                KernelInterfaceRecord {
                    name: "tun-proxyctl".into(),
                    index: 77,
                    is_tun: true,
                },
                KernelInterfaceRecord {
                    name: "other0".into(),
                    index: 77,
                    is_tun: false,
                },
            ],
        ] {
            assert!(verify_created_interface(&policy, &invalid).is_err());
        }
    }

    #[test]
    fn plans_dual_stack_tun_routes_and_marked_core_bypass_without_shell() {
        let plan = KernelCommandPlan::from_policy(&policy(), 1000, 1000).unwrap();
        assert_eq!(plan.apply.len(), 8);
        assert_eq!(
            plan.apply[0].arguments,
            [
                "tuntap",
                "add",
                "dev",
                "tun-proxyctl",
                "mode",
                "tun",
                "user",
                "1000",
                "group",
                "1000"
            ]
        );
        assert!(plan.apply.iter().all(|command| {
            !command
                .arguments
                .iter()
                .any(|arg| arg.contains(';') || arg.contains('|'))
        }));
        assert!(plan.apply.iter().any(|command| command.arguments
            == [
                "-4",
                "rule",
                "add",
                "priority",
                "42410",
                "fwmark",
                "0x42/0xff",
                "lookup",
                "254"
            ]));
        assert!(plan.apply.iter().any(|command| command.arguments
            == [
                "-6",
                "route",
                "add",
                "::/0",
                "dev",
                "tun-proxyctl",
                "table",
                "42420"
            ]));
    }

    #[test]
    fn cleanup_is_exact_reverse_order_of_resource_creation() {
        let plan = KernelCommandPlan::from_policy(&policy(), 1000, 1000).unwrap();
        // Cleanup is represented as typed identities, never destructive CLI strings.
        // The backend must compare each live fingerprint before removing it.
        assert_eq!(plan.apply.len(), 8);
        assert_eq!(plan.cleanup.len(), 6);
        assert!(plan.cleanup[..4]
            .iter()
            .all(|target| matches!(target, CleanupTarget::Rule(_))));
        assert!(plan.cleanup[4..]
            .iter()
            .all(|target| matches!(target, CleanupTarget::Route(_))));
        assert_eq!(
            plan.interface_cleanup,
            InterfaceDeleteGuard {
                interface_name: "tun-proxyctl".into(),
                interface_index: 77,
            }
        );
        plan.interface_cleanup.validate().unwrap();
        assert!(plan.cleanup.iter().all(|target| match target {
            CleanupTarget::Rule(rule) => rule.priority > 0,
            CleanupTarget::Route(route) => {
                route.interface_name == "tun-proxyctl" && route.interface_index == 77
            }
        }));
    }

    #[test]
    fn interface_cleanup_guard_rejects_missing_or_invalid_identity() {
        let mut guard = InterfaceDeleteGuard {
            interface_name: "tun-proxyctl".into(),
            interface_index: 77,
        };
        guard.validate().unwrap();
        guard.interface_index = 0;
        assert!(guard.validate().is_err());
        guard.interface_index = 77;
        guard.interface_name = "bad/name".into();
        assert!(guard.validate().is_err());
    }

    #[test]
    fn rejects_invalid_policy_before_producing_any_commands() {
        let mut invalid = policy();
        invalid.interface_name = "invalid/name".into();
        assert!(KernelCommandPlan::from_policy(&invalid, 1000, 1000).is_err());
    }
}
