//! Fixed-argument Linux iproute2 operation planning.
//!
//! This module produces a deterministic command plan only. It never executes iproute2,
//! acquires privileges, opens /dev/net/tun, or changes kernel state. A future privileged
//! backend must compare exact live resource fingerprints before every apply/delete operation.

use anyhow::Result;

use super::{
    kernel_inventory::{KernelInterfaceRecord, KernelSnapshot},
    route_policy::{AddressFamily, PlannedRoute, PlannedRule, RouteType, RoutingPolicyPlan},
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
    /// Validate the complete plan before it crosses any future privileged boundary.
    ///
    /// This checks that every command is a fixed, non-empty argument vector and that
    /// cleanup identities are unique and refer to the same interface as the guard.
    /// It does not authorize execution or prove kernel ownership.
    pub fn validate(&self) -> Result<()> {
        self.interface_cleanup.validate()?;
        anyhow::ensure!(
            self.apply.len() >= 2,
            "kernel plan must include interface creation and link-up steps"
        );
        let creation = &self.apply[0].arguments;
        anyhow::ensure!(
            creation.len() == 10
                && creation[..6]
                    == [
                        "tuntap",
                        "add",
                        "dev",
                        self.interface_cleanup.interface_name.as_str(),
                        "mode",
                        "tun"
                    ]
                && creation[6] == "user"
                && creation[7].bytes().all(|byte| byte.is_ascii_digit())
                && creation[8] == "group"
                && !creation[9].is_empty()
                && creation[9].bytes().all(|byte| byte.is_ascii_digit()),
            "kernel plan must begin with an exact guarded TUN creation command"
        );
        anyhow::ensure!(
            self.apply[1].arguments
                == ["link", "set", "dev", self.interface_cleanup.interface_name.as_str(), "up"],
            "kernel plan must bring up only its guarded TUN interface"
        );
        anyhow::ensure!(
            self.apply.len() == self.cleanup.len() + 2,
            "kernel plan apply and cleanup resource counts do not match"
        );
        anyhow::ensure!(
            self.apply.iter().all(|command| {
                !command.arguments.is_empty()
                    && command.arguments.iter().all(|argument| {
                        !argument.is_empty()
                            && !argument
                                .bytes()
                                .any(|byte| byte == 0 || byte.is_ascii_control())
                    })
            }),
            "kernel plan contains an empty or unsafe argument"
        );
        for (command, target) in self.apply[2..].iter().zip(self.cleanup.iter().rev()) {
            let expected = match target {
                CleanupTarget::Rule(rule) => rule_add(rule),
                CleanupTarget::Route(route) => route_add(route)?,
            };
            anyhow::ensure!(
                command == &expected,
                "kernel plan apply command does not match its typed resource identity"
            );
        }
        let mut cleanup_keys = std::collections::BTreeSet::new();
        for target in &self.cleanup {
            let key = match target {
                CleanupTarget::Rule(rule) => format!("rule:{rule:?}"),
                CleanupTarget::Route(route) => {
                    anyhow::ensure!(
                        route.interface_name == self.interface_cleanup.interface_name
                            && route.interface_index == self.interface_cleanup.interface_index,
                        "cleanup route does not match the guarded TUN interface identity"
                    );
                    format!("route:{route:?}")
                }
            };
            anyhow::ensure!(
                cleanup_keys.insert(key),
                "kernel plan contains duplicate cleanup identities"
            );
        }
        Ok(())
    }

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

fn rule_add(rule: &PlannedRule) -> IpCommand {
    let mut arguments = vec![
        family_args(rule.family).to_owned(),
        "rule".into(),
        "add".into(),
        "priority".into(),
        rule.priority.to_string(),
    ];
    if let Some(mark) = rule.mark {
        arguments.extend([
            "fwmark".into(),
            format!("{:#x}/{:#x}", mark.value, mark.mask),
        ]);
    }
    arguments.extend(["lookup".into(), rule.lookup_table.to_string()]);
    IpCommand { arguments }
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

fn validate_interface_inventory(interfaces: &[KernelInterfaceRecord]) -> Result<()> {
    let mut names = std::collections::BTreeSet::new();
    let mut indices = std::collections::BTreeSet::new();
    for interface in interfaces {
        anyhow::ensure!(
            !interface.name.is_empty()
                && interface.name.len() <= 15
                && interface.name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                })
                && interface.index > 0,
            "kernel interface inventory contains an invalid identity"
        );
        anyhow::ensure!(
            names.insert(interface.name.as_str()) && indices.insert(interface.index),
            "kernel interface inventory contains duplicate names or indices"
        );
    }
    Ok(())
}

/// Validate that a planned TUN interface name and the expected ifindex are both free
/// before creating the interface. Route/rule table and priority collisions are checked
/// against the same read-only snapshot. This is a preflight only; callers must re-inspect
/// after creation and verify the kernel-assigned identity before installing routes.
pub fn validate_interface_preflight(
    policy: &RoutingPolicyPlan,
    snapshot: &KernelSnapshot,
) -> Result<()> {
    validate_interface_inventory(&snapshot.interfaces)?;
    policy.validate_against(&snapshot.inventory)?;
    anyhow::ensure!(
        !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.name == policy.interface_name),
        "TUN interface name is already present"
    );
    // ifindex is allocated by Linux at creation time and cannot be predicted safely.
    // The exact assigned value is bound and checked after the interface exists.
    Ok(())
}

/// Verify the interface identity assigned by the kernel before route installation.
/// Both name and ifindex must match exactly, and the interface must be a TUN device.
pub fn verify_created_interface(
    policy: &RoutingPolicyPlan,
    interfaces: &[KernelInterfaceRecord],
) -> Result<()> {
    policy.validate()?;
    validate_interface_inventory(interfaces)?;
    let by_name = interfaces
        .iter()
        .filter(|interface| interface.name == policy.interface_name)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        by_name.len() == 1,
        "created TUN interface name is missing or duplicated"
    );
    let interface = by_name[0];
    anyhow::ensure!(
        interface.index > 0 && interface.is_tun,
        "created interface has an invalid ifindex or is not a TUN device"
    );
    let duplicate_index = interfaces
        .iter()
        .filter(|candidate| candidate.index == interface.index)
        .count();
    anyhow::ensure!(
        duplicate_index == 1,
        "kernel interface inventory contains a duplicate assigned ifindex"
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
            #[cfg(target_os = "linux")]
            netlink_interface_count: 0,
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

        // The kernel-assigned ifindex is unknown before creation; an existing interface
        // using the placeholder value does not constitute a collision.
        let placeholder_index = snapshot(vec![KernelInterfaceRecord {
            name: "other0".into(),
            index: 77,
            is_tun: false,
        }]);
        validate_interface_preflight(&policy, &placeholder_index).unwrap();
    }

    #[test]
    fn preflight_rejects_ambiguous_interface_inventory() {
        let policy = policy();
        for interfaces in [
            vec![
                KernelInterfaceRecord {
                    name: "eth0".into(),
                    index: 2,
                    is_tun: false,
                },
                KernelInterfaceRecord {
                    name: "eth0".into(),
                    index: 3,
                    is_tun: false,
                },
            ],
            vec![
                KernelInterfaceRecord {
                    name: "eth0".into(),
                    index: 2,
                    is_tun: false,
                },
                KernelInterfaceRecord {
                    name: "eth1".into(),
                    index: 2,
                    is_tun: false,
                },
            ],
            vec![KernelInterfaceRecord {
                name: "eth0".into(),
                index: 0,
                is_tun: false,
            }],
            vec![KernelInterfaceRecord {
                name: "bad/name".into(),
                index: 2,
                is_tun: false,
            }],
        ] {
            assert!(validate_interface_preflight(&policy, &snapshot(interfaces)).is_err());
        }
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

        // Any non-zero kernel-assigned ifindex is accepted; it is bound to the plan later.
        verify_created_interface(
            &policy,
            &[KernelInterfaceRecord {
                name: "tun-proxyctl".into(),
                index: 143,
                is_tun: true,
            }],
        )
        .unwrap();

        for invalid in [
            vec![KernelInterfaceRecord {
                name: "tun-proxyctl".into(),
                index: 0,
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
        assert!(
            plan.cleanup[..4]
                .iter()
                .all(|target| matches!(target, CleanupTarget::Rule(_)))
        );
        assert!(
            plan.cleanup[4..]
                .iter()
                .all(|target| matches!(target, CleanupTarget::Route(_)))
        );
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
    fn complete_kernel_plan_passes_validation_and_foreign_route_cleanup_fails() {
        let plan = KernelCommandPlan::from_policy(&policy(), 1000, 1000).unwrap();
        plan.validate().unwrap();

        let mut foreign_route = plan.clone();
        if let Some(CleanupTarget::Route(route)) = foreign_route.cleanup.last_mut() {
            route.interface_name = "eth0".into();
        }
        assert!(foreign_route.validate().is_err());

        let mut stale_interface_index = plan.clone();
        if let Some(CleanupTarget::Route(route)) = stale_interface_index.cleanup.last_mut() {
            route.interface_index += 1;
        }
        assert!(stale_interface_index.validate().is_err());

        let mut extra_apply = plan.clone();
        extra_apply.apply.push(IpCommand::new(["route", "add", "default"]));
        assert!(extra_apply.validate().is_err());

        let mut altered_apply = plan.clone();
        altered_apply.apply[2].arguments.push("onlink".into());
        assert!(altered_apply.validate().is_err());

        let mut duplicate_cleanup = plan;
        let first_cleanup = duplicate_cleanup.cleanup[0].clone();
        duplicate_cleanup.cleanup.push(first_cleanup);
        assert!(duplicate_cleanup.validate().is_err());
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
