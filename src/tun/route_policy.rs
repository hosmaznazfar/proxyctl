//! Pure routing-policy planning and validation for the future Linux TUN backend.
//!
//! This module does not inspect or mutate the kernel. It validates the exact policy shape that
//! a later rtnetlink implementation must apply and compare against a synthetic/live inventory.

use anyhow::{Result, ensure};

pub const RT_TABLE_MAIN: u32 = 254;
pub const RT_TABLE_LOCAL: u32 = 255;
pub const RT_TABLE_DEFAULT: u32 = 253;
pub const RT_TABLE_MIN_PROXYCTL: u32 = 10_000;
pub const RPDB_PRIORITY_MIN_PROXYCTL: u32 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub fn default_prefix(self) -> &'static str {
        match self {
            Self::Ipv4 => "0.0.0.0/0",
            Self::Ipv6 => "::/0",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    Unicast,
    Blackhole,
    Unreachable,
    Prohibit,
    Throw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRoute {
    pub family: AddressFamily,
    pub destination: String,
    pub table_id: u32,
    pub interface_name: String,
    pub interface_index: u32,
    pub route_type: RouteType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkSelector {
    pub value: u32,
    pub mask: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulePurpose {
    CoreTrafficBypass,
    ProxyTraffic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedRule {
    pub family: AddressFamily,
    pub priority: u32,
    pub purpose: RulePurpose,
    pub mark: Option<MarkSelector>,
    pub lookup_table: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingPolicyPlan {
    pub table_id: u32,
    pub bypass_priority: u32,
    pub proxy_priority: u32,
    pub core_mark: u32,
    pub core_mark_mask: u32,
    pub interface_name: String,
    pub interface_index: u32,
    pub routes: Vec<PlannedRoute>,
    pub rules: Vec<PlannedRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KernelInventory {
    pub occupied_tables: Vec<u32>,
    pub rule_priorities: Vec<(AddressFamily, u32)>,
}

/// Derive a stable, non-zero mark in Proxyctl's private high-bit range from a canonical UUID.
pub fn mark_for_activation_id(activation_id: &str) -> Result<(u32, u32)> {
    ensure!(activation_id.len() == 36 && activation_id.bytes().enumerate().all(|(index, byte)| {
        if [8, 13, 18, 23].contains(&index) { byte == b'-' }
        else { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() }
    }), "activation ID must be a canonical lowercase UUID");
    let digits = activation_id.bytes().filter(|byte| *byte != b'-').take(7)
        .collect::<Vec<_>>();
    ensure!(digits.len() == 7, "activation ID does not contain enough mark entropy");
    let text = std::str::from_utf8(&digits)?;
    let suffix = u32::from_str_radix(text, 16)? & 0x0fff_ffff;
    let mark = 0x4000_0000 | suffix;
    let mask = 0x7fff_ffff;
    ensure!(mark != 0 && mark & !mask == 0, "derived Proxyctl socket mark is invalid");
    Ok((mark, mask))
}

/// Allocate a free private table and consecutive policy priorities from one live snapshot.
///
/// The caller must still let the broker re-check conflicts transactionally because another
/// network manager can change the kernel inventory between this read-only selection and commit.
pub fn allocate_policy_identifiers(inventory: &KernelInventory) -> Result<(u32, u32, u32)> {
    let table = (RT_TABLE_MIN_PROXYCTL..=RT_TABLE_MIN_PROXYCTL + 4095)
        .find(|candidate| !inventory.occupied_tables.contains(candidate))
        .ok_or_else(|| anyhow::anyhow!("no free Proxyctl routing table is available in the private allocation range"))?;
    let priority_pair = (RPDB_PRIORITY_MIN_PROXYCTL..=32_000u32)
        .find(|priority| {
            let Some(next) = priority.checked_add(1) else { return false; };
            next <= 32_000
                && [AddressFamily::Ipv4, AddressFamily::Ipv6].iter().all(|family| {
                    !inventory.rule_priorities.contains(&(*family, *priority))
                        && !inventory.rule_priorities.contains(&(*family, next))
                })
        })
        .ok_or_else(|| anyhow::anyhow!("no consecutive free Proxyctl policy priorities are available"))?;
    Ok((table, priority_pair, priority_pair + 1))
}

impl RoutingPolicyPlan {
    /// Build an explicit dual-stack plan. Core sockets must set the configured SO_MARK value.
    pub fn new(
        table_id: u32,
        bypass_priority: u32,
        proxy_priority: u32,
        core_mark: u32,
        core_mark_mask: u32,
        interface_name: impl Into<String>,
        interface_index: u32,
    ) -> Self {
        let interface_name = interface_name.into();
        let routes = [AddressFamily::Ipv4, AddressFamily::Ipv6]
            .into_iter()
            .map(|family| PlannedRoute {
                family,
                destination: family.default_prefix().into(),
                table_id,
                interface_name: interface_name.clone(),
                interface_index,
                route_type: RouteType::Unicast,
            })
            .collect();
        let mut rules = Vec::with_capacity(4);
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            rules.push(PlannedRule {
                family,
                priority: bypass_priority,
                purpose: RulePurpose::CoreTrafficBypass,
                mark: Some(MarkSelector {
                    value: core_mark,
                    mask: core_mark_mask,
                }),
                lookup_table: RT_TABLE_MAIN,
            });
            rules.push(PlannedRule {
                family,
                priority: proxy_priority,
                purpose: RulePurpose::ProxyTraffic,
                mark: None,
                lookup_table: table_id,
            });
        }
        Self {
            table_id,
            bypass_priority,
            proxy_priority,
            core_mark,
            core_mark_mask,
            interface_name,
            interface_index,
            routes,
            rules,
        }
    }

    /// Bind the policy to the actual ifindex returned by the kernel after TUN creation.
    ///
    /// The constructor's interface index is only a non-zero planning placeholder. Linux assigns
    /// the real ifindex dynamically; every route must use this value before it is installed.
    pub fn bind_interface_index(&self, interface_index: u32) -> Result<Self> {
        ensure!(
            interface_index > 0,
            "kernel-assigned TUN ifindex must be non-zero"
        );
        let mut bound = self.clone();
        bound.interface_index = interface_index;
        for route in &mut bound.routes {
            route.interface_index = interface_index;
        }
        bound.validate()?;
        Ok(bound)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.table_id >= RT_TABLE_MIN_PROXYCTL
                && ![RT_TABLE_DEFAULT, RT_TABLE_MAIN, RT_TABLE_LOCAL].contains(&self.table_id),
            "Proxyctl routing table ID is reserved or below the private allocation floor"
        );
        ensure!(
            self.bypass_priority >= RPDB_PRIORITY_MIN_PROXYCTL
                && self.proxy_priority >= RPDB_PRIORITY_MIN_PROXYCTL
                && self.bypass_priority <= i32::MAX as u32
                && self.proxy_priority <= i32::MAX as u32
                && self.bypass_priority < self.proxy_priority,
            "Proxyctl policy priorities must be in the signed native range with core bypass before proxy traffic"
        );
        ensure!(
            self.core_mark != 0
                && self.core_mark_mask != 0
                && self.core_mark & !self.core_mark_mask == 0,
            "core socket mark must be non-zero and fit a non-zero mark mask"
        );
        ensure!(
            !self.interface_name.is_empty()
                && self.interface_name != "."
                && self.interface_name != ".."
                && self.interface_name.len() <= 15
                && self.interface_name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                }),
            "invalid TUN interface name"
        );
        ensure!(
            self.interface_index > 0,
            "TUN interface index must be non-zero"
        );
        ensure!(
            self.routes.len() == 2,
            "routing plan must contain one default route per family"
        );
        ensure!(
            self.rules.len() == 4,
            "routing plan must contain bypass and proxy rules per family"
        );
        ensure!(
            self.routes.iter().all(|route| route.interface_index == self.interface_index && route.interface_name == self.interface_name && route.table_id == self.table_id),
            "all routes must bind the plan's interface identity and dedicated table"
        );
        ensure!(
            self.rules.iter().all(|rule| rule.priority >= RPDB_PRIORITY_MIN_PROXYCTL),
            "every rule priority must be in the Proxyctl allocation range"
        );

        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let mut routes = self.routes.iter().filter(|route| route.family == family);
            let route = routes
                .next()
                .ok_or_else(|| anyhow::anyhow!("routing plan is missing a family route"))?;
            ensure!(
                routes.next().is_none(),
                "routing plan has duplicate family routes"
            );
            ensure!(
                route.destination == family.default_prefix()
                    && route.table_id == self.table_id
                    && route.interface_name == self.interface_name
                    && route.interface_index == self.interface_index
                    && route.route_type == RouteType::Unicast,
                "route is not the exact unicast default route through the owned TUN interface"
            );

            let mut bypass_rules = self.rules.iter().filter(|rule| {
                rule.family == family && rule.purpose == RulePurpose::CoreTrafficBypass
            });
            let bypass = bypass_rules
                .next()
                .ok_or_else(|| anyhow::anyhow!("routing plan is missing a core bypass rule"))?;
            ensure!(
                bypass_rules.next().is_none(),
                "routing plan has duplicate core bypass rules"
            );
            let mut proxy_rules = self
                .rules
                .iter()
                .filter(|rule| rule.family == family && rule.purpose == RulePurpose::ProxyTraffic);
            let proxy = proxy_rules
                .next()
                .ok_or_else(|| anyhow::anyhow!("routing plan is missing a proxy rule"))?;
            ensure!(
                proxy_rules.next().is_none(),
                "routing plan has duplicate proxy rules"
            );
            ensure!(
                bypass.priority == self.bypass_priority
                    && bypass.mark
                        == Some(MarkSelector {
                            value: self.core_mark,
                            mask: self.core_mark_mask,
                        })
                    && bypass.lookup_table == RT_TABLE_MAIN,
                "core bypass rule must match the exact socket mark and consult the main table"
            );
            ensure!(
                proxy.priority == self.proxy_priority
                    && proxy.mark.is_none()
                    && proxy.lookup_table == self.table_id,
                "proxy rule must send unmarked traffic to the dedicated Proxyctl table"
            );
        }

        // Rules are lookup-only. An empty dedicated table therefore has no terminal
        // action here and the kernel can continue to later RPDB rules.
        Ok(())
    }

    /// Refuse any pre-existing use of the exact table or rule priorities before mutation.
    pub fn validate_against(&self, inventory: &KernelInventory) -> Result<()> {
        self.validate()?;
        ensure!(
            !inventory.occupied_tables.contains(&self.table_id),
            "dedicated routing table is already occupied"
        );
        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            ensure!(
                !inventory
                    .rule_priorities
                    .contains(&(family, self.bypass_priority)),
                "core bypass rule priority is already occupied"
            );
            ensure!(
                !inventory
                    .rule_priorities
                    .contains(&(family, self.proxy_priority)),
                "proxy rule priority is already occupied"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn derives_a_stable_mark_in_the_proxyctl_private_range() {
        let id = "12345678-1234-4234-8234-123456789abc";
        let (mark, mask) = mark_for_activation_id(id).unwrap();
        assert_eq!((mark, mask), (0x4123_4567, 0x7fff_ffff));
        assert_eq!(mark_for_activation_id(id).unwrap(), (mark, mask));
        assert!(mark_for_activation_id("invalid").is_err());
    }

    #[test]
    fn allocates_a_free_table_and_dual_stack_priority_pair() {
        let inventory = KernelInventory {
            occupied_tables: vec![RT_TABLE_MIN_PROXYCTL],
            rule_priorities: vec![
                (AddressFamily::Ipv4, RPDB_PRIORITY_MIN_PROXYCTL),
                (AddressFamily::Ipv6, RPDB_PRIORITY_MIN_PROXYCTL),
                (AddressFamily::Ipv4, RPDB_PRIORITY_MIN_PROXYCTL + 1),
            ],
        };
        assert_eq!(
            allocate_policy_identifiers(&inventory).unwrap(),
            (RT_TABLE_MIN_PROXYCTL + 1, RPDB_PRIORITY_MIN_PROXYCTL + 2, RPDB_PRIORITY_MIN_PROXYCTL + 3)
        );
    }

    use super::*;

    fn sample_plan() -> RoutingPolicyPlan {
        RoutingPolicyPlan::new(42_420, 42_410, 42_420, 0x42, 0xff, "tun-proxyctl", 77)
    }

    #[test]
    fn creates_valid_dual_stack_policy_with_core_bypass_before_proxy_rule() {
        let plan = sample_plan();
        plan.validate().unwrap();
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.rules.len(), 4);
        assert!(plan.bypass_priority < plan.proxy_priority);
    }

    #[test]
    fn binds_every_default_route_to_the_actual_kernel_interface_index() {
        let plan = sample_plan().bind_interface_index(143).unwrap();
        assert_eq!(plan.interface_index, 143);
        assert!(plan.routes.iter().all(|route| route.interface_index == 143));
        assert!(plan.bind_interface_index(0).is_err());
    }

    #[test]
    fn rejects_reserved_or_low_routing_table_ids() {
        for table in [0, RT_TABLE_DEFAULT, RT_TABLE_MAIN, RT_TABLE_LOCAL, 9999] {
            let mut plan = sample_plan();
            plan.table_id = table;
            assert!(plan.validate().is_err(), "accepted table {table}");
        }
    }

    #[test]
    fn rejects_dot_only_interface_names() {
        for name in [".", ".."] {
            let mut plan = sample_plan();
            plan.interface_name = name.to_owned();
            assert!(plan.validate().is_err(), "accepted interface name {name:?}");
        }
    }

    #[test]
    fn rejects_invalid_mark_and_mask() {
        let mut plan = sample_plan();
        plan.core_mark_mask = 0;
        assert!(plan.validate().is_err());
        let mut plan = sample_plan();
        plan.core_mark = 0x100;
        plan.core_mark_mask = 0xff;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_zero_core_mark_that_would_match_unmarked_traffic() {
        let mut plan = sample_plan();
        plan.core_mark = 0;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_policy_priorities_in_reserved_low_range() {
        let mut plan = sample_plan();
        plan.bypass_priority = 100;
        plan.proxy_priority = 200;
        assert!(plan.validate().is_err());

        let plan = RoutingPolicyPlan::new(
            42_420,
            RPDB_PRIORITY_MIN_PROXYCTL,
            RPDB_PRIORITY_MIN_PROXYCTL + 1,
            0x42,
            0xff,
            "tun-proxyctl",
            77,
        );
        plan.validate().unwrap();
    }

    #[test]
    fn rejects_priorities_outside_signed_native_range() {
        let mut plan = sample_plan();
        plan.proxy_priority = i32::MAX as u32 + 1;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_bypass_rule_after_proxy_rule() {
        let mut plan = sample_plan();
        plan.bypass_priority = 50_000;
        plan.proxy_priority = 40_000;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_terminal_route_types_and_foreign_interface_identity() {
        let mut plan = sample_plan();
        plan.routes[0].route_type = RouteType::Blackhole;
        assert!(plan.validate().is_err());
        let mut plan = sample_plan();
        plan.routes[1].interface_index += 1;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_missing_or_duplicate_family_resources() {
        let mut plan = sample_plan();
        plan.routes.pop();
        assert!(plan.validate().is_err());
        let mut plan = sample_plan();
        plan.rules.push(plan.rules[0].clone());
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_occupied_table_and_rule_priorities() {
        let plan = sample_plan();
        let mut inventory = KernelInventory::default();
        inventory.occupied_tables.push(plan.table_id);
        assert!(plan.validate_against(&inventory).is_err());
        inventory.occupied_tables.clear();
        inventory
            .rule_priorities
            .push((AddressFamily::Ipv6, plan.proxy_priority));
        assert!(plan.validate_against(&inventory).is_err());
    }

    #[test]
    fn accepts_unoccupied_exact_plan_without_terminal_fallback_rules() {
        let plan = sample_plan();
        plan.validate_against(&KernelInventory::default()).unwrap();
        assert!(
            plan.routes
                .iter()
                .all(|route| route.route_type == RouteType::Unicast)
        );
        assert!(
            plan.rules
                .iter()
                .all(|rule| rule.lookup_table != RT_TABLE_DEFAULT)
        );
    }
}
