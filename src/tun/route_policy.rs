//! Pure routing-policy planning and validation for the future Linux TUN backend.
//!
//! This module does not inspect or mutate the kernel. It validates the exact policy shape that
//! a later rtnetlink implementation must apply and compare against a synthetic/live inventory.

use anyhow::{Result, ensure};

pub const RT_TABLE_MAIN: u32 = 254;
pub const RT_TABLE_LOCAL: u32 = 255;
pub const RT_TABLE_DEFAULT: u32 = 253;
pub const RT_TABLE_MIN_PROXYCTL: u32 = 10_000;

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

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.table_id >= RT_TABLE_MIN_PROXYCTL
                && ![RT_TABLE_DEFAULT, RT_TABLE_MAIN, RT_TABLE_LOCAL].contains(&self.table_id),
            "Proxyctl routing table ID is reserved or below the private allocation floor"
        );
        ensure!(
            self.bypass_priority > 0
                && self.proxy_priority > 0
                && self.bypass_priority < self.proxy_priority,
            "core bypass rule must have a non-zero priority before the proxy rule"
        );
        ensure!(
            self.core_mark_mask != 0 && self.core_mark & !self.core_mark_mask == 0,
            "core socket mark must fit a non-zero mark mask"
        );
        ensure!(
            !self.interface_name.is_empty()
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

        for family in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let routes = self
                .routes
                .iter()
                .filter(|route| route.family == family)
                .collect::<Vec<_>>();
            ensure!(
                routes.len() == 1,
                "routing plan has a missing or duplicate family route"
            );
            let route = routes[0];
            ensure!(
                route.destination == family.default_prefix()
                    && route.table_id == self.table_id
                    && route.interface_name == self.interface_name
                    && route.interface_index == self.interface_index
                    && route.route_type == RouteType::Unicast,
                "route is not the exact unicast default route through the owned TUN interface"
            );

            let bypass = self
                .rules
                .iter()
                .filter(|rule| {
                    rule.family == family && rule.purpose == RulePurpose::CoreTrafficBypass
                })
                .collect::<Vec<_>>();
            let proxy = self
                .rules
                .iter()
                .filter(|rule| rule.family == family && rule.purpose == RulePurpose::ProxyTraffic)
                .collect::<Vec<_>>();
            ensure!(
                bypass.len() == 1 && proxy.len() == 1,
                "routing plan has missing or duplicate rules"
            );
            let bypass = bypass[0];
            let proxy = proxy[0];
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
    use super::*;

    fn plan() -> RoutingPolicyPlan {
        RoutingPolicyPlan::new(42_420, 42_410, 42_420, 0x42, 0xff, "tun-proxyctl", 77)
    }

    #[test]
    fn creates_valid_dual_stack_policy_with_core_bypass_before_proxy_rule() {
        let plan = plan();
        plan.validate().unwrap();
        assert_eq!(plan.routes.len(), 2);
        assert_eq!(plan.rules.len(), 4);
        assert!(plan.bypass_priority < plan.proxy_priority);
    }

    #[test]
    fn rejects_reserved_or_low_routing_table_ids() {
        for table in [0, RT_TABLE_DEFAULT, RT_TABLE_MAIN, RT_TABLE_LOCAL, 9999] {
            let mut plan = plan();
            plan.table_id = table;
            assert!(plan.validate().is_err(), "accepted table {table}");
        }
    }

    #[test]
    fn rejects_invalid_mark_and_mask() {
        let mut plan = plan();
        plan.core_mark_mask = 0;
        assert!(plan.validate().is_err());
        let mut plan = plan();
        plan.core_mark = 0x100;
        plan.core_mark_mask = 0xff;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_bypass_rule_after_proxy_rule() {
        let mut plan = plan();
        plan.bypass_priority = 50_000;
        plan.proxy_priority = 40_000;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_terminal_route_types_and_foreign_interface_identity() {
        let mut plan = plan();
        plan.routes[0].route_type = RouteType::Blackhole;
        assert!(plan.validate().is_err());
        let mut plan = plan();
        plan.routes[1].interface_index += 1;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_missing_or_duplicate_family_resources() {
        let mut plan = plan();
        plan.routes.pop();
        assert!(plan.validate().is_err());
        let mut plan = plan();
        plan.rules.push(plan.rules[0].clone());
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_occupied_table_and_rule_priorities() {
        let plan = plan();
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
        let plan = plan();
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
