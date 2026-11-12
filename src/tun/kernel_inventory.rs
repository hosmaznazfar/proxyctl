//! Read-only kernel routing inventory using iproute2 JSON output.
//!
//! This module never mutates networking. It invokes only fixed `ip -j` inspection commands
//! and fails closed when the output is incomplete or cannot be interpreted.

use crate::tun::route_policy::{AddressFamily, KernelInventory};
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use anyhow::ensure;
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::process::Command;

/// Inspect route tables and rule priorities for both address families.
///
/// Requires iproute2's `ip` executable on PATH. No shell is used and all arguments are fixed.
#[cfg(target_os = "linux")]
pub fn inspect() -> Result<KernelInventory> {
    let ipv4_routes = run_ip(&["-j", "-4", "route", "show", "table", "all"])?;
    let ipv6_routes = run_ip(&["-j", "-6", "route", "show", "table", "all"])?;
    let ipv4_rules = run_ip(&["-j", "-4", "rule", "show"])?;
    let ipv6_rules = run_ip(&["-j", "-6", "rule", "show"])?;

    parse_snapshot(&ipv4_routes, &ipv6_routes, &ipv4_rules, &ipv6_rules)
}

#[cfg(not(target_os = "linux"))]
pub fn inspect() -> Result<KernelInventory> {
    anyhow::bail!("kernel routing inventory is currently supported only on Linux");
}

#[cfg(target_os = "linux")]
fn run_ip(arguments: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .with_context(|| format!("cannot execute iproute2 inspection command: ip {}", arguments.join(" ")))?;
    ensure!(
        output.status.success(),
        "iproute2 inspection failed for a read-only routing query"
    );
    Ok(output.stdout)
}

fn parse_snapshot(
    ipv4_routes: &[u8],
    ipv6_routes: &[u8],
    ipv4_rules: &[u8],
    ipv6_rules: &[u8],
) -> Result<KernelInventory> {
    let mut inventory = KernelInventory::default();
    inventory.occupied_tables.extend(parse_route_tables(ipv4_routes)?);
    inventory.occupied_tables.extend(parse_route_tables(ipv6_routes)?);

    let (ipv4_tables, ipv4_priorities) = parse_rules(ipv4_rules, AddressFamily::Ipv4)?;
    let (ipv6_tables, ipv6_priorities) = parse_rules(ipv6_rules, AddressFamily::Ipv6)?;
    inventory.occupied_tables.extend(ipv4_tables);
    inventory.occupied_tables.extend(ipv6_tables);
    inventory.rule_priorities.extend(ipv4_priorities);
    inventory.rule_priorities.extend(ipv6_priorities);

    inventory.occupied_tables.sort_unstable();
    inventory.occupied_tables.dedup();
    inventory.rule_priorities.sort_by_key(|(family, priority)| {
        let family_order = match family {
            AddressFamily::Ipv4 => 4,
            AddressFamily::Ipv6 => 6,
        };
        (family_order, *priority)
    });
    inventory.rule_priorities.dedup();
    Ok(inventory)
}

fn parse_route_tables(bytes: &[u8]) -> Result<Vec<u32>> {
    let routes = parse_array(bytes, "route")?;
    routes
        .iter()
        .map(|route| {
            route
                .get("table")
                .map(parse_table_id)
                .unwrap_or(Ok(crate::tun::route_policy::RT_TABLE_MAIN))
        })
        .collect()
}

fn parse_rules(
    bytes: &[u8],
    family: AddressFamily,
) -> Result<(Vec<u32>, Vec<(AddressFamily, u32)>)> {
    let rules = parse_array(bytes, "rule")?;
    let mut tables = Vec::new();
    let mut priorities = Vec::with_capacity(rules.len());
    for rule in rules {
        let priority = rule
            .get("priority")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .context("iproute2 rule is missing a valid numeric priority")?;
        priorities.push((family, priority));
        if let Some(table) = rule.get("table").or_else(|| rule.get("lookup")) {
            tables.push(parse_table_id(table)?);
        }
    }
    Ok((tables, priorities))
}

fn parse_array(bytes: &[u8], kind: &str) -> Result<Vec<Value>> {
    let value: Value = serde_json::from_slice(bytes)
        .with_context(|| format!("iproute2 returned invalid JSON for {kind} inventory"))?;
    value
        .as_array()
        .cloned()
        .with_context(|| format!("iproute2 returned a non-array {kind} inventory"))
}

fn parse_table_id(value: &Value) -> Result<u32> {
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).context("routing table ID exceeds u32");
    }
    let name = value
        .as_str()
        .context("routing table identifier is neither a number nor a name")?;
    match name {
        "default" => Ok(crate::tun::route_policy::RT_TABLE_DEFAULT),
        "main" => Ok(crate::tun::route_policy::RT_TABLE_MAIN),
        "local" => Ok(crate::tun::route_policy::RT_TABLE_LOCAL),
        numeric => numeric
            .parse::<u32>()
            .with_context(|| format!("unknown named routing table: {numeric}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dual_stack_routes_and_rules_into_deduplicated_inventory() {
        let ipv4_routes = br#"[{"dst":"default","dev":"eth0"},{"dst":"10.0.0.0/8","table":100}] "#;
        let ipv6_routes = br#"[{"dst":"::/0","table":"main"},{"dst":"2001:db8::/32","table":100}]"#;
        let ipv4_rules = br#"[{"priority":0,"table":"local"},{"priority":100,"lookup":"main"},{"priority":10000,"table":42420}]"#;
        let ipv6_rules = br#"[{"priority":0,"table":255},{"priority":100,"table":254}]"#;

        let inventory = parse_snapshot(ipv4_routes, ipv6_routes, ipv4_rules, ipv6_rules).unwrap();
        assert_eq!(inventory.occupied_tables, [100, 254, 255, 42420]);
        assert_eq!(
            inventory.rule_priorities,
            [
                (AddressFamily::Ipv4, 0),
                (AddressFamily::Ipv4, 100),
                (AddressFamily::Ipv4, 10_000),
                (AddressFamily::Ipv6, 0),
                (AddressFamily::Ipv6, 100),
            ]
        );
    }

    #[test]
    fn defaults_routes_without_table_to_main() {
        assert_eq!(
            parse_route_tables(br#"[{"dst":"default","dev":"eth0"}]"#).unwrap(),
            [crate::tun::route_policy::RT_TABLE_MAIN]
        );
    }

    #[test]
    fn rejects_unknown_named_tables_instead_of_guessing() {
        assert!(parse_route_tables(br#"[{"table":"vpn-private"}]"#).is_err());
    }

    #[test]
    fn rejects_malformed_or_incomplete_rule_inventory() {
        assert!(parse_rules(b"not-json", AddressFamily::Ipv4).is_err());
        assert!(
            parse_rules(br#"[{"table":"main"}]"#, AddressFamily::Ipv4).is_err()
        );
    }

    #[test]
    fn includes_rule_lookup_tables_even_without_routes() {
        let (tables, priorities) = parse_rules(
            br#"[{"priority":123,"table":42420}]"#,
            AddressFamily::Ipv4,
        )
        .unwrap();
        assert_eq!(tables, [42420]);
        assert_eq!(priorities, [(AddressFamily::Ipv4, 123)]);
    }
}
