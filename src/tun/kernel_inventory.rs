//! Read-only kernel routing inventory using iproute2 JSON output.
//!
//! This module never mutates networking. It invokes only fixed `ip -j` inspection commands
//! and fails closed when the output is incomplete or cannot be interpreted.

use crate::tun::route_policy::{AddressFamily, KernelInventory};
#[cfg(target_os = "linux")]
use anyhow::ensure;
use anyhow::{Context, Result};
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::{
    io::{Read, Seek, SeekFrom},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

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
const IP_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const MAX_IP_COMMAND_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn run_ip(arguments: &[&str]) -> Result<Vec<u8>> {
    run_ip_command("ip", arguments, IP_COMMAND_TIMEOUT)
}

#[cfg(target_os = "linux")]
fn run_ip_command(executable: &str, arguments: &[&str], timeout: Duration) -> Result<Vec<u8>> {
    let mut output_file =
        tempfile::tempfile().context("cannot create private iproute2 output file")?;
    let child_output = output_file.try_clone()?;
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(child_output))
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| {
            format!(
                "cannot execute iproute2 inspection command: {} {}",
                executable,
                arguments.join(" ")
            )
        })?;

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("could not inspect iproute2 process status");
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "iproute2 inspection timed out after {} ms",
                timeout.as_millis()
            );
        }
        thread::sleep(Duration::from_millis(10));
    };

    ensure!(
        status.success(),
        "iproute2 inspection failed for a read-only routing query"
    );
    let output_size = output_file.metadata()?.len();
    ensure!(
        output_size <= MAX_IP_COMMAND_OUTPUT_BYTES,
        "iproute2 inspection output exceeds the {}-byte safety limit",
        MAX_IP_COMMAND_OUTPUT_BYTES
    );
    output_file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(output_size as usize);
    output_file
        .take(MAX_IP_COMMAND_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_IP_COMMAND_OUTPUT_BYTES,
        "iproute2 inspection output exceeded the safety limit while reading"
    );
    Ok(bytes)
}

fn parse_snapshot(
    ipv4_routes: &[u8],
    ipv6_routes: &[u8],
    ipv4_rules: &[u8],
    ipv6_rules: &[u8],
) -> Result<KernelInventory> {
    let mut inventory = KernelInventory::default();
    inventory
        .occupied_tables
        .extend(parse_route_tables(ipv4_routes)?);
    inventory
        .occupied_tables
        .extend(parse_route_tables(ipv6_routes)?);

    let ipv4_rules = parse_rules(ipv4_rules, AddressFamily::Ipv4)?;
    let ipv6_rules = parse_rules(ipv6_rules, AddressFamily::Ipv6)?;
    inventory.occupied_tables.extend(ipv4_rules.tables);
    inventory.occupied_tables.extend(ipv6_rules.tables);
    inventory.rule_priorities.extend(ipv4_rules.priorities);
    inventory.rule_priorities.extend(ipv6_rules.priorities);

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

struct ParsedRules {
    tables: Vec<u32>,
    priorities: Vec<(AddressFamily, u32)>,
}

fn parse_rules(bytes: &[u8], family: AddressFamily) -> Result<ParsedRules> {
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
    Ok(ParsedRules { tables, priorities })
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

    #[cfg(target_os = "linux")]
    use std::{fs, os::unix::fs::PermissionsExt};

    #[cfg(target_os = "linux")]
    #[test]
    fn bounds_inspection_process_runtime_and_reaps_timeout() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("busy");
        fs::write(&executable, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let started = Instant::now();
        let result = run_ip_command(executable.to_str().unwrap(), &[], Duration::from_millis(40));
        assert!(result.unwrap_err().to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_command_output_above_the_fixed_memory_limit() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("oversized");
        fs::write(
            &executable,
            "#!/bin/sh\\nhead -c 4194305 /dev/zero\\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let error = run_ip_command(executable.to_str().unwrap(), &[], Duration::from_secs(2))
            .unwrap_err();
        assert!(error.to_string().contains("safety limit"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn captures_command_output_to_file_without_pipe_backpressure() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("emit");
        fs::write(&executable, "#!/bin/sh\nprintf '[{}]\n'\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let output =
            run_ip_command(executable.to_str().unwrap(), &[], Duration::from_secs(1)).unwrap();
        assert_eq!(output, b"[{}]\n");
    }

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
        assert!(parse_rules(br#"[{"table":"main"}]"#, AddressFamily::Ipv4).is_err());
    }

    #[test]
    fn includes_rule_lookup_tables_even_without_routes() {
        let parsed =
            parse_rules(br#"[{"priority":123,"table":42420}]"#, AddressFamily::Ipv4).unwrap();
        assert_eq!(parsed.tables, [42420]);
        assert_eq!(parsed.priorities, [(AddressFamily::Ipv4, 123)]);
    }
}
