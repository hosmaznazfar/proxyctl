//! Read-only verification that marked core traffic resolves through physical egress.
//!
//! This is a preflight observation, not a guarantee against later host-network changes.
//! It never creates interfaces, changes routes, or applies socket marks.

use anyhow::{Context, Result, ensure};
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::path::Path;

use super::{
    kernel_inventory::{self, KernelInterfaceRecord},
    route_policy::{AddressFamily, RT_TABLE_MAIN, RoutingPolicyPlan},
};

const IPV4_PROBE_DESTINATION: &str = "1.1.1.1";
const IPV6_PROBE_DESTINATION: &str = "2606:4700:4700::1111";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRouteEvidence {
    pub family: AddressFamily,
    pub destination: String,
    pub interface_name: String,
    pub interface_index: u32,
    pub gateway: Option<String>,
    pub table_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressBypassEvidence {
    pub mark: u32,
    pub mask: u32,
    pub ipv4: EgressRouteEvidence,
    pub ipv6: EgressRouteEvidence,
}

/// Resolve both address families using the exact core socket mark and require a physical
/// interface through the main routing table. Failure in either family blocks TUN preflight.
///
/// This proves only the kernel's current marked route lookup. The core adapter must separately
/// prove that its outbound sockets actually set this SO_MARK value.
#[cfg(target_os = "linux")]
pub fn inspect_marked_egress(plan: &RoutingPolicyPlan) -> Result<EgressBypassEvidence> {
    plan.validate()?;
    let snapshot = kernel_inventory::inspect_snapshot()?;
    let mark = format!("{:#x}", plan.core_mark);
    let ipv4 = resolve_marked_route(
        AddressFamily::Ipv4,
        IPV4_PROBE_DESTINATION,
        &mark,
        &snapshot.interfaces,
        &plan.interface_name,
    )?;
    let ipv6 = resolve_marked_route(
        AddressFamily::Ipv6,
        IPV6_PROBE_DESTINATION,
        &mark,
        &snapshot.interfaces,
        &plan.interface_name,
    )?;
    verify_hardware_backed_egress(&ipv4, Path::new("/sys/class/net"))?;
    verify_hardware_backed_egress(&ipv6, Path::new("/sys/class/net"))?;
    Ok(EgressBypassEvidence {
        mark: plan.core_mark,
        mask: plan.core_mark_mask,
        ipv4,
        ipv6,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn inspect_marked_egress(_plan: &RoutingPolicyPlan) -> Result<EgressBypassEvidence> {
    anyhow::bail!("marked physical-egress inspection is supported only on Linux");
}

#[cfg(target_os = "linux")]
fn resolve_marked_route(
    family: AddressFamily,
    destination: &str,
    mark: &str,
    interfaces: &[KernelInterfaceRecord],
    tun_name: &str,
) -> Result<EgressRouteEvidence> {
    let family_flag = match family {
        AddressFamily::Ipv4 => "-4",
        AddressFamily::Ipv6 => "-6",
    };
    let output =
        kernel_inventory::run_ip(&["-j", family_flag, "route", "get", destination, "mark", mark])
            .with_context(|| format!("could not resolve {family:?} marked egress route"))?;
    parse_marked_route(&output, family, destination, interfaces, tun_name).with_context(|| {
        format!(
            "marked route lookup for {family:?} destination {destination} with mark {mark} returned {}",
            String::from_utf8_lossy(&output).trim()
        )
    })
}

fn parse_marked_route(
    bytes: &[u8],
    family: AddressFamily,
    destination: &str,
    interfaces: &[KernelInterfaceRecord],
    tun_name: &str,
) -> Result<EgressRouteEvidence> {
    let value: Value =
        serde_json::from_slice(bytes).context("marked route lookup returned invalid JSON")?;
    let routes = value
        .as_array()
        .context("marked route lookup returned a non-array response")?;
    ensure!(
        routes.len() == 1,
        "marked route lookup must return exactly one route"
    );
    let route = &routes[0];

    let interface_name = route
        .get("dev")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .context("marked route lookup has no output interface")?;
    ensure!(
        interface_name != tun_name && interface_name != "lo",
        "marked core traffic resolves through the TUN or loopback interface"
    );

    let interface = interfaces
        .iter()
        .find(|interface| interface.name == interface_name)
        .context("marked route output interface is absent from the kernel interface inventory")?;
    ensure!(
        interface.index > 0 && !interface.is_tun,
        "marked route output interface is not a verified physical interface"
    );

    let table_id = route
        .get("table")
        .map(parse_table_id)
        .transpose()?
        .unwrap_or(RT_TABLE_MAIN);
    ensure!(
        table_id == RT_TABLE_MAIN,
        "marked core traffic did not resolve through the main routing table"
    );

    let gateway = route
        .get("gateway")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(EgressRouteEvidence {
        family,
        destination: destination.to_owned(),
        interface_name: interface.name.clone(),
        interface_index: interface.index,
        gateway,
        table_id,
    })
}

#[cfg(target_os = "linux")]
fn verify_hardware_backed_egress(route: &EgressRouteEvidence, sysfs_root: &Path) -> Result<()> {
    let device_path = sysfs_root.join(&route.interface_name).join("device");
    ensure!(
        device_path.exists(),
        "marked route resolves through an interface without a verified hardware device"
    );
    Ok(())
}

fn parse_table_id(value: &Value) -> Result<u32> {
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).context("route table ID exceeds u32");
    }
    match value
        .as_str()
        .context("route table is not a number or name")?
    {
        "main" => Ok(RT_TABLE_MAIN),
        "default" => Ok(crate::tun::route_policy::RT_TABLE_DEFAULT),
        "local" => Ok(crate::tun::route_policy::RT_TABLE_LOCAL),
        numeric => numeric
            .parse::<u32>()
            .with_context(|| format!("unknown route table name: {numeric}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interfaces() -> Vec<KernelInterfaceRecord> {
        vec![
            KernelInterfaceRecord {
                name: "wlo1".into(),
                index: 3,
                is_tun: false,
            },
            KernelInterfaceRecord {
                name: "tun-proxyctl".into(),
                index: 77,
                is_tun: true,
            },
        ]
    }

    #[test]
    fn accepts_marked_routes_through_verified_physical_interface() {
        let ipv4 = parse_marked_route(
            br#"[{"dst":"1.1.1.1","dev":"wlo1","gateway":"192.0.2.1","table":254}]"#,
            AddressFamily::Ipv4,
            IPV4_PROBE_DESTINATION,
            &interfaces(),
            "tun-proxyctl",
        )
        .unwrap();
        assert_eq!(ipv4.interface_name, "wlo1");
        assert_eq!(ipv4.interface_index, 3);
        assert_eq!(ipv4.gateway.as_deref(), Some("192.0.2.1"));
        assert_eq!(ipv4.table_id, RT_TABLE_MAIN);
    }

    #[test]
    fn rejects_tun_loopback_and_uninventoried_egress() {
        for (device, inventory) in [
            ("tun-proxyctl", interfaces()),
            ("lo", interfaces()),
            ("eth9", interfaces()),
        ] {
            let json = format!(r#"[{{"dev":"{device}"}}]"#);
            assert!(
                parse_marked_route(
                    json.as_bytes(),
                    AddressFamily::Ipv4,
                    IPV4_PROBE_DESTINATION,
                    &inventory,
                    "tun-proxyctl",
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_tun_kind_even_when_name_differs() {
        let inventory = vec![KernelInterfaceRecord {
            name: "vpn0".into(),
            index: 12,
            is_tun: true,
        }];
        assert!(
            parse_marked_route(
                br#"[{"dev":"vpn0"}]"#,
                AddressFamily::Ipv6,
                IPV6_PROBE_DESTINATION,
                &inventory,
                "tun-proxyctl",
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_non_main_table_and_ambiguous_or_incomplete_responses() {
        let inventory = interfaces();
        for json in [
            br#"[{"dev":"wlo1","table":42420}]"#.as_slice(),
            br#"[]"#,
            br#"[{"dev":"wlo1"},{"dev":"wlo1"}]"#,
            br#"[{"gateway":"192.0.2.1"}]"#,
            b"not-json",
        ] {
            assert!(
                parse_marked_route(
                    json,
                    AddressFamily::Ipv4,
                    IPV4_PROBE_DESTINATION,
                    &inventory,
                    "tun-proxyctl",
                )
                .is_err()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn requires_a_hardware_backed_egress_interface() {
        let directory = tempfile::tempdir().unwrap();
        let route = EgressRouteEvidence {
            family: AddressFamily::Ipv4,
            destination: IPV4_PROBE_DESTINATION.into(),
            interface_name: "wlo1".into(),
            interface_index: 3,
            gateway: None,
            table_id: RT_TABLE_MAIN,
        };
        let interface = directory.path().join("wlo1");
        std::fs::create_dir_all(&interface).unwrap();
        assert!(verify_hardware_backed_egress(&route, directory.path()).is_err());
        std::fs::create_dir_all(interface.join("device")).unwrap();
        verify_hardware_backed_egress(&route, directory.path()).unwrap();
    }

    #[test]
    fn rejects_unknown_table_names_instead_of_guessing() {
        assert!(
            parse_marked_route(
                br#"[{"dev":"wlo1","table":"vpn-private"}]"#,
                AddressFamily::Ipv4,
                IPV4_PROBE_DESTINATION,
                &interfaces(),
                "tun-proxyctl",
            )
            .is_err()
        );
    }
}
