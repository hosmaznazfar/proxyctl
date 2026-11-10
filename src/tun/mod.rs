//! Read-only Linux network inspection for the future TUN lifecycle.
//!
//! This module deliberately has no mutation APIs. It inspects procfs/sysfs and,
//! when available, invokes firewall listing commands only.

#[cfg(target_os = "linux")]
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkStatus {
    pub interfaces: Vec<String>,
    pub tun_interfaces: Vec<String>,
    pub default_routes: Vec<String>,
    pub routes_inspected: bool,
    pub dns_servers: Vec<String>,
    pub dns_inspected: bool,
    pub resolv_conf_target: Option<String>,
    pub network_manager_runtime: bool,
    pub systemd_resolved_runtime: bool,
    pub firewall: FirewallStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallStatus {
    pub backend: String,
    pub tables: usize,
    pub chains: usize,
    pub rules: usize,
    pub detail: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct InspectionPaths {
    sys_class_net: PathBuf,
    proc_net_route: PathBuf,
    proc_net_ipv6_route: PathBuf,
    resolv_conf: PathBuf,
    run: PathBuf,
    proc_net_ip_tables_names: PathBuf,
    proc_net_ip6_tables_names: PathBuf,
}

#[cfg(target_os = "linux")]
impl Default for InspectionPaths {
    fn default() -> Self {
        Self {
            sys_class_net: PathBuf::from("/sys/class/net"),
            proc_net_route: PathBuf::from("/proc/net/route"),
            proc_net_ipv6_route: PathBuf::from("/proc/net/ipv6_route"),
            resolv_conf: PathBuf::from("/etc/resolv.conf"),
            run: PathBuf::from("/run"),
            proc_net_ip_tables_names: PathBuf::from("/proc/net/ip_tables_names"),
            proc_net_ip6_tables_names: PathBuf::from("/proc/net/ip6_tables_names"),
        }
    }
}

/// Inspect current Linux networking state without changing it.
#[cfg(target_os = "linux")]
pub fn inspect() -> Result<NetworkStatus> {
    inspect_with_paths(&InspectionPaths::default())
}

#[cfg(not(target_os = "linux"))]
pub fn inspect() -> Result<NetworkStatus> {
    anyhow::bail!("TUN network inspection is currently supported only on Linux");
}

#[cfg(target_os = "linux")]
fn inspect_with_paths(paths: &InspectionPaths) -> Result<NetworkStatus> {
    inspect_with_paths_and_firewall(paths, None)
}

#[cfg(target_os = "linux")]
fn inspect_with_paths_and_firewall(
    paths: &InspectionPaths,
    firewall_override: Option<FirewallStatus>,
) -> Result<NetworkStatus> {
    let mut interfaces = Vec::new();
    let mut tun_interfaces = Vec::new();

    for entry in fs::read_dir(&paths.sys_class_net)
        .with_context(|| format!("cannot inspect {}", paths.sys_class_net.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.is_empty() || name.contains('/') {
            continue;
        }
        let is_tun = entry.path().join("tun_flags").exists()
            || name.starts_with("tun")
            || name.starts_with("tap");
        if is_tun {
            tun_interfaces.push(name.clone());
        }
        interfaces.push(name);
    }
    interfaces.sort();
    tun_interfaces.sort();

    let mut default_routes = Vec::new();
    let ipv4_routes = fs::read_to_string(&paths.proc_net_route);
    let ipv6_routes = fs::read_to_string(&paths.proc_net_ipv6_route);
    if let Ok(contents) = &ipv4_routes {
        default_routes.extend(parse_ipv4_default_routes(contents));
    }
    if let Ok(contents) = &ipv6_routes {
        default_routes.extend(parse_ipv6_default_routes(contents));
    }
    let routes_inspected = ipv4_routes.is_ok() && ipv6_routes.is_ok();

    let resolv_conf_target = fs::read_link(&paths.resolv_conf)
        .ok()
        .map(|target| target.display().to_string());
    let resolver_contents = fs::read_to_string(&paths.resolv_conf);
    let dns_servers = resolver_contents
        .as_ref()
        .map(|contents| parse_dns_servers(contents))
        .unwrap_or_default();
    let dns_inspected = resolver_contents.is_ok();

    let firewall = firewall_override.unwrap_or_else(|| inspect_firewall(paths));
    Ok(NetworkStatus {
        interfaces,
        tun_interfaces,
        default_routes,
        routes_inspected,
        dns_servers,
        dns_inspected,
        resolv_conf_target,
        network_manager_runtime: paths.run.join("NetworkManager").exists(),
        systemd_resolved_runtime: paths.run.join("systemd/resolve").exists(),
        firewall,
    })
}

#[cfg(target_os = "linux")]
fn parse_ipv4_default_routes(contents: &str) -> Vec<String> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[1] != "00000000" {
                return None;
            }
            let flags = u32::from_str_radix(fields[3], 16).ok()?;
            (flags & 1 != 0).then(|| format!("IPv4 default via {}", fields[0]))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn parse_ipv6_default_routes(contents: &str) -> Vec<String> {
    let mut routes = contents
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10
                || fields[0] != "00000000000000000000000000000000"
                || fields[1] != "00"
            {
                return None;
            }
            // /proc/net/ipv6_route field 8 contains route flags. Ignore entries
            // that are not marked RTF_UP, just as the IPv4 parser does.
            let flags = u32::from_str_radix(fields[8], 16).ok()?;
            let interface = fields[9];
            (flags & 1 != 0 && !interface.is_empty())
                .then(|| format!("IPv6 default via {interface}"))
        })
        .collect::<Vec<_>>();
    routes.sort();
    routes.dedup();
    routes
}

#[cfg(target_os = "linux")]
fn parse_dns_servers(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next()? == "nameserver").then(|| fields.next().unwrap_or_default().to_owned())
        })
        .filter(|server| !server.is_empty())
        .collect()
}

#[cfg(target_os = "linux")]
fn find_tool(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(|candidate| PathBuf::from(*candidate))
        .find(|path| path.is_file())
}

#[cfg(target_os = "linux")]
fn inspect_firewall(paths: &InspectionPaths) -> FirewallStatus {
    let nft = find_tool(&["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft"]);
    if let Some(executable) = nft {
        match Command::new(executable)
            .args(["-j", "list", "ruleset"])
            .output()
        {
            Ok(output) if output.status.success() => {
                return parse_nft_ruleset(&output.stdout).unwrap_or_else(|_| FirewallStatus {
                    backend: "nftables".into(),
                    tables: 0,
                    chains: 0,
                    rules: 0,
                    detail: "ruleset returned an unrecognized response".into(),
                });
            }
            Ok(_) => {
                return FirewallStatus {
                    backend: "nftables".into(),
                    tables: 0,
                    chains: 0,
                    rules: 0,
                    detail: "ruleset inspection was not permitted or failed".into(),
                };
            }
            Err(_) => {}
        }
    }

    let ipv4 = find_tool(&[
        "/usr/bin/iptables-save",
        "/usr/sbin/iptables-save",
        "/sbin/iptables-save",
    ]);
    let ipv6 = find_tool(&[
        "/usr/bin/ip6tables-save",
        "/usr/sbin/ip6tables-save",
        "/sbin/ip6tables-save",
    ]);
    if ipv4.is_some() || ipv6.is_some() {
        let mut totals = (0, 0, 0);
        let mut inspected = 0;
        for executable in [ipv4, ipv6].into_iter().flatten() {
            if let Ok(output) = Command::new(executable).output()
                && output.status.success()
            {
                let counts = parse_iptables_save(&output.stdout);
                totals.0 += counts.0;
                totals.1 += counts.1;
                totals.2 += counts.2;
                inspected += 1;
            }
        }
        return FirewallStatus {
            backend: "iptables".into(),
            tables: totals.0,
            chains: totals.1,
            rules: totals.2,
            detail: if inspected == 0 {
                "iptables ruleset inspection failed".into()
            } else {
                format!("read-only snapshot from {inspected} address family command(s)")
            },
        };
    }

    let legacy_tables = read_table_names(&paths.proc_net_ip_tables_names)
        + read_table_names(&paths.proc_net_ip6_tables_names);
    FirewallStatus {
        backend: "not available".into(),
        tables: legacy_tables,
        chains: 0,
        rules: 0,
        detail: "no supported firewall listing utility found; kernel table names are incomplete evidence".into(),
    }
}

#[cfg(target_os = "linux")]
fn parse_nft_ruleset(bytes: &[u8]) -> Result<FirewallStatus> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let entries = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .context("missing nftables array")?;
    let mut tables = 0;
    let mut chains = 0;
    let mut rules = 0;
    for entry in entries {
        tables += if entry.get("table").is_some() { 1 } else { 0 };
        chains += if entry.get("chain").is_some() { 1 } else { 0 };
        rules += if entry.get("rule").is_some() { 1 } else { 0 };
    }
    Ok(FirewallStatus {
        backend: "nftables".into(),
        tables,
        chains,
        rules,
        detail: "read-only JSON ruleset snapshot".into(),
    })
}

#[cfg(target_os = "linux")]
fn parse_iptables_save(bytes: &[u8]) -> (usize, usize, usize) {
    let contents = String::from_utf8_lossy(bytes);
    let mut tables = 0;
    let mut chains = 0;
    let mut rules = 0;
    for line in contents.lines() {
        if line.starts_with('*') {
            tables += 1;
        } else if line.starts_with(':') {
            chains += 1;
        } else if line.starts_with("-A ") {
            rules += 1;
        }
    }
    (tables, chains, rules)
}

#[cfg(target_os = "linux")]
fn read_table_names(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|contents| {
            contents
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count()
        })
        .unwrap_or_default()
}

impl NetworkStatus {
    pub fn print(&self) {
        println!("Network inspection (read-only; no changes made)");
        println!("Interfaces: {}", display_list(&self.interfaces));
        println!("TUN/TAP interfaces: {}", display_list(&self.tun_interfaces));
        println!(
            "Default routes: {}",
            if self.routes_inspected {
                display_list(&self.default_routes)
            } else {
                "inspection incomplete (one or both route tables unreadable)".into()
            }
        );
        println!(
            "DNS servers: {}",
            if self.dns_inspected {
                display_list(&self.dns_servers)
            } else {
                "inspection incomplete (resolv.conf unreadable)".into()
            }
        );
        println!(
            "resolv.conf target: {}",
            self.resolv_conf_target
                .as_deref()
                .unwrap_or("regular file or unavailable")
        );
        println!(
            "NetworkManager runtime directory: {}",
            yes_no(self.network_manager_runtime)
        );
        println!(
            "systemd-resolved runtime directory: {}",
            yes_no(self.systemd_resolved_runtime)
        );
        println!(
            "Firewall: {} ({} tables, {} chains, {} rules) — {}",
            self.firewall.backend,
            self.firewall.tables,
            self.firewall.chains,
            self.firewall.rules,
            self.firewall.detail
        );
        println!("No interfaces, routes, DNS settings, or firewall rules were modified.");
    }
}

fn display_list(values: &[String]) -> String {
    if values.is_empty() {
        "none detected".into()
    } else {
        values.join(", ")
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "present" } else { "not detected" }
}

#[cfg(all(target_os = "linux", test))]
mod tests {
    use super::*;

    #[test]
    fn parses_only_active_ipv4_default_routes() {
        let routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 0100000A 0003 0 0 100 00000000\ntun0 00000000 00000000 0000 0 0 0 00000000\n";
        assert_eq!(parse_ipv4_default_routes(routes), ["IPv4 default via eth0"]);
    }

    #[test]
    fn parses_ipv6_default_routes() {
        let routes = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000 00000000 00000000 00000000 00000001 eth0\n00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000 00000000 00000000 00000000 00000000 lo\n20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000 00000000 00000000 00000000 00000001 eth1\n";
        assert_eq!(parse_ipv6_default_routes(routes), ["IPv6 default via eth0"]);
    }

    #[test]
    fn parses_dns_servers_without_other_resolver_options() {
        let resolv = "search example.test\nnameserver 127.0.0.53\noptions edns0 trust-ad\nnameserver 1.1.1.1\n";
        assert_eq!(parse_dns_servers(resolv), ["127.0.0.53", "1.1.1.1"]);
    }

    #[test]
    fn counts_nftables_objects_without_returning_rule_contents() {
        let json = br#"{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"filter"}},{"chain":{"family":"inet","table":"filter","name":"input"}},{"rule":{"family":"inet","table":"filter","chain":"input","expr":[]}}]}"#;
        let status = parse_nft_ruleset(json).unwrap();
        assert_eq!((status.tables, status.chains, status.rules), (1, 1, 1));
        assert_eq!(status.backend, "nftables");
    }

    #[test]
    fn inspects_temporary_system_state_without_running_host_firewall_tools() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let sys_class_net = root.join("sys/class/net");
        let proc_dir = root.join("proc/net");
        let run = root.join("run");
        fs::create_dir_all(sys_class_net.join("eth0")).unwrap();
        fs::create_dir_all(sys_class_net.join("tun0")).unwrap();
        fs::write(sys_class_net.join("tun0/tun_flags"), "0001").unwrap();
        fs::create_dir_all(run.join("NetworkManager")).unwrap();
        fs::create_dir_all(run.join("systemd/resolve")).unwrap();
        fs::create_dir_all(&proc_dir).unwrap();
        fs::write(
            proc_dir.join("route"),
            "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 0100000A 0003 0 0 100 00000000\n",
        )
        .unwrap();
        fs::write(
            proc_dir.join("ipv6_route"),
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000 00000000 00000000 00000000 00000000 eth0\n",
        )
        .unwrap();
        let resolv_conf = root.join("etc/resolv.conf");
        fs::create_dir_all(resolv_conf.parent().unwrap()).unwrap();
        fs::write(&resolv_conf, "nameserver 127.0.0.53\nnameserver 1.1.1.1\n").unwrap();

        let paths = InspectionPaths {
            sys_class_net,
            proc_net_route: proc_dir.join("route"),
            proc_net_ipv6_route: proc_dir.join("ipv6_route"),
            resolv_conf,
            run,
            proc_net_ip_tables_names: proc_dir.join("ip_tables_names"),
            proc_net_ip6_tables_names: proc_dir.join("ip6_tables_names"),
        };
        let firewall = FirewallStatus {
            backend: "test fixture".into(),
            tables: 1,
            chains: 2,
            rules: 3,
            detail: "injected read-only fixture".into(),
        };

        let status = inspect_with_paths_and_firewall(&paths, Some(firewall)).unwrap();
        assert_eq!(status.interfaces, ["eth0", "tun0"]);
        assert_eq!(status.tun_interfaces, ["tun0"]);
        assert_eq!(
            status.default_routes,
            ["IPv4 default via eth0", "IPv6 default via eth0"]
        );
        assert_eq!(status.dns_servers, ["127.0.0.53", "1.1.1.1"]);
        assert!(status.network_manager_runtime);
        assert!(status.systemd_resolved_runtime);
        assert!(status.routes_inspected);
        assert!(status.dns_inspected);
        assert_eq!(status.firewall.rules, 3);
    }

    #[test]
    fn counts_iptables_save_lines() {
        let saved = b"*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n-A INPUT -i lo -j ACCEPT\nCOMMIT\n";
        assert_eq!(parse_iptables_save(saved), (1, 2, 1));
    }
}
