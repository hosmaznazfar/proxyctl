//! Typed Linux rtnetlink route and policy-rule mutation primitives.
#![cfg(target_os = "linux")]
use super::route_policy::{AddressFamily, PlannedRoute, PlannedRule, RouteType};
use super::rtnetlink::RouteNetlink;
use anyhow::{Result, ensure};
use std::time::Duration;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const RTA_OIF: u16 = 4;
const RTA_TABLE: u16 = 15;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_FWMASK: u16 = 11;
const FRA_TABLE: u16 = 15;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const FR_ACT_TO_TBL: u8 = 1;
fn family(f: AddressFamily) -> u8 {
    match f {
        AddressFamily::Ipv4 => libc::AF_INET as u8,
        AddressFamily::Ipv6 => libc::AF_INET6 as u8,
    }
}
fn attr(kind: u16, value: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let len = 4usize
        .checked_add(value.len())
        .ok_or_else(|| anyhow::anyhow!("attribute overflow"))?;
    ensure!(len <= u16::MAX as usize, "attribute too large");
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    Ok(())
}
fn request(kind: u16, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b.extend_from_slice(payload);
    let len = b.len() as u32;
    b[0..4].copy_from_slice(&len.to_ne_bytes());
    b[4..6].copy_from_slice(&kind.to_ne_bytes());
    b[6..8].copy_from_slice(&flags.to_ne_bytes());
    b
}

const RTM_NEWLINK: u16 = 16;
const IFLA_IFALIAS: u16 = 20;

/// Set an activation-generation alias on an interface before making a native TUN persistent.
/// The alias is a recovery identity for the crash window between TUNSETPERSIST and journal ACK.
pub fn set_interface_alias(index: u32, alias: &str) -> Result<()> {
    ensure!(index > 0, "interface alias requires a non-zero ifindex");
    ensure!(!alias.is_empty() && alias.len() <= 240
        && !alias.bytes().any(|byte| byte == 0 || byte.is_ascii_control()),
        "interface alias is empty, oversized, or contains control characters");
    let mut payload = vec![0u8; 16];
    payload[0] = libc::AF_UNSPEC as u8;
    payload[4..8].copy_from_slice(&(index as i32).to_ne_bytes());
    let mut value = alias.as_bytes().to_vec();
    value.push(0);
    attr(IFLA_IFALIAS, &value, &mut payload)?;
    let message = request(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, &payload);
    let mut socket = RouteNetlink::open()?;
    socket.transact(&message, Duration::from_secs(3))?;
    Ok(())
}

/// Installs an exact default unicast route into a dedicated table, using an ACK.
pub fn add_route(route: &PlannedRoute) -> Result<()> {
    ensure!(
        route.interface_index > 0 && route.table_id > 0,
        "route identity invalid"
    );
    ensure!(
        route.destination == route.family.default_prefix(),
        "only default routes supported by this primitive"
    );
    ensure!(
        route.route_type == RouteType::Unicast,
        "only unicast routes supported"
    );
    let mut p = vec![0u8; 12];
    p[0] = family(route.family);
    p[4] = RTPROT_STATIC;
    p[5] = RT_SCOPE_UNIVERSE;
    p[6] = RTN_UNICAST;
    p[7] = 0;
    let mut attrs = Vec::new();
    attr(RTA_OIF, &route.interface_index.to_ne_bytes(), &mut attrs)?;
    attr(RTA_TABLE, &route.table_id.to_ne_bytes(), &mut attrs)?;
    p.extend(attrs);
    let mut nl = request(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        &p,
    );
    let mut sock = RouteNetlink::open()?;
    sock.transact(&nl, Duration::from_secs(3))?;
    nl.clear();
    Ok(())
}
/// Installs a typed routing policy rule. The selector and table are encoded as attributes.
pub fn add_rule(rule: &PlannedRule) -> Result<()> {
    ensure!(
        rule.priority > 0 && rule.lookup_table > 0,
        "rule identity invalid"
    );
    let mut p = vec![0u8; 12];
    p[0] = family(rule.family);
    p[7] = FR_ACT_TO_TBL;
    let mut attrs = Vec::new();
    attr(FRA_PRIORITY, &rule.priority.to_ne_bytes(), &mut attrs)?;
    attr(FRA_TABLE, &rule.lookup_table.to_ne_bytes(), &mut attrs)?;
    if let Some(mark) = rule.mark {
        ensure!(
            mark.mask != 0 && mark.value & !mark.mask == 0,
            "invalid mark selector"
        );
        attr(FRA_FWMARK, &mark.value.to_ne_bytes(), &mut attrs)?;
        attr(FRA_FWMASK, &mark.mask.to_ne_bytes(), &mut attrs)?;
    }
    p.extend(attrs);
    let nl = request(
        RTM_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        &p,
    );
    let mut sock = RouteNetlink::open()?;
    sock.transact(&nl, Duration::from_secs(3))?;
    Ok(())
}

/// Removes a route only by its exact default prefix, table, and interface selector.
pub fn delete_route(route: &PlannedRoute) -> Result<()> {
    ensure!(
        route.interface_index > 0
            && route.table_id > 0
            && route.destination == route.family.default_prefix(),
        "route deletion selector invalid"
    );
    ensure!(
        route.route_type == RouteType::Unicast,
        "only unicast route deletion supported"
    );
    let mut p = vec![0u8; 12];
    p[0] = family(route.family);
    p[4] = RTPROT_STATIC;
    p[5] = RT_SCOPE_UNIVERSE;
    p[6] = RTN_UNICAST;
    let mut attrs = Vec::new();
    attr(RTA_OIF, &route.interface_index.to_ne_bytes(), &mut attrs)?;
    attr(RTA_TABLE, &route.table_id.to_ne_bytes(), &mut attrs)?;
    p.extend(attrs);
    let nl = request(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, &p);
    let mut sock = RouteNetlink::open()?;
    sock.transact(&nl, Duration::from_secs(3))?;
    Ok(())
}
/// Removes a policy rule using the exact priority/table and optional mark selector.
pub fn delete_rule(rule: &PlannedRule) -> Result<()> {
    ensure!(
        rule.priority > 0 && rule.lookup_table > 0,
        "rule deletion selector invalid"
    );
    let mut p = vec![0u8; 12];
    p[0] = family(rule.family);
    p[7] = FR_ACT_TO_TBL;
    let mut attrs = Vec::new();
    attr(FRA_PRIORITY, &rule.priority.to_ne_bytes(), &mut attrs)?;
    attr(FRA_TABLE, &rule.lookup_table.to_ne_bytes(), &mut attrs)?;
    if let Some(mark) = rule.mark {
        ensure!(
            mark.mask != 0 && mark.value & !mark.mask == 0,
            "invalid mark selector"
        );
        attr(FRA_FWMARK, &mark.value.to_ne_bytes(), &mut attrs)?;
        attr(FRA_FWMASK, &mark.mask.to_ne_bytes(), &mut attrs)?;
    }
    p.extend(attrs);
    let nl = request(RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, &p);
    let mut sock = RouteNetlink::open()?;
    sock.transact(&nl, Duration::from_secs(3))?;
    Ok(())
}
