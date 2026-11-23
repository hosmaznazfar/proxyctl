//! Typed Linux rtnetlink route and policy-rule mutation primitives.
#![cfg(target_os = "linux")]
use super::route_policy::{AddressFamily, PlannedRoute, PlannedRule, RouteType};
use super::rtnetlink::RouteNetlink;
use anyhow::{Result, ensure};
use std::time::Duration;
const RTM_NEWROUTE: u16 = 24;
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
const FRA_FWMASK: u16 = 16;
const FRA_TABLE: u16 = 15;
const FRA_PROTOCOL: u16 = 19;
// Locally assigned protocol marker used to distinguish Proxyctl-owned routes/rules.
const PROXYCTL_ROUTE_PROTOCOL: u8 = 99;
const RTPROT_PROXYCTL: u8 = PROXYCTL_ROUTE_PROTOCOL;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const FR_ACT_TO_TBL: u8 = 1;
fn set_proxyctl_route_protocol(header: &mut [u8]) -> Result<()> {
    ensure!(header.len() >= 8, "route header is truncated");
    header[4] = RTPROT_PROXYCTL;
    Ok(())
}

fn append_proxyctl_rule_protocol(attrs: &mut Vec<u8>) -> Result<()> {
    attr(FRA_PROTOCOL, &[PROXYCTL_ROUTE_PROTOCOL], attrs)
}

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

fn validate_interface_alias(index: u32, alias: &str) -> Result<()> {
    ensure!(index > 0, "interface alias requires a non-zero ifindex");
    ensure!(
        !alias.is_empty()
            && alias.len() <= 240
            && !alias
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control()),
        "interface alias is empty, oversized, or contains control characters"
    );
    Ok(())
}

/// Set an activation-generation alias on an interface before making a native TUN persistent.
/// The alias is a recovery identity for the crash window between TUNSETPERSIST and journal ACK.
pub fn set_interface_alias(index: u32, alias: &str) -> Result<()> {
    validate_interface_alias(index, alias)?;
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
    set_proxyctl_route_protocol(&mut p)?;
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
fn rule_payload(rule: &PlannedRule) -> Result<Vec<u8>> {
    ensure!(
        rule.priority > 0 && rule.lookup_table > 0,
        "rule identity invalid"
    );
    ensure!(
        matches!(
            (rule.purpose, rule.mark),
            (super::route_policy::RulePurpose::ProxyTraffic, None)
                | (super::route_policy::RulePurpose::CoreTrafficBypass, Some(_))
        ),
        "rule purpose and mark selector disagree"
    );
    let mut payload = vec![0u8; 12];
    payload[0] = family(rule.family);
    payload[7] = FR_ACT_TO_TBL;
    let mut attrs = Vec::new();
    attr(FRA_PRIORITY, &rule.priority.to_ne_bytes(), &mut attrs)?;
    attr(FRA_TABLE, &rule.lookup_table.to_ne_bytes(), &mut attrs)?;
    append_proxyctl_rule_protocol(&mut attrs)?;
    if let Some(mark) = rule.mark {
        ensure!(
            mark.mask != 0 && mark.value & !mark.mask == 0,
            "invalid mark selector"
        );
        attr(FRA_FWMARK, &mark.value.to_ne_bytes(), &mut attrs)?;
        attr(FRA_FWMASK, &mark.mask.to_ne_bytes(), &mut attrs)?;
    }
    payload.extend(attrs);
    Ok(payload)
}

/// Installs a typed routing policy rule. The selector and table are encoded as attributes.
pub fn add_rule(rule: &PlannedRule) -> Result<()> {
    let payload = rule_payload(rule)?;
    let nl = request(
        RTM_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        &payload,
    );
    let mut sock = RouteNetlink::open()?;
    sock.transact(&nl, Duration::from_secs(3))?;
    Ok(())
}

/// Removes a policy rule using its typed identity and Proxyctl protocol marker.
///
/// The unmarked proxy-traffic rule intentionally has no fwmark attribute because it must
/// match all traffic marks. Linux therefore treats omitted mark/interface/UID/port selectors
/// as wildcards in fib_rule_find; the complete live fingerprint check cannot make those
/// omitted kernel delete selectors exact. This limitation is documented in TUN_DESIGN.md.
pub fn delete_rule(rule: &PlannedRule) -> Result<()> {
    let payload = rule_payload(rule)?;
    let nl = request(RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, &payload);
    let mut sock = RouteNetlink::open()?;
    sock.transact(&nl, Duration::from_secs(3))?;
    Ok(())
}

#[cfg(test)]
mod interface_alias_tests {
    use super::*;

    #[test]
    fn proxyctl_route_protocol_marker_is_written_to_route_header() {
        let mut header = [0u8; 12];
        set_proxyctl_route_protocol(&mut header).unwrap();
        assert_eq!(header[4], 99);
        assert!(set_proxyctl_route_protocol(&mut header[..4]).is_err());
    }

    #[test]
    fn proxyctl_rule_protocol_marker_is_encoded_as_exact_u8_selector() {
        let mut attrs = Vec::new();
        append_proxyctl_rule_protocol(&mut attrs).unwrap();
        assert_eq!(u16::from_ne_bytes(attrs[0..2].try_into().unwrap()), 5);
        assert_eq!(
            u16::from_ne_bytes(attrs[2..4].try_into().unwrap()),
            FRA_PROTOCOL
        );
        assert_eq!(attrs[4], PROXYCTL_ROUTE_PROTOCOL);
        assert_eq!(RTPROT_PROXYCTL, PROXYCTL_ROUTE_PROTOCOL);
        assert_eq!(FRA_FWMARK, 10);
        assert_eq!(FRA_FWMASK, 16);
        assert_eq!(FRA_TABLE, 15);
        assert_eq!(FRA_PROTOCOL, 19);
        let mut mask_attribute = Vec::new();
        attr(FRA_FWMASK, &0xffu32.to_ne_bytes(), &mut mask_attribute).unwrap();
        assert_eq!(
            u16::from_ne_bytes(mask_attribute[2..4].try_into().unwrap()),
            16
        );
    }

    fn find_attribute(payload: &[u8], wanted: u16) -> Option<&[u8]> {
        let mut offset = 12usize;
        while offset + 4 <= payload.len() {
            let length = u16::from_ne_bytes(payload[offset..offset + 2].try_into().ok()?) as usize;
            let kind = u16::from_ne_bytes(payload[offset + 2..offset + 4].try_into().ok()?);
            if length < 4 || offset + length > payload.len() {
                return None;
            }
            if kind == wanted {
                return Some(&payload[offset + 4..offset + length]);
            }
            offset = (offset + length + 3) & !3;
        }
        None
    }

    #[test]
    fn rule_payload_pins_protocol_and_marked_bypass_selectors() {
        use super::super::route_policy::{MarkSelector, RulePurpose};
        let proxy = PlannedRule {
            family: AddressFamily::Ipv4,
            priority: 42_420,
            purpose: RulePurpose::ProxyTraffic,
            mark: None,
            lookup_table: 42_420,
        };
        let proxy_payload = rule_payload(&proxy).unwrap();
        assert_eq!(proxy_payload[0], libc::AF_INET as u8);
        assert_eq!(proxy_payload[7], FR_ACT_TO_TBL);
        assert_eq!(
            find_attribute(&proxy_payload, FRA_PROTOCOL),
            Some(&[PROXYCTL_ROUTE_PROTOCOL][..])
        );
        // No mark selector is correct for the all-traffic proxy rule, but means the
        // kernel's delete matcher treats any mark condition on a colliding rule as wildcard.
        assert!(find_attribute(&proxy_payload, FRA_FWMARK).is_none());
        assert!(find_attribute(&proxy_payload, FRA_FWMASK).is_none());

        let bypass = PlannedRule {
            family: AddressFamily::Ipv6,
            priority: 42_410,
            purpose: RulePurpose::CoreTrafficBypass,
            mark: Some(MarkSelector { value: 0x42, mask: 0xff }),
            lookup_table: 42_420,
        };
        let bypass_payload = rule_payload(&bypass).unwrap();
        assert_eq!(
            find_attribute(&bypass_payload, FRA_FWMARK),
            Some(&0x42u32.to_ne_bytes()[..])
        );
        assert_eq!(
            find_attribute(&bypass_payload, FRA_FWMASK),
            Some(&0xffu32.to_ne_bytes()[..])
        );
    }

    #[test]
    fn rule_payload_rejects_purpose_mark_mismatch() {
        use super::super::route_policy::RulePurpose;
        let invalid = PlannedRule {
            family: AddressFamily::Ipv4,
            priority: 42_420,
            purpose: RulePurpose::ProxyTraffic,
            mark: Some(super::super::route_policy::MarkSelector { value: 1, mask: 1 }),
            lookup_table: 42_420,
        };
        assert!(rule_payload(&invalid).is_err());
    }

    #[test]
    fn validates_generation_alias_before_netlink_mutation() {
        assert!(validate_interface_alias(7, "proxyctl:activation:1").is_ok());
        assert!(validate_interface_alias(0, "proxyctl:activation:1").is_err());
        assert!(validate_interface_alias(7, "").is_err());
        assert!(validate_interface_alias(7, &"x".repeat(241)).is_err());
        assert!(validate_interface_alias(7, "bad\nalias").is_err());
    }
}
