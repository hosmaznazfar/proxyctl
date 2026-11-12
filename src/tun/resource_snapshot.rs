//! Read-only comparison of durable ownership records with a kernel snapshot.
//!
//! Snapshot comparison is advisory: the kernel can change immediately after inspection.
//! A production cleanup backend must still perform an atomic compare-and-delete operation.

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::{
    kernel_inventory::{KernelRouteRecord, KernelRuleRecord, KernelSnapshot},
    ownership::RouteManifest,
    route_policy::AddressFamily,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotResourceState {
    PresentAndMatching,
    Absent,
    ChangedOrAmbiguous,
    UnsupportedIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceComparison {
    pub key: String,
    pub state: SnapshotResourceState,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SnapshotComparison {
    pub resources: Vec<ResourceComparison>,
}

impl SnapshotComparison {
    /// True only when every manifest key is understood and is either absent or exact.
    ///
    /// This is not permission to delete: callers must re-check atomically in the
    /// privileged backend immediately before each mutation.
    pub fn has_no_conflicts(&self) -> bool {
        self.resources.iter().all(|resource| {
            matches!(
                resource.state,
                SnapshotResourceState::PresentAndMatching | SnapshotResourceState::Absent
            )
        })
    }
}

/// Compare every manifest resource against one immutable read-only kernel snapshot.
///
/// Supported stable keys:
/// - `route:v4:<table-id>:<destination>`
/// - `route:v6:<table-id>:<destination>`
/// - `rule:v4:<priority>`
/// - `rule:v6:<priority>`
///
/// Route identity is family + table + destination. The full canonical JSON record is
/// compared as the fingerprint, so changed gateway/device/metric/protocol attributes
/// are conflicts. Rule identity is family + priority, with every selector/action retained
/// in the canonical fingerprint.
pub fn compare_manifest(
    manifest: &RouteManifest,
    snapshot: &KernelSnapshot,
) -> Result<SnapshotComparison> {
    manifest.validate()?;
    let mut comparison = SnapshotComparison::default();

    for resource in &manifest.resources {
        let state = match parse_resource_key(&resource.key) {
            Ok(ResourceKey::Route {
                family,
                table_id,
                destination,
            }) if table_id == manifest.table_id && destination == family.default_prefix() => {
                compare_route(
                    family,
                    table_id,
                    &destination,
                    &manifest.interface_name,
                    &resource.fingerprint,
                    &snapshot.routes,
                )
            }
            Ok(ResourceKey::Rule { family, priority }) if priority > 0 => compare_rule(
                family,
                priority,
                &resource.fingerprint,
                &snapshot.rules,
            ),
            Err(_) => SnapshotResourceState::UnsupportedIdentity,
        };
        comparison.resources.push(ResourceComparison {
            key: resource.key.clone(),
            state,
        });
    }

    Ok(comparison)
}

enum ResourceKey {
    Route {
        family: AddressFamily,
        table_id: u32,
        destination: String,
    },
    Rule {
        family: AddressFamily,
        priority: u32,
    },
}

fn parse_resource_key(key: &str) -> Result<ResourceKey> {
    let mut fields = key.splitn(4, ':');
    let kind = fields.next().unwrap_or_default();
    let family = parse_family(fields.next().context("resource key has no family")?)?;

    match kind {
        "route" => {
            let table_id = fields
                .next()
                .context("route resource key has no table ID")?
                .parse::<u32>()
                .context("route resource key has an invalid table ID")?;
            let destination = fields
                .next()
                .context("route resource key has no destination")?;
            ensure!(table_id > 0, "route resource table ID must be non-zero");
            ensure!(!destination.is_empty(), "route resource destination is empty");
            Ok(ResourceKey::Route {
                family,
                table_id,
                destination: destination.to_owned(),
            })
        }
        "rule" => {
            let priority = fields
                .next()
                .context("rule resource key has no priority")?
                .parse::<u32>()
                .context("rule resource key has an invalid priority")?;
            ensure!(fields.next().is_none(), "rule resource key has extra fields");
            Ok(ResourceKey::Rule { family, priority })
        }
        _ => anyhow::bail!("unsupported manifest resource kind"),
    }
}

fn parse_family(value: &str) -> Result<AddressFamily> {
    match value {
        "v4" => Ok(AddressFamily::Ipv4),
        "v6" => Ok(AddressFamily::Ipv6),
        _ => anyhow::bail!("unsupported resource address family"),
    }
}

fn compare_route(
    family: AddressFamily,
    table_id: u32,
    destination: &str,
    interface_name: &str,
    expected: &str,
    routes: &[KernelRouteRecord],
) -> SnapshotResourceState {
    let matches = routes
        .iter()
        .filter(|route| {
            if route.family != family || route.table_id != table_id {
                return false;
            }
            let Ok(value) = serde_json::from_str::<Value>(&route.canonical_attributes) else {
                return false;
            };
            let route_destination = value.get("dst").and_then(Value::as_str);
            let destination_matches = route_destination.is_some_and(|actual| {
                actual == destination
                    || (actual == "default"
                        && matches!(
                            (family, destination),
                            (AddressFamily::Ipv4, "0.0.0.0/0")
                                | (AddressFamily::Ipv6, "::/0")
                        ))
            });
            destination_matches
        })
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => SnapshotResourceState::Absent,
        [route]
            if route.canonical_attributes == expected
                && serde_json::from_str::<Value>(&route.canonical_attributes)
                    .ok()
                    .and_then(|value| value.get("dev").and_then(Value::as_str).map(str::to_owned))
                    .as_deref()
                    == Some(interface_name) =>
        {
            SnapshotResourceState::PresentAndMatching
        }
        [_] | [_, _, ..] => SnapshotResourceState::ChangedOrAmbiguous,
    }
}

fn compare_rule(
    family: AddressFamily,
    priority: u32,
    expected: &str,
    rules: &[KernelRuleRecord],
) -> SnapshotResourceState {
    let matches = rules
        .iter()
        .filter(|rule| rule.family == family && rule.priority == priority)
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => SnapshotResourceState::Absent,
        [rule] if rule.canonical_attributes == expected => {
            SnapshotResourceState::PresentAndMatching
        }
        [_] | [_, _, ..] => SnapshotResourceState::ChangedOrAmbiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::ownership::{MANIFEST_VERSION, OwnedResource};

    fn fixture() -> (RouteManifest, KernelSnapshot) {
        let ipv4_route = r#"{"dev":"tun-proxyctl","dst":"default","protocol":"static","table":42420}"#;
        let ipv6_route = r#"{"dev":"tun-proxyctl","dst":"default","protocol":"static","table":42420}"#;
        let ipv4_rule = r#"{"fwmark":"0x42/0xff","priority":42410,"table":254}"#;
        let snapshot = KernelSnapshot {
            inventory: Default::default(),
            routes: vec![
                KernelRouteRecord {
                    family: AddressFamily::Ipv4,
                    table_id: 42420,
                    canonical_attributes: ipv4_route.into(),
                },
                KernelRouteRecord {
                    family: AddressFamily::Ipv6,
                    table_id: 42420,
                    canonical_attributes: ipv6_route.into(),
                },
            ],
            rules: vec![
                KernelRuleRecord {
                    family: AddressFamily::Ipv4,
                    priority: 42410,
                    table_id: Some(254),
                    canonical_attributes: ipv4_rule.into(),
                },
                KernelRuleRecord {
                    family: AddressFamily::Ipv6,
                    priority: 42410,
                    table_id: Some(254),
                    canonical_attributes: ipv4_rule.into(),
                },
            ],
        };
        let resources = vec![
            OwnedResource {
                key: "route:v4:42420:0.0.0.0/0".into(),
                fingerprint: snapshot.routes[0].canonical_attributes.clone(),
            },
            OwnedResource {
                key: "route:v6:42420:::/0".into(),
                fingerprint: snapshot.routes[1].canonical_attributes.clone(),
            },
            OwnedResource {
                key: "rule:v4:42410".into(),
                fingerprint: snapshot.rules[0].canonical_attributes.clone(),
            },
        ];
        (
            RouteManifest {
                version: MANIFEST_VERSION,
                activation_id: "12345678-1234-4234-8234-123456789abc".into(),
                table_id: 42420,
                rule_priority: 42410,
                interface_name: "tun-proxyctl".into(),
                interface_index: 77,
                resources,
            },
            snapshot,
        )
    }

    #[test]
    fn recognizes_exact_dual_stack_routes_and_rule_selectors() {
        let (manifest, snapshot) = fixture();
        let comparison = compare_manifest(&manifest, &snapshot).unwrap();
        assert!(comparison.has_no_conflicts());
        assert_eq!(comparison.resources.len(), 3);
        assert!(
            comparison.resources.iter().all(|resource| {
                resource.state == SnapshotResourceState::PresentAndMatching
            })
        );
    }

    #[test]
    fn treats_missing_resources_as_idempotently_absent() {
        let (manifest, _) = fixture();
        let comparison = compare_manifest(&manifest, &KernelSnapshot::default()).unwrap();
        assert!(comparison.has_no_conflicts());
        assert!(
            comparison
                .resources
                .iter()
                .all(|resource| resource.state == SnapshotResourceState::Absent)
        );
    }

    #[test]
    fn changed_route_or_rule_attributes_are_conflicts() {
        let (manifest, mut snapshot) = fixture();
        snapshot.routes[0].canonical_attributes = r#"{"dev":"eth0","dst":"default","protocol":"static","table":42420}"#.into();
        snapshot.rules[0].canonical_attributes = r#"{"priority":42410,"table":254}"#.into();
        let comparison = compare_manifest(&manifest, &snapshot).unwrap();
        assert_eq!(
            comparison.resources[0].state,
            SnapshotResourceState::ChangedOrAmbiguous
        );
        assert_eq!(
            comparison.resources[2].state,
            SnapshotResourceState::ChangedOrAmbiguous
        );
        assert!(!comparison.has_no_conflicts());
    }

    #[test]
    fn duplicate_kernel_identity_and_unknown_manifest_keys_fail_closed() {
        let (mut manifest, mut snapshot) = fixture();
        snapshot.routes.push(snapshot.routes[0].clone());
        let comparison = compare_manifest(&manifest, &snapshot).unwrap();
        assert_eq!(
            comparison.resources[0].state,
            SnapshotResourceState::ChangedOrAmbiguous
        );

        manifest.resources[0].key = "firewall:table:proxyctl".into();
        let comparison = compare_manifest(&manifest, &snapshot).unwrap();
        assert_eq!(
            comparison.resources[0].state,
            SnapshotResourceState::UnsupportedIdentity
        );
        assert!(!comparison.has_no_conflicts());
    }

    #[test]
    fn malformed_resource_keys_do_not_get_guessed() {
        let (mut manifest, snapshot) = fixture();
        manifest.resources[0].key = "route:v7:42420:0.0.0.0/0".into();
        assert_eq!(
            compare_manifest(&manifest, &snapshot).unwrap().resources[0].state,
            SnapshotResourceState::UnsupportedIdentity
        );
    }
}
