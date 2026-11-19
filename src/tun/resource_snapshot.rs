//! Read-only comparison of durable ownership records with a kernel snapshot.
//!
//! Snapshot comparison is advisory: the kernel can change immediately after inspection.
//! A production cleanup backend must still perform an atomic compare-and-delete operation.

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::{
    kernel_inventory::{
        KernelInterfaceRecord, KernelRouteRecord, KernelRuleRecord, KernelSnapshot,
    },
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
    pub interface_state: Option<SnapshotResourceState>,
}

impl SnapshotComparison {
    /// True only when every manifest key is understood and is either absent or exact.
    ///
    /// This is not permission to delete: callers must re-check atomically in the
    /// privileged backend immediately before each mutation.
    pub fn has_no_conflicts(&self) -> bool {
        self.interface_state.is_none_or(|state| {
            matches!(
                state,
                SnapshotResourceState::PresentAndMatching | SnapshotResourceState::Absent
            )
        }) && self.resources.iter().all(|resource| {
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
    let mut comparison = SnapshotComparison {
        interface_state: Some(compare_interface(
            &manifest.interface_name,
            manifest.interface_index,
            &snapshot.interfaces,
        )),
        ..SnapshotComparison::default()
    };

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
            Ok(ResourceKey::Rule { family, priority }) if priority > 0 => {
                compare_rule(family, priority, &resource.fingerprint, &snapshot.rules)
            }
            Ok(_) | Err(_) => SnapshotResourceState::UnsupportedIdentity,
        };
        comparison.resources.push(ResourceComparison {
            key: resource.key.clone(),
            state,
        });
    }

    Ok(comparison)
}

fn compare_interface(
    expected_name: &str,
    expected_index: u32,
    interfaces: &[KernelInterfaceRecord],
) -> SnapshotResourceState {
    let by_name = interfaces
        .iter()
        .filter(|item| item.name == expected_name)
        .collect::<Vec<_>>();
    let by_index = interfaces
        .iter()
        .filter(|item| item.index == expected_index)
        .collect::<Vec<_>>();
    match (by_name.as_slice(), by_index.as_slice()) {
        ([], []) => SnapshotResourceState::Absent,
        ([interface], [same])
            if interface.name == same.name
                && interface.index == expected_index
                && interface.is_tun =>
        {
            SnapshotResourceState::PresentAndMatching
        }
        _ => SnapshotResourceState::ChangedOrAmbiguous,
    }
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
            let table_id = parse_canonical_positive_u32(
                fields
                    .next()
                    .context("route resource key has no table ID")?,
                "route resource table ID",
            )?;
            let destination = fields
                .next()
                .context("route resource key has no destination")?;
            ensure!(table_id > 0, "route resource table ID must be non-zero");
            ensure!(
                !destination.is_empty(),
                "route resource destination is empty"
            );
            Ok(ResourceKey::Route {
                family,
                table_id,
                destination: destination.to_owned(),
            })
        }
        "rule" => {
            let priority = parse_canonical_positive_u32(
                fields.next().context("rule resource key has no priority")?,
                "rule resource priority",
            )?;
            ensure!(
                fields.next().is_none(),
                "rule resource key has extra fields"
            );
            Ok(ResourceKey::Rule { family, priority })
        }
        _ => anyhow::bail!("unsupported manifest resource kind"),
    }
}

fn parse_canonical_positive_u32(value: &str, label: &str) -> Result<u32> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "{label} is not canonical decimal"
    );
    let parsed = value.parse::<u32>().with_context(|| label.to_owned())?;
    ensure!(
        parsed > 0 && parsed.to_string() == value,
        "{label} is not canonical positive decimal"
    );
    Ok(parsed)
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
    let family_table_routes = routes
        .iter()
        .filter(|route| route.family == family && route.table_id == table_id)
        .collect::<Vec<_>>();
    if family_table_routes
        .iter()
        .any(|route| serde_json::from_str::<Value>(&route.canonical_attributes).is_err())
    {
        return SnapshotResourceState::ChangedOrAmbiguous;
    }
    let matches = family_table_routes
        .into_iter()
        .filter(|route| {
            let Ok(value) = serde_json::from_str::<Value>(&route.canonical_attributes) else {
                return false;
            };
            let route_destination = value.get("dst").and_then(Value::as_str);
            route_destination.is_some_and(|actual| {
                actual == destination
                    || (actual == "default"
                        && matches!(
                            (family, destination),
                            (AddressFamily::Ipv4, "0.0.0.0/0") | (AddressFamily::Ipv6, "::/0")
                        ))
            })
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


/// Build the exact observed-fingerprint map required by journal recovery from one fresh
/// kernel snapshot. Fingerprints are copied from live canonical records, never reconstructed
/// from planned route/rule attributes. Every journal key receives an observation; an absent
/// exact identity is represented by `None`.
pub fn observe_journal_resources(
    journal: &super::journal::TransactionJournal,
    snapshot: &KernelSnapshot,
) -> Result<std::collections::BTreeMap<String, Option<String>>> {
    use super::journal::JournalOperationKind;

    journal.validate()?;
    let mut observations = std::collections::BTreeMap::new();
    for operation in &journal.operations {
        let fingerprint = match operation.kind {
            JournalOperationKind::CreateInterface => {
                let name = operation
                    .resource_key
                    .strip_prefix("interface:")
                    .context("invalid journal interface key")?;
                let matches = snapshot
                    .interfaces
                    .iter()
                    .filter(|interface| interface.name == name)
                    .collect::<Vec<_>>();
                match matches.as_slice() {
                    [] => None,
                    [interface] if interface.is_tun => Some(serde_json::to_string(
                        &serde_json::json!({
                            "ifindex": interface.index,
                            "kind": "tun",
                            "name": interface.name
                        }),
                    )?),
                    _ => anyhow::bail!("journal interface identity is changed or ambiguous")
                }
            }
            JournalOperationKind::AddRoute => {
                let ResourceKey::Route {
                    family,
                    table_id,
                    destination,
                } = parse_resource_key(&operation.resource_key)?
                else {
                    anyhow::bail!("journal route key has an unsupported identity")
                };
                let candidates = snapshot
                    .routes
                    .iter()
                    .filter(|route| route.family == family && route.table_id == table_id)
                    .filter_map(|route| {
                        let value: Value = serde_json::from_str(&route.canonical_attributes).ok()?;
                        let actual = value.get("dst")?.as_str()?;
                        let same_destination = actual == destination
                            || (actual == "default"
                                && matches!(
                                    (family, destination.as_str()),
                                    (AddressFamily::Ipv4, "0.0.0.0/0")
                                        | (AddressFamily::Ipv6, "::/0")
                                ));
                        same_destination.then_some(route)
                    })
                    .collect::<Vec<_>>();
                match candidates.as_slice() {
                    [] => None,
                    [route] => Some(route.canonical_attributes.clone()),
                    [_, ..] => anyhow::bail!(
                        "journal route identity has duplicate live kernel records"
                    ),
                }
            }
            JournalOperationKind::AddRule => {
                let ResourceKey::Rule { family, priority } =
                    parse_resource_key(&operation.resource_key)?
                else {
                    anyhow::bail!("journal rule key has an unsupported identity")
                };
                let matches = snapshot
                    .rules
                    .iter()
                    .filter(|rule| rule.family == family && rule.priority == priority)
                    .collect::<Vec<_>>();
                match matches.as_slice() {
                    [] => None,
                    [rule] => Some(rule.canonical_attributes.clone()),
                    [_, ..] => anyhow::bail!(
                        "journal rule identity has duplicate live kernel records"
                    ),
                }
            }
        };
        // The route's live record must be attributed to the activation's exact TUN name.
        // A route with the same family/table/destination but another device remains an
        // observed fingerprint and will conflict with the journal's applied fingerprint.
        if operation.kind == JournalOperationKind::AddRoute
            && let Some(value) = &fingerprint
        {
            let record: Value = serde_json::from_str(value)
                .context("live route canonical attributes are malformed")?;
            ensure!(
                record
                    .get("dev")
                    .and_then(Value::as_str)
                    .is_some_and(|name| !name.is_empty()),
                "live route identity has no interface selector"
            );
        }
        observations.insert(operation.resource_key.clone(), fingerprint);
    }
    Ok(observations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::ownership::{MANIFEST_VERSION, OwnedResource};

    fn fixture() -> (RouteManifest, KernelSnapshot) {
        let ipv4_route =
            r#"{"dev":"tun-proxyctl","dst":"default","protocol":"static","table":42420}"#;
        let ipv6_route =
            r#"{"dev":"tun-proxyctl","dst":"default","protocol":"static","table":42420}"#;
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
            #[cfg(target_os = "linux")]
            netlink_interface_count: 0,
            interfaces: vec![KernelInterfaceRecord {
                name: "tun-proxyctl".into(),
                index: 77,
                is_tun: true,
            }],
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
            comparison
                .resources
                .iter()
                .all(|resource| { resource.state == SnapshotResourceState::PresentAndMatching })
        );
    }

    #[test]
    fn treats_missing_resources_as_idempotently_absent() {
        let (manifest, _) = fixture();
        let comparison = compare_manifest(&manifest, &KernelSnapshot::default()).unwrap();
        assert!(comparison.has_no_conflicts());
        assert_eq!(
            comparison.interface_state,
            Some(SnapshotResourceState::Absent)
        );
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
        snapshot.routes[0].canonical_attributes =
            r#"{"dev":"eth0","dst":"default","protocol":"static","table":42420}"#.into();
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
    fn malformed_route_snapshot_attributes_are_ambiguous_not_absent() {
        let (manifest, mut snapshot) = fixture();
        snapshot.routes[0].canonical_attributes = "not-json".into();
        let comparison = compare_manifest(&manifest, &snapshot).unwrap();
        assert_eq!(
            comparison.resources[0].state,
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
    fn manifest_keys_outside_its_dedicated_default_route_table_fail_closed() {
        let (mut manifest, snapshot) = fixture();
        manifest.resources[0].key = "route:v4:254:0.0.0.0/0".into();
        assert_eq!(
            compare_manifest(&manifest, &snapshot).unwrap().resources[0].state,
            SnapshotResourceState::UnsupportedIdentity
        );

        manifest.resources[0].key = "route:v4:42420:10.0.0.0/8".into();
        assert_eq!(
            compare_manifest(&manifest, &snapshot).unwrap().resources[0].state,
            SnapshotResourceState::UnsupportedIdentity
        );
    }

    #[test]
    fn interface_name_index_and_tun_kind_must_match_exactly() {
        let (manifest, mut snapshot) = fixture();
        assert_eq!(
            compare_manifest(&manifest, &snapshot)
                .unwrap()
                .interface_state,
            Some(SnapshotResourceState::PresentAndMatching)
        );

        snapshot.interfaces[0].index = 78;
        assert_eq!(
            compare_manifest(&manifest, &snapshot)
                .unwrap()
                .interface_state,
            Some(SnapshotResourceState::ChangedOrAmbiguous)
        );

        snapshot.interfaces[0].index = 77;
        snapshot.interfaces[0].is_tun = false;
        assert_eq!(
            compare_manifest(&manifest, &snapshot)
                .unwrap()
                .interface_state,
            Some(SnapshotResourceState::ChangedOrAmbiguous)
        );

        snapshot.interfaces[0].is_tun = true;
        snapshot.interfaces[0].name = "foreign0".into();
        assert_eq!(
            compare_manifest(&manifest, &snapshot)
                .unwrap()
                .interface_state,
            Some(SnapshotResourceState::ChangedOrAmbiguous)
        );
    }

    #[test]
    fn resource_keys_reject_zero_and_noncanonical_numeric_aliases() {
        for key in ["rule:v4:0", "rule:v4:042410", "route:v4:042420:0.0.0.0/0"] {
            let (mut manifest, snapshot) = fixture();
            manifest.resources[0].key = key.into();
            let comparison = compare_manifest(&manifest, &snapshot).unwrap();
            assert_eq!(
                comparison.resources[0].state,
                SnapshotResourceState::UnsupportedIdentity,
                "accepted {key}"
            );
        }
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
