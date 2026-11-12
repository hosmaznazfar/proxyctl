//! Exact, manifest-driven ownership and idempotent cleanup planning.
//!
//! This module has no Linux networking implementation. Production mutation must be supplied
//! by a backend that can conditionally delete an exact resource identity. Tests use memory only.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedResource {
    pub key: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteManifest {
    pub version: u32,
    pub activation_id: String,
    pub table_id: u32,
    pub rule_priority: u32,
    pub interface_name: String,
    pub interface_index: u32,
    pub resources: Vec<OwnedResource>,
}

impl RouteManifest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == MANIFEST_VERSION,
            "unsupported TUN manifest version"
        );
        ensure!(
            valid_activation_id(&self.activation_id),
            "invalid activation identity"
        );
        ensure!(self.table_id > 0, "routing table ID must be non-zero");
        ensure!(
            self.rule_priority > 0,
            "policy-rule priority must be non-zero"
        );
        ensure!(
            !self.interface_name.is_empty()
                && !self.interface_name.contains('/')
                && self.interface_name.len() <= 15,
            "invalid TUN interface name"
        );
        ensure!(
            self.interface_index > 0,
            "TUN interface index must be non-zero"
        );
        let mut keys = BTreeSet::new();
        for resource in &self.resources {
            ensure!(!resource.key.is_empty(), "owned resource key is empty");
            ensure!(
                !resource.fingerprint.is_empty(),
                "owned resource fingerprint is empty"
            );
            ensure!(
                keys.insert(&resource.key),
                "duplicate resource identity in manifest"
            );
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec_pretty(self)?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(manifest)
    }
}

fn valid_activation_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState {
    Removed,
    AlreadyAbsent,
    ChangedOrForeign,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CleanupReport {
    pub removed: Vec<String>,
    pub already_absent: Vec<String>,
    pub conflicts: Vec<String>,
}

/// Implementations must compare the complete current identity/fingerprint before deletion.
/// remove_if_matches must be atomic with respect to the backend resource mutation.
pub trait OwnedResourceBackend {
    fn fingerprint(&mut self, key: &str) -> Result<Option<String>>;
    fn remove_if_matches(&mut self, key: &str, expected_fingerprint: &str)
    -> Result<ResourceState>;
}

/// Remove only exact manifest resources. Changed resources are preserved and reported.
/// Repeating cleanup after partial success is safe because already-absent entries are accepted.
pub fn cleanup<B: OwnedResourceBackend>(
    manifest: &RouteManifest,
    backend: &mut B,
) -> Result<CleanupReport> {
    manifest.validate()?;
    let mut report = CleanupReport::default();

    // Preflight every resource before the first deletion to avoid partial teardown on conflict.
    for resource in &manifest.resources {
        match backend.fingerprint(&resource.key)? {
            None => report.already_absent.push(resource.key.clone()),
            Some(current) if current == resource.fingerprint => {}
            Some(_) => report.conflicts.push(resource.key.clone()),
        }
    }
    ensure!(
        report.conflicts.is_empty(),
        "cleanup refused: one or more manifest resources changed or are foreign"
    );

    for resource in manifest.resources.iter().rev() {
        match backend.remove_if_matches(&resource.key, &resource.fingerprint)? {
            ResourceState::Removed => report.removed.push(resource.key.clone()),
            ResourceState::AlreadyAbsent => report.already_absent.push(resource.key.clone()),
            ResourceState::ChangedOrForeign => {
                report.conflicts.push(resource.key.clone());
                break;
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeBackend {
        resources: BTreeMap<String, String>,
        fail_once: Option<String>,
    }

    impl OwnedResourceBackend for FakeBackend {
        fn fingerprint(&mut self, key: &str) -> Result<Option<String>> {
            Ok(self.resources.get(key).cloned())
        }

        fn remove_if_matches(&mut self, key: &str, expected: &str) -> Result<ResourceState> {
            if self.fail_once.as_deref() == Some(key) {
                self.fail_once = None;
                anyhow::bail!("injected backend failure");
            }
            match self.resources.get(key) {
                None => Ok(ResourceState::AlreadyAbsent),
                Some(current) if current == expected => {
                    self.resources.remove(key);
                    Ok(ResourceState::Removed)
                }
                Some(_) => Ok(ResourceState::ChangedOrForeign),
            }
        }
    }

    fn manifest() -> RouteManifest {
        RouteManifest {
            version: MANIFEST_VERSION,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            table_id: 42420,
            rule_priority: 42420,
            interface_name: "tun-proxyctl".into(),
            interface_index: 77,
            resources: vec![
                OwnedResource {
                    key: "route:v4-default".into(),
                    fingerprint: "route-fp".into(),
                },
                OwnedResource {
                    key: "rule:v4-proxyctl".into(),
                    fingerprint: "rule-fp".into(),
                },
            ],
        }
    }

    fn backend() -> FakeBackend {
        FakeBackend {
            resources: BTreeMap::from([
                ("route:v4-default".into(), "route-fp".into()),
                ("rule:v4-proxyctl".into(), "rule-fp".into()),
                ("foreign:docker-route".into(), "foreign-fp".into()),
            ]),
            fail_once: None,
        }
    }

    #[test]
    fn manifest_round_trip_and_validation_preserve_exact_resource_identity() {
        let original = manifest();
        assert_eq!(
            RouteManifest::decode(&original.encode().unwrap()).unwrap(),
            original
        );
        let mut invalid = original;
        invalid.resources.push(invalid.resources[0].clone());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn cleanup_removes_only_manifest_resources_and_preserves_foreign_state() {
        let mut backend = backend();
        let report = cleanup(&manifest(), &mut backend).unwrap();
        assert_eq!(report.removed.len(), 2);
        assert_eq!(
            backend.resources.get("foreign:docker-route").unwrap(),
            "foreign-fp"
        );
    }

    #[test]
    fn changed_or_foreign_resource_refuses_cleanup_before_any_mutation() {
        let mut backend = backend();
        backend
            .resources
            .insert("route:v4-default".into(), "changed-by-other-app".into());
        assert!(cleanup(&manifest(), &mut backend).is_err());
        assert!(backend.resources.contains_key("rule:v4-proxyctl"));
    }

    #[test]
    fn cleanup_is_idempotent_when_resources_are_already_absent() {
        let mut backend = backend();
        cleanup(&manifest(), &mut backend).unwrap();
        let report = cleanup(&manifest(), &mut backend).unwrap();
        assert_eq!(report.already_absent.len(), 2);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn partial_backend_failure_can_be_retried_without_touching_foreign_resources() {
        let mut backend = backend();
        backend.fail_once = Some("route:v4-default".into());
        assert!(cleanup(&manifest(), &mut backend).is_err());
        let report = cleanup(&manifest(), &mut backend).unwrap();
        assert!(report.removed.len() <= 2);
        assert!(backend.resources.contains_key("foreign:docker-route"));
    }

    #[test]
    fn invalid_activation_ids_and_interface_names_are_rejected() {
        let mut invalid = manifest();
        invalid.activation_id = "../systemd".into();
        assert!(invalid.validate().is_err());
        let mut invalid = manifest();
        invalid.interface_name = "name/with/slash".into();
        assert!(invalid.validate().is_err());
    }
}
