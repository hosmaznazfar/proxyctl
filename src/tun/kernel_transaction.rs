//! Failure-aware orchestration for a future privileged kernel transaction.
//!
//! This module intentionally contains no operating-system mutator. A concrete broker must
//! implement the backend contract with durable write-ahead ownership recording and atomic
//! compare-and-delete semantics. The executor is exercised only with fake backends here;
//! production TUN activation remains gated until such a backend and supervisor exist.

use anyhow::{Context, Result, ensure};

use super::{
    kernel_inventory::KernelInterfaceRecord,
    ownership::{ResourceState, RouteManifest},
    route_policy::{PlannedRoute, PlannedRule, RoutingPolicyPlan},
};

/// Operations are ordered so policy is installed only after the TUN device exists and is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyStep {
    CreateInterface { name: String, uid: u32, gid: u32 },
    AddRoute(PlannedRoute),
    AddRule(PlannedRule),
}

/// A complete immutable request. It is validated before the backend is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelTransaction {
    pub activation_id: String,
    pub policy: RoutingPolicyPlan,
    pub owner_uid: u32,
    pub owner_gid: u32,
}

impl KernelTransaction {
    pub fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        ensure!(
            valid_activation_id(&self.activation_id),
            "invalid kernel transaction activation identity"
        );
        Ok(())
    }

    pub fn steps(&self) -> Result<Vec<ApplyStep>> {
        self.validate()?;
        let mut steps = vec![ApplyStep::CreateInterface {
            name: self.policy.interface_name.clone(),
            uid: self.owner_uid,
            gid: self.owner_gid,
        }];
        steps.extend(self.policy.routes.iter().cloned().map(ApplyStep::AddRoute));
        steps.extend(self.policy.rules.iter().cloned().map(ApplyStep::AddRule));
        Ok(steps)
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

/// Contract for a future broker-owned transaction backend.
///
/// Each mutating method must durably journal the exact resource identity before returning.
/// The journal must survive controller/core termination. Deletion must compare the current
/// complete fingerprint atomically with the delete. This trait alone is not an implementation
/// of those guarantees.
pub trait KernelTransactionBackend {
    fn create_owned_interface(
        &mut self,
        activation_id: &str,
        name: &str,
        uid: u32,
        gid: u32,
    ) -> Result<KernelInterfaceRecord>;

    fn add_owned_route(
        &mut self,
        activation_id: &str,
        route: &PlannedRoute,
    ) -> Result<String>;

    fn add_owned_rule(
        &mut self,
        activation_id: &str,
        rule: &PlannedRule,
    ) -> Result<String>;

    fn remove_resource_if_matches(
        &mut self,
        activation_id: &str,
        key: &str,
        fingerprint: &str,
    ) -> Result<ResourceState>;

    fn remove_interface_if_matches(
        &mut self,
        activation_id: &str,
        name: &str,
        index: u32,
    ) -> Result<ResourceState>;

    /// Keep the durable journal when rollback is incomplete or detects foreign state.
    fn retain_recovery_journal(&mut self, activation_id: &str) -> Result<()>;

    /// Atomically promote the write-ahead journal to the durable active manifest.
    /// This must succeed before the controller is allowed to launch a core.
    fn commit_manifest(&mut self, manifest: &RouteManifest) -> Result<()>;

    /// Remove the journal only after all resources have been verified absent.
    fn finish_transaction(&mut self, activation_id: &str) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedKernelTransaction {
    pub manifest: RouteManifest,
}

/// Execute the fixed policy order. On failure, rollback proceeds in exact reverse order.
/// If rollback is incomplete, the backend is explicitly asked to retain its recovery journal.
pub fn apply<B: KernelTransactionBackend>(
    transaction: &KernelTransaction,
    backend: &mut B,
) -> Result<AppliedKernelTransaction> {
    transaction.validate()?;
    let activation_id = &transaction.activation_id;
    let policy = &transaction.policy;

    let interface = backend
        .create_owned_interface(
            activation_id,
            &policy.interface_name,
            transaction.owner_uid,
            transaction.owner_gid,
        )
        .context("failed to create and journal the owned TUN interface")?;

    if interface.name != policy.interface_name || interface.index == 0 || !interface.is_tun {
        backend
            .retain_recovery_journal(activation_id)
            .context("kernel returned an unexpected interface and recovery journal could not be retained")?;
        anyhow::bail!(
            "kernel returned an unexpected TUN interface identity; recovery journal retained"
        );
    }

    let mut resources = Vec::with_capacity(policy.routes.len() + policy.rules.len());
    let apply_result = (|| -> Result<()> {
        for route in &policy.routes {
            let fingerprint = backend
                .add_owned_route(activation_id, route)
                .context("failed to add and journal an owned TUN route")?;
            ensure!(!fingerprint.is_empty(), "route backend returned an empty fingerprint");
            resources.push(super::ownership::OwnedResource {
                key: route_key(route),
                fingerprint,
            });
        }
        for rule in &policy.rules {
            let fingerprint = backend
                .add_owned_rule(activation_id, rule)
                .context("failed to add and journal an owned policy rule")?;
            ensure!(!fingerprint.is_empty(), "rule backend returned an empty fingerprint");
            resources.push(super::ownership::OwnedResource {
                key: rule_key(rule),
                fingerprint,
            });
        }
        Ok(())
    })();

    if let Err(error) = apply_result {
        let rollback = rollback(
            activation_id,
            &resources,
            &interface.name,
            interface.index,
            backend,
        );
        if rollback.is_err() {
            let _ = backend.retain_recovery_journal(activation_id);
            return Err(error).context("kernel transaction failed and rollback is incomplete; recovery journal retained");
        }
        backend
            .finish_transaction(activation_id)
            .context("kernel transaction rollback completed but journal finalization failed")?;
        return Err(error);
    }

    let manifest = RouteManifest {
        version: super::ownership::MANIFEST_VERSION,
        activation_id: activation_id.clone(),
        table_id: policy.table_id,
        rule_priority: policy.proxy_priority,
        interface_name: interface.name,
        interface_index: interface.index,
        resources,
    };
    manifest.validate()?;
    if let Err(error) = backend.commit_manifest(&manifest) {
        backend
            .retain_recovery_journal(activation_id)
            .context("manifest commit failed and recovery journal could not be retained")?;
        return Err(error).context("could not commit the active TUN ownership manifest");
    }
    Ok(AppliedKernelTransaction { manifest })
}

fn rollback<B: KernelTransactionBackend>(
    activation_id: &str,
    resources: &[super::ownership::OwnedResource],
    interface_name: &str,
    interface_index: u32,
    backend: &mut B,
) -> Result<()> {
    for resource in resources.iter().rev() {
        match backend.remove_resource_if_matches(
            activation_id,
            &resource.key,
            &resource.fingerprint,
        )? {
            ResourceState::Removed | ResourceState::AlreadyAbsent => {}
            ResourceState::ChangedOrForeign => {
                anyhow::bail!("rollback found a changed or foreign resource: {}", resource.key)
            }
        }
    }
    match backend.remove_interface_if_matches(activation_id, interface_name, interface_index)? {
        ResourceState::Removed | ResourceState::AlreadyAbsent => Ok(()),
        ResourceState::ChangedOrForeign => {
            anyhow::bail!("rollback found a changed or foreign TUN interface")
        }
    }
}

fn route_key(route: &PlannedRoute) -> String {
    let family = match route.family {
        super::route_policy::AddressFamily::Ipv4 => "v4",
        super::route_policy::AddressFamily::Ipv6 => "v6",
    };
    format!("route:{family}:{}:{}", route.table_id, route.destination)
}

fn rule_key(rule: &PlannedRule) -> String {
    let family = match rule.family {
        super::route_policy::AddressFamily::Ipv4 => "v4",
        super::route_policy::AddressFamily::Ipv6 => "v6",
    };
    format!("rule:{family}:{}", rule.priority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeBackend {
        interface: Option<KernelInterfaceRecord>,
        resources: BTreeMap<String, String>,
        fail_add_at: Option<usize>,
        add_count: usize,
        fail_remove: bool,
        journal_retained: bool,
        finalized: bool,
        committed: Option<RouteManifest>,
    }

    impl KernelTransactionBackend for FakeBackend {
        fn create_owned_interface(&mut self, _id: &str, name: &str, _uid: u32, _gid: u32) -> Result<KernelInterfaceRecord> {
            let interface = KernelInterfaceRecord { name: name.into(), index: 77, is_tun: true };
            self.interface = Some(interface.clone());
            Ok(interface)
        }

        fn add_owned_route(&mut self, _id: &str, route: &PlannedRoute) -> Result<String> {
            self.add_count += 1;
            if self.fail_add_at == Some(self.add_count) { anyhow::bail!("injected route failure"); }
            let key = route_key(route);
            let fingerprint = format!("fp:{key}");
            self.resources.insert(key, fingerprint.clone());
            Ok(fingerprint)
        }

        fn add_owned_rule(&mut self, _id: &str, rule: &PlannedRule) -> Result<String> {
            self.add_count += 1;
            if self.fail_add_at == Some(self.add_count) { anyhow::bail!("injected rule failure"); }
            let key = rule_key(rule);
            let fingerprint = format!("fp:{key}");
            self.resources.insert(key, fingerprint.clone());
            Ok(fingerprint)
        }

        fn remove_resource_if_matches(&mut self, _id: &str, key: &str, fp: &str) -> Result<ResourceState> {
            if self.fail_remove { anyhow::bail!("injected rollback failure"); }
            match self.resources.get(key) {
                None => Ok(ResourceState::AlreadyAbsent),
                Some(current) if current == fp => { self.resources.remove(key); Ok(ResourceState::Removed) }
                Some(_) => Ok(ResourceState::ChangedOrForeign),
            }
        }

        fn remove_interface_if_matches(&mut self, _id: &str, name: &str, index: u32) -> Result<ResourceState> {
            if self.fail_remove { anyhow::bail!("injected interface rollback failure"); }
            match &self.interface {
                None => Ok(ResourceState::AlreadyAbsent),
                Some(item) if item.name == name && item.index == index && item.is_tun => {
                    self.interface = None; Ok(ResourceState::Removed)
                }
                Some(_) => Ok(ResourceState::ChangedOrForeign),
            }
        }

        fn retain_recovery_journal(&mut self, _id: &str) -> Result<()> { self.journal_retained = true; Ok(()) }
        fn commit_manifest(&mut self, manifest: &RouteManifest) -> Result<()> {
            self.committed = Some(manifest.clone());
            Ok(())
        }

        fn finish_transaction(&mut self, _id: &str) -> Result<()> { self.finalized = true; Ok(()) }
    }

    fn transaction() -> KernelTransaction {
        KernelTransaction {
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            policy: RoutingPolicyPlan::new(42_420, 42_410, 42_420, 0x42, 0xff, "tun-proxyctl", 77),
            owner_uid: 1000,
            owner_gid: 1000,
        }
    }

    #[test]
    fn emits_fixed_dual_stack_steps_with_interface_first() {
        let steps = transaction().steps().unwrap();
        assert_eq!(steps.len(), 7);
        assert!(matches!(steps.first(), Some(ApplyStep::CreateInterface { .. })));
        assert!(steps[1..3].iter().all(|step| matches!(step, ApplyStep::AddRoute(_))));
        assert!(steps[3..].iter().all(|step| matches!(step, ApplyStep::AddRule(_))));
    }

    #[test]
    fn rejects_invalid_transaction_before_backend_calls() {
        let mut tx = transaction();
        tx.activation_id = "../bad".into();
        let mut backend = FakeBackend::default();
        assert!(apply(&tx, &mut backend).is_err());
        assert!(backend.interface.is_none());
        assert!(backend.resources.is_empty());
    }

    #[test]
    fn successful_apply_returns_exact_interface_and_resource_manifest() {
        let mut backend = FakeBackend::default();
        let result = apply(&transaction(), &mut backend).unwrap();
        assert_eq!(result.manifest.interface_name, "tun-proxyctl");
        assert_eq!(result.manifest.interface_index, 77);
        assert_eq!(result.manifest.resources.len(), 6);
        result.manifest.validate().unwrap();
        assert_eq!(backend.resources.len(), 6);
        assert_eq!(backend.committed.as_ref(), Some(&result.manifest));
        assert!(!backend.finalized);
    }

    #[test]
    fn failed_apply_rolls_back_in_reverse_and_finalizes_only_after_success() {
        let mut backend = FakeBackend { fail_add_at: Some(4), ..Default::default() };
        assert!(apply(&transaction(), &mut backend).is_err());
        assert!(backend.resources.is_empty());
        assert!(backend.interface.is_none());
        assert!(backend.finalized);
        assert!(!backend.journal_retained);
    }

    #[test]
    fn failed_rollback_retains_recovery_journal_and_preserves_resources() {
        let mut backend = FakeBackend { fail_add_at: Some(3), fail_remove: true, ..Default::default() };
        assert!(apply(&transaction(), &mut backend).is_err());
        assert!(backend.journal_retained);
        assert!(!backend.finalized);
        assert!(backend.interface.is_some());
    }

    #[test]
    fn rejects_unexpected_kernel_interface_identity_and_does_not_add_routes() {
        struct WrongInterface(FakeBackend);
        impl KernelTransactionBackend for WrongInterface {
            fn create_owned_interface(&mut self, _: &str, _: &str, _: u32, _: u32) -> Result<KernelInterfaceRecord> {
                Ok(KernelInterfaceRecord { name: "foreign0".into(), index: 99, is_tun: true })
            }
            fn add_owned_route(&mut self, id: &str, route: &PlannedRoute) -> Result<String> { self.0.add_owned_route(id, route) }
            fn add_owned_rule(&mut self, id: &str, rule: &PlannedRule) -> Result<String> { self.0.add_owned_rule(id, rule) }
            fn remove_resource_if_matches(&mut self, id: &str, key: &str, fp: &str) -> Result<ResourceState> { self.0.remove_resource_if_matches(id, key, fp) }
            fn remove_interface_if_matches(&mut self, id: &str, name: &str, index: u32) -> Result<ResourceState> { self.0.remove_interface_if_matches(id, name, index) }
            fn retain_recovery_journal(&mut self, id: &str) -> Result<()> { self.0.retain_recovery_journal(id) }
            fn commit_manifest(&mut self, manifest: &RouteManifest) -> Result<()> { self.0.commit_manifest(manifest) }
            fn finish_transaction(&mut self, id: &str) -> Result<()> { self.0.finish_transaction(id) }
        }
        let mut backend = WrongInterface(FakeBackend::default());
        assert!(apply(&transaction(), &mut backend).is_err());
        assert!(backend.0.resources.is_empty());
    }
}
