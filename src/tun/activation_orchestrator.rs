//! Draft unified TUN activation orchestration.
//!
//! Composes the broker policy transaction and lifecycle coordinator. Core-side TUN
//! attachment remains an integration contract that must be verified by the caller.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};

use super::{
    lifecycle_coordinator::LifecycleCoordinator,
    managed_activation::{self, ManagedActivation},
    mutation_helper_launcher::MutationHelper,
    process::ProcessIdentity,
};

/// Parameters for one generation-scoped activation.
#[derive(Debug, Clone)]
pub struct ActivationRequest {
    pub activation_id: String,
    pub generation: u64,
    pub interface_name: String,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub table_id: u32,
    pub bypass_priority: u32,
    pub proxy_priority: u32,
    pub core_mark: u32,
    pub core_mark_mask: u32,
}

impl ActivationRequest {
    /// Validate local invariants before the broker can mutate the host network.
    pub fn validate(&self) -> Result<()> {
        ensure!(canonical_activation_id(&self.activation_id), "activation ID must be a canonical lowercase UUID");
        ensure!(self.generation > 0, "activation generation must be positive");
        ensure!(!self.interface_name.is_empty() && self.interface_name.len() < 16 && self.interface_name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')), "interface name must be valid and fit Linux IFNAMSIZ");
        ensure!(self.table_id >= super::route_policy::RT_TABLE_MIN_PROXYCTL, "routing table ID must be in the Proxyctl allocation range");
        ensure!(self.bypass_priority >= super::route_policy::RPDB_PRIORITY_MIN_PROXYCTL && self.proxy_priority >= super::route_policy::RPDB_PRIORITY_MIN_PROXYCTL, "rule priorities must be in the Proxyctl allocation range");
        ensure!(self.bypass_priority > 0 && self.proxy_priority > 0, "routing rule priorities must be positive");
        ensure!(self.bypass_priority != self.proxy_priority, "routing rule priorities must be distinct");
        ensure!(self.core_mark > 0 && self.core_mark <= i32::MAX as u32, "core mark must be non-zero and fit the native-core range");
        ensure!(self.core_mark_mask > 0 && self.core_mark & !self.core_mark_mask == 0, "core mark must fit a non-zero mark mask");
        ensure!(self.core_mark_mask <= i32::MAX as u32, "core mark mask must fit the native-core range");
        Ok(())
    }
}

/// Unified orchestration façade: broker policy setup, manifest adoption, and core binding.
/// The core process must already have been launched using matching configuration.
pub struct ActivationOrchestrator<'a> {
    helper: &'a MutationHelper,
    coordinator: &'a LifecycleCoordinator,
}

impl<'a> ActivationOrchestrator<'a> {
    pub fn new(helper: &'a MutationHelper, coordinator: &'a LifecycleCoordinator) -> Self {
        Self { helper, coordinator }
    }

    pub fn activate(&self, request: ActivationRequest, process: ProcessIdentity) -> Result<ManagedActivation> {
        request.validate().context("invalid TUN activation request")?;
        ensure!(self.coordinator.load_current()?.is_none(), "an activation manifest already exists; recover it before creating another");
        managed_activation::activate_managed_core(
            self.helper, self.coordinator,
            request.activation_id, request.generation, request.interface_name,
            request.owner_uid, request.owner_gid, request.table_id,
            request.bypass_priority, request.proxy_priority,
            request.core_mark, request.core_mark_mask, process,
        ).context("unified TUN activation failed")
    }

    /// Monitor the persisted Running activation and request exact-generation cleanup on exit.
    pub fn monitor_current(&self) -> Result<()> {
        let current = self.coordinator.load_current()?.context("no activation to monitor")?;
        ensure!(current.snapshot.phase == super::recovery::SupervisorPhase::Running, "only a Running activation can be monitored");
        let identity = current.snapshot.core_process.context("Running activation lacks process identity")?;
        let process = super::process::ProcessHandle::open(identity).context("cannot pin managed core process")?;
        let activation = ManagedActivation { token: current.token, activation_message: "monitoring persisted activation".into() };
        managed_activation::monitor_managed_core(self.helper, self.coordinator, &activation, &process)
            .context("managed TUN monitoring and cleanup failed")?;
        Ok(())
    }

    /// Recover only the explicitly supplied activation generation.
    pub fn recover(&self, activation_id: &str, generation: u64) -> Result<()> {
        ensure!(canonical_activation_id(activation_id) && generation > 0, "invalid recovery identity");
        let response = self.helper.recover(activation_id.to_owned(), generation)?;
        ensure!(response.success, "broker recovery failed: {}", response.message);
        Ok(())
    }

    /// Recover the currently persisted generation, if one exists.
    pub fn recover_current(&self) -> Result<()> {
        if let Some(current) = self.coordinator.load_current()? {
            self.recover(current.token.activation_id(), current.token.generation())?;
        }
        Ok(())
    }

    /// Resume existing supervision or retry its durable cleanup state.
    pub fn resume(&self) -> Result<()> {
        managed_activation::resume_managed_supervision(self.helper, self.coordinator)
            .context("cannot resume unified TUN supervision")?;
        Ok(())
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    fn valid() -> ActivationRequest {
        ActivationRequest { activation_id: "12345678-1234-4234-8234-123456789abc".into(), generation: 1, interface_name: "tun-proxyctl".into(), owner_uid: 1000, owner_gid: 1000, table_id: super::route_policy::RT_TABLE_MIN_PROXYCTL, bypass_priority: super::route_policy::RPDB_PRIORITY_MIN_PROXYCTL, proxy_priority: super::route_policy::RPDB_PRIORITY_MIN_PROXYCTL + 1, core_mark: 0x42, core_mark_mask: 0xff }
    }

    #[test]
    fn accepts_valid_request() { assert!(valid().validate().is_ok()); }
    #[test]
    fn rejects_noncanonical_activation_id() { let mut r=valid(); r.activation_id="draft".into(); assert!(r.validate().is_err()); }
    #[test]
    fn rejects_low_table_allocation() { let mut r=valid(); r.table_id=254; assert!(r.validate().is_err()); }
    #[test]
    fn rejects_zero_generation() { let mut r=valid(); r.generation=0; assert!(r.validate().is_err()); }
    #[test]
    fn rejects_duplicate_priorities() { let mut r=valid(); r.proxy_priority=r.bypass_priority; assert!(r.validate().is_err()); }
    #[test]
    fn rejects_mark_outside_mask() { let mut r=valid(); r.core_mark=0x100; assert!(r.validate().is_err()); }
    #[test]
    fn rejects_invalid_interface_length() { let mut r=valid(); r.interface_name="1234567890123456".into(); assert!(r.validate().is_err()); }
}


fn canonical_activation_id(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() })
}
