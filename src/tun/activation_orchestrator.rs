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
        ensure!(!self.activation_id.is_empty() && self.activation_id.len() <= 128, "activation ID must be non-empty and bounded");
        ensure!(self.generation > 0, "activation generation must be positive");
        ensure!(!self.interface_name.is_empty() && self.interface_name.len() < 16, "interface name must be non-empty and fit Linux IFNAMSIZ");
        ensure!(self.table_id > 0, "routing table ID must be positive");
        ensure!(self.bypass_priority > 0 && self.proxy_priority > 0, "routing rule priorities must be positive");
        ensure!(self.bypass_priority != self.proxy_priority, "routing rule priorities must be distinct");
        ensure!(self.core_mark > 0 && self.core_mark <= i32::MAX as u32, "core mark must be non-zero and fit the native-core range");
        ensure!(self.core_mark_mask > 0 && self.core_mark & !self.core_mark_mask == 0, "core mark must fit a non-zero mark mask");
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

    /// Recover only the explicitly supplied activation generation.
    pub fn recover(&self, activation_id: &str, generation: u64) -> Result<()> {
        ensure!(!activation_id.is_empty() && generation > 0, "invalid recovery identity");
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
