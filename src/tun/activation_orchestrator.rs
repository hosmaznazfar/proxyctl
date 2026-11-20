//! Draft unified TUN activation orchestration.
//!
//! This draft composes the existing mutation-broker policy transaction and lifecycle
//! coordinator into one entry point. It delegates device creation to the broker
//! transaction and process supervision to the existing managed activation layer.
//! Core-side TUN attachment behavior remains an integration assumption for this draft.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result};

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

/// Unified orchestrator façade: broker policy setup, manifest adoption, and core binding.
/// The core process must already have been launched using the matching configuration.
pub struct ActivationOrchestrator<'a> {
    helper: &'a MutationHelper,
    coordinator: &'a LifecycleCoordinator,
}

impl<'a> ActivationOrchestrator<'a> {
    pub fn new(helper: &'a MutationHelper, coordinator: &'a LifecycleCoordinator) -> Self {
        Self { helper, coordinator }
    }

    pub fn activate(
        &self,
        request: ActivationRequest,
        process: ProcessIdentity,
    ) -> Result<ManagedActivation> {
        managed_activation::activate_managed_core(
            self.helper,
            self.coordinator,
            request.activation_id,
            request.generation,
            request.interface_name,
            request.owner_uid,
            request.owner_gid,
            request.table_id,
            request.bypass_priority,
            request.proxy_priority,
            request.core_mark,
            request.core_mark_mask,
            process,
        )
        .context("unified TUN activation failed")
    }

    pub fn recover(&self, activation_id: &str, generation: u64) -> Result<()> {
        let response = self.helper.recover(activation_id.to_owned(), generation)?;
        anyhow::ensure!(response.success, "broker recovery failed: {}", response.message);
        Ok(())
    }

    pub fn resume(&self) -> Result<()> {
        managed_activation::resume_managed_supervision(self.helper, self.coordinator)
            .context("cannot resume unified TUN supervision")?;
        Ok(())
    }
}
