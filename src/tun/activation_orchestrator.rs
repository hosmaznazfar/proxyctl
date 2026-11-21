//! Draft unified TUN activation orchestration.
//!
//! Composes the broker policy transaction and lifecycle coordinator. Core-side TUN
//! attachment remains an integration contract that must be verified by the caller.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{io::Write, path::Path, process::Child, time::Duration};

use crate::{
    cores::{CoreId, adapters::{adapter, CoreAdapter, TunAttachmentMode, TunOutboundMark, XRAY_TUN_INTERFACE_NAME}},
    domain::ProxyNode,
};

use super::{
    managed_activation::{self, ManagedActivation},
    mutation_helper_launcher::MutationHelper,
    process::ProcessIdentity,
    lifecycle_coordinator::{ActivationToken, LifecycleCoordinator},
    recovery::{RecoverySupervisor, SupervisorIdentity},
    systemd_recovery::SystemdRecoverySupervisor,
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
        ensure!(self.bypass_priority < self.proxy_priority, "core bypass priority must precede proxy routing priority");
        ensure!(self.core_mark > 0 && self.core_mark <= i32::MAX as u32, "core mark must be non-zero and fit the native-core range");
        ensure!(self.core_mark_mask > 0 && self.core_mark & !self.core_mark_mask == 0, "core mark must fit a non-zero mark mask");
        ensure!(self.core_mark_mask <= i32::MAX as u32, "core mark mask must fit the native-core range");
        Ok(())
    }
}

/// Unified orchestration façade: broker policy setup, manifest adoption, and core binding.
/// The core process must already have been launched using matching configuration.
pub struct XrayActivation {
    pub child: Child,
    pub managed: ManagedActivation,
}

pub struct ActivationOrchestrator<'a> {
    helper: &'a MutationHelper,
    coordinator: &'a LifecycleCoordinator,
}

impl<'a> ActivationOrchestrator<'a> {
    pub fn new(helper: &'a MutationHelper, coordinator: &'a LifecycleCoordinator) -> Self {
        Self { helper, coordinator }
    }

    /// Activate only when a caller supplies generation/process-bound attachment evidence.
    pub fn activate_with_attachment_evidence(
        &self,
        request: ActivationRequest,
        process: ProcessIdentity,
        evidence: &super::attachment_contract::AttachmentEvidence,
    ) -> Result<ManagedActivation> {
        evidence.validate_binding(&request, &process).context("invalid TUN attachment evidence")?;
        self.activate(request, process)
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

    /// Generate, validate, and launch Xray from the selected Proxyctl node using the
    /// broker-owned descriptor path. The temporary config is private (0600) and is kept
    /// alive through startup/readiness; no caller-supplied config can silently omit the TUN
    /// inbound or outbound socket mark.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_xray_node_with_readiness<F>(
        &self,
        request: ActivationRequest,
        node: &ProxyNode,
        listen_port: u16,
        executable: &Path,
        attachment_timeout: Duration,
        readiness: F,
    ) -> Result<XrayActivation>
    where
        F: FnOnce(&ProcessIdentity, &ActivationToken) -> Result<()>,
    {
        request.validate().context("invalid Xray TUN activation request")?;
        ensure!(request.interface_name == XRAY_TUN_INTERFACE_NAME,
            "Xray adapter currently binds its external TUN descriptor to tun-proxyctl");
        let core = adapter(CoreId::Xray);
        ensure!(core.tun_attachment_mode() == TunAttachmentMode::ExternalDescriptorEnvironment {
            variable: "XRAY_TUN_FD"
        }, "Xray adapter does not expose the verified Linux descriptor environment contract");
        let mark = TunOutboundMark::new(request.core_mark, request.core_mark_mask)
            .context("invalid Xray proxy-outbound socket mark")?;
        let generated = core.generate_tun_activation_config(node, listen_port, mark)
            .context("cannot generate the native Xray TUN activation configuration")?;
        let mut config = tempfile::Builder::new()
            .prefix("proxyctl-xray-tun-")
            .tempfile()
            .context("cannot create a private temporary Xray TUN configuration")?;
        config.write_all(&generated.content)
            .context("cannot write the generated Xray TUN configuration")?;
        config.flush().context("cannot flush the generated Xray TUN configuration")?;
        core.validate_config(executable, config.path())
            .context("Xray rejected the generated TUN configuration before activation")?;
        self.activate_xray_with_readiness(
            request, executable, config.path(), attachment_timeout, readiness,
        )
    }

    /// Prepare broker-owned TUN resources, launch Xray with the retained descriptor, and
    /// require caller-supplied full readiness verification before committing Running.
    ///
    /// The readiness callback is mandatory and executes while the manifest is still Prepared.
    /// Any launch, attachment, or readiness failure terminates the child (when created) and
    /// requests exact-generation broker recovery. This API does not provide a default/no-op
    /// readiness implementation.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_xray_with_readiness<F>(
        &self,
        request: ActivationRequest,
        executable: &Path,
        config: &Path,
        attachment_timeout: Duration,
        readiness: F,
    ) -> Result<XrayActivation>
    where
        F: FnOnce(&ProcessIdentity, &ActivationToken) -> Result<()>,
    {
        request.validate().context("invalid Xray TUN activation request")?;
        ensure!(self.coordinator.load_current()?.is_none(),
            "an activation manifest already exists; recover it before creating another");
        let (token, _) = managed_activation::prepare_managed_activation(
            self.helper, self.coordinator,
            request.activation_id.clone(), request.generation, request.interface_name.clone(),
            request.owner_uid, request.owner_gid, request.table_id,
            request.bypass_priority, request.proxy_priority,
            request.core_mark, request.core_mark_mask,
        ).context("could not prepare broker-owned Xray TUN resources")?;

        let prepared_result = (|| -> Result<u32> {
            let prepared = self.coordinator.load_current()?
                .context("broker-prepared Xray activation manifest disappeared")?;
            ensure!(prepared.token == token && prepared.snapshot.phase == super::recovery::SupervisorPhase::Prepared,
                "Xray activation manifest is not the exact Prepared generation");
            ensure!(prepared.snapshot.manifest.interface_name == request.interface_name
                && prepared.snapshot.manifest.table_id == request.table_id
                && prepared.snapshot.manifest.interface_index > 0,
                "broker-prepared Xray manifest does not match the requested interface and routing table");
            Ok(prepared.snapshot.manifest.interface_index)
        })();
        let expected_ifindex = match prepared_result {
            Ok(index) => index,
            Err(error) => {
                let recovery = self.helper.recover(request.activation_id.clone(), request.generation);
                return match recovery {
                    Ok(response) if response.success =>
                        Err(error).context("prepared manifest validation failed; exact-generation TUN resources were recovered"),
                    Ok(response) =>
                        Err(anyhow::anyhow!("prepared manifest validation failed ({error:#}); broker recovery failed: {}", response.message)),
                    Err(recovery_error) =>
                        Err(anyhow::anyhow!("prepared manifest validation failed ({error:#}); broker recovery request failed: {recovery_error:#}")),
                };
            }
        };

        // Start the independent supervisor while the manifest is still Prepared. It waits
        // boundedly for this generation to become Running, or recovers it if the CLI vanishes.
        let prepared_activation = ManagedActivation {
            token: token.clone(),
            activation_message: "prepared activation awaiting core startup".into(),
        };
        if let Err(error) = self.start_recovery_supervisor(&prepared_activation) {
            let recovery = self.helper.recover(request.activation_id.clone(), request.generation);
            return match recovery {
                Ok(response) if response.success =>
                    Err(error).context("recovery supervisor could not start; Prepared TUN resources were recovered"),
                Ok(response) =>
                    Err(anyhow::anyhow!("recovery supervisor startup failed ({error:#}); broker recovery failed: {}", response.message)),
                Err(recovery_error) =>
                    Err(anyhow::anyhow!("recovery supervisor startup failed ({error:#}); broker recovery request failed: {recovery_error:#}")),
            };
        }

        let (mut child, process) = match super::xray_launcher::spawn_xray_with_verified_attachment(
            self.helper, &request.activation_id, request.generation,
            executable, config, &request.interface_name, expected_ifindex, attachment_timeout,
        ) {
            Ok(started) => started,
            Err(error) => {
                let recovery = self.helper.recover(request.activation_id.clone(), request.generation);
                return match recovery {
                    Ok(response) if response.success => Err(error).context("Xray launch/attachment failed; exact-generation TUN resources were recovered"),
                    Ok(response) => Err(anyhow::anyhow!("Xray launch/attachment failed ({error:#}); broker recovery failed: {}", response.message)),
                    Err(recovery_error) => Err(anyhow::anyhow!("Xray launch/attachment failed ({error:#}); broker recovery request failed: {recovery_error:#}")),
                };
            }
        };

        if let Err(error) = readiness(&process, &token) {
            let reap = super::xray_launcher::terminate_and_reap_xray(&mut child, &process);
            let recovery = self.helper.recover(request.activation_id.clone(), request.generation);
            return match (reap, recovery) {
                (Ok(()), Ok(response)) if response.success =>
                    Err(error).context("Xray readiness failed; child was reaped and exact-generation TUN resources were recovered"),
                (Err(reap_error), Ok(response)) if response.success =>
                    Err(anyhow::anyhow!("Xray readiness failed ({error:#}); child reaping failed: {reap_error}; TUN resources were recovered")),
                (reap_result, Ok(response)) =>
                    Err(anyhow::anyhow!("Xray readiness failed ({error:#}); child reaping: {}; broker recovery failed: {}", reap_result.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()), response.message)),
                (reap_result, Err(recovery_error)) =>
                    Err(anyhow::anyhow!("Xray readiness failed ({error:#}); child reaping: {}; broker recovery request failed: {recovery_error:#}", reap_result.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()))),
            };
        }

        let managed = match managed_activation::commit_managed_process(
            self.helper, self.coordinator, &token, process.clone(),
        ) {
            Ok(managed) => managed,
            Err(error) => {
                let termination = super::xray_launcher::terminate_and_reap_xray(&mut child, &process);
                let recovery = self.helper.recover(request.activation_id.clone(), request.generation);
                return match (termination, recovery) {
                    (Ok(()), Ok(response)) if response.success =>
                        Err(error).context("Xray process commit failed; child was terminated and exact-generation resources recovered"),
                    (Err(termination_error), Ok(response)) if response.success =>
                        Err(anyhow::anyhow!("Xray process commit failed ({error:#}); termination/reaping failed: {termination_error:#}; TUN resources recovered")),
                    (termination_result, Ok(response)) =>
                        Err(anyhow::anyhow!("Xray process commit failed ({error:#}); termination/reaping: {}; broker recovery failed: {}", termination_result.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()), response.message)),
                    (termination_result, Err(recovery_error)) =>
                        Err(anyhow::anyhow!("Xray process commit failed ({error:#}); termination/reaping: {}; broker recovery request failed: {recovery_error:#}", termination_result.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()))),
                };
            }
        };

        Ok(XrayActivation { child, managed })
    }

    /// Start the CLI-independent systemd user service for an already committed generation.
    ///
    /// The service is started only after the manifest reaches Running; if service startup fails,
    /// the caller must terminate the core and request exact-generation broker recovery.
    fn start_recovery_supervisor(&self, activation: &ManagedActivation) -> Result<()> {
        let runtime = self.coordinator.runtime_directory()?;
        let manifest = runtime.join("tun-manifest.json");
        let executable = std::env::current_exe()
            .context("cannot locate the Proxyctl executable for supervisor discovery")?
            .canonicalize()
            .context("cannot canonicalize the Proxyctl executable path")?
            .with_file_name("proxyctl-tun-supervisor");
        let identity = SupervisorIdentity::for_activation(
            activation.token.activation_id(),
            manifest.to_string_lossy().into_owned(),
            activation.token.generation(),
        )?;
        let mut supervisor = SystemdRecoverySupervisor::for_current_manager(executable, runtime)?;
        supervisor.start(&identity).context("could not start the generation-bound systemd recovery service")
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

    /// Resume an exact generation, allowing a bounded Prepared-to-Running startup window.
    pub fn resume_generation(&self, activation_id: &str, generation: u64) -> Result<()> {
        managed_activation::resume_managed_supervision_after_startup(
            self.helper,
            self.coordinator,
            activation_id,
            generation,
            Duration::from_secs(30),
        )
        .context("cannot resume generation-bound TUN supervision")
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
    fn rejects_bypass_priority_after_proxy_priority() { let mut r=valid(); r.bypass_priority=r.proxy_priority+1; assert!(r.validate().is_err()); }
    #[test]
    fn rejects_mark_outside_mask() { let mut r=valid(); r.core_mark=0x100; assert!(r.validate().is_err()); }
    #[test]
    fn rejects_invalid_interface_length() { let mut r=valid(); r.interface_name="1234567890123456".into(); assert!(r.validate().is_err()); }
    #[test]
    fn rejects_invalid_interface_characters() { let mut r=valid(); r.interface_name="tun/unsafe".into(); assert!(r.validate().is_err()); }
    #[test]
    fn rejects_mask_outside_native_range() { let mut r=valid(); r.core_mark_mask=u32::MAX; assert!(r.validate().is_err()); }
    #[test]
    fn rejects_priority_below_allocation_floor() { let mut r=valid(); r.bypass_priority=1; assert!(r.validate().is_err()); }
}


fn canonical_activation_id(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() && !b.is_ascii_uppercase() })
}
