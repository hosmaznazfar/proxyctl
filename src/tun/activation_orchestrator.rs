//! Draft unified TUN activation orchestration.
//!
//! Composes the broker policy transaction and lifecycle coordinator. Core-side TUN
//! attachment remains an integration contract that must be verified by the caller.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{io::Write, path::Path, process::Child, time::Duration};

use crate::{
    cores::{CoreId, adapters::{adapter, CoreAdapter, TunAttachmentMode, TunOutboundMark, XRAY_TUN_INTERFACE_NAME, XRAY_TUN_FD_ENV}},
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

    /// Core-dispatched node activation. Only adapters with a concrete broker-owned
    /// descriptor contract may enter this path; native self-created TUN and unsupported
    /// adapters are rejected before a broker mutation is requested.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_core_node_with_readiness<F>(
        &self,
        core_id: CoreId,
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
        match (core_id, adapter(core_id).tun_attachment_mode()) {
            (CoreId::Xray, mode)
                if mode.external_descriptor_environment() == Some(XRAY_TUN_FD_ENV) =>
            {
                self.activate_xray_node_with_readiness(
                    request, node, listen_port, executable, attachment_timeout, readiness,
                )
            }
            (CoreId::SingBox, TunAttachmentMode::NativeDeviceCreation) =>
                anyhow::bail!("sing-box creates its own named TUN device and has no verified broker-owned descriptor adoption path; refusing to start it in this lifecycle"),
            (CoreId::Mihomo, TunAttachmentMode::NativeDeviceCreation) =>
                anyhow::bail!("Mihomo creates and owns its named TUN device; the persistent native-device broker backend is not implemented yet, so refusing activation"),
            _ => anyhow::bail!("{core_id:?} does not expose a supported broker-owned TUN descriptor contract"),
        }
    }

    /// Prepare and launch sing-box or Mihomo with a broker-owned persistent named TUN device.
    ///
    /// The caller must provide a full readiness callback. No native core is committed Running
    /// until its process identity and traffic/routing evidence have been checked.
    pub fn activate_native_core_node_with_readiness<F>(
        &self,
        core_id: CoreId,
        request: ActivationRequest,
        node: &ProxyNode,
        listen_port: u16,
        executable: &Path,
        readiness: F,
    ) -> Result<ManagedActivation>
    where
        F: FnOnce(&ProcessIdentity, &ActivationToken) -> Result<()>,
    {
        ensure!(matches!(core_id, CoreId::SingBox | CoreId::Mihomo),
            "native persistent-device activation supports only sing-box and Mihomo");
        request.validate().context("invalid native TUN activation request")?;
        ensure!(request.interface_name == "tun-proxyctl",
            "native TUN adapters currently require the interface name tun-proxyctl");
        ensure!(adapter(core_id).tun_attachment_mode() == TunAttachmentMode::NativeDeviceCreation,
            "selected core does not advertise native TUN device creation");
        ensure!(self.coordinator.load_current()?.is_none(),
            "an activation manifest already exists; recover it before creating another");

        let core = adapter(core_id);
        let mark = TunOutboundMark::new(request.core_mark, request.core_mark_mask)
            .context("invalid native-core proxy outbound socket mark")?;
        let generated = core.generate_tun_activation_config(node, listen_port, mark)
            .with_context(|| format!("cannot generate {core_id} native TUN configuration"))?;
        let runtime = self.coordinator.runtime_directory()
            .context("cannot resolve private native TUN runtime directory")?;
        let mut config = tempfile::Builder::new()
            .prefix("proxyctl-native-tun-")
            .tempfile_in(&runtime)
            .context("cannot create private native TUN configuration")?;
        config.write_all(&generated.content)?;
        config.flush()?;
        core.validate_config(executable, config.path())
            .with_context(|| format!("{core_id} rejected its generated native TUN configuration"))?;

        let (token, _) = managed_activation::prepare_native_managed_activation(
            self.helper, self.coordinator,
            request.activation_id.clone(), request.generation, request.interface_name.clone(),
            request.owner_uid, request.owner_gid, request.table_id,
            request.bypass_priority, request.proxy_priority,
            request.core_mark, request.core_mark_mask,
        ).context("could not prepare persistent native TUN resources")?;

        let expected_ifindex = match self.coordinator.load_current()? {
            Some(current) if current.token == token
                && current.snapshot.phase == super::recovery::SupervisorPhase::Prepared
                && current.snapshot.manifest.interface_name == request.interface_name
                && current.snapshot.manifest.table_id == request.table_id
                && current.snapshot.manifest.interface_index > 0 =>
                    current.snapshot.manifest.interface_index,
            _ => {
                self.helper.recover(request.activation_id.clone(), request.generation)?;
                anyhow::bail!("native TUN manifest does not match the exact Prepared generation");
            }
        };

        let prepared = ManagedActivation {
            token: token.clone(),
            activation_message: "native TUN resources prepared; awaiting core startup".into(),
        };
        if let Err(error) = self.start_recovery_supervisor(&prepared) {
            let _ = self.helper.recover(request.activation_id.clone(), request.generation);
            return Err(error).context("native TUN recovery supervisor could not start");
        }

        let process = match super::native_core_launcher::spawn_native_core_service(
            core_id, &request.activation_id, request.generation, executable, config.path(),
        ) {
            Ok(process) => process,
            Err(error) => {
                self.stop_core_and_recover_generation(&request.activation_id, request.generation, None)?;
                return Err(error).context("native core service launch failed; exact-generation recovery completed");
            }
        };
        if let Err(error) = readiness(&process, &token) {
            self.stop_core_and_recover_generation(&request.activation_id, request.generation, Some(&process))?;
            return Err(error).context("native core readiness failed; exact service stopped before broker cleanup");
        }
        let managed = match managed_activation::commit_prepared_managed_process(
            self.coordinator, &token, process.clone(),
        ) {
            Ok(managed) => managed,
            Err(error) => {
                self.stop_core_and_recover_generation(&request.activation_id, request.generation, Some(&process))?;
                return Err(error).context("native core process commit failed; exact service stopped before broker cleanup");
            }
        };
        ensure!(expected_ifindex > 0, "native TUN ifindex became invalid before activation commit");
        Ok(managed)
    }

    fn stop_core_and_recover_generation(
        &self,
        activation_id: &str,
        generation: u64,
        process: Option<&ProcessIdentity>,
    ) -> Result<()> {
        super::xray_launcher::stop_core_service_generation(activation_id, generation, process)
            .context("cannot confirm that the exact managed core service has stopped")?;
        let recovery = self.helper.recover(activation_id.to_owned(), generation);
        if matches!(recovery.as_ref(), Ok(response) if response.success) {
            return Ok(());
        }
        let store = super::manifest_store::ManifestStore::open(
            self.coordinator.runtime_directory().to_path_buf()
        )?;
        let message = match &recovery {
            Ok(response) => response.message.clone(),
            Err(error) => format!("{error:#}"),
        };
        ensure!(store.load()?.is_none() && store.load_transaction_journal()?.is_none(),
            "exact-generation native TUN cleanup is incomplete: {message}");
        Ok(())
    }

    /// Activate Xray only after a concrete HTTP CONNECT probe and independently collected
    /// process, route, mark, physical-egress, DNS, and firewall evidence all pass.
    #[allow(clippy::too_many_arguments)]
    pub fn activate_xray_node_end_to_end(
        &self,
        request: ActivationRequest,
        node: &ProxyNode,
        listen_port: u16,
        executable: &Path,
        attachment_timeout: Duration,
        expected_peers: Vec<std::net::SocketAddr>,
        traffic_target: super::readiness::HttpProbeTarget,
        probe_timeout: Duration,
        maximum_response_bytes: usize,
    ) -> Result<XrayActivation> {
        ensure!(!expected_peers.is_empty() && expected_peers.len() <= 8
            && expected_peers.iter().all(|peer| peer.port() == node.port
                && !peer.ip().is_unspecified() && !peer.ip().is_multicast()),
            "Xray peer candidates must be one to eight unicast addresses matching the selected node's port");
        traffic_target.validate()?;
        let baseline_host = crate::tun::inspect()
            .context("cannot capture pre-activation DNS and firewall baseline")?;
        ensure!(baseline_host.routes_inspected && baseline_host.dns_inspected,
            "TUN activation requires complete pre-activation route and DNS inspection");

        let runtime_directory = self.coordinator.runtime_directory()
            .context("cannot resolve private TUN runtime directory")?;
        let activation_request = request.clone();
        let target = traffic_target.clone();
        self.activate_xray_node_with_readiness(
            CoreId::Xray, request, node, listen_port, executable, attachment_timeout,
            move |process, token| {
                let current = self.coordinator.load_current()?
                    .context("Prepared Xray activation manifest disappeared before readiness")?;
                ensure!(current.token == *token
                    && current.snapshot.phase == super::recovery::SupervisorPhase::Prepared,
                    "Xray readiness does not match the exact Prepared activation generation");
                let interface_index = current.snapshot.manifest.interface_index;
                let plan = super::route_policy::RoutingPolicyPlan::new(
                    activation_request.table_id,
                    activation_request.bypass_priority,
                    activation_request.proxy_priority,
                    activation_request.core_mark,
                    activation_request.core_mark_mask,
                    activation_request.interface_name.clone(),
                    interface_index,
                );
                plan.validate()?;
                let expected = super::readiness::ReadinessExpectation {
                    interface_name: &activation_request.interface_name,
                    interface_index,
                    core_mark: activation_request.core_mark,
                    core_mark_mask: activation_request.core_mark_mask,
                };
                let current_host = crate::tun::inspect()
                    .context("cannot capture post-activation DNS and firewall state")?;
                super::xray_launcher::verify_xray_end_to_end_readiness(
                    &runtime_directory,
                    process,
                    &activation_request.interface_name,
                    &expected,
                    std::net::SocketAddr::from(([127, 0, 0, 1], listen_port)),
                    Duration::from_secs(5),
                    &plan,
                    &expected_peers,
                    super::privilege_broker::BrokerSocketTransport::Tcp,
                    &target,
                    token.activation_id(),
                    token.generation(),
                    probe_timeout,
                    maximum_response_bytes,
                    &baseline_host,
                    &current_host,
                ).map(|_| ())
            },
        )
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
        ensure!(core.tun_attachment_mode().external_descriptor_environment() == Some(XRAY_TUN_FD_ENV),
            "Xray adapter does not expose the verified Linux descriptor environment contract");
        let mark = TunOutboundMark::new(request.core_mark, request.core_mark_mask)
            .context("invalid Xray proxy-outbound socket mark")?;
        let generated = core.generate_tun_activation_config(node, listen_port, mark)
            .context("cannot generate the native Xray TUN activation configuration")?;
        let runtime = self.coordinator.runtime_directory()
            .context("cannot resolve the private TUN activation runtime directory")?;
        let mut config = tempfile::Builder::new()
            .prefix("proxyctl-xray-tun-")
            .tempfile_in(&runtime)
            .context("cannot create a private Xray TUN configuration in the shared service runtime")?;
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
                if let Err(stop_error) = self.stop_xray_and_recover_generation(
                    &request.activation_id, request.generation, None,
                ) {
                    return Err(anyhow::anyhow!(
                        "Xray launch/attachment failed ({error:#}); exact service stop or generation recovery also failed ({stop_error:#}); Prepared resources remain supervisor-owned"
                    ));
                }
                return Err(error).context(
                    "Xray launch/attachment failed; the exact systemd service was stopped before generation recovery",
                );
            }
        };

        if let Err(error) = readiness(&process, &token) {
            if let Err(stop_error) = self.stop_xray_and_recover_generation(
                request.activation_id.as_str(), request.generation, Some(&process),
            ) {
                return Err(anyhow::anyhow!(
                    "Xray readiness failed ({error:#}); exact service stop or generation recovery failed ({stop_error:#}); Prepared resources remain supervisor-owned"
                ));
            }
            let _ = child.try_wait();
            return Err(error).context(
                "Xray readiness failed; the exact systemd service was stopped before generation recovery",
            );
        }

        let managed = match managed_activation::commit_prepared_managed_process(
            self.coordinator, &token, process.clone(),
        ) {
            Ok(managed) => managed,
            Err(error) => {
                if let Err(stop_error) = self.stop_xray_and_recover_generation(
                    request.activation_id.as_str(), request.generation, Some(&process),
                ) {
                    return Err(anyhow::anyhow!(
                        "Xray process commit failed ({error:#}); exact service stop or generation recovery failed ({stop_error:#}); Prepared resources remain supervisor-owned"
                    ));
                }
                let _ = child.try_wait();
                return Err(error).context(
                    "Xray process commit failed; the exact systemd service was stopped before generation recovery",
                );
            }
        };

        Ok(XrayActivation { child, managed })
    }

    fn stop_xray_and_recover_generation(
        &self,
        activation_id: &str,
        generation: u64,
        process: Option<&ProcessIdentity>,
    ) -> Result<()> {
        super::xray_launcher::stop_xray_generation(activation_id, generation, process)
            .context("cannot confirm that the exact Xray system service has stopped")?;
        let recovery = self.helper.recover(activation_id.to_owned(), generation);
        if matches!(recovery.as_ref(), Ok(response) if response.success) {
            return Ok(());
        }
        let store = super::manifest_store::ManifestStore::open(
            self.coordinator.runtime_directory().to_path_buf()
        )?;
        let recovery_message = match &recovery {
            Ok(response) => response.message.clone(),
            Err(error) => format!("{error:#}"),
        };
        ensure!(store.load()?.is_none() && store.load_transaction_journal()?.is_none(),
            "exact-generation Xray TUN cleanup is incomplete: {recovery_message}");
        Ok(())
    }

    /// Start the CLI-independent systemd user service while the manifest is Prepared.
    ///
    /// The supervisor waits for this exact generation to commit Running; if the controller
    /// disappears or startup stalls, it terminates any persisted Prepared core before recovery.
    fn start_recovery_supervisor(&self, activation: &ManagedActivation) -> Result<()> {
        let runtime = self.coordinator.runtime_directory()?;
        let manifest = runtime.join("tun-manifest.json");
        const SUPERVISOR: &str = "/usr/libexec/proxyctl-tun-supervisor";
        let executable = Path::new(SUPERVISOR);
        let metadata = std::fs::symlink_metadata(executable)
            .context("installed TUN recovery supervisor is missing; install the Proxyctl TUN helper bundle")?;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(metadata.file_type().is_file() && metadata.uid() == 0
            && metadata.permissions().mode() & 0o111 != 0
            && metadata.permissions().mode() & 0o022 == 0
            && metadata.permissions().mode() & 0o7000 == 0
            && metadata.nlink() == 1,
            "TUN recovery supervisor must be a root-owned, non-writable, single-link executable");
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

    /// Stop the exact managed Xray service before asking the broker to remove its TUN routes.
    ///
    /// The helper recovery request is never sent while the recorded Xray process is still live.
    pub fn stop_current_xray(&self) -> Result<()> {
        let Some(current) = self.coordinator.load_current()?
            else { return Ok(()); };
        ensure!(matches!(
            current.snapshot.phase,
            super::recovery::SupervisorPhase::Prepared
                | super::recovery::SupervisorPhase::Running
                | super::recovery::SupervisorPhase::CleanupPending
        ), "current activation is not in a stoppable lifecycle phase");
        let process = current.snapshot.core_process.as_ref();
        super::xray_launcher::stop_xray_generation(
            current.token.activation_id(),
            current.token.generation(),
            process,
        ).context("could not stop the exact Xray service before TUN cleanup")?;
        let recovery = self.helper.recover(
            current.token.activation_id().to_owned(),
            current.token.generation(),
        );
        if matches!(recovery.as_ref(), Ok(response) if response.success) {
            return Ok(());
        }
        // The independent systemd supervisor may win the race and finish the same generation
        // while the explicit stop request is waiting. Accept that only when both durable
        // ownership records are absent; never infer success from a failed IPC response alone.
        let store = super::manifest_store::ManifestStore::open(
            self.coordinator.runtime_directory().to_path_buf()
        )?;
        let recovery_message = match &recovery {
            Ok(response) => response.message.clone(),
            Err(error) => format!("{error:#}"),
        };
        ensure!(store.load()?.is_none() && store.load_transaction_journal()?.is_none(),
            "exact-generation Xray TUN cleanup is incomplete: {recovery_message}");
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
