//! Complete single-executable startup and monitoring for native persistent-device TUN cores.
//!
//! The privileged supervisor owns the staged config, kernel transaction, exact core child,
//! durable session receipt, and cleanup monitor for the full session lifetime.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{net::SocketAddr, process::ExitStatus, time::Duration};

use super::{
    config_staging::{self, StagedConfig},
    direct_core_launcher::SupervisedCore,
    launch_spec::{CoreKind, LaunchSpec},
    lifecycle_coordinator::{ActivationToken, LifecycleCoordinator},
    linux_journal_backend::LinuxJournalBackend,
    manifest_store::ManifestStore,
    native_session,
    privilege_broker::BrokerSocketTransport,
    recovery::SupervisorPhase,
    route_policy::RoutingPolicyPlan,
    session_record::{SessionRecord, SessionStore},
    supervisor_activation,
};

/// A committed native TUN session whose resources remain owned until this value is monitored
/// to core exit. Dropping it also drops the staged config, so callers must keep it alive.
pub struct RunningNativeSession {
    core: SupervisedCore,
    _staged_config: StagedConfig,
    store: ManifestStore,
    coordinator: LifecycleCoordinator,
    sessions: SessionStore,
    token: ActivationToken,
    pub record: SessionRecord,
}

impl RunningNativeSession {
    /// Wait for the exact launched child to exit, then recover only this activation generation.
    ///
    /// A concurrent `proxyctl tun stop` may already have completed recovery. In that case
    /// the absent manifest is treated as an already-finished session, never as permission to
    /// touch a newer generation.
    pub fn wait_and_recover(mut self) -> Result<ExitStatus> {
        let status = self
            .core
            .child
            .wait()
            .context("cannot wait for the managed native TUN core")?;
        self.recover_if_current()?;
        ensure!(
            status.success(),
            "managed {} TUN core exited with {status}",
            self.record.core.as_str()
        );
        Ok(status)
    }

    fn recover_if_current(&self) -> Result<()> {
        let Some(current) = self.coordinator.load_current()? else {
            return Ok(());
        };
        ensure!(
            current.token == self.token
                && current.snapshot.phase == SupervisorPhase::Running,
            "TUN session changed before supervisor cleanup; preserving the newer or inconsistent generation"
        );
        let mut backend = LinuxJournalBackend::open_for_recovery(
            self.store.clone(),
            self.token.activation_id(),
            self.token.generation(),
        )
        .context("cannot reopen the exact TUN journal after core exit")?;
        self.coordinator
            .recover_session(&self.token, &self.sessions, &mut backend)
            .context("cannot recover the completed native TUN session")
    }
}

/// Start a native persistent-device session after capturing an independent host baseline.
///
/// All node/database resolution has already happened in the unprivileged preparation process.
/// This function accepts only the bounded LaunchSpec data, derives every privileged path and
/// executable locally, and runs the complete end-to-end readiness gate before committing Running.
pub fn start(
    spec: &LaunchSpec,
    invoking_uid: u32,
    invoking_gid: u32,
    runtime: std::path::PathBuf,
) -> Result<RunningNativeSession> {
    ensure!(
        unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0,
        "native TUN startup must run inside the real/effective-root supervisor"
    );
    ensure!(
        matches!(spec.core, CoreKind::SingBox | CoreKind::Mihomo),
        "native persistent-device supervisor supports only sing-box and Mihomo"
    );
    spec.validate()?;
    ensure!(invoking_uid != 0, "invoking TUN UID must be non-zero");
    ensure!(
        runtime == std::path::PathBuf::from("/run/proxyctl").join(invoking_uid.to_string()),
        "TUN runtime path does not match the authenticated invoking UID"
    );

    let baseline_host = crate::tun::inspect()
        .context("cannot capture pre-activation host network baseline")?;
    ensure!(
        baseline_host.routes_inspected && baseline_host.dns_inspected,
        "native TUN startup requires complete pre-activation route and DNS inspection"
    );
    super::readiness::verify_host_network_unchanged(&baseline_host, &baseline_host)
        .context("pre-activation DNS or firewall evidence is incomplete")?;

    let staged_config = config_staging::stage_config(
        &runtime,
        spec.generated_config.as_bytes(),
    )
    .context("cannot stage generated core configuration in the root-owned runtime")?;
    staged_config.sync()?;

    let store = ManifestStore::open(runtime.clone())?;
    let coordinator = LifecycleCoordinator::new(store.clone())?;
    let sessions = SessionStore::open_root_owned(runtime.clone(), invoking_uid)?;
    ensure!(
        sessions.load()?.is_none(),
        "an existing privileged TUN session must be recovered before starting another"
    );

    let (token, applied) = match supervisor_activation::apply_native_kernel_plan(
        spec.core,
        store.clone(),
        &coordinator,
        &spec.activation_id,
        spec.generation,
        invoking_uid,
        invoking_gid,
    ) {
        Ok(value) => value,
        Err(error) => {
            let recovery = recover_unmanifested_start(&store);
            return Err(error).context(match recovery {
                Ok(()) => "native TUN kernel setup failed; any recoverable partial transaction was cleaned",
                Err(ref recovery_error) => {
                    return Err(error).context(format!(
                        "native TUN kernel setup failed; automatic recovery also failed ({recovery_error:#}); durable evidence was retained"
                    ));
                }
            });
        }
    };

    let (core_mark, core_mark_mask) =
        super::route_policy::mark_for_activation_id(&spec.activation_id)?;
    let bypass_priority = applied
        .manifest
        .rule_priority
        .checked_sub(1)
        .context("journaled TUN proxy priority has no preceding core-bypass priority")?;
    let plan = RoutingPolicyPlan::new(
        applied.manifest.table_id,
        bypass_priority,
        applied.manifest.rule_priority,
        core_mark,
        core_mark_mask,
        applied.manifest.interface_name.clone(),
        applied.manifest.interface_index,
    );
    plan.validate()?;

    let listener = SocketAddr::from(([127, 0, 0, 1], spec.listen_port));
    let readiness = |process: &super::process::ProcessIdentity,
                     token: &ActivationToken|
     -> Result<()> {
        let current_host = crate::tun::inspect()
            .context("cannot capture post-activation DNS and firewall state")?;
        super::readiness::verify_native_core_dual_stack_end_to_end_readiness(
            &runtime,
            process,
            &applied.manifest.interface_name,
            applied.manifest.interface_index,
            core_mark,
            core_mark_mask,
            listener,
            Duration::from_secs(5),
            &plan,
            &spec.expected_peers,
            BrokerSocketTransport::Tcp,
            &spec.traffic_targets,
            token.activation_id(),
            token.generation(),
            Duration::from_secs(10),
            64 * 1024,
            &baseline_host,
            &current_host,
        )
        .map(|_| ())
    };

    let (core, record) = match native_session::launch_and_commit_native_session(
        spec,
        staged_config.path(),
        invoking_uid,
        &coordinator,
        &token,
        &sessions,
        readiness,
    ) {
        Ok(value) => value,
        Err(error) => {
            let recovery = recover_committed_start(&store, &coordinator, &sessions, &token);
            return match recovery {
                Ok(()) => Err(error).context(
                    "native TUN startup failed; the core was terminated and the journaled activation was recovered",
                ),
                Err(recovery_error) => Err(error).context(format!(
                    "native TUN startup failed; automatic recovery also failed ({recovery_error:#}); durable evidence was retained"
                )),
            };
        }
    };

    Ok(RunningNativeSession {
        core,
        _staged_config: staged_config,
        store,
        coordinator,
        sessions,
        token,
        record,
    })
}

fn recover_unmanifested_start(store: &ManifestStore) -> Result<()> {
    let Some(journal) = store.load_transaction_journal()? else {
        return Ok(());
    };
    let mut backend = LinuxJournalBackend::open_for_recovery(
        store.clone(),
        &journal.activation_id,
        journal.generation,
    )?;
    super::journal_recovery_executor::recover(store, &mut backend)
        .context("cannot recover the partial pre-manifest TUN transaction")?;
    Ok(())
}

fn recover_committed_start(
    store: &ManifestStore,
    coordinator: &LifecycleCoordinator,
    sessions: &SessionStore,
    token: &ActivationToken,
) -> Result<()> {
    let mut backend = LinuxJournalBackend::open_for_recovery(
        store.clone(),
        token.activation_id(),
        token.generation(),
    )?;
    coordinator
        .recover_session(token, sessions, &mut backend)
        .context("cannot recover the failed native TUN startup generation")?;
    Ok(())
}
