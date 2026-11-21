//! Coordinates privileged TUN policy activation with the managed core process.
//!
//! The mutation broker commits the Prepared ownership manifest. This module adopts that
//! exact generation, pins the launched core process, and only then commits Running. Any
//! failure after successful kernel activation requests generation-matched broker recovery.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};

use super::{
    lifecycle_coordinator::{ActivationToken, LifecycleCoordinator},
    mutation_helper_launcher::MutationHelper,
    process::{ProcessHandle, ProcessIdentity},
    mutation_broker::MutationResponse,
    recovery::{SupervisorEvent, SupervisorPhase},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedActivation {
    pub token: ActivationToken,
    pub activation_message: String,
}

/// Activate the typed kernel policy and bind it to the already-launched core process.
///
/// The caller must launch the core with its native TUN configuration and socket mark
/// configured before calling this function. The process identity is captured from that
/// exact child, not reconstructed from a PID later.
#[allow(clippy::too_many_arguments)]
pub fn prepare_managed_activation(
    helper: &MutationHelper,
    coordinator: &LifecycleCoordinator,
    activation_id: String,
    generation: u64,
    interface_name: String,
    owner_uid: u32,
    owner_gid: u32,
    table_id: u32,
    bypass_priority: u32,
    proxy_priority: u32,
    core_mark: u32,
    core_mark_mask: u32,
) -> Result<(ActivationToken, String)> {
    let response = helper.activate(
        activation_id.clone(), generation, interface_name, owner_uid, owner_gid,
        table_id, bypass_priority, proxy_priority, core_mark, core_mark_mask,
    )?;
    if !response.success {
        anyhow::bail!(
            "privileged TUN activation failed: {}; inspect and recover this generation if its durable journal was retained",
            response.message
        );
    }
    let token = match coordinator.adopt_prepared(&activation_id, generation) {
        Ok(token) => token,
        Err(error) => {
            let recovery = helper.recover(activation_id, generation);
            return Err(error).context(match recovery {
                Ok(result) if result.success => "activation manifest adoption failed; broker recovery completed",
                Ok(result) => return Err(anyhow::anyhow!(
                    "activation manifest adoption failed ({error:#}); broker recovery failed: {}",
                    result.message
                )),
                Err(recovery_error) => return Err(anyhow::anyhow!(
                    "activation manifest adoption failed ({error:#}); broker recovery request failed: {recovery_error:#}"
                )),
            });
        }
    };
    Ok((token, response.message))
}

/// Commit a process after readiness without performing broker recovery.
///
/// Xray's systemd service must be stopped by the orchestrator before its broker routes are
/// recovered; this primitive therefore changes only the durable lifecycle phase.
pub fn commit_prepared_managed_process(
    coordinator: &LifecycleCoordinator,
    token: &ActivationToken,
    process: ProcessIdentity,
) -> Result<ManagedActivation> {
    let current = coordinator.load_current()?
        .context("prepared activation manifest disappeared before process commit")?;
    ensure!(current.token == *token,
        "managed process commit token does not match the current activation");
    match current.snapshot.core_process {
        Some(ref persisted) => {
            ensure!(persisted == &process && persisted.verify()?,
                "persisted core process identity differs from the launched process");
        }
        None => coordinator.bind_core_process(token, process)?,
    }
    coordinator.apply_event(token, SupervisorEvent::StartCommitted)?;
    Ok(ManagedActivation {
        token: token.clone(),
        activation_message: "managed core process committed after readiness".into(),
    })
}

/// Compatibility commit for callers that own process termination and broker recovery directly.
pub fn commit_managed_process(
    helper: &MutationHelper,
    coordinator: &LifecycleCoordinator,
    token: &ActivationToken,
    process: ProcessIdentity,
) -> Result<ManagedActivation> {
    match commit_prepared_managed_process(coordinator, token, process.clone()) {
        Ok(activation) => Ok(activation),
        Err(error) => {
            if let Err(termination_error) = terminate_process_identity(&process) {
                return Err(anyhow::anyhow!(
                    "managed core commit failed ({error:#}); the core could not be confirmed stopped ({termination_error:#}); TUN resources were retained for the independent recovery supervisor"
                ));
            }
            let recovery = helper.recover(token.activation_id().to_owned(), token.generation());
            match recovery {
                Ok(result) if result.success => Err(error).context(
                    "managed core commit failed; the exact process was stopped and broker resources were recovered",
                ),
                Ok(result) => Err(anyhow::anyhow!(
                    "managed core commit failed ({error:#}); process stopped but generation recovery failed: {}",
                    result.message
                )),
                Err(recovery_error) => Err(anyhow::anyhow!(
                    "managed core commit failed ({error:#}); process stopped but generation recovery request failed: {recovery_error:#}"
                )),
            }
        }
    }
}

/// Compatibility composition for callers that have already launched and validated a core.
#[allow(clippy::too_many_arguments)]
pub fn activate_managed_core(
    helper: &MutationHelper,
    coordinator: &LifecycleCoordinator,
    activation_id: String,
    generation: u64,
    interface_name: String,
    owner_uid: u32,
    owner_gid: u32,
    table_id: u32,
    bypass_priority: u32,
    proxy_priority: u32,
    core_mark: u32,
    core_mark_mask: u32,
    process: ProcessIdentity,
) -> Result<ManagedActivation> {
    let (token, _message) = prepare_managed_activation(
        helper, coordinator, activation_id, generation, interface_name, owner_uid, owner_gid,
        table_id, bypass_priority, proxy_priority, core_mark, core_mark_mask,
    )?;
    commit_managed_process(helper, coordinator, &token, process)
}

/// Supervise a broker-owned activation and request exact-generation cleanup on core exit.
///
/// Unlike the backend-injected supervisor, this production-facing handoff leaves the
/// privileged LinuxJournalBackend inside the persistent broker. The pidfd pins the core
/// instance while waiting; the broker performs journal-backed compare-and-remove cleanup.
pub fn monitor_managed_core(
    helper: &MutationHelper,
    coordinator: &LifecycleCoordinator,
    activation: &ManagedActivation,
    process: &ProcessHandle,
) -> Result<MutationResponse> {
    let current = coordinator
        .load_current()?
        .context("managed TUN manifest disappeared before supervision")?;
    anyhow::ensure!(
        current.token == activation.token
            && current.snapshot.phase == SupervisorPhase::Running,
        "managed supervisor token is stale or activation is not Running"
    );
    anyhow::ensure!(
        current.snapshot.core_process.as_ref() == Some(process.identity()),
        "supervisor pidfd does not match the persisted core process identity"
    );

    while !process.wait_exit(std::time::Duration::from_millis(250))? {}

    // Persist the exit before asking the broker to mutate kernel state. A failed recovery
    // therefore leaves a durable CleanupPending/Conflicted record for a later retry.
    coordinator.apply_event(&activation.token, SupervisorEvent::CoreExited)?;
    stop_core_service_for_generation(&activation.token, Some(process.identity()))?;
    let response = helper.recover(
        activation.token.activation_id().to_owned(),
        activation.token.generation(),
    )?;
    if !response.success {
        let _ = coordinator.apply_event(&activation.token, SupervisorEvent::CleanupConflicted);
        anyhow::bail!("broker cleanup failed; durable recovery state retained: {}", response.message);
    }
    Ok(response)
}


/// Stop a core whose identity was persisted while its activation is still Prepared.
#[cfg(target_os = "linux")]
fn stop_core_service_for_generation(
    token: &ActivationToken,
    process: Option<&ProcessIdentity>,
) -> Result<()> {
    super::xray_launcher::stop_xray_generation(
        token.activation_id(), token.generation(), process,
    ).context("cannot confirm stop of the generation-bound Xray system service")
}

#[cfg(not(target_os = "linux"))]
fn stop_core_service_for_generation(
    _token: &ActivationToken,
    _process: Option<&ProcessIdentity>,
) -> Result<()> {
    Ok(())
}

fn terminate_prepared_core_process(
    coordinator: &LifecycleCoordinator,
    token: &ActivationToken,
) -> Result<()> {
    let current = coordinator.load_current()?
        .context("Prepared activation disappeared before orphaned core cleanup")?;
    ensure!(current.token == *token && current.snapshot.phase == SupervisorPhase::Prepared,
        "orphaned core cleanup token does not match the Prepared activation");
    let Some(identity) = current.snapshot.core_process else {
        return Ok(());
    };
    if !identity.verify()? {
        return Ok(());
    }
    terminate_process_identity(&identity)
        .context("cannot terminate the orphaned Prepared core process")
}

fn terminate_process_identity(identity: &ProcessIdentity) -> Result<()> {
    if !identity.verify()? {
        return Ok(());
    }
    let process = match ProcessHandle::open(identity.clone()) {
        Ok(process) => process,
        Err(_error) if !identity.verify()? => return Ok(()),
        Err(error) => return Err(error).context("cannot pin managed core process for termination"),
    };
    if !process.wait_exit(std::time::Duration::ZERO)? {
        if let Err(error) = process.signal(libc::SIGTERM) {
            if identity.verify()? {
                return Err(error).context("cannot request termination of managed core process");
            }
        }
        if !process.wait_exit(std::time::Duration::from_secs(1))? {
            process.signal(libc::SIGKILL)
                .context("cannot force-stop managed core process")?;
            ensure!(process.wait_exit(std::time::Duration::from_secs(2))?,
                "managed core process did not exit within the termination deadline");
        }
    }
    ensure!(!identity.verify()?, "managed core process identity remains live after termination");
    Ok(())
}

/// Resume a broker-backed supervisor after its unprivileged process restarts.
///
/// CleanupPending is retried immediately through the broker. Running activations are rebound
/// to the persisted process identity and monitored; a vanished or replaced core is converted
/// into CoreExited before exact-generation broker recovery is requested.
pub fn resume_managed_supervision(
    helper: &MutationHelper,
    coordinator: &LifecycleCoordinator,
) -> Result<MutationResponse> {
    let current = coordinator
        .load_current()?
        .context("no managed TUN activation is available to resume")?;
    let token = current.token;
    if matches!(current.snapshot.phase, SupervisorPhase::CleanupPending | SupervisorPhase::Prepared) {
        let phase = current.snapshot.phase;
        if phase == SupervisorPhase::Prepared {
            terminate_prepared_core_process(coordinator, &token)?;
        }
        stop_core_service_for_generation(&token, current.snapshot.core_process.as_ref())?;
        let response = helper.recover(token.activation_id().to_owned(), token.generation())?;
        anyhow::ensure!(response.success,
            "broker cleanup for interrupted {phase:?} activation failed: {}", response.message);
        return Ok(response);
    }
    anyhow::ensure!(
        current.snapshot.phase == SupervisorPhase::Running,
        "only Running, Prepared, or CleanupPending activations can be resumed"
    );
    let identity = current
        .snapshot
        .core_process
        .context("running activation has no persisted core process identity")?;
    if !identity.verify()? {
        coordinator.apply_event(&token, SupervisorEvent::CoreExited)?;
        stop_core_service_for_generation(&token, Some(&identity))?;
        let response = helper.recover(token.activation_id().to_owned(), token.generation())?;
        anyhow::ensure!(response.success, "dead-core broker cleanup failed: {}", response.message);
        return Ok(response);
    }
    let process = match ProcessHandle::open(identity.clone()) {
        Ok(process) => process,
        Err(_error) if !identity.verify()? => {
            coordinator.apply_event(&token, SupervisorEvent::CoreExited)?;
            stop_core_service_for_generation(&token, Some(&identity))?;
            let response = helper.recover(token.activation_id().to_owned(), token.generation())?;
            anyhow::ensure!(response.success, "dead-core broker cleanup failed: {}", response.message);
            return Ok(response);
        }
        Err(error) => return Err(error).context("cannot safely reopen the managed core pidfd"),
    };
    if process.is_exited()? {
        coordinator.apply_event(&token, SupervisorEvent::CoreExited)?;
        stop_core_service_for_generation(&token, Some(&identity))?;
        let response = helper.recover(token.activation_id().to_owned(), token.generation())?;
        anyhow::ensure!(response.success, "exited-core broker cleanup failed: {}", response.message);
        return Ok(response);
    }
    let activation = ManagedActivation {
        token,
        activation_message: "resumed existing managed activation".into(),
    };
    monitor_managed_core(helper, coordinator, &activation, &process)
}


/// Wait for the exact Prepared generation to either commit Running or enter cleanup.
///
/// The recovery service is launched before the core. Prepared is therefore a legitimate
/// transient state, not an instruction to tear down immediately. If the CLI disappears before
/// committing Running, the bounded startup deadline converts the orphaned Prepared generation
/// into exact-generation broker recovery.
pub fn resume_managed_supervision_after_startup(
    helper: &MutationHelper,
    coordinator: &LifecycleCoordinator,
    activation_id: &str,
    generation: u64,
    startup_timeout: std::time::Duration,
) -> Result<()> {
    ensure!(!activation_id.is_empty() && generation > 0, "invalid supervisor activation identity");
    ensure!(
        !startup_timeout.is_zero() && startup_timeout <= std::time::Duration::from_secs(60),
        "supervisor startup wait must be between 1ms and 60s"
    );
    let deadline = std::time::Instant::now() + startup_timeout;
    loop {
        let Some(current) = coordinator.load_current()? else {
            // Successful broker cleanup removes the durable manifest.
            return Ok(());
        };
        ensure!(
            current.token.activation_id() == activation_id
                && current.token.generation() == generation,
            "supervisor observed a different activation generation; refusing cross-generation recovery"
        );
        match current.snapshot.phase {
            SupervisorPhase::Prepared if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            SupervisorPhase::Prepared | SupervisorPhase::CleanupPending => {
                if current.snapshot.phase == SupervisorPhase::Prepared {
                    terminate_prepared_core_process(coordinator, &current.token)?;
                }
                let response = helper.recover(activation_id.to_owned(), generation)?;
                ensure!(response.success, "orphaned activation recovery failed: {}", response.message);
                return Ok(());
            }
            SupervisorPhase::Running => {
                resume_managed_supervision(helper, coordinator)?;
                return Ok(());
            }
            SupervisorPhase::Cleaned => return Ok(()),
        }
    }
}
