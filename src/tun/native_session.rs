//! Core startup and durable session commit for native persistent-device TUN cores.
//!
//! This module does not create kernel resources. It consumes the exact Prepared activation
//! committed by `supervisor_activation`, launches only the selected native-device core,
//! verifies its attachment and caller-supplied end-to-end readiness, then commits the
//! root-owned session receipt before the manifest transitions to Running.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{path::Path, time::Duration};

use super::{
    direct_core_launcher::{self, SupervisedCore},
    launch_spec::{CoreKind, LaunchSpec},
    lifecycle_coordinator::{ActivationToken, LifecycleCoordinator},
    manifest_store::ManifestSnapshot,
    recovery::SupervisorPhase,
    session_record::{SessionRecord, SessionStore},
};

/// Validate that the launch request, Prepared manifest, and token describe one exact native
/// persistent-device activation. Xray is deliberately excluded because its current adapter
/// contract is descriptor-backed.
pub fn validate_prepared_native_activation(
    spec: &LaunchSpec,
    token: &ActivationToken,
    snapshot: &ManifestSnapshot,
) -> Result<()> {
    spec.validate()?;
    ensure!(
        matches!(spec.core, CoreKind::SingBox | CoreKind::Mihomo),
        "native persistent-device startup supports only sing-box and Mihomo"
    );
    ensure!(
        spec.activation_id == token.activation_id()
            && snapshot.manifest.activation_id == token.activation_id()
            && snapshot.generation == token.generation(),
        "launch request, Prepared manifest, and lifecycle token identities do not match"
    );
    ensure!(
        snapshot.phase == SupervisorPhase::Prepared && snapshot.core_process.is_none(),
        "native core startup requires an unbound Prepared manifest"
    );
    ensure!(
        snapshot.manifest.interface_name == super::activation_plan::TUN_INTERFACE_NAME
            && snapshot.manifest.interface_index > 0,
        "Prepared manifest does not contain the expected persistent native TUN interface"
    );
    Ok(())
}

/// Launch a native-device core and commit its exact process identity as a durable session.
///
/// `readiness` is mandatory: callers must supply the complete end-to-end readiness check,
/// not merely a listener probe. If any step after spawn fails, this function kills and reaps
/// the direct child but deliberately retains the Prepared manifest, journal, and any session
/// receipt already committed. The caller must leave those records for the explicit recovery
/// path; it must never attempt ad-hoc interface or route deletion.
///
/// The caller must keep `staged_config` alive for the entire core lifetime.
pub fn launch_and_commit_native_session<F>(
    spec: &LaunchSpec,
    staged_config: &Path,
    invoking_uid: u32,
    coordinator: &LifecycleCoordinator,
    token: &ActivationToken,
    sessions: &SessionStore,
    readiness: F,
) -> Result<(SupervisedCore, SessionRecord)>
where
    F: FnOnce(&super::process::ProcessIdentity, &ActivationToken) -> Result<()>,
{
    ensure!(invoking_uid != 0, "invoking TUN user UID must be non-zero");
    let runtime_directory = coordinator.runtime_directory()?;
    ensure!(
        sessions.path().parent() == Some(runtime_directory.as_path()),
        "session receipt and lifecycle manifest must share one runtime directory"
    );
    let current = coordinator
        .load_current()?
        .context("Prepared native TUN activation disappeared before core startup")?;
    validate_prepared_native_activation(spec, token, &current.snapshot)?;

    let mut core = direct_core_launcher::spawn_core(
        spec.core,
        &spec.managed_core_root,
        staged_config,
        invoking_uid,
        None,
    )
    .context("cannot launch selected native TUN core")?;

    let startup = (|| -> Result<SessionRecord> {
        super::process_attachment::wait_for_process_tun_attachment(
            &core.identity,
            &current.snapshot.manifest.interface_name,
            current.snapshot.manifest.interface_index,
            Duration::from_secs(5),
        )
        .context("native core did not attach to the exact persistent TUN interface")?;

        readiness(&core.identity, token)
            .context("native core end-to-end readiness verification failed")?;

        let record = SessionRecord::new(
            invoking_uid,
            token.activation_id().to_owned(),
            token.generation(),
            spec.core,
            core.identity.clone(),
        )
        .context("cannot construct the privileged native TUN session receipt")?;
        coordinator
            .bind_core_session(token, sessions, &record)
            .context("cannot durably commit the native TUN core session")?;
        Ok(record)
    })();

    match startup {
        Ok(record) => Ok((core, record)),
        Err(error) => {
            // The Child is still our unreaped direct child, so its PID cannot be reused
            // between spawn and this kill/wait pair. Durable recovery evidence is retained.
            let kill_error = core.child.kill().err();
            let wait_error = core.child.wait().err();
            if kill_error.is_some() || wait_error.is_some() {
                let startup_error = format!("{error:#}");
                return Err(error).context(format!(
                    "startup failed ({startup_error}); child termination error: {}; child reaping error: {}; durable recovery evidence was retained",
                    kill_error.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                    wait_error.map_or_else(|| "none".to_owned(), |value| value.to_string())
                ));
            }
            Err(error).context(
                "native TUN startup failed; the direct child was terminated where possible and durable recovery evidence was retained",
            )
        }
    }
}
