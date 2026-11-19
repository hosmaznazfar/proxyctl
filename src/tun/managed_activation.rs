//! Coordinates privileged TUN policy activation with the managed core process.
//!
//! The mutation broker commits the Prepared ownership manifest. This module adopts that
//! exact generation, pins the launched core process, and only then commits Running. Any
//! failure after successful kernel activation requests generation-matched broker recovery.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result};

use super::{
    lifecycle_coordinator::{ActivationToken, LifecycleCoordinator},
    mutation_helper_launcher::MutationHelper,
    process::ProcessIdentity,
    recovery::SupervisorEvent,
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
    let response = helper.activate(
        activation_id.clone(),
        generation,
        interface_name,
        owner_uid,
        owner_gid,
        table_id,
        bypass_priority,
        proxy_priority,
        core_mark,
        core_mark_mask,
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

    if let Err(error) = coordinator
        .bind_core_process(&token, process)
        .and_then(|()| coordinator.apply_event(&token, SupervisorEvent::StartCommitted).map(|_| ()))
    {
        let recovery = helper.recover(activation_id, generation);
        return match recovery {
            Ok(result) if result.success => Err(error).context(
                "managed core binding failed; the exact broker activation was recovered",
            ),
            Ok(result) => Err(anyhow::anyhow!(
                "managed core binding failed ({error:#}); generation recovery failed: {}",
                result.message
            )),
            Err(recovery_error) => Err(anyhow::anyhow!(
                "managed core binding failed ({error:#}); generation recovery request failed: {recovery_error:#}"
            )),
        };
    }

    Ok(ManagedActivation {
        token,
        activation_message: response.message,
    })
}
