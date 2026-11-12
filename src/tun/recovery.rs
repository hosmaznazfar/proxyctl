//! Recovery-supervisor contract and explicit backend selection.
//!
//! No service is started here. A concrete backend is not activation-ready until it implements
//! this contract and passes the same crash/recovery fault-injection suite.

use super::service_manager::ServiceManager;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryBackendKind {
    Systemd,
    OpenRc,
    Runit,
    S6,
    Dinit,
    SysVinit,
    Unsupported,
}

impl RecoveryBackendKind {
    pub fn for_manager(manager: ServiceManager) -> Self {
        match manager {
            ServiceManager::Systemd => Self::Systemd,
            ServiceManager::OpenRc => Self::OpenRc,
            ServiceManager::Runit => Self::Runit,
            ServiceManager::S6 => Self::S6,
            ServiceManager::Dinit => Self::Dinit,
            ServiceManager::SysVinit => Self::SysVinit,
            ServiceManager::Unknown => Self::Unsupported,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::OpenRc => "OpenRC",
            Self::Runit => "runit",
            Self::S6 => "s6",
            Self::Dinit => "dinit",
            Self::SysVinit => "SysVinit",
            Self::Unsupported => "unsupported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorIdentity {
    pub activation_id: String,
    pub service_name: String,
    pub manifest_path: String,
    pub generation: u64,
}

impl SupervisorIdentity {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.activation_id.len() == 36
                && self.activation_id.bytes().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit()
                    }
                }),
            "invalid supervisor activation identity"
        );
        ensure!(
            self.service_name.starts_with("proxyctl-tun-")
                && self.service_name.len() <= 64
                && self
                    .service_name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid supervisor service identity"
        );
        ensure!(
            !self.manifest_path.is_empty(),
            "supervisor manifest path is empty"
        );
        ensure!(
            self.generation > 0,
            "supervisor generation must be non-zero"
        );
        Ok(())
    }
}

/// start/stop must be idempotent and generation-checked; a stale request may not stop a newer run.
pub trait RecoverySupervisor {
    fn start(&mut self, identity: &SupervisorIdentity) -> Result<()>;
    fn is_alive(&mut self, identity: &SupervisorIdentity) -> Result<bool>;
    fn stop(&mut self, identity: &SupervisorIdentity) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_manager_selection_is_explicit_and_never_falls_back() {
        for (manager, expected) in [
            (ServiceManager::Systemd, RecoveryBackendKind::Systemd),
            (ServiceManager::OpenRc, RecoveryBackendKind::OpenRc),
            (ServiceManager::Runit, RecoveryBackendKind::Runit),
            (ServiceManager::S6, RecoveryBackendKind::S6),
            (ServiceManager::Dinit, RecoveryBackendKind::Dinit),
            (ServiceManager::SysVinit, RecoveryBackendKind::SysVinit),
            (ServiceManager::Unknown, RecoveryBackendKind::Unsupported),
        ] {
            assert_eq!(RecoveryBackendKind::for_manager(manager), expected);
        }
        assert_eq!(
            RecoveryBackendKind::for_manager(ServiceManager::Unknown).as_str(),
            "unsupported"
        );
    }

    #[test]
    fn supervisor_identity_rejects_service_name_injection() {
        let valid = SupervisorIdentity {
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            service_name: "proxyctl-tun-12345678".into(),
            manifest_path: "/private/runtime/tun-manifest.json".into(),
            generation: 1,
        };
        valid.validate().unwrap();
        let mut invalid = valid.clone();
        invalid.service_name = "proxyctl-tun-x;stop".into();
        assert!(invalid.validate().is_err());
        let mut invalid = valid;
        invalid.generation = 0;
        assert!(invalid.validate().is_err());
    }
}

/// Durable lifecycle phase written by the supervisor alongside the ownership manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorPhase {
    Prepared,
    Running,
    CleanupPending,
    Cleaned,
}

/// Events are generation-scoped. A service restart must reload the persisted phase before
/// accepting events, and stale events from an earlier activation must never affect a newer one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorEvent {
    StartCommitted,
    CoreReady,
    CoreExited,
    CleanupCompleted,
    CleanupConflicted,
}

/// The supervisor returns an instruction; the caller performs it through its injected backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    None,
    StartManagedCore,
    CleanupManifestResources,
    RemoveManifest,
    PreserveManifestAndReportConflict,
    IgnoreStaleEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleTransition {
    pub phase: SupervisorPhase,
    pub action: RecoveryAction,
}

/// Pure, deterministic transition function shared by every service-manager backend.
/// It deliberately performs no process, filesystem, privilege, or network operation.
pub fn transition(
    phase: SupervisorPhase,
    event: SupervisorEvent,
    event_generation: u64,
    active_generation: u64,
) -> LifecycleTransition {
    if event_generation == 0 || event_generation != active_generation {
        return LifecycleTransition {
            phase,
            action: RecoveryAction::IgnoreStaleEvent,
        };
    }

    match (phase, event) {
        (SupervisorPhase::Prepared, SupervisorEvent::StartCommitted) => LifecycleTransition {
            phase: SupervisorPhase::Running,
            action: RecoveryAction::StartManagedCore,
        },
        (SupervisorPhase::Running, SupervisorEvent::CoreReady) => LifecycleTransition {
            phase: SupervisorPhase::Running,
            action: RecoveryAction::None,
        },
        (SupervisorPhase::Running, SupervisorEvent::CoreExited)
        | (SupervisorPhase::Prepared, SupervisorEvent::CoreExited) => LifecycleTransition {
            phase: SupervisorPhase::CleanupPending,
            action: RecoveryAction::CleanupManifestResources,
        },
        (SupervisorPhase::CleanupPending, SupervisorEvent::CleanupCompleted) => {
            LifecycleTransition {
                phase: SupervisorPhase::Cleaned,
                action: RecoveryAction::RemoveManifest,
            }
        }
        (SupervisorPhase::CleanupPending, SupervisorEvent::CleanupConflicted) => {
            LifecycleTransition {
                phase: SupervisorPhase::CleanupPending,
                action: RecoveryAction::PreserveManifestAndReportConflict,
            }
        }
        (SupervisorPhase::Cleaned, _) => LifecycleTransition {
            phase: SupervisorPhase::Cleaned,
            action: RecoveryAction::None,
        },
        (phase, _) => LifecycleTransition {
            phase,
            action: RecoveryAction::None,
        },
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn stale_generation_cannot_change_phase_or_request_cleanup() {
        let result = transition(SupervisorPhase::Running, SupervisorEvent::CoreExited, 6, 7);
        assert_eq!(result.phase, SupervisorPhase::Running);
        assert_eq!(result.action, RecoveryAction::IgnoreStaleEvent);
    }

    #[test]
    fn core_exit_enters_cleanup_and_manifest_is_removed_only_after_success() {
        let cleanup = transition(SupervisorPhase::Running, SupervisorEvent::CoreExited, 7, 7);
        assert_eq!(cleanup.phase, SupervisorPhase::CleanupPending);
        assert_eq!(cleanup.action, RecoveryAction::CleanupManifestResources);

        let completed = transition(cleanup.phase, SupervisorEvent::CleanupCompleted, 7, 7);
        assert_eq!(completed.phase, SupervisorPhase::Cleaned);
        assert_eq!(completed.action, RecoveryAction::RemoveManifest);
    }

    #[test]
    fn cleanup_conflict_keeps_manifest_for_recovery() {
        let result = transition(
            SupervisorPhase::CleanupPending,
            SupervisorEvent::CleanupConflicted,
            7,
            7,
        );
        assert_eq!(result.phase, SupervisorPhase::CleanupPending);
        assert_eq!(
            result.action,
            RecoveryAction::PreserveManifestAndReportConflict
        );
    }

    #[test]
    fn cleaned_generation_is_terminal_and_repeated_events_are_harmless() {
        let result = transition(SupervisorPhase::Cleaned, SupervisorEvent::CoreExited, 7, 7);
        assert_eq!(result.phase, SupervisorPhase::Cleaned);
        assert_eq!(result.action, RecoveryAction::None);
    }

    #[test]
    fn zero_generation_is_always_rejected() {
        let result = transition(
            SupervisorPhase::Prepared,
            SupervisorEvent::StartCommitted,
            0,
            0,
        );
        assert_eq!(result.phase, SupervisorPhase::Prepared);
        assert_eq!(result.action, RecoveryAction::IgnoreStaleEvent);
    }
}
