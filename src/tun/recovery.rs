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
