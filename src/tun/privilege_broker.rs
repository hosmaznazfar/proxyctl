//! Narrow TUN privilege-broker contract and read-only candidate discovery.
//!
//! This module deliberately does not execute sudo/doas/pkexec or perform privileged work.
//! A candidate executable is not proof that authorization is available or safe.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    path::{Component, Path, PathBuf},
};

pub const BROKER_REQUEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeBrokerKind {
    Sudo,
    Doas,
    Pkexec,
}

impl PrivilegeBrokerKind {
    fn executable_name(self) -> &'static str {
        match self {
            Self::Sudo => "sudo",
            Self::Doas => "doas",
            Self::Pkexec => "pkexec",
        }
    }
}

/// A binary found on PATH. This says nothing about its policy, authorization state, or safety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerCandidate {
    pub kind: PrivilegeBrokerKind,
    pub executable: PathBuf,
}

/// Resolve known broker candidates without invoking them or assuming a distribution layout.
#[cfg(target_os = "linux")]
pub fn discover_candidates(path: Option<&OsStr>) -> Vec<BrokerCandidate> {
    let Some(path) = path else {
        return Vec::new();
    };
    let directories = std::env::split_paths(path).collect::<Vec<_>>();
    [
        PrivilegeBrokerKind::Sudo,
        PrivilegeBrokerKind::Doas,
        PrivilegeBrokerKind::Pkexec,
    ]
    .into_iter()
    .filter_map(|kind| {
        directories
            .iter()
            .map(|directory| directory.join(kind.executable_name()))
            .find(|candidate| is_executable_file(candidate))
            .map(|executable| BrokerCandidate { kind, executable })
    })
    .collect()
}

#[cfg(not(target_os = "linux"))]
pub fn discover_candidates(_path: Option<&OsStr>) -> Vec<BrokerCandidate> {
    Vec::new()
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(_path: &Path) -> bool {
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerAction {
    ApplyPreparedManifest,
    CleanupManifest,
}

/// The only request shape a future privileged helper may accept.
///
/// The helper must reopen and validate the private manifest, verify activation/generation,
/// and derive every kernel operation from its exact resource records. No arbitrary argv,
/// shell text, executable path, interface command, route string, or firewall operation exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerRequest {
    pub version: u32,
    pub activation_id: String,
    pub generation: u64,
    pub manifest_path: PathBuf,
    pub action: BrokerAction,
}

impl BrokerRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == BROKER_REQUEST_VERSION,
            "unsupported privilege-broker request version"
        );
        ensure!(
            valid_activation_id(&self.activation_id),
            "invalid privilege-broker activation identity"
        );
        ensure!(
            self.generation > 0,
            "privilege-broker generation must be non-zero"
        );
        ensure!(
            self.manifest_path.is_absolute(),
            "privilege-broker manifest path must be absolute"
        );
        ensure!(
            self.manifest_path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
            "privilege-broker manifest path contains an unsafe component"
        );
        ensure!(
            self.manifest_path.file_name().and_then(OsStr::to_str) == Some("tun-manifest.json"),
            "privilege-broker request does not reference a TUN manifest"
        );
        Ok(())
    }

    /// Bind a request to the exact durable snapshot before a helper may act.
    /// The helper must still reopen the file and repeat this check itself.
    pub fn validate_snapshot(&self, snapshot: &ManifestSnapshot) -> Result<()> {
        self.validate()?;
        snapshot.validate()?;
        ensure!(
            self.activation_id == snapshot.manifest.activation_id
                && self.generation == snapshot.generation,
            "privilege-broker request does not match the durable activation"
        );
        match (self.action, snapshot.phase) {
            (BrokerAction::ApplyPreparedManifest, SupervisorPhase::Prepared)
            | (BrokerAction::CleanupManifest, SupervisorPhase::CleanupPending) => Ok(()),
            _ => anyhow::bail!("privilege-broker action is invalid for the manifest lifecycle phase"),
        }
    }
}

fn valid_activation_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{ffi::OsString, fs};

    fn request() -> BrokerRequest {
        BrokerRequest {
            version: BROKER_REQUEST_VERSION,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 4,
            manifest_path: "/run/user/1000/proxyctl/tun-manifest.json".into(),
            action: BrokerAction::CleanupManifest,
        }
    }

    #[test]
    fn request_accepts_only_versioned_generation_scoped_manifest_actions() {
        request().validate().unwrap();
        let mut invalid = request();
        invalid.generation = 0;
        assert!(invalid.validate().is_err());
        let mut invalid = request();
        invalid.version += 1;
        assert!(invalid.validate().is_err());
        let mut invalid = request();
        invalid.activation_id = "not-an-activation".into();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn request_must_match_snapshot_generation_activation_and_phase() {
        use crate::tun::{
            manifest_store::ManifestSnapshot,
            ownership::{MANIFEST_VERSION, OwnedResource, RouteManifest},
            recovery::SupervisorPhase,
        };
        let mut snapshot = ManifestSnapshot {
            schema_version: 1,
            generation: 4,
            phase: SupervisorPhase::CleanupPending,
            #[cfg(target_os = "linux")]
            core_process: None,
            manifest: RouteManifest {
                version: MANIFEST_VERSION,
                activation_id: "12345678-1234-4234-8234-123456789abc".into(),
                table_id: 42420,
                rule_priority: 42420,
                interface_name: "tun-proxyctl".into(),
                interface_index: 77,
                resources: vec![OwnedResource {
                    key: "route:v4-default".into(),
                    fingerprint: "route-fp".into(),
                }],
            },
        };
        request().validate_snapshot(&snapshot).unwrap();

        let mut invalid = request();
        invalid.generation += 1;
        assert!(invalid.validate_snapshot(&snapshot).is_err());

        snapshot.phase = SupervisorPhase::Running;
        assert!(request().validate_snapshot(&snapshot).is_err());

        snapshot.phase = SupervisorPhase::CleanupPending;
        snapshot.manifest.activation_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
        assert!(request().validate_snapshot(&snapshot).is_err());
    }

    #[test]
    fn request_rejects_relative_traversal_and_non_manifest_paths() {
        for path in [
            PathBuf::from("run/tun-manifest.json"),
            PathBuf::from("/run/user/../etc/tun-manifest.json"),
            PathBuf::from("/run/user/1000/proxyctl/other.json"),
        ] {
            let mut invalid = request();
            invalid.manifest_path = path;
            assert!(invalid.validate().is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn discovers_only_executable_candidates_without_running_them() {
        let directory = tempfile::tempdir().unwrap();
        let sudo = directory.path().join("sudo");
        let doas = directory.path().join("doas");
        fs::write(&sudo, "not executed").unwrap();
        fs::write(&doas, "not executed").unwrap();
        fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&doas, fs::Permissions::from_mode(0o600)).unwrap();

        let candidates = discover_candidates(Some(directory.path().as_os_str()));
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, PrivilegeBrokerKind::Sudo);
        assert_eq!(candidates[0].executable, sudo);
        assert!(discover_candidates(None).is_empty());
        let _unused: OsString = directory.path().as_os_str().to_owned();
    }
}
