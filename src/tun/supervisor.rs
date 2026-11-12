//! Supervisor runtime for monitoring one pinned core process and recovering its manifest.
//!
//! The runtime is deliberately backend-injected: it never shells out, escalates privileges,
//! or mutates networking itself. Production activation remains disabled until a concrete
//! exact-resource kernel backend and a service-manager-owned supervisor are connected.

use super::{
    lifecycle_coordinator::{ActivationToken, LifecycleCoordinator},
    ownership::{CleanupReport, OwnedResourceBackend, cleanup},
    process::{ProcessHandle, ProcessIdentity},
    recovery::{RecoveryAction, SupervisorEvent, SupervisorPhase},
};
use anyhow::{Context, Result, ensure};
use std::time::Duration;

const MONITOR_INTERVAL: Duration = Duration::from_millis(250);

/// Monitor the exact core instance and clean only resources recorded by its activation.
///
/// The pidfd remains pinned for the duration of monitoring. A core exit is persisted before
/// cleanup begins; a cleanup error persists CleanupPending and retains the manifest.
pub fn monitor_core<B: OwnedResourceBackend>(
    coordinator: &LifecycleCoordinator,
    token: &ActivationToken,
    process: &ProcessHandle,
    backend: &mut B,
) -> Result<CleanupReport> {
    let current = coordinator
        .load_current()?
        .context("no active TUN manifest exists for the supervisor")?;
    ensure!(current.token == *token, "supervisor activation token is stale");
    ensure!(
        matches!(
            current.snapshot.phase,
            SupervisorPhase::Prepared | SupervisorPhase::Running
        ),
        "supervisor manifest is not in a monitorable phase"
    );

    while !process.wait_exit(MONITOR_INTERVAL)? {}

    let current = coordinator
        .load_current()?
        .context("TUN manifest disappeared while monitoring core")?;
    ensure!(current.token == *token, "TUN activation changed while monitoring core");
    coordinator.apply_event(token, SupervisorEvent::CoreExited)?;

    let current = coordinator
        .load_current()?
        .context("TUN manifest disappeared before cleanup")?;
    let report = match cleanup(&current.snapshot.manifest, backend) {
        Ok(report) => report,
        Err(error) => {
            coordinator.apply_event(token, SupervisorEvent::CleanupConflicted)?;
            return Err(error).context("TUN cleanup failed; recovery manifest was retained");
        }
    };
    let action = coordinator.apply_event(token, SupervisorEvent::CleanupCompleted)?;
    ensure!(
        action == RecoveryAction::RemoveManifest,
        "TUN cleanup completed but manifest transition was not accepted"
    );
    Ok(report)
}


/// Resume monitoring from the durable process identity after a supervisor restart.
///
/// If the recorded process instance no longer exists (or its PID has been reused), cleanup
/// begins. If it is still alive, a pidfd is opened and monitoring resumes. An inability to
/// inspect a still-matching process is an error, never evidence that cleanup is safe.
pub fn resume_or_recover<B: OwnedResourceBackend>(
    coordinator: &LifecycleCoordinator,
    token: &ActivationToken,
    backend: &mut B,
) -> Result<Option<CleanupReport>> {
    let current = coordinator
        .load_current()?
        .context("no TUN recovery manifest exists")?;
    ensure!(current.token == *token, "recovery activation token is stale");
    if current.snapshot.phase == SupervisorPhase::CleanupPending {
        return recover_pending_cleanup(coordinator, token, backend).map(Some);
    }
    let identity = current
        .snapshot
        .core_process
        .context("TUN manifest has no persisted managed-core identity")?;
    if !identity.verify()? {
        coordinator.apply_event(token, SupervisorEvent::CoreExited)?;
        return recover_pending_cleanup(coordinator, token, backend).map(Some);
    }
    let process = match ProcessHandle::open(identity.clone()) {
        Ok(process) => process,
        Err(error) if !identity.verify()? => {
            coordinator.apply_event(token, SupervisorEvent::CoreExited)?;
            return recover_pending_cleanup(coordinator, token, backend).map(Some);
        }
        Err(error) => return Err(error).context("cannot monitor the still-running managed core"),
    };
    monitor_core(coordinator, token, &process, backend).map(Some)
}

/// Retry cleanup after a supervisor restart when the durable phase is CleanupPending.
///
/// Running manifests are never cleaned based on absence of a supervisor process alone: the
/// caller must first establish that the recorded core process has exited.
pub fn recover_pending_cleanup<B: OwnedResourceBackend>(
    coordinator: &LifecycleCoordinator,
    token: &ActivationToken,
    backend: &mut B,
) -> Result<CleanupReport> {
    let current = coordinator
        .load_current()?
        .context("no TUN recovery manifest exists")?;
    ensure!(current.token == *token, "recovery activation token is stale");
    ensure!(
        current.snapshot.phase == SupervisorPhase::CleanupPending,
        "recovery manifest is not waiting for cleanup"
    );
    let report = match cleanup(&current.snapshot.manifest, backend) {
        Ok(report) => report,
        Err(error) => {
            coordinator.apply_event(token, SupervisorEvent::CleanupConflicted)?;
            return Err(error).context("TUN recovery cleanup failed; manifest was retained");
        }
    };
    let action = coordinator.apply_event(token, SupervisorEvent::CleanupCompleted)?;
    ensure!(
        action == RecoveryAction::RemoveManifest,
        "TUN recovery cleanup completed but manifest transition was not accepted"
    );
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::{
        manifest_store::{ManifestSnapshot, ManifestStore},
        ownership::{MANIFEST_VERSION, OwnedResource, ResourceState, RouteManifest},
        process::{ProcessHandle, ProcessIdentity},
    };
    use anyhow::Result;
    use std::{
        collections::BTreeMap,
        process::{Command, Stdio},
        thread,
        time::Duration,
    };

    #[derive(Default)]
    struct FakeBackend {
        resources: BTreeMap<String, String>,
    }

    impl OwnedResourceBackend for FakeBackend {
        fn fingerprint(&mut self, key: &str) -> Result<Option<String>> {
            Ok(self.resources.get(key).cloned())
        }

        fn remove_if_matches(&mut self, key: &str, expected: &str) -> Result<ResourceState> {
            match self.resources.get(key) {
                None => Ok(ResourceState::AlreadyAbsent),
                Some(value) if value != expected => Ok(ResourceState::ChangedOrForeign),
                Some(_) => {
                    self.resources.remove(key);
                    Ok(ResourceState::Removed)
                }
            }
        }
    }

    fn setup(phase: SupervisorPhase) -> (tempfile::TempDir, LifecycleCoordinator, ActivationToken) {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().join("runtime")).unwrap();
        let coordinator = LifecycleCoordinator::new(store).unwrap();
        let snapshot = ManifestSnapshot {
            schema_version: 1,
            generation: 1,
            phase: SupervisorPhase::Prepared,
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
                    fingerprint: "route-fingerprint".into(),
                }],
            },
        };
        let token = coordinator.create_prepared(&snapshot).unwrap();
        if matches!(phase, SupervisorPhase::Running | SupervisorPhase::CleanupPending) {
            coordinator.apply_event(&token, SupervisorEvent::StartCommitted).unwrap();
        }
        if phase == SupervisorPhase::CleanupPending {
            coordinator.apply_event(&token, SupervisorEvent::CoreExited).unwrap();
        }
        (directory, coordinator, token)
    }

    fn backend() -> FakeBackend {
        FakeBackend {
            resources: BTreeMap::from([(
                "route:v4-default".into(),
                "route-fingerprint".into(),
            )]),
        }
    }

    #[test]
    fn monitors_fake_core_and_cleans_exact_manifest_resources() {
        let (_directory, coordinator, token) = setup(SupervisorPhase::Running);
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let identity = ProcessIdentity::capture(child.id()).unwrap();
        coordinator.bind_core_process(&token, identity.clone()).unwrap();
        let process = ProcessHandle::open(identity).unwrap();
        let worker = thread::spawn(move || {
            let mut backend = backend();
            let result = monitor_core(&coordinator, &token, &process, &mut backend);
            (result, backend)
        });
        thread::sleep(Duration::from_millis(50));
        child.kill().unwrap();
        child.wait().unwrap();
        let (result, backend) = worker.join().unwrap();
        assert_eq!(result.unwrap().removed, ["route:v4-default"]);
        assert!(backend.resources.is_empty());
    }

    #[test]
    fn cleanup_conflict_retains_manifest_for_recovery() {
        let (_directory, coordinator, token) = setup(SupervisorPhase::CleanupPending);
        let mut backend = FakeBackend {
            resources: BTreeMap::from([("route:v4-default".into(), "foreign".into())]),
        };
        assert!(recover_pending_cleanup(&coordinator, &token, &mut backend).is_err());
        let current = coordinator.load_current().unwrap().unwrap();
        assert_eq!(current.snapshot.phase, SupervisorPhase::CleanupPending);
        assert_eq!(backend.resources.len(), 1);
    }

    #[test]
    fn restart_recovery_retries_only_cleanup_pending_manifest() {
        let (_directory, coordinator, token) = setup(SupervisorPhase::CleanupPending);
        let mut backend = backend();
        let report = recover_pending_cleanup(&coordinator, &token, &mut backend).unwrap();
        assert_eq!(report.removed, ["route:v4-default"]);
        assert!(coordinator.load_current().unwrap().is_none());
    }

    #[test]
    fn recovery_refuses_running_manifest_without_core_exit_evidence() {
        let (_directory, coordinator, token) = setup(SupervisorPhase::Running);
        let mut backend = backend();
        assert!(recover_pending_cleanup(&coordinator, &token, &mut backend).is_err());
        assert!(coordinator.load_current().unwrap().is_some());
        assert_eq!(backend.resources.len(), 1);
    }

    #[test]
    fn stale_token_cannot_clean_a_new_activation() {
        let (_directory, coordinator, old_token) = setup(SupervisorPhase::CleanupPending);
        let mut backend = backend();
        recover_pending_cleanup(&coordinator, &old_token, &mut backend).unwrap();

        let new_snapshot = ManifestSnapshot {
            schema_version: 1,
            generation: 1,
            phase: SupervisorPhase::Prepared,
            core_process: None,
            manifest: RouteManifest {
                version: MANIFEST_VERSION,
                activation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
                table_id: 42420,
                rule_priority: 42420,
                interface_name: "tun-proxyctl".into(),
                interface_index: 77,
                resources: vec![OwnedResource {
                    key: "route:v4-default".into(),
                    fingerprint: "new-route".into(),
                }],
            },
        };
        let new_token = coordinator.create_prepared(&new_snapshot).unwrap();
        assert!(recover_pending_cleanup(&coordinator, &old_token, &mut backend).is_err());
        assert_eq!(coordinator.load_current().unwrap().unwrap().token, new_token);
        assert!(backend.resources.is_empty());
    }
}
