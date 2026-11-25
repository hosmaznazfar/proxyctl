//! Privileged, journal-backed application of a native-core TUN kernel plan.
//!
//! This is the mutation boundary between read-only activation planning and the supervised
//! core lifecycle. It deliberately stops at a durable Prepared manifest: callers must still
//! launch the selected core, verify readiness, persist its exact process receipt, and bind
//! the manifest Running before acknowledging a session to the CLI.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};

use super::{
    activation_plan,
    kernel_transaction::{self, AppliedKernelTransaction},
    launch_spec::CoreKind,
    lifecycle_coordinator::{ActivationToken, LifecycleCoordinator},
    linux_journal_backend::LinuxJournalBackend,
    manifest_store::ManifestStore,
};

/// Apply the exact native-device transaction for one activation and adopt its Prepared
/// manifest into the lifecycle coordinator.
///
/// The transaction journal is created before the first kernel mutation. On any failure the
/// kernel transaction executor either completes exact rollback and removes the journal, or
/// preserves it for the existing recovery path. A successful return means the interface,
/// routes, rules, journal, and Prepared manifest are all durable; it does not mean a core is
/// running or that traffic readiness has passed.
///
/// The caller must already have authenticated the invoking user and validated that
/// `owner_uid`/`owner_gid` are the intended unprivileged TUN device owner.
pub fn apply_native_kernel_plan(
    core: CoreKind,
    store: ManifestStore,
    coordinator: &LifecycleCoordinator,
    activation_id: &str,
    generation: u64,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(ActivationToken, AppliedKernelTransaction)> {
    ensure!(
        matches!(core, CoreKind::SingBox | CoreKind::Mihomo),
        "journaled persistent-device activation supports only sing-box and Mihomo; Xray requires its separate descriptor-backed attachment path"
    );
    ensure!(generation > 0, "TUN activation generation must be non-zero");
    ensure!(owner_uid != 0, "TUN interface owner UID must be non-zero");
    let store_path = store.path();
    let store_runtime = store_path
        .parent()
        .context("TUN manifest store has no runtime directory")?;
    ensure!(
        coordinator.runtime_directory()?.as_path() == store_runtime,
        "kernel journal and lifecycle coordinator must share one runtime directory"
    );
    ensure!(
        coordinator.load_current()?.is_none(),
        "an existing TUN activation must be recovered before starting another"
    );

    // Planning is read-only. The backend persists the generation-scoped journal before
    // apply_native can create the first persistent interface or install a route/rule.
    let transaction = activation_plan::prepare_current(activation_id, owner_uid, owner_gid)
        .context("cannot prepare the native TUN kernel transaction")?;
    let mut backend = LinuxJournalBackend::new_native(store, activation_id, generation)
        .context("cannot create the durable native TUN transaction journal")?;
    let applied = kernel_transaction::apply_native(&transaction, &mut backend)
        .context("journal-backed native TUN kernel transaction failed")?;
    let token = coordinator
        .adopt_prepared(activation_id, generation)
        .context("kernel transaction committed but its Prepared manifest could not be adopted")?;

    Ok((token, applied))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_a_journal_store_outside_the_lifecycle_runtime() {
        let manifest_dir = tempfile::tempdir().unwrap();
        let journal_dir = tempfile::tempdir().unwrap();
        let manifest_store = ManifestStore::open(manifest_dir.path().to_path_buf()).unwrap();
        let journal_store = ManifestStore::open(journal_dir.path().to_path_buf()).unwrap();
        let coordinator = LifecycleCoordinator::new(manifest_store).unwrap();

        let result = apply_native_kernel_plan(
            CoreKind::SingBox,
            journal_store,
            &coordinator,
            "12345678-1234-4234-8234-123456789abc",
            1,
            1000,
            1000,
        );

        assert!(result.is_err());
    }

    #[test]
    fn rejects_xray_before_opening_or_mutating_the_kernel_backend() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path().to_path_buf()).unwrap();
        let coordinator = LifecycleCoordinator::new(store.clone()).unwrap();

        let result = apply_native_kernel_plan(
            CoreKind::Xray,
            store.clone(),
            &coordinator,
            "12345678-1234-4234-8234-123456789abc",
            1,
            1000,
            1000,
        );

        assert!(result.is_err());
        assert!(store.load_transaction_journal().unwrap().is_none());
        assert!(store.load().unwrap().is_none());
    }
}
