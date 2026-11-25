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
    store: ManifestStore,
    coordinator: &LifecycleCoordinator,
    activation_id: &str,
    generation: u64,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(ActivationToken, AppliedKernelTransaction)> {
    ensure!(generation > 0, "TUN activation generation must be non-zero");
    ensure!(owner_uid != 0, "TUN interface owner UID must be non-zero");
    ensure!(
        coordinator.runtime_directory()? == store.path().parent().unwrap_or_default(),
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
