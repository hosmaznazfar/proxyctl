//! Durable reverse-order executor for detached transaction-journal recovery.
//!
//! The executor owns the recovery algorithm and persistence ordering. A concrete privileged
//! backend supplies fresh kernel snapshots and narrowly typed compare-before-delete methods.
//! It never constructs shell commands or accepts raw netlink payloads.

use anyhow::{Context, Result, ensure};

use super::{
    journal::{
        JournalOperationKind, JournalOperationState, JournalRecoveryDecision, plan_journal_recovery,
    },
    kernel_inventory::KernelSnapshot,
    manifest_store::ManifestStore,
    ownership::ResourceState,
    resource_snapshot::observe_journal_resources,
};

/// Privileged operations required by journal recovery.
///
/// Implementations must re-inspect the exact kernel identity immediately before deletion,
/// compare the complete live fingerprint, and issue only the typed removal represented by
/// `resource_key`. The method must never treat a prior snapshot alone as delete authority.
pub trait JournalRecoveryBackend {
    fn inspect_fresh(&mut self) -> Result<KernelSnapshot>;

    fn remove_if_fingerprint_matches(
        &mut self,
        kind: JournalOperationKind,
        resource_key: &str,
        expected_fingerprint: &str,
    ) -> Result<ResourceState>;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JournalRecoveryReport {
    pub removed: Vec<String>,
    pub already_absent: Vec<String>,
    pub resolved_intents: Vec<String>,
}

/// Execute recovery one operation at a time in reverse journal order.
///
/// Each loop obtains a new full inventory. The journal transition is fsynced by ManifestStore
/// only after the backend confirms removal/absence. An unresolved intent is resolved only
/// when fresh inventory proves the exact resource absent. Any mismatch or ambiguous identity
/// stops recovery and leaves the journal available for another recovery attempt.
pub fn recover<B: JournalRecoveryBackend>(
    store: &ManifestStore,
    backend: &mut B,
) -> Result<JournalRecoveryReport> {
    let mut report = JournalRecoveryReport::default();
    let journal = store
        .load_transaction_journal()?
        .context("no transaction journal is available for recovery")?;
    journal.validate()?;

    for operation in journal.operations.iter().rev() {
        if matches!(
            operation.state,
            JournalOperationState::Removed | JournalOperationState::Absent
        ) {
            continue;
        }

        let snapshot = backend
            .inspect_fresh()
            .context("cannot obtain a fresh kernel snapshot during journal recovery")?;
        let observed = observe_journal_resources(&journal, &snapshot)
            .context("cannot derive canonical live fingerprints for journal recovery")?;
        let decisions = plan_journal_recovery(&journal, &observed)?;
        let decision = decisions
            .iter()
            .find(|(key, _)| key == &operation.resource_key)
            .map(|(_, decision)| decision)
            .context("recovery planner omitted a journal operation")?;

        match decision {
            JournalRecoveryDecision::Skip => {}
            JournalRecoveryDecision::PreserveAndReportConflict => {
                anyhow::bail!(
                    "recovery preserved ambiguous or changed resource {}",
                    operation.resource_key
                );
            }
            JournalRecoveryDecision::MarkAbsent => {
                ensure!(
                    operation.state == JournalOperationState::Intent,
                    "only an unresolved intent may be marked absent"
                );
                store.mark_intent_absent(
                    &journal.activation_id,
                    journal.generation,
                    &operation.resource_key,
                )?;
                report.resolved_intents.push(operation.resource_key.clone());
            }
            JournalRecoveryDecision::MarkRemoved => {
                ensure!(
                    operation.state == JournalOperationState::Applied,
                    "only an applied operation may be marked removed"
                );
                store.mark_operation_removed(
                    &journal.activation_id,
                    journal.generation,
                    &operation.resource_key,
                )?;
                report.already_absent.push(operation.resource_key.clone());
            }
            JournalRecoveryDecision::CompareAndDelete {
                expected_fingerprint,
            } => {
                if operation.state == JournalOperationState::Intent
                    && operation.kind == JournalOperationKind::CreatePersistentInterface
                {
                    // The exact generation alias proves this intent reached the persistent
                    // state before the broker crashed. Promote the observed fingerprint
                    // durably first; a second crash then follows ordinary Applied recovery.
                    store.mark_operation_applied(
                        &journal.activation_id,
                        journal.generation,
                        &operation.resource_key,
                        expected_fingerprint,
                    )?;
                } else {
                    ensure!(
                        operation.state == JournalOperationState::Applied,
                        "compare-and-delete requires an applied journal operation"
                    );
                }
                let state = backend
                    .remove_if_fingerprint_matches(
                        operation.kind,
                        &operation.resource_key,
                        expected_fingerprint,
                    )
                    .with_context(|| {
                        format!(
                            "cannot remove journal-owned resource {}",
                            operation.resource_key
                        )
                    })?;
                match state {
                    ResourceState::Removed | ResourceState::AlreadyAbsent => {
                        // Persist cleanup progress only after the backend has confirmed
                        // the exact resource was removed or is now absent.
                        store.mark_operation_removed(
                            &journal.activation_id,
                            journal.generation,
                            &operation.resource_key,
                        )?;
                        if state == ResourceState::Removed {
                            report.removed.push(operation.resource_key.clone());
                        } else {
                            report.already_absent.push(operation.resource_key.clone());
                        }
                    }
                    ResourceState::ChangedOrForeign => {
                        anyhow::bail!(
                            "recovery refused to remove changed or foreign resource {}",
                            operation.resource_key
                        );
                    }
                }
            }
        }
    }

    let completed = store
        .load_transaction_journal()?
        .context("transaction journal disappeared before recovery finalization")?;
    ensure!(
        completed.activation_id == journal.activation_id
            && completed.generation == journal.generation
            && completed.operations.iter().all(|operation| {
                matches!(
                    operation.state,
                    JournalOperationState::Removed | JournalOperationState::Absent
                )
            }),
        "transaction journal is not fully resolved after recovery"
    );
    store.remove_completed_transaction_journal(&journal.activation_id, journal.generation)?;
    Ok(report)
}
