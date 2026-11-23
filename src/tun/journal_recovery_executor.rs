//! Durable reverse-order executor for detached transaction-journal recovery.
//!
//! The executor owns the recovery algorithm and persistence ordering. A concrete privileged
//! backend supplies fresh kernel snapshots and narrowly typed compare-before-delete methods.
//! It never constructs shell commands or accepts raw netlink payloads.

use anyhow::{Context, Result, ensure};
use std::cmp::Reverse;

use super::{
    journal::{
        JournalOperation, JournalOperationKind, JournalOperationState, JournalRecoveryDecision,
        TransactionJournal, plan_journal_recovery,
    },
    kernel_inventory::KernelSnapshot,
    manifest_store::ManifestStore,
    ownership::ResourceState,
    resource_snapshot::observe_journal_resources,
};

/// Privileged operations required by journal recovery.
///
/// Implementations must re-inspect exact kernel state immediately before mutation. Policy
/// rules use typed protocol-tagged selectors; routes are never deleted directly and must be
/// absent after the exact TUN interface is unregistered. A prior snapshot alone never grants
/// deletion authority.
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

/// Execute recovery in dependency-safe teardown order: rules, interface, then route checks.
///
/// Linux removes routes attached to a netdevice when that exact device is unregistered. The
/// interface must therefore be released before route records are finalized. Route records are
/// verification-only after link teardown; they are never deleted by a weaker route selector.
///
/// Each operation obtains a new full inventory. Journal progress is fsynced only after the
/// backend confirms removal/absence. Any mismatch or ambiguous identity stops recovery and
/// leaves the journal available for another attempt.
pub fn recover<B: JournalRecoveryBackend>(
    store: &ManifestStore,
    backend: &mut B,
) -> Result<JournalRecoveryReport> {
    let mut report = JournalRecoveryReport::default();
    let journal = store
        .load_transaction_journal()?
        .context("no transaction journal is available for recovery")?;
    journal.validate()?;

    for operation in ordered_cleanup_operations(&journal) {
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

fn ordered_cleanup_operations(journal: &TransactionJournal) -> Vec<&JournalOperation> {
    let mut operations = journal.operations.iter().collect::<Vec<_>>();
    operations.sort_by_key(|operation| {
        let phase = match operation.kind {
            JournalOperationKind::AddRule => 0u8,
            JournalOperationKind::CreateInterface
            | JournalOperationKind::CreatePersistentInterface => 1u8,
            JournalOperationKind::AddRoute => 2u8,
        };
        (phase, Reverse(operation.sequence))
    });
    operations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_orders_rules_before_link_and_route_verification_after_link() {
        let journal = TransactionJournal {
            schema_version: 1,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 9,
            operations: vec![
                JournalOperation {
                    sequence: 0,
                    kind: JournalOperationKind::CreatePersistentInterface,
                    resource_key: "interface:tun-proxyctl".into(),
                    state: JournalOperationState::Applied,
                    fingerprint: Some("interface".into()),
                },
                JournalOperation {
                    sequence: 1,
                    kind: JournalOperationKind::AddRoute,
                    resource_key: "route:v4:42420:0.0.0.0/0".into(),
                    state: JournalOperationState::Applied,
                    fingerprint: Some("route-v4".into()),
                },
                JournalOperation {
                    sequence: 2,
                    kind: JournalOperationKind::AddRoute,
                    resource_key: "route:v6:42420:::/0".into(),
                    state: JournalOperationState::Applied,
                    fingerprint: Some("route-v6".into()),
                },
                JournalOperation {
                    sequence: 3,
                    kind: JournalOperationKind::AddRule,
                    resource_key: "rule:v4:42410".into(),
                    state: JournalOperationState::Applied,
                    fingerprint: Some("rule-v4".into()),
                },
                JournalOperation {
                    sequence: 4,
                    kind: JournalOperationKind::AddRule,
                    resource_key: "rule:v6:42410".into(),
                    state: JournalOperationState::Applied,
                    fingerprint: Some("rule-v6".into()),
                },
            ],
        };

        journal.validate().unwrap();
        let ordered = ordered_cleanup_operations(&journal);
        assert_eq!(
            ordered
                .iter()
                .map(|operation| operation.kind)
                .collect::<Vec<_>>(),
            [
                JournalOperationKind::AddRule,
                JournalOperationKind::AddRule,
                JournalOperationKind::CreatePersistentInterface,
                JournalOperationKind::AddRoute,
                JournalOperationKind::AddRoute,
            ]
        );
        assert_eq!(ordered[0].sequence, 4);
        assert_eq!(ordered[1].sequence, 3);
        assert_eq!(ordered[3].sequence, 2);
        assert_eq!(ordered[4].sequence, 1);
    }
}
