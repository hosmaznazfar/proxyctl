//! Validated TUN transaction journal types and pure recovery planning.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

const MAX_JOURNAL_OPERATIONS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalOperationKind {
    CreateInterface,
    AddRoute,
    AddRule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalOperationState {
    Intent,
    Applied,
    Removed,
    Absent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalOperation {
    pub sequence: u32,
    pub kind: JournalOperationKind,
    pub resource_key: String,
    pub state: JournalOperationState,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionJournal {
    pub schema_version: u32,
    pub activation_id: String,
    pub generation: u64,
    pub operations: Vec<JournalOperation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalRecoveryAction {
    /// Kernel state must be inspected; no deletion is authorized by an intent alone.
    InspectAmbiguousIntent,
    /// Compare the live resource's full fingerprint before attempting deletion.
    CompareAndDelete,
    /// Cleanup was durably recorded; do not repeat the mutation.
    SkipAlreadyRemoved,
}

pub fn recovery_action(operation: &JournalOperation) -> JournalRecoveryAction {
    match operation.state {
        JournalOperationState::Intent => JournalRecoveryAction::InspectAmbiguousIntent,
        JournalOperationState::Applied => JournalRecoveryAction::CompareAndDelete,
        JournalOperationState::Removed | JournalOperationState::Absent => {
            JournalRecoveryAction::SkipAlreadyRemoved
        }
    }
}

/// A fail-closed recovery decision derived from one journal operation and a fresh exact
/// kernel fingerprint lookup. This planner never performs a mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalRecoveryDecision {
    MarkAbsent,
    CompareAndDelete { expected_fingerprint: String },
    MarkRemoved,
    PreserveAndReportConflict,
    Skip,
}

/// Plan recovery in reverse creation order. The observed map must come from a fresh exact
/// kernel inventory; None means the exact resource identity is absent.
pub fn plan_journal_recovery(
    journal: &TransactionJournal,
    observed: &std::collections::BTreeMap<String, Option<String>>,
) -> Result<Vec<(String, JournalRecoveryDecision)>> {
    journal.validate()?;
    let mut decisions = Vec::with_capacity(journal.operations.len());
    for operation in journal.operations.iter().rev() {
        let current = observed.get(&operation.resource_key).cloned().flatten();
        let decision = match operation.state {
            JournalOperationState::Intent => {
                if observed.contains_key(&operation.resource_key) && current.is_none() {
                    JournalRecoveryDecision::MarkAbsent
                } else {
                    JournalRecoveryDecision::PreserveAndReportConflict
                }
            }
            JournalOperationState::Applied => {
                if !observed.contains_key(&operation.resource_key) {
                    JournalRecoveryDecision::PreserveAndReportConflict
                } else {
                    match (operation.fingerprint.as_ref(), current) {
                        (Some(_), None) => JournalRecoveryDecision::MarkRemoved,
                        (Some(expected), Some(actual)) if *expected == actual => {
                            JournalRecoveryDecision::CompareAndDelete {
                                expected_fingerprint: expected.clone(),
                            }
                        }
                        _ => JournalRecoveryDecision::PreserveAndReportConflict,
                    }
                }
            }
            JournalOperationState::Removed | JournalOperationState::Absent => {
                JournalRecoveryDecision::Skip
            }
        };
        decisions.push((operation.resource_key.clone(), decision));
    }
    Ok(decisions)
}

impl TransactionJournal {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported TUN transaction journal version"
        );
        ensure!(
            valid_journal_activation_id(&self.activation_id),
            "invalid journal activation identity"
        );
        ensure!(self.generation > 0, "journal generation must be non-zero");
        ensure!(
            self.operations.len() <= MAX_JOURNAL_OPERATIONS,
            "too many journal operations"
        );
        let mut keys = std::collections::BTreeSet::new();
        let mut interface_seen = false;
        let mut rules_started = false;
        for (index, operation) in self.operations.iter().enumerate() {
            match operation.kind {
                JournalOperationKind::CreateInterface => {
                    ensure!(
                        index == 0 && !interface_seen,
                        "interface creation must be the first and only interface operation"
                    );
                    interface_seen = true;
                }
                JournalOperationKind::AddRoute => ensure!(
                    !rules_started,
                    "routes cannot be journaled after policy rules"
                ),
                JournalOperationKind::AddRule => rules_started = true,
            }
            ensure!(
                operation.sequence as usize == index,
                "journal operation sequence is not contiguous"
            );
            ensure!(
                !operation.resource_key.is_empty() && operation.resource_key.len() <= 512,
                "invalid journal resource key"
            );
            ensure!(
                !operation.resource_key.chars().any(char::is_control),
                "journal resource key contains control characters"
            );
            ensure!(
                valid_journal_resource_key(operation.kind, &operation.resource_key),
                "journal resource key does not match its operation kind"
            );
            ensure!(
                keys.insert(operation.resource_key.as_str()),
                "duplicate journal resource key"
            );
            match operation.state {
                JournalOperationState::Intent => ensure!(
                    operation.fingerprint.is_none(),
                    "intent cannot contain a fingerprint"
                ),
                JournalOperationState::Applied | JournalOperationState::Removed => ensure!(
                    operation
                        .fingerprint
                        .as_ref()
                        .is_some_and(|value| !value.is_empty()
                            && value.len() <= 16 * 1024
                            && !value.chars().any(char::is_control)),
                    "applied journal operation requires a valid fingerprint"
                ),
                JournalOperationState::Absent => ensure!(
                    operation.fingerprint.is_none(),
                    "absent journal operation cannot contain a fingerprint"
                ),
            }
        }
        Ok(())
    }
}

fn valid_journal_activation_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn valid_journal_resource_key(kind: JournalOperationKind, key: &str) -> bool {
    match kind {
        JournalOperationKind::CreateInterface => {
            let Some(name) = key.strip_prefix("interface:") else {
                return false;
            };
            !name.is_empty()
                && name.len() <= 15
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        }
        JournalOperationKind::AddRoute => {
            let mut parts = key.splitn(4, ':');
            matches!(parts.next(), Some("route"))
                && matches!(parts.next(), Some("v4" | "v6"))
                && parts
                    .next()
                    .is_some_and(|table| table.parse::<u32>().is_ok_and(|value| value > 0))
                && parts.next().is_some_and(|destination| {
                    !destination.is_empty() && !destination.chars().any(char::is_whitespace)
                })
        }
        JournalOperationKind::AddRule => {
            let mut parts = key.split(':');
            matches!(parts.next(), Some("rule"))
                && matches!(parts.next(), Some("v4" | "v6"))
                && parts
                    .next()
                    .is_some_and(|priority| priority.parse::<u32>().is_ok_and(|value| value > 0))
                && parts.next().is_none()
        }
    }
}


