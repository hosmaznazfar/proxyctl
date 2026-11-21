//! Validated TUN transaction journal types and pure recovery planning.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub(super) const MAX_JOURNAL_OPERATIONS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalOperationKind {
    CreateInterface,
    CreatePersistentInterface,
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
#[serde(deny_unknown_fields)]
pub struct JournalOperation {
    pub sequence: u32,
    pub kind: JournalOperationKind,
    pub resource_key: String,
    pub state: JournalOperationState,
    pub fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    for (key, fingerprint) in observed {
        ensure!(
            journal
                .operations
                .iter()
                .any(|operation| operation.resource_key == *key),
            "kernel observation contains a resource outside the transaction journal"
        );
        if let Some(fingerprint) = fingerprint {
            ensure!(
                !fingerprint.trim().is_empty()
                    && fingerprint.len() <= 16 * 1024
                    && !fingerprint.chars().any(char::is_control),
                "kernel observation contains an invalid resource fingerprint"
            );
        }
    }
    let mut decisions = Vec::new();
    decisions.try_reserve(journal.operations.len())?;
    for operation in journal.operations.iter().rev() {
        let current = observed.get(&operation.resource_key).cloned().flatten();
        let decision = match operation.state {
            JournalOperationState::Intent => {
                if observed.contains_key(&operation.resource_key) && current.is_none() {
                    JournalRecoveryDecision::MarkAbsent
                } else if operation.kind == JournalOperationKind::CreatePersistentInterface
                    && let Some(actual) = current
                {
                    let expected_alias = format!("proxyctl:{}:{}", journal.activation_id, journal.generation);
                    let identity: serde_json::Value = serde_json::from_str(&actual).unwrap_or_default();
                    let expected_name = operation.resource_key.strip_prefix("interface:").unwrap_or_default();
                    if identity.get("name").and_then(serde_json::Value::as_str) == Some(expected_name)
                        && identity.get("kind").and_then(serde_json::Value::as_str) == Some("tun")
                        && identity.get("alias").and_then(serde_json::Value::as_str) == Some(expected_alias.as_str())
                        && identity.get("ifindex").and_then(serde_json::Value::as_u64).is_some_and(|index| index > 0)
                    {
                        JournalRecoveryDecision::CompareAndDelete { expected_fingerprint: actual }
                    } else {
                        JournalRecoveryDecision::PreserveAndReportConflict
                    }
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
        let mut unresolved_intent_seen = false;
        let mut cleanup_started = false;
        for (index, operation) in self.operations.iter().enumerate() {
            match operation.kind {
                JournalOperationKind::CreateInterface | JournalOperationKind::CreatePersistentInterface => {
                    ensure!(
                        index == 0 && !interface_seen,
                        "interface creation must be the first and only interface operation"
                    );
                    interface_seen = true;
                }
                JournalOperationKind::AddRoute => {
                    ensure!(interface_seen, "routes require a journaled TUN interface");
                    ensure!(
                        !rules_started,
                        "routes cannot be journaled after policy rules"
                    );
                }
                JournalOperationKind::AddRule => {
                    ensure!(interface_seen, "rules require a journaled TUN interface");
                    rules_started = true;
                }
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
                JournalOperationState::Intent => {
                    ensure!(
                        index + 1 == self.operations.len()
                            && !unresolved_intent_seen
                            && !cleanup_started,
                        "only the final journal operation may remain an unresolved intent"
                    );
                    unresolved_intent_seen = true;
                    ensure!(
                        operation.fingerprint.is_none(),
                        "intent cannot contain a fingerprint"
                    );
                }
                JournalOperationState::Applied => {
                    ensure!(
                        !unresolved_intent_seen && !cleanup_started,
                        "applied operations cannot follow an unresolved intent or cleanup"
                    );
                    ensure!(
                        operation
                            .fingerprint
                            .as_ref()
                            .is_some_and(|value| !value.trim().is_empty()
                                && value.len() <= 16 * 1024
                                && !value.chars().any(char::is_control)),
                        "applied journal operation requires a valid fingerprint"
                    );
                }
                JournalOperationState::Removed => {
                    cleanup_started = true;
                    ensure!(
                        operation
                            .fingerprint
                            .as_ref()
                            .is_some_and(|value| !value.is_empty()
                                && value.len() <= 16 * 1024
                                && !value.chars().any(char::is_control)),
                        "removed journal operation requires its original fingerprint"
                    );
                }
                JournalOperationState::Absent => {
                    cleanup_started = true;
                    ensure!(
                        operation.fingerprint.is_none(),
                        "absent journal operation cannot contain a fingerprint"
                    );
                }
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
                byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            }
        })
}

fn canonical_positive_u32(value: &str) -> bool {
    value
        .parse::<u32>()
        .is_ok_and(|parsed| parsed > 0 && parsed.to_string() == value)
}

fn address_text(destination: &str) -> &str {
    destination.split('/').next().unwrap_or_default()
}

fn valid_route_destination(key: &str, destination: &str) -> bool {
    let family = key.split(':').nth(1);
    if destination == "default" {
        return true;
    }
    // The resource-key separator and a leading IPv6 compression colon are adjacent
    // for destinations such as "::/0". Restore the colon consumed by split_once(':')
    // before parsing; otherwise valid leading-compression IPv6 routes are rejected.
    let normalized_destination = if family == Some("v6") && destination.starts_with(':') {
        format!(":{destination}")
    } else {
        destination.to_owned()
    };
    let Some((address, prefix)) = normalized_destination.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    match (family, address) {
        (Some("v4"), std::net::IpAddr::V4(address)) => {
            prefix <= 32 && address.to_string() == address_text(&normalized_destination)
        }
        (Some("v6"), std::net::IpAddr::V6(address)) => {
            prefix <= 128 && address.to_string() == address_text(&normalized_destination)
        }
        _ => false,
    }
}

fn valid_journal_resource_key(kind: JournalOperationKind, key: &str) -> bool {
    match kind {
        JournalOperationKind::CreateInterface | JournalOperationKind::CreatePersistentInterface => {
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
            let Some(rest) = key.strip_prefix("route:") else {
                return false;
            };
            let Some((family, rest)) = rest.split_once(':') else {
                return false;
            };
            let Some((table, destination)) = rest.split_once(':') else {
                return false;
            };
            matches!(family, "v4" | "v6")
                && canonical_positive_u32(table)
                && valid_route_destination(key, destination)
        }
        JournalOperationKind::AddRule => {
            let mut parts = key.split(':');
            matches!(parts.next(), Some("rule"))
                && matches!(parts.next(), Some("v4" | "v6"))
                && parts.next().is_some_and(canonical_positive_u32)
                && parts.next().is_none()
        }
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    fn journal(operations: Vec<JournalOperation>) -> TransactionJournal {
        TransactionJournal {
            schema_version: 1,
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 1,
            operations,
        }
    }

    fn operation(sequence: u32, kind: JournalOperationKind, key: &str) -> JournalOperation {
        JournalOperation {
            sequence,
            kind,
            resource_key: key.into(),
            state: JournalOperationState::Applied,
            fingerprint: Some("fixture-fingerprint".into()),
        }
    }

    #[test]
    fn journal_wire_types_reject_unknown_fields() {
        let operation = br#"{"sequence":0,"kind":"create_interface","resource_key":"interface:tun-proxyctl","state":"intent","fingerprint":null,"extra":true}"#;
        assert!(serde_json::from_slice::<JournalOperation>(operation).is_err());

        let journal = br#"{"schema_version":1,"activation_id":"12345678-1234-4234-8234-123456789abc","generation":1,"operations":[],"extra":true}"#;
        assert!(serde_json::from_slice::<TransactionJournal>(journal).is_err());
    }

    #[test]
    fn journal_activation_id_must_use_canonical_lowercase_hex() {
        let mut value = journal(Vec::new());
        value.activation_id = "12345678-1234-4234-8234-123456789ABC".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn journal_rejects_whitespace_only_applied_fingerprints() {
        for fingerprint in ["", "   ", "\n\t"] {
            let mut value = journal(vec![operation(
                0,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            )]);
            value.operations[0].fingerprint = Some(fingerprint.into());
            assert!(value.validate().is_err());
        }
    }

    #[test]
    fn every_route_and_rule_requires_the_interface_creation_intent_first() {
        let route_first = journal(vec![operation(
            0,
            JournalOperationKind::AddRoute,
            "route:v4:42420:0.0.0.0/0",
        )]);
        assert!(route_first.validate().is_err());

        let rule_first = journal(vec![operation(
            0,
            JournalOperationKind::AddRule,
            "rule:v4:42410",
        )]);
        assert!(rule_first.validate().is_err());

        let complete = journal(vec![
            operation(
                0,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            ),
            operation(
                1,
                JournalOperationKind::AddRoute,
                "route:v4:42420:0.0.0.0/0",
            ),
            operation(2, JournalOperationKind::AddRule, "rule:v4:42410"),
        ]);
        complete.validate().unwrap();
    }
    #[test]
    fn journal_states_follow_apply_then_reverse_cleanup_order() {
        let mut valid = journal(vec![
            operation(
                0,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            ),
            operation(
                1,
                JournalOperationKind::AddRoute,
                "route:v4:42420:0.0.0.0/0",
            ),
            operation(2, JournalOperationKind::AddRule, "rule:v4:42410"),
        ]);
        valid.operations[0].state = JournalOperationState::Applied;
        valid.operations[0].fingerprint = Some("ifindex:77".into());
        valid.operations[1].state = JournalOperationState::Removed;
        valid.operations[1].fingerprint = Some("route-fingerprint".into());
        valid.operations[2].state = JournalOperationState::Absent;
        valid.operations[2].fingerprint = None;
        valid.validate().unwrap();

        let mut invalid = valid.clone();
        invalid.operations.swap(0, 2);
        for (index, item) in invalid.operations.iter_mut().enumerate() {
            item.sequence = index as u32;
        }
        assert!(invalid.validate().is_err());

        let mut invalid = valid;
        invalid.operations[1].state = JournalOperationState::Intent;
        invalid.operations[1].fingerprint = None;
        invalid.operations[2].state = JournalOperationState::Applied;
        invalid.operations[2].fingerprint = Some("rule-fingerprint".into());
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn journal_resource_keys_require_canonical_numeric_identifiers() {
        for key in [
            "route:v4:042420:0.0.0.0/0",
            "route:v4:0:0.0.0.0/0",
            "route:v4:4294967296:0.0.0.0/0",
        ] {
            let value = journal(vec![
                operation(
                    0,
                    JournalOperationKind::CreateInterface,
                    "interface:tun-proxyctl",
                ),
                operation(1, JournalOperationKind::AddRoute, key),
            ]);
            assert!(value.validate().is_err(), "accepted {key}");
        }
        for key in ["rule:v4:042410", "rule:v6:0", "rule:v6:4294967296"] {
            let value = journal(vec![
                operation(
                    0,
                    JournalOperationKind::CreateInterface,
                    "interface:tun-proxyctl",
                ),
                operation(1, JournalOperationKind::AddRule, key),
            ]);
            assert!(value.validate().is_err(), "accepted {key}");
        }
    }

    #[test]
    fn route_journal_keys_require_a_valid_family_address_and_prefix() {
        for key in [
            "route:v4:42420:0.0.0.0/33",
            "route:v4:42420:2001:db8::/0",
            "route:v6:42420:192.0.2.0/24",
            "route:v6:42420:not-an-address/0",
            "route:v4:42420:0.0.0.0",
        ] {
            let invalid = journal(vec![
                operation(
                    0,
                    JournalOperationKind::CreateInterface,
                    "interface:tun-proxyctl",
                ),
                operation(1, JournalOperationKind::AddRoute, key),
            ]);
            assert!(invalid.validate().is_err(), "accepted {key}");
        }
        let valid = journal(vec![
            operation(
                0,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            ),
            operation(
                1,
                JournalOperationKind::AddRoute,
                "route:v4:42420:0.0.0.0/0",
            ),
            operation(2, JournalOperationKind::AddRoute, "route:v6:42420::/0"),
            operation(3, JournalOperationKind::AddRoute, "route:v6:42420::1/128"),
        ]);
        valid.validate().unwrap();
    }

    #[test]
    fn recovery_rejects_unjournaled_or_malformed_kernel_observations() {
        let value = journal(vec![
            operation(
                0,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            ),
            operation(
                1,
                JournalOperationKind::AddRoute,
                "route:v4:42420:0.0.0.0/0",
            ),
        ]);
        let unknown =
            std::collections::BTreeMap::from([("route:v4:42420:192.0.2.0/24".to_owned(), None)]);
        assert!(plan_journal_recovery(&value, &unknown).is_err());

        let malformed = std::collections::BTreeMap::from([(
            "interface:tun-proxyctl".to_owned(),
            Some("bad\nfingerprint".to_owned()),
        )]);
        assert!(plan_journal_recovery(&value, &malformed).is_err());

        for fingerprint in ["", "   ", "\n\t"] {
            let malformed = std::collections::BTreeMap::from([(
                "interface:tun-proxyctl".to_owned(),
                Some(fingerprint.to_owned()),
            )]);
            assert!(plan_journal_recovery(&value, &malformed).is_err());
        }

        let incomplete = std::collections::BTreeMap::from([(
            "interface:tun-proxyctl".to_owned(),
            Some("foreign-interface".to_owned()),
        )]);
        let decisions = plan_journal_recovery(&value, &incomplete).unwrap();
        assert_eq!(
            decisions[1].1,
            JournalRecoveryDecision::PreserveAndReportConflict
        );
    }

    #[test]
    fn recovery_plan_is_reverse_ordered_and_conflicts_are_resource_local() {
        let mut value = journal(vec![
            operation(
                0,
                JournalOperationKind::CreateInterface,
                "interface:tun-proxyctl",
            ),
            operation(
                1,
                JournalOperationKind::AddRoute,
                "route:v4:42420:0.0.0.0/0",
            ),
            operation(2, JournalOperationKind::AddRule, "rule:v4:42410"),
        ]);
        for (item, fingerprint) in value.operations.iter_mut().zip([
            "interface-fingerprint",
            "route-fingerprint",
            "rule-fingerprint",
        ]) {
            item.state = JournalOperationState::Applied;
            item.fingerprint = Some(fingerprint.into());
        }
        let observed = std::collections::BTreeMap::from([
            (
                "interface:tun-proxyctl".into(),
                Some("interface-fingerprint".into()),
            ),
            (
                "route:v4:42420:0.0.0.0/0".into(),
                Some("foreign-route".into()),
            ),
            ("rule:v4:42410".into(), Some("rule-fingerprint".into())),
        ]);
        let decisions = plan_journal_recovery(&value, &observed).unwrap();
        assert_eq!(
            decisions
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            [
                "rule:v4:42410",
                "route:v4:42420:0.0.0.0/0",
                "interface:tun-proxyctl",
            ]
        );
        assert_eq!(
            decisions[0].1,
            JournalRecoveryDecision::CompareAndDelete {
                expected_fingerprint: "rule-fingerprint".into(),
            }
        );
        assert_eq!(
            decisions[1].1,
            JournalRecoveryDecision::PreserveAndReportConflict
        );
        assert_eq!(
            decisions[2].1,
            JournalRecoveryDecision::CompareAndDelete {
                expected_fingerprint: "interface-fingerprint".into(),
            }
        );
    }
}

    #[test]
    fn persistent_interface_creation_is_a_valid_first_journal_operation() {
        let value = journal(vec![operation(
            0,
            JournalOperationKind::CreatePersistentInterface,
            "interface:tun-proxyctl",
        )]);
        assert!(value.validate().is_ok());
        let encoded = serde_json::to_vec(&value).unwrap();
        let decoded: TransactionJournal = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.operations[0].kind, JournalOperationKind::CreatePersistentInterface);
    }

    #[test]
    fn persistent_interface_operation_rejects_non_interface_resource_keys() {
        let value = journal(vec![operation(
            0,
            JournalOperationKind::CreatePersistentInterface,
            "route:v4:42420:0.0.0.0/0",
        )]);
        assert!(value.validate().is_err());
    }
