//! Concrete Linux journal-backed TUN transaction and recovery backend.
//!
//! All mutations are typed. The journal intent is fsynced before each syscall; canonical
//! fingerprints are captured from a fresh kernel inventory after successful ACKs. Cleanup
//! re-inspects immediately before issuing a typed delete and records progress only afterwards.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use serde_json::Value;

use super::{
    journal::{JournalOperationKind, JournalOperationState},
    journal_recovery_executor::JournalRecoveryBackend,
    kernel_inventory::{self, KernelInterfaceRecord, KernelSnapshot},
    kernel_transaction::KernelTransactionBackend,
    manifest_store::{ManifestSnapshot, ManifestStore},
    ownership::{ResourceState, RouteManifest},
    persistent_tun_owner::{NativePersistentTunOwner, PersistentTunOwner},
    recovery::SupervisorPhase,
    resource_snapshot::observe_journal_resources,
    route_policy::{AddressFamily, MarkSelector, PlannedRoute, PlannedRule, RulePurpose},
    rtnetlink_mutations,
};

/// Own this object for the complete privileged activation. Its owner registry keeps the TUN
/// descriptor open; dropping the backend closes descriptors and leaves the journal for recovery.
pub struct LinuxJournalBackend {
    store: ManifestStore,
    generation: u64,
    owner: PersistentTunOwner,
    native_owner: NativePersistentTunOwner,
}

impl LinuxJournalBackend {
    /// Borrow the descriptor retained for this backend's exact activation generation.
    pub fn tun_descriptor(
        &self,
        activation_id: &str,
        generation: u64,
    ) -> Result<std::os::fd::BorrowedFd<'_>> {
        ensure!(
            generation == self.generation,
            "TUN descriptor request has a stale generation"
        );
        let journal = self
            .store
            .load_transaction_journal()?
            .context("TUN transaction journal is missing")?;
        ensure!(
            journal.activation_id == activation_id && journal.generation == generation,
            "TUN descriptor request does not match the active journal"
        );
        ensure!(
            journal
                .operations
                .iter()
                .any(|operation| operation.kind == JournalOperationKind::CreateInterface),
            "this activation uses a persistent native TUN device and cannot export a broker descriptor"
        );
        self.owner.descriptor(activation_id, generation)
    }

    pub fn new(store: ManifestStore, activation_id: &str, generation: u64) -> Result<Self> {
        ensure!(generation > 0, "activation generation must be non-zero");
        ensure!(
            store.load_transaction_journal()?.is_none(),
            "an unresolved transaction journal must be recovered first"
        );
        ensure!(
            store.load()?.is_none(),
            "an existing ownership manifest must be cleaned before a new activation"
        );
        store.create_transaction_journal(activation_id, generation)?;
        Ok(Self {
            store,
            generation,
            owner: PersistentTunOwner::new(),
            native_owner: NativePersistentTunOwner::new(),
        })
    }

    /// Start a journal-backed transaction for a native core using a persistent named TUN device.
    pub fn new_native(store: ManifestStore, activation_id: &str, generation: u64) -> Result<Self> {
        ensure!(generation > 0, "activation generation must be non-zero");
        ensure!(
            store.load_transaction_journal()?.is_none(),
            "an unresolved transaction journal must be recovered first"
        );
        ensure!(
            store.load()?.is_none(),
            "an existing ownership manifest must be cleaned before a new activation"
        );
        store.create_transaction_journal(activation_id, generation)?;
        Ok(Self {
            store,
            generation,
            owner: PersistentTunOwner::new(),
            native_owner: NativePersistentTunOwner::new(),
        })
    }

    /// Reopen an existing journal for detached recovery after a helper restart.
    /// The old non-persistent TUN descriptor is intentionally not reconstructed.
    pub fn open_for_recovery(
        store: ManifestStore,
        activation_id: &str,
        generation: u64,
    ) -> Result<Self> {
        ensure!(generation > 0, "activation generation must be non-zero");
        let journal = store
            .load_transaction_journal()?
            .context("no transaction journal exists for recovery")?;
        ensure!(
            journal.activation_id == activation_id && journal.generation == generation,
            "recovery identity does not match the durable journal"
        );
        Ok(Self {
            store,
            generation,
            owner: PersistentTunOwner::new(),
            native_owner: NativePersistentTunOwner::new(),
        })
    }

    fn journal_identity(&self, activation_id: &str) -> Result<()> {
        let journal = self
            .store
            .load_transaction_journal()?
            .context("transaction journal is missing")?;
        ensure!(
            journal.activation_id == activation_id && journal.generation == self.generation,
            "kernel mutation does not match the active journal generation"
        );
        Ok(())
    }

    fn fingerprint(&mut self, key: &str) -> Result<String> {
        let journal = self
            .store
            .load_transaction_journal()?
            .context("transaction journal disappeared")?;
        let snapshot = kernel_inventory::inspect_snapshot()?;
        observe_journal_resources(&journal, &snapshot)?
            .remove(key)
            .flatten()
            .context("mutated resource is absent from fresh kernel inventory")
    }

    fn remove_live(
        &mut self,
        kind: JournalOperationKind,
        key: &str,
        expected: &str,
    ) -> Result<ResourceState> {
        let journal = self
            .store
            .load_transaction_journal()?
            .context("transaction journal is missing")?;
        let snapshot = kernel_inventory::inspect_snapshot()?;
        let observed = observe_journal_resources(&journal, &snapshot)?;
        let Some(current) = observed.get(key).cloned().flatten() else {
            if kind == JournalOperationKind::CreatePersistentInterface {
                let expected_value: Value = serde_json::from_str(expected)?;
                let name = expected_value
                    .get("name")
                    .and_then(Value::as_str)
                    .context("persistent interface fingerprint has no name")?;
                let index = expected_value
                    .get("ifindex")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .context("persistent interface fingerprint has invalid ifindex")?;
                let alias = expected_value
                    .get("alias")
                    .and_then(Value::as_str)
                    .context("persistent interface fingerprint has no generation alias")?;
                let expected_alias =
                    format!("proxyctl:{}:{}", journal.activation_id, self.generation);
                ensure!(
                    alias == expected_alias,
                    "persistent interface fingerprint belongs to a different activation generation"
                );
                self.native_owner.forget_if_absent(name, index)?;
                return Ok(ResourceState::AlreadyAbsent);
            }
            if kind == JournalOperationKind::CreateInterface
                && let Ok(interface) = self
                    .owner
                    .identity(&journal.activation_id, self.generation)
                    .cloned()
            {
                self.owner.release(
                    &journal.activation_id,
                    self.generation,
                    &interface.name,
                    interface.index,
                )?;
                let after = kernel_inventory::inspect_snapshot()?;
                if after
                    .interfaces
                    .iter()
                    .any(|item| item.name == interface.name || item.index == interface.index)
                {
                    return Ok(ResourceState::ChangedOrForeign);
                }
                return Ok(ResourceState::Removed);
            }
            return Ok(ResourceState::AlreadyAbsent);
        };
        if current != expected {
            return Ok(ResourceState::ChangedOrForeign);
        }
        match kind {
            JournalOperationKind::CreateInterface
            | JournalOperationKind::CreatePersistentInterface => {
                let value: Value = serde_json::from_str(&current)?;
                let name = value
                    .get("name")
                    .and_then(Value::as_str)
                    .context("interface fingerprint has no name")?;
                let index = value
                    .get("ifindex")
                    .and_then(Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok())
                    .context("interface fingerprint has invalid ifindex")?;
                let live = snapshot
                    .interfaces
                    .iter()
                    .find(|item| item.name == name && item.index == index && item.is_tun);
                if live.is_none() {
                    return Ok(ResourceState::ChangedOrForeign);
                }
                if kind == JournalOperationKind::CreatePersistentInterface {
                    let alias = value
                        .get("alias")
                        .and_then(Value::as_str)
                        .context("persistent interface fingerprint has no generation alias")?;
                    let expected_alias =
                        format!("proxyctl:{}:{}", journal.activation_id, self.generation);
                    ensure!(
                        alias == expected_alias,
                        "persistent TUN alias does not match the journal activation generation"
                    );
                    self.native_owner.release_recovered(name, index, alias)?;
                } else {
                    self.owner
                        .release(&journal.activation_id, self.generation, name, index)?;
                }
                let after = kernel_inventory::inspect_snapshot()?;
                if after
                    .interfaces
                    .iter()
                    .any(|item| item.name == name || item.index == index)
                {
                    return Ok(ResourceState::ChangedOrForeign);
                }
                Ok(ResourceState::Removed)
            }
            JournalOperationKind::AddRoute => {
                let (owned_name, owned_index) = journal_interface_identity(&journal)?;
                ensure!(
                    !snapshot
                        .interfaces
                        .iter()
                        .any(|item| item.name == owned_name || item.index == owned_index),
                    "route cleanup verification ran before the owned TUN interface was removed"
                );

                // Do not issue RTM_DELROUTE. The kernel removes routes bound to the exact
                // TUN ifindex as part of netdevice unregister. If a route remains after that
                // operation, it is no longer safe to infer that it is ours: preserve it and
                // retain the journal rather than deleting by a weaker route selector.
                Ok(ResourceState::ChangedOrForeign)
            }
            JournalOperationKind::AddRule => {
                let (family, priority) = parse_rule_key(key)?;
                let value: Value = serde_json::from_str(&current)?;
                ensure!(
                    has_proxyctl_protocol_marker(&value),
                    "rule inventory does not prove the Proxyctl ownership protocol marker"
                );
                let table_value = value
                    .get("table")
                    .or_else(|| value.get("lookup"))
                    .context("rule fingerprint has no table selector")?;
                let table = parse_table_value(table_value)?;
                let mark = value
                    .get("fwmark")
                    .map(|mark| parse_mark(mark, value.get("fwmask")))
                    .transpose()?;
                ensure!(
                    value.get("fwmask").is_none() || value.get("fwmark").is_some(),
                    "rule fingerprint has a mask without a mark"
                );
                let rule = PlannedRule {
                    family,
                    priority,
                    purpose: if mark.is_some() {
                        RulePurpose::CoreTrafficBypass
                    } else {
                        RulePurpose::ProxyTraffic
                    },
                    mark,
                    lookup_table: table,
                };
                rtnetlink_mutations::delete_rule(&rule)?;
                let after = kernel_inventory::inspect_snapshot()?;
                let after_journal = self
                    .store
                    .load_transaction_journal()?
                    .context("journal disappeared during rule removal")?;
                let after_observed = observe_journal_resources(&after_journal, &after)?;
                if after_observed.get(key).is_some_and(Option::is_none) {
                    Ok(ResourceState::Removed)
                } else {
                    Ok(ResourceState::ChangedOrForeign)
                }
            }
        }
    }
}

impl KernelTransactionBackend for LinuxJournalBackend {
    fn create_owned_interface(
        &mut self,
        id: &str,
        name: &str,
        uid: u32,
        gid: u32,
    ) -> Result<KernelInterfaceRecord> {
        self.journal_identity(id)?;
        let key = format!("interface:{name}");
        self.store.record_operation_intent(
            id,
            self.generation,
            JournalOperationKind::CreateInterface,
            &key,
        )?;
        let interface = self.owner.create(id, self.generation, name, uid, gid)?;
        let fp = self.fingerprint(&key)?;
        self.store
            .mark_operation_applied(id, self.generation, &key, &fp)?;
        Ok(interface)
    }

    fn create_persistent_owned_interface(
        &mut self,
        id: &str,
        name: &str,
        uid: u32,
        gid: u32,
    ) -> Result<KernelInterfaceRecord> {
        self.journal_identity(id)?;
        let key = format!("interface:{name}");
        self.store.record_operation_intent(
            id,
            self.generation,
            JournalOperationKind::CreatePersistentInterface,
            &key,
        )?;
        let interface = self
            .native_owner
            .create(id, self.generation, name, uid, gid)?;
        let fingerprint = self.fingerprint(&key)?;
        self.store
            .mark_operation_applied(id, self.generation, &key, &fingerprint)?;
        Ok(interface)
    }

    fn add_owned_route(&mut self, id: &str, route: &PlannedRoute) -> Result<String> {
        self.journal_identity(id)?;
        let key = format!(
            "route:{}:{}:{}",
            family_key(route.family),
            route.table_id,
            route.destination
        );
        self.store.record_operation_intent(
            id,
            self.generation,
            JournalOperationKind::AddRoute,
            &key,
        )?;
        rtnetlink_mutations::add_route(route)?;
        let fp = self.fingerprint(&key)?;
        self.store
            .mark_operation_applied(id, self.generation, &key, &fp)?;
        Ok(fp)
    }

    fn add_owned_rule(&mut self, id: &str, rule: &PlannedRule) -> Result<String> {
        self.journal_identity(id)?;
        let key = format!("rule:{}:{}", family_key(rule.family), rule.priority);
        self.store.record_operation_intent(
            id,
            self.generation,
            JournalOperationKind::AddRule,
            &key,
        )?;
        rtnetlink_mutations::add_rule(rule)?;
        let fp = self.fingerprint(&key)?;
        self.store
            .mark_operation_applied(id, self.generation, &key, &fp)?;
        Ok(fp)
    }

    fn remove_resource_if_matches(
        &mut self,
        id: &str,
        key: &str,
        fp: &str,
    ) -> Result<ResourceState> {
        self.journal_identity(id)?;
        let journal = self
            .store
            .load_transaction_journal()?
            .context("journal is missing")?;
        let operation = journal
            .operations
            .iter()
            .find(|item| item.resource_key == key)
            .context("resource is not in this journal")?;
        let state = self.remove_live(operation.kind, key, fp)?;
        if matches!(state, ResourceState::Removed | ResourceState::AlreadyAbsent) {
            self.store
                .mark_operation_removed(id, self.generation, key)?;
        }
        Ok(state)
    }

    fn remove_interface_if_matches(
        &mut self,
        id: &str,
        name: &str,
        index: u32,
    ) -> Result<ResourceState> {
        self.journal_identity(id)?;
        let key = format!("interface:{name}");
        let journal = self
            .store
            .load_transaction_journal()?
            .context("transaction journal is missing while removing the TUN interface")?;
        let interface_operation = journal
            .operations
            .iter()
            .find(|operation| operation.resource_key == key)
            .context("journal has no interface creation operation")?;
        let interface_kind = interface_operation.kind;
        ensure!(
            matches!(
                interface_kind,
                JournalOperationKind::CreateInterface
                    | JournalOperationKind::CreatePersistentInterface
            ),
            "journal interface operation has an invalid kind"
        );
        ensure!(
            interface_operation.state == JournalOperationState::Applied,
            "interface cleanup requires a durably applied interface operation"
        );
        let fp = interface_operation
            .fingerprint
            .as_deref()
            .context("journal interface operation has no applied fingerprint")?;
        validate_interface_fingerprint(fp, name, index)?;
        let state = self.remove_live(interface_kind, &key, fp)?;
        if matches!(state, ResourceState::Removed | ResourceState::AlreadyAbsent) {
            self.store
                .mark_operation_removed(id, self.generation, &key)?;
        }
        Ok(state)
    }

    fn retain_recovery_journal(&mut self, id: &str) -> Result<()> {
        self.journal_identity(id)
    }

    fn commit_manifest(&mut self, manifest: &RouteManifest) -> Result<()> {
        let journal = self
            .store
            .load_transaction_journal()?
            .context("transaction journal is missing")?;
        ensure!(
            journal.activation_id == manifest.activation_id
                && journal.generation == self.generation,
            "manifest does not match transaction journal"
        );
        ensure!(
            journal
                .operations
                .iter()
                .all(|op| op.state == JournalOperationState::Applied),
            "cannot commit a manifest before every journal operation is applied"
        );
        self.store.write(&ManifestSnapshot {
            schema_version: 1,
            generation: self.generation,
            phase: SupervisorPhase::Prepared,
            manifest: manifest.clone(),
            #[cfg(target_os = "linux")]
            core_process: None,
        })
    }

    fn finish_transaction(&mut self, id: &str) -> Result<()> {
        self.journal_identity(id)?;
        let journal = self
            .store
            .load_transaction_journal()?
            .context("journal is missing")?;
        ensure!(
            journal.operations.iter().all(|op| matches!(
                op.state,
                JournalOperationState::Removed | JournalOperationState::Absent
            )),
            "cannot finish a transaction with live journal operations"
        );
        self.store
            .remove_completed_transaction_journal(id, self.generation)
    }
}

impl JournalRecoveryBackend for LinuxJournalBackend {
    fn inspect_fresh(&mut self) -> Result<KernelSnapshot> {
        kernel_inventory::inspect_snapshot()
    }
    fn remove_if_fingerprint_matches(
        &mut self,
        kind: JournalOperationKind,
        key: &str,
        expected: &str,
    ) -> Result<ResourceState> {
        self.remove_live(kind, key, expected)
    }
}

fn validate_interface_fingerprint(fingerprint: &str, name: &str, index: u32) -> Result<()> {
    let value: Value =
        serde_json::from_str(fingerprint).context("journal interface fingerprint is malformed")?;
    ensure!(
        value.get("name").and_then(Value::as_str) == Some(name)
            && value.get("ifindex").and_then(Value::as_u64) == Some(index as u64)
            && value.get("kind").and_then(Value::as_str) == Some("tun"),
        "requested interface identity does not match its durable journal fingerprint"
    );
    Ok(())
}

fn has_proxyctl_protocol_marker(value: &Value) -> bool {
    const PROXYCTL_PROTOCOL: u64 = 99;
    // iproute2 resolves RTPROT_OPENR (99) to "openr" in both detailed
    // human-readable output and JSON. Accept that canonical name as well as
    // numeric representations; all other protocol names remain foreign.
    value.get("protocol").is_some_and(|protocol| {
        protocol.as_u64() == Some(PROXYCTL_PROTOCOL)
            || matches!(protocol.as_str(), Some("99" | "openr"))
    })
}

fn journal_interface_identity(
    journal: &super::journal::TransactionJournal,
) -> Result<(String, u32)> {
    let operation = journal
        .operations
        .iter()
        .find(|operation| {
            matches!(
                operation.kind,
                JournalOperationKind::CreateInterface
                    | JournalOperationKind::CreatePersistentInterface
            )
        })
        .context("journal has no TUN interface creation operation")?;
    let fingerprint = operation
        .fingerprint
        .as_deref()
        .context("journal interface operation has no applied fingerprint")?;
    let value: Value =
        serde_json::from_str(fingerprint).context("journal interface fingerprint is malformed")?;
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .context("journal interface fingerprint has no name")?
        .to_owned();
    let index = value
        .get("ifindex")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .context("journal interface fingerprint has invalid ifindex")?;
    ensure!(index > 0, "journal interface fingerprint has zero ifindex");
    Ok((name, index))
}

fn family_key(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::Ipv4 => "v4",
        AddressFamily::Ipv6 => "v6",
    }
}
fn parse_rule_key(key: &str) -> Result<(AddressFamily, u32)> {
    let rest = key.strip_prefix("rule:").context("invalid rule key")?;
    let (family, priority) = rest.split_once(':').context("invalid rule priority")?;
    let parsed_priority = priority.parse::<u32>()?;
    ensure!(
        parsed_priority > 0
            && parsed_priority <= i32::MAX as u32
            && parsed_priority.to_string() == priority,
        "rule priority is not canonical or exceeds the native signed range"
    );
    Ok((parse_family(family)?, parsed_priority))
}
fn parse_family(value: &str) -> Result<AddressFamily> {
    match value {
        "v4" => Ok(AddressFamily::Ipv4),
        "v6" => Ok(AddressFamily::Ipv6),
        _ => anyhow::bail!("unsupported address family"),
    }
}
fn parse_mark(value: &Value, mask: Option<&Value>) -> Result<MarkSelector> {
    fn parse_u32(value: &Value, field: &str) -> Result<u32> {
        if let Some(number) = value.as_u64() {
            return u32::try_from(number).with_context(|| format!("{field} exceeds u32"));
        }
        let text = value
            .as_str()
            .with_context(|| format!("{field} is not a string or unsigned integer"))?;
        let (radix, digits) =
            if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                (16, hex)
            } else {
                (10, text)
            };
        u32::from_str_radix(digits, radix).with_context(|| format!("invalid {field}"))
    }

    // iproute2 JSON emits the fwmark and fwmask as separate fields. When the
    // mask is the full u32 mask, iproute2 omits fwmask entirely.
    let value = parse_u32(value, "fwmark")?;
    let mask = mask
        .map(|mask| parse_u32(mask, "fwmask"))
        .transpose()?
        .unwrap_or(u32::MAX);
    ensure!(mask != 0 && value & !mask == 0, "invalid fwmark selector");
    Ok(MarkSelector { value, mask })
}

fn parse_table_value(value: &Value) -> Result<u32> {
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).context("rule table exceeds u32");
    }
    match value
        .as_str()
        .context("rule table is not numeric or named")?
    {
        "default" => Ok(crate::tun::route_policy::RT_TABLE_DEFAULT),
        "main" => Ok(crate::tun::route_policy::RT_TABLE_MAIN),
        "local" => Ok(crate::tun::route_policy::RT_TABLE_LOCAL),
        value => {
            let table = value
                .parse::<u32>()
                .context("unsupported rule table name")?;
            ensure!(table.to_string() == value, "rule table ID is not canonical");
            Ok(table)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_fingerprint_validation_preserves_persistent_generation_alias() {
        let fingerprint = serde_json::json!({
            "alias": "proxyctl:12345678-1234-4234-8234-123456789abc:7",
            "ifindex": 91,
            "kind": "tun",
            "name": "tun-proxyctl"
        })
        .to_string();
        assert!(validate_interface_fingerprint(&fingerprint, "tun-proxyctl", 91).is_ok());
        assert!(validate_interface_fingerprint(&fingerprint, "tun-proxyctl", 92).is_err());
        assert!(validate_interface_fingerprint(&fingerprint, "tun-other", 91).is_err());
    }

    #[test]
    fn interface_fingerprint_validation_rejects_missing_or_wrong_kind() {
        assert!(
            validate_interface_fingerprint(
                r#"{"ifindex":91,"kind":"dummy","name":"tun-proxyctl"}"#,
                "tun-proxyctl",
                91
            )
            .is_err()
        );
        assert!(
            validate_interface_fingerprint(
                r#"{"ifindex":91,"name":"tun-proxyctl"}"#,
                "tun-proxyctl",
                91
            )
            .is_err()
        );
    }

    #[test]
    fn cleanup_requires_the_explicit_proxyctl_protocol_marker() {
        assert!(has_proxyctl_protocol_marker(
            &serde_json::json!({"protocol": 99})
        ));
        assert!(has_proxyctl_protocol_marker(
            &serde_json::json!({"protocol": "99"})
        ));
        assert!(has_proxyctl_protocol_marker(
            &serde_json::json!({"protocol": "openr"})
        ));
        assert!(!has_proxyctl_protocol_marker(
            &serde_json::json!({"protocol": "static"})
        ));
        assert!(!has_proxyctl_protocol_marker(
            &serde_json::json!({"protocol": 4})
        ));
        assert!(!has_proxyctl_protocol_marker(&serde_json::json!({})));
    }

    #[test]
    fn native_journal_generation_never_exports_a_descriptor() {
        let directory = tempfile::tempdir().unwrap();
        let store = ManifestStore::open(directory.path()).unwrap();
        let activation_id = "12345678-1234-4234-8234-123456789abc";
        let generation = 44;
        let backend =
            LinuxJournalBackend::new_native(store.clone(), activation_id, generation).unwrap();
        store
            .record_operation_intent(
                activation_id,
                generation,
                JournalOperationKind::CreatePersistentInterface,
                "interface:tun-proxyctl",
            )
            .unwrap();
        assert!(backend.tun_descriptor(activation_id, generation).is_err());
    }
    #[test]
    fn rejects_noncanonical_or_unsupported_cleanup_keys() {
        assert!(parse_rule_key("rule:v6:0").is_err());
        assert!(parse_rule_key("rule:v4:042410").is_err());
    }

    #[test]
    fn rejects_cleanup_rule_priority_outside_native_range() {
        assert!(parse_rule_key(&format!("rule:v4:{}", i32::MAX as u64 + 1)).is_err());
        assert!(parse_rule_key(&format!("rule:v4:{}", i32::MAX)).is_ok());
    }

    #[test]
    fn parses_iproute2_json_fwmark_and_fwmask_fields() {
        assert_eq!(
            parse_mark(&serde_json::json!("0x42"), Some(&serde_json::json!("0xff"))).unwrap(),
            MarkSelector {
                value: 0x42,
                mask: 0xff
            }
        );
        assert_eq!(
            parse_mark(&serde_json::json!("0x42"), None).unwrap(),
            MarkSelector {
                value: 0x42,
                mask: u32::MAX
            }
        );
        assert_eq!(
            parse_mark(&serde_json::json!(66), Some(&serde_json::json!(255))).unwrap(),
            MarkSelector {
                value: 66,
                mask: 255
            }
        );
        assert!(
            parse_mark(
                &serde_json::json!("0x100"),
                Some(&serde_json::json!("0xff"))
            )
            .is_err()
        );
        assert!(parse_mark(&serde_json::json!("0x42"), Some(&serde_json::json!("0"))).is_err());
        assert!(parse_mark(&serde_json::json!("not-a-mark"), None).is_err());
    }
}
