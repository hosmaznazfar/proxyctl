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
    persistent_tun_owner::PersistentTunOwner,
    resource_snapshot::observe_journal_resources,
    recovery::SupervisorPhase,
    route_policy::{AddressFamily, MarkSelector, PlannedRoute, PlannedRule, RouteType, RulePurpose},
    rtnetlink_mutations,
};

/// Own this object for the complete privileged activation. Its owner registry keeps the TUN
/// descriptor open; dropping the backend closes descriptors and leaves the journal for recovery.
pub struct LinuxJournalBackend {
    store: ManifestStore,
    generation: u64,
    owner: PersistentTunOwner,
}

impl LinuxJournalBackend {
    pub fn new(store: ManifestStore, activation_id: &str, generation: u64) -> Result<Self> {
        ensure!(generation > 0, "activation generation must be non-zero");
        ensure!(store.load_transaction_journal()?.is_none(), "an unresolved transaction journal must be recovered first");
        ensure!(store.load()?.is_none(), "an existing ownership manifest must be cleaned before a new activation");
        store.create_transaction_journal(activation_id, generation)?;
        Ok(Self { store, generation, owner: PersistentTunOwner::new() })
    }

    /// Reopen an existing journal for detached recovery after a helper restart.
    /// The old non-persistent TUN descriptor is intentionally not reconstructed.
    pub fn open_for_recovery(store: ManifestStore, activation_id: &str, generation: u64) -> Result<Self> {
        ensure!(generation > 0, "activation generation must be non-zero");
        let journal = store.load_transaction_journal()?.context("no transaction journal exists for recovery")?;
        ensure!(journal.activation_id == activation_id && journal.generation == generation,
            "recovery identity does not match the durable journal");
        Ok(Self { store, generation, owner: PersistentTunOwner::new() })
    }

    fn journal_identity(&self, activation_id: &str) -> Result<()> {
        let journal = self.store.load_transaction_journal()?.context("transaction journal is missing")?;
        ensure!(journal.activation_id == activation_id && journal.generation == self.generation,
            "kernel mutation does not match the active journal generation");
        Ok(())
    }

    fn fingerprint(&mut self, key: &str) -> Result<String> {
        let journal = self.store.load_transaction_journal()?.context("transaction journal disappeared")?;
        let snapshot = kernel_inventory::inspect_snapshot()?;
        observe_journal_resources(&journal, &snapshot)?
            .remove(key).flatten().context("mutated resource is absent from fresh kernel inventory")
    }

    fn remove_live(&mut self, kind: JournalOperationKind, key: &str, expected: &str) -> Result<ResourceState> {
        let journal = self.store.load_transaction_journal()?.context("transaction journal is missing")?;
        let snapshot = kernel_inventory::inspect_snapshot()?;
        let observed = observe_journal_resources(&journal, &snapshot)?;
        let Some(current) = observed.get(key).cloned().flatten() else {
            if kind == JournalOperationKind::CreateInterface
                && let Ok(interface) = self.owner.identity(&journal.activation_id, self.generation).cloned()
            {
                self.owner.release(&journal.activation_id, self.generation, &interface.name, interface.index)?;
                let after = kernel_inventory::inspect_snapshot()?;
                if after.interfaces.iter().any(|item| item.name == interface.name || item.index == interface.index) {
                    return Ok(ResourceState::ChangedOrForeign);
                }
                return Ok(ResourceState::Removed);
            }
            return Ok(ResourceState::AlreadyAbsent);
        };
        if current != expected { return Ok(ResourceState::ChangedOrForeign); }
        match kind {
            JournalOperationKind::CreateInterface => {
                let value: Value = serde_json::from_str(&current)?;
                let name = value.get("name").and_then(Value::as_str).context("interface fingerprint has no name")?;
                let index = value.get("ifindex").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok()).context("interface fingerprint has invalid ifindex")?;
                let live = snapshot.interfaces.iter().find(|item| item.name == name && item.index == index && item.is_tun);
                if live.is_none() { return Ok(ResourceState::ChangedOrForeign); }
                self.owner.release(&journal.activation_id, self.generation, name, index)?;
                let after = kernel_inventory::inspect_snapshot()?;
                if after.interfaces.iter().any(|item| item.name == name || item.index == index) {
                    return Ok(ResourceState::ChangedOrForeign);
                }
                Ok(ResourceState::Removed)
            }
            JournalOperationKind::AddRoute => {
                let (family, table, destination) = parse_route_key(key)?;
                let value: Value = serde_json::from_str(&current)?;
                let dev = value.get("dev").and_then(Value::as_str).context("route fingerprint has no device")?;
                let retained = self.owner.identity(&journal.activation_id, self.generation)
                    .context("route cleanup has no retained TUN descriptor owner")?;
                ensure!(retained.name == dev, "route fingerprint targets a different interface");
                let interface = snapshot.interfaces.iter().find(|item| item.name == dev && item.index == retained.index && item.is_tun)
                    .context("route device does not match the retained TUN identity")?;
                let route = PlannedRoute { family, destination: family.default_prefix().into(), table_id: table,
                    interface_name: dev.into(), interface_index: interface.index, route_type: RouteType::Unicast };
                rtnetlink_mutations::delete_route(&route)?;
                let after = kernel_inventory::inspect_snapshot()?;
                let after_journal = self.store.load_transaction_journal()?.context("journal disappeared during route removal")?;
                let after_observed = observe_journal_resources(&after_journal, &after)?;
                if after_observed.get(key).is_some_and(Option::is_none) { Ok(ResourceState::Removed) }
                else { Ok(ResourceState::ChangedOrForeign) }
            }
            JournalOperationKind::AddRule => {
                let (family, priority) = parse_rule_key(key)?;
                let value: Value = serde_json::from_str(&current)?;
                let table_value = value.get("table").or_else(|| value.get("lookup"))
                    .context("rule fingerprint has no table selector")?;
                let table = parse_table_value(table_value)?;
                let mark = value.get("fwmark").and_then(Value::as_str).map(parse_mark).transpose()?;
                let rule = PlannedRule { family, priority, purpose: if mark.is_some() { RulePurpose::CoreTrafficBypass } else { RulePurpose::ProxyTraffic }, mark, lookup_table: table };
                rtnetlink_mutations::delete_rule(&rule)?;
                let after = kernel_inventory::inspect_snapshot()?;
                let after_journal = self.store.load_transaction_journal()?.context("journal disappeared during rule removal")?;
                let after_observed = observe_journal_resources(&after_journal, &after)?;
                if after_observed.get(key).is_some_and(Option::is_none) { Ok(ResourceState::Removed) }
                else { Ok(ResourceState::ChangedOrForeign) }
            }
        }
    }
}

impl KernelTransactionBackend for LinuxJournalBackend {
    fn create_owned_interface(&mut self, id: &str, name: &str, uid: u32, gid: u32) -> Result<KernelInterfaceRecord> {
        self.journal_identity(id)?;
        let key = format!("interface:{name}");
        self.store.record_operation_intent(id, self.generation, JournalOperationKind::CreateInterface, &key)?;
        let interface = self.owner.create(id, self.generation, name, uid, gid)?;
        let fp = self.fingerprint(&key)?;
        self.store.mark_operation_applied(id, self.generation, &key, &fp)?;
        Ok(interface)
    }

    fn add_owned_route(&mut self, id: &str, route: &PlannedRoute) -> Result<String> {
        self.journal_identity(id)?;
        let key = format!("route:{}:{}:{}", family_key(route.family), route.table_id, route.destination);
        self.store.record_operation_intent(id, self.generation, JournalOperationKind::AddRoute, &key)?;
        rtnetlink_mutations::add_route(route)?;
        let fp = self.fingerprint(&key)?;
        self.store.mark_operation_applied(id, self.generation, &key, &fp)?;
        Ok(fp)
    }

    fn add_owned_rule(&mut self, id: &str, rule: &PlannedRule) -> Result<String> {
        self.journal_identity(id)?;
        let key = format!("rule:{}:{}", family_key(rule.family), rule.priority);
        self.store.record_operation_intent(id, self.generation, JournalOperationKind::AddRule, &key)?;
        rtnetlink_mutations::add_rule(rule)?;
        let fp = self.fingerprint(&key)?;
        self.store.mark_operation_applied(id, self.generation, &key, &fp)?;
        Ok(fp)
    }

    fn remove_resource_if_matches(&mut self, id: &str, key: &str, fp: &str) -> Result<ResourceState> {
        self.journal_identity(id)?;
        let journal = self.store.load_transaction_journal()?.context("journal is missing")?;
        let operation = journal.operations.iter().find(|item| item.resource_key == key).context("resource is not in this journal")?;
        let state = self.remove_live(operation.kind, key, fp)?;
        if matches!(state, ResourceState::Removed | ResourceState::AlreadyAbsent) {
            self.store.mark_operation_removed(id, self.generation, key)?;
        }
        Ok(state)
    }

    fn remove_interface_if_matches(&mut self, id: &str, name: &str, index: u32) -> Result<ResourceState> {
        self.journal_identity(id)?;
        let key = format!("interface:{name}");
        let fp = serde_json::to_string(&serde_json::json!({"ifindex":index,"kind":"tun","name":name}))?;
        let state = self.remove_live(JournalOperationKind::CreateInterface, &key, &fp)?;
        if matches!(state, ResourceState::Removed | ResourceState::AlreadyAbsent) {
            self.store.mark_operation_removed(id, self.generation, &key)?;
        }
        Ok(state)
    }

    fn retain_recovery_journal(&mut self, id: &str) -> Result<()> { self.journal_identity(id) }

    fn commit_manifest(&mut self, manifest: &RouteManifest) -> Result<()> {
        let journal = self.store.load_transaction_journal()?.context("transaction journal is missing")?;
        ensure!(journal.activation_id == manifest.activation_id && journal.generation == self.generation,
            "manifest does not match transaction journal");
        ensure!(journal.operations.iter().all(|op| op.state == JournalOperationState::Applied),
            "cannot commit a manifest before every journal operation is applied");
        self.store.write(&ManifestSnapshot { schema_version: 1, generation: self.generation,
            phase: SupervisorPhase::Prepared, manifest: manifest.clone(), #[cfg(target_os="linux")] core_process: None })
    }

    fn finish_transaction(&mut self, id: &str) -> Result<()> {
        self.journal_identity(id)?;
        let journal = self.store.load_transaction_journal()?.context("journal is missing")?;
        ensure!(journal.operations.iter().all(|op| matches!(op.state, JournalOperationState::Removed | JournalOperationState::Absent)),
            "cannot finish a transaction with live journal operations");
        self.store.remove_completed_transaction_journal(id, self.generation)
    }
}

impl JournalRecoveryBackend for LinuxJournalBackend {
    fn inspect_fresh(&mut self) -> Result<KernelSnapshot> { kernel_inventory::inspect_snapshot() }
    fn remove_if_fingerprint_matches(&mut self, kind: JournalOperationKind, key: &str, expected: &str) -> Result<ResourceState> {
        self.remove_live(kind, key, expected)
    }
}

fn family_key(family: AddressFamily) -> &'static str { match family { AddressFamily::Ipv4 => "v4", AddressFamily::Ipv6 => "v6" } }
fn parse_route_key(key: &str) -> Result<(AddressFamily, u32, String)> {
    let rest = key.strip_prefix("route:").context("invalid route key")?;
    let (family, rest) = rest.split_once(':').context("invalid route family")?;
    let (table, destination) = rest.split_once(':').context("invalid route table")?;
    let family = parse_family(family)?;
    let table = table.parse::<u32>()?;
    ensure!(table > 0 && (destination == family.default_prefix() || destination == "default"),
        "unsupported route identity");
    Ok((family, table, family.default_prefix().to_owned()))
}
fn parse_rule_key(key: &str) -> Result<(AddressFamily, u32)> {
    let rest = key.strip_prefix("rule:").context("invalid rule key")?;
    let (family, priority) = rest.split_once(':').context("invalid rule priority")?;
    let priority = priority.parse::<u32>()?;
    ensure!(priority > 0, "invalid rule priority");
    Ok((parse_family(family)?, priority))
}
fn parse_family(value: &str) -> Result<AddressFamily> {
    match value { "v4" => Ok(AddressFamily::Ipv4), "v6" => Ok(AddressFamily::Ipv6), _ => anyhow::bail!("unsupported address family") }
}
fn parse_mark(value: &str) -> Result<MarkSelector> {
    let (value, mask) = value.split_once('/').context("invalid fwmark selector")?;
    let value = u32::from_str_radix(value.trim_start_matches("0x"), 16)?;
    let mask = u32::from_str_radix(mask.trim_start_matches("0x"), 16)?;
    ensure!(mask != 0 && value & !mask == 0, "invalid fwmark selector");
    Ok(MarkSelector { value, mask })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_route_keys_without_losing_ipv6_colons() {
        assert_eq!(parse_route_key("route:v4:42420:0.0.0.0/0").unwrap(),
            (AddressFamily::Ipv4, 42420, "0.0.0.0/0".into()));
        assert_eq!(parse_route_key("route:v6:42420:::/0").unwrap(),
            (AddressFamily::Ipv6, 42420, "::/0".into()));
    }

    #[test]
    fn rejects_noncanonical_or_unsupported_cleanup_keys() {
        assert!(parse_route_key("route:v7:42420:0.0.0.0/0").is_err());
        assert!(parse_route_key("route:v4:0:0.0.0.0/0").is_err());
        assert!(parse_rule_key("rule:v6:0").is_err());
        assert!(parse_rule_key("rule:v4:042410").is_err());
    }

    #[test]
    fn parses_only_valid_marked_rule_selectors() {
        assert_eq!(parse_mark("0x42/0xff").unwrap(), MarkSelector { value: 0x42, mask: 0xff });
        assert!(parse_mark("0x100/0xff").is_err());
        assert!(parse_mark("0x42/0").is_err());
    }
}

fn parse_table_value(value: &Value) -> Result<u32> {
    if let Some(number) = value.as_u64() {
        return u32::try_from(number).context("rule table exceeds u32");
    }
    match value.as_str().context("rule table is not numeric or named")? {
        "default" => Ok(crate::tun::route_policy::RT_TABLE_DEFAULT),
        "main" => Ok(crate::tun::route_policy::RT_TABLE_MAIN),
        "local" => Ok(crate::tun::route_policy::RT_TABLE_LOCAL),
        value => value.parse::<u32>().context("unsupported rule table name"),
    }
}
