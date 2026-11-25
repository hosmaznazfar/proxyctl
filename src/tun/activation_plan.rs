//! Read-only construction of the exact dual-stack kernel transaction for one TUN activation.
//!
//! This module allocates private table/rule identifiers from a complete kernel snapshot. It
//! performs no mutation; the privileged transaction backend must still journal and revalidate
//! every operation because other network managers can race this preflight.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};

use super::{
    kernel_inventory::{self, KernelSnapshot},
    kernel_transaction::KernelTransaction,
    route_policy::{self, RoutingPolicyPlan},
};

pub const TUN_INTERFACE_NAME: &str = "tun-proxyctl";

/// Build a deterministic policy transaction from a caller-supplied read-only snapshot.
///
/// The placeholder ifindex is replaced with the kernel-assigned index by
/// `KernelTransaction::apply_native` after the persistent TUN device is created.
pub fn build_from_snapshot(
    activation_id: &str,
    snapshot: &KernelSnapshot,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<KernelTransaction> {
    ensure!(owner_uid != 0, "TUN device owner UID must be non-zero");
    ensure!(
        !snapshot
            .interfaces
            .iter()
            .any(|interface| interface.name == TUN_INTERFACE_NAME),
        "the requested Proxyctl TUN interface name is already present"
    );

    let (table_id, bypass_priority, proxy_priority) =
        route_policy::allocate_policy_identifiers(&snapshot.inventory)
            .context("cannot allocate conflict-free Proxyctl routing identifiers")?;
    let (core_mark, core_mark_mask) = route_policy::mark_for_activation_id(activation_id)?;
    let policy = RoutingPolicyPlan::new(
        table_id,
        bypass_priority,
        proxy_priority,
        core_mark,
        core_mark_mask,
        TUN_INTERFACE_NAME,
        1,
    );
    let transaction = KernelTransaction {
        activation_id: activation_id.to_owned(),
        policy,
        owner_uid,
        owner_gid,
    };
    transaction.validate()?;
    Ok(transaction)
}

/// Capture the current read-only kernel inventory and construct a transaction plan.
///
/// The returned transaction is not a reservation. The backend must repeat conflict checks
/// while applying the journaled operations and preserve the journal on any ambiguity.
pub fn prepare_current(
    activation_id: &str,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<KernelTransaction> {
    let snapshot = kernel_inventory::inspect_snapshot()
        .context("cannot capture a consistent kernel inventory for TUN preflight")?;
    build_from_snapshot(activation_id, &snapshot, owner_uid, owner_gid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::{
        kernel_inventory::{KernelInterfaceRecord, KernelSnapshot},
        route_policy::{AddressFamily, KernelInventory, RT_TABLE_MIN_PROXYCTL},
    };

    fn snapshot() -> KernelSnapshot {
        KernelSnapshot {
            inventory: KernelInventory::default(),
            routes: Vec::new(),
            rules: Vec::new(),
            interfaces: Vec::new(),
            netlink_interface_count: 0,
        }
    }

    #[test]
    fn builds_dual_stack_transaction_with_activation_bound_mark() {
        let activation_id = "12345678-1234-4234-8234-123456789abc";
        let transaction = build_from_snapshot(activation_id, &snapshot(), 1000, 1000).unwrap();

        assert_eq!(transaction.activation_id, activation_id);
        assert_eq!(transaction.owner_uid, 1000);
        assert_eq!(transaction.owner_gid, 1000);
        assert_eq!(transaction.policy.interface_name, TUN_INTERFACE_NAME);
        assert_eq!(transaction.policy.interface_index, 1);
        assert_eq!(transaction.policy.table_id, RT_TABLE_MIN_PROXYCTL);
        assert_eq!(transaction.policy.routes.len(), 2);
        assert_eq!(transaction.policy.rules.len(), 4);
        assert!(
            transaction
                .policy
                .routes
                .iter()
                .any(|route| route.family == AddressFamily::Ipv4 && route.destination == "0.0.0.0/0")
        );
        assert!(
            transaction
                .policy
                .routes
                .iter()
                .any(|route| route.family == AddressFamily::Ipv6 && route.destination == "::/0")
        );
        assert_eq!(
            transaction.policy.core_mark,
            route_policy::mark_for_activation_id(activation_id).unwrap().0
        );
    }

    #[test]
    fn allocates_around_existing_tables_and_rule_priorities() {
        let mut inventory = KernelInventory::default();
        inventory.occupied_tables.push(RT_TABLE_MIN_PROXYCTL);
        inventory.rule_priorities.extend([
            (AddressFamily::Ipv4, 10_000),
            (AddressFamily::Ipv6, 10_000),
            (AddressFamily::Ipv4, 10_001),
            (AddressFamily::Ipv6, 10_001),
        ]);
        let mut current = snapshot();
        current.inventory = inventory;
        let transaction = build_from_snapshot(
            "12345678-1234-4234-8234-123456789abc",
            &current,
            1000,
            1000,
        )
        .unwrap();
        assert_eq!(transaction.policy.table_id, RT_TABLE_MIN_PROXYCTL + 1);
        assert_eq!(transaction.policy.bypass_priority, 10_001);
        assert_eq!(transaction.policy.proxy_priority, 10_002);
    }

    #[test]
    fn refuses_existing_interface_and_root_device_owner() {
        let mut current = snapshot();
        current.interfaces.push(KernelInterfaceRecord {
            name: TUN_INTERFACE_NAME.to_owned(),
            index: 17,
            is_tun: true,
        });
        assert!(
            build_from_snapshot(
                "12345678-1234-4234-8234-123456789abc",
                &current,
                1000,
                1000
            )
            .is_err()
        );
        assert!(
            build_from_snapshot(
                "12345678-1234-4234-8234-123456789abc",
                &snapshot(),
                0,
                0
            )
            .is_err()
        );
    }
}
