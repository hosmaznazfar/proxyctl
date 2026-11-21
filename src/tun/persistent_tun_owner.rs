//! Long-lived ownership of non-persistent TUN descriptors.
//!
//! The owner must live in the privileged broker process for the complete activation.
//! Dropping an entry closes its TUN descriptor and therefore releases that interface.
//! This registry deliberately exposes no raw descriptor transfer or arbitrary ioctl API.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};

const MAX_RETAINED_TUN_DEVICES: usize = 64;

use super::{
    kernel_inventory::{self, KernelInterfaceRecord},
    tun_device::TunDevice,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OwnerKey {
    activation_id: String,
    generation: u64,
}

#[derive(Debug)]
struct OwnedTun {
    device: TunDevice,
    interface: KernelInterfaceRecord,
}

/// Retains each TUN attachment until its exact activation generation is released.
///
/// Construct this inside the persistent mutation-broker service, not in a short-lived
/// CLI request handler. The map is intentionally process-local: a broker crash closes
/// non-persistent TUN descriptors, while the durable journal remains available to recovery.
#[derive(Debug, Default)]
pub struct PersistentTunOwner {
    devices: BTreeMap<OwnerKey, OwnedTun>,
}

impl PersistentTunOwner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate and retain one exclusive TUN device for an activation generation.
    ///
    /// The returned identity is taken from a fresh cross-checked kernel snapshot after
    /// allocation; no ifindex is predicted or copied from the routing plan.
    pub fn create(
        &mut self,
        activation_id: &str,
        generation: u64,
        name: &str,
        uid: u32,
        gid: u32,
    ) -> Result<KernelInterfaceRecord> {
        validate_identity(activation_id, generation)?;
        let key = OwnerKey {
            activation_id: activation_id.to_owned(),
            generation,
        };
        ensure!(
            !self.devices.contains_key(&key),
            "this activation generation already owns a TUN device"
        );
        ensure!(
            self.devices.len() < MAX_RETAINED_TUN_DEVICES,
            "the broker has reached its retained TUN device limit"
        );
        ensure!(
            !self
                .devices
                .values()
                .any(|owned| owned.interface.name == name),
            "the requested TUN name is already retained by another activation"
        );

        let device = TunDevice::create(name, uid, gid)
            .with_context(|| format!("cannot allocate owned TUN interface {name}"))?;
        let snapshot = match kernel_inventory::inspect_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                drop(device);
                return Err(error).context("cannot verify newly allocated TUN interface");
            }
        };
        let matches = snapshot
            .interfaces
            .iter()
            .filter(|interface| interface.name == name && interface.is_tun);
        let mut matches = matches.cloned();
        let interface = matches
            .next()
            .context("new TUN interface is absent from the fresh kernel inventory")?;
        ensure!(
            matches.next().is_none(),
            "fresh kernel inventory contains duplicate TUN interface identity"
        );
        ensure!(
            interface.index > 0 && device.name() == interface.name,
            "fresh kernel inventory does not match the retained TUN descriptor"
        );

        self.devices.insert(
            key,
            OwnedTun {
                device,
                interface: interface.clone(),
            },
        );
        Ok(interface)
    }

    /// Return the live identity only for the exact activation and generation.
    pub fn identity(&self, activation_id: &str, generation: u64) -> Result<&KernelInterfaceRecord> {
        validate_identity(activation_id, generation)?;
        self.devices
            .get(&OwnerKey {
                activation_id: activation_id.to_owned(),
                generation,
            })
            .and_then(|owned| {
                (owned.device.name() == owned.interface.name && owned.interface.index > 0)
                    .then_some(&owned.interface)
            })
            .context("activation generation does not own a consistent retained TUN device")
    }

    /// Release the descriptor only when activation, generation, name and ifindex all match.
    ///
    /// Removing the entry closes the descriptor. A stale request cannot release a newer
    /// generation, and a reused interface name cannot satisfy the ifindex comparison.
    pub fn release(
        &mut self,
        activation_id: &str,
        generation: u64,
        name: &str,
        index: u32,
    ) -> Result<()> {
        validate_identity(activation_id, generation)?;
        let key = OwnerKey {
            activation_id: activation_id.to_owned(),
            generation,
        };
        let owned = self
            .devices
            .get(&key)
            .context("activation generation does not own a retained TUN device")?;
        ensure!(
            owned.device.name() == owned.interface.name
                && owned.interface.index > 0
                && owned.interface.name == name
                && owned.interface.index == index,
            "refusing to release a TUN descriptor with a mismatched interface identity"
        );
        let owned = self.devices.remove(&key).expect("entry checked above");
        drop(owned);
        Ok(())
    }

    /// Borrow the live descriptor for the exact activation generation.
    pub fn descriptor(&self, activation_id: &str, generation: u64) -> Result<std::os::fd::BorrowedFd<'_>> {
        validate_identity(activation_id, generation)?;
        self.devices.get(&OwnerKey { activation_id: activation_id.to_owned(), generation })
            .filter(|owned| owned.device.name() == owned.interface.name && owned.interface.index > 0)
            .map(|owned| owned.device.as_fd())
            .context("activation generation does not own a consistent retained TUN descriptor")
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

fn validate_identity(activation_id: &str, generation: u64) -> Result<()> {
    ensure!(
        activation_id.len() == 36
            && activation_id.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                }
            }),
        "invalid canonical activation UUID"
    );
    ensure!(generation > 0, "activation generation must be non-zero");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_generation_scoped_owner_identity() {
        assert!(validate_identity("12345678-1234-4234-8234-123456789abc", 1).is_ok());
        assert!(validate_identity("12345678-1234-4234-8234-123456789ABC", 1).is_err());
        assert!(validate_identity("not-a-uuid", 1).is_err());
        assert!(validate_identity("12345678-1234-4234-8234-123456789abc", 0).is_err());
    }
}


/// Registry for native cores that attach to a persistent named TUN device.
///
/// Unlike PersistentTunOwner, this registry does not retain an open TUN queue.
/// An idle broker queue would compete with a native core for packets. The durable
/// journal remains the recovery authority after a broker crash; this map only
/// prevents duplicate live generations in one process.
#[derive(Debug, Default)]
pub struct NativePersistentTunOwner {
    devices: BTreeMap<OwnerKey, KernelInterfaceRecord>,
}

impl NativePersistentTunOwner {
    pub fn new() -> Self { Self::default() }

    pub fn create(&mut self, activation_id: &str, generation: u64, name: &str, uid: u32, gid: u32) -> Result<KernelInterfaceRecord> {
        validate_identity(activation_id, generation)?;
        let key = OwnerKey { activation_id: activation_id.to_owned(), generation };
        ensure!(!self.devices.contains_key(&key), "native TUN generation is already registered");
        ensure!(self.devices.len() < MAX_RETAINED_TUN_DEVICES, "native TUN registry limit reached");
        ensure!(!self.devices.values().any(|device| device.name == name), "native TUN name is already owned");

        super::tun_device::create_persistent(name, uid, gid)
            .with_context(|| format!("cannot create persistent native TUN interface {name}"))?;
        let snapshot = match kernel_inventory::inspect_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let rollback = super::tun_device::current_interface_index(name)
                    .and_then(|index| super::tun_device::remove_persistent(name, index));
                return match rollback {
                    Ok(()) => Err(error).context("cannot verify persistent native TUN interface; persistence was rolled back"),
                    Err(cleanup) => anyhow::bail!("cannot verify persistent native TUN interface ({error:#}); persistence rollback also failed ({cleanup:#})"),
                };
            }
        };
        let mut matches = snapshot.interfaces.iter().filter(|interface| interface.name == name && interface.is_tun).cloned();
        let interface = matches.next().context("persistent native TUN interface is absent from fresh kernel inventory")?;
        ensure!(matches.next().is_none(), "kernel inventory contains duplicate native TUN names");
        ensure!(interface.index > 0, "persistent native TUN interface has an invalid ifindex");
        self.devices.insert(key, interface.clone());
        Ok(interface)
    }

    pub fn identity(&self, activation_id: &str, generation: u64) -> Result<&KernelInterfaceRecord> {
        validate_identity(activation_id, generation)?;
        self.devices.get(&OwnerKey { activation_id: activation_id.to_owned(), generation })
            .filter(|interface| interface.index > 0)
            .context("native TUN generation is not registered")
    }

    /// Remove the persistent device only after the caller has stopped its exact core service.
    pub fn release(&mut self, activation_id: &str, generation: u64, name: &str, index: u32) -> Result<()> {
        validate_identity(activation_id, generation)?;
        let key = OwnerKey { activation_id: activation_id.to_owned(), generation };
        let owned = self.devices.get(&key).context("native TUN generation is not registered")?;
        ensure!(owned.name == name && owned.index == index && index > 0,
            "refusing to remove a native TUN device with mismatched durable identity");
        let snapshot = kernel_inventory::inspect_snapshot()?;
        let mut matches = snapshot.interfaces.iter().filter(|interface| interface.name == name);
        let live = matches.next().context("native TUN interface disappeared before cleanup")?;
        ensure!(matches.next().is_none(), "kernel inventory contains duplicate interface names");
        ensure!(live.is_tun && live.index == index,
            "native TUN interface identity changed; refusing persistent cleanup");
        super::tun_device::remove_persistent(name, index)
            .context("cannot clear persistence from the exact owned native TUN interface")?;
        self.devices.remove(&key);
        Ok(())
    }

    pub fn len(&self) -> usize { self.devices.len() }
    pub fn is_empty(&self) -> bool { self.devices.is_empty() }
}


#[cfg(test)]
mod native_owner_tests {
    use super::*;

    #[test]
    fn native_registry_starts_empty_and_rejects_unknown_generation() {
        let owner = NativePersistentTunOwner::new();
        assert!(owner.is_empty());
        assert_eq!(owner.len(), 0);
        assert!(owner.identity("12345678-1234-4234-8234-123456789abc", 1).is_err());
    }

    #[test]
    fn native_registry_release_requires_exact_name_and_ifindex_before_kernel_access() {
        let mut owner = NativePersistentTunOwner::new();
        let key = OwnerKey { activation_id: "12345678-1234-4234-8234-123456789abc".into(), generation: 9 };
        owner.devices.insert(key, KernelInterfaceRecord { name: "tun-proxyctl".into(), index: 17, is_tun: true });
        assert!(owner.release("12345678-1234-4234-8234-123456789abc", 9, "tun-other", 17).is_err());
        assert!(owner.release("12345678-1234-4234-8234-123456789abc", 9, "tun-proxyctl", 18).is_err());
        assert_eq!(owner.len(), 1);
    }

    #[test]
    fn native_registry_rejects_stale_generation_and_invalid_uuid() {
        let owner = NativePersistentTunOwner::new();
        assert!(owner.identity("12345678-1234-4234-8234-123456789ABC", 1).is_err());
        assert!(owner.identity("12345678-1234-4234-8234-123456789abc", 0).is_err());
    }
}
