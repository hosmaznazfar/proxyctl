use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use redb::{Database as RedbDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::domain::ProxyNode;

const SCHEMA_VERSION: u64 = 1;
const METADATA: TableDefinition<&str, u64> = TableDefinition::new("metadata");
const NODES: TableDefinition<u64, &[u8]> = TableDefinition::new("nodes");
const NODE_FINGERPRINTS: TableDefinition<&str, u64> = TableDefinition::new("node_fingerprints");
const BENCHMARK_RUNS: TableDefinition<u64, &[u8]> = TableDefinition::new("benchmark_runs");
const BENCHMARK_SAMPLES: TableDefinition<u64, &[u8]> = TableDefinition::new("benchmark_samples");

/// A persisted node and its lifecycle metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NodeRecord {
    pub id: u64,
    pub node: ProxyNode,
    pub created_at: u64,
    pub deleted_at: Option<u64>,
}

impl NodeRecord {
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }
}

/// Result of adding a node to the database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddNodeOutcome {
    Added(u64),
    Duplicate(u64),
}

/// A short-lived database handle. Drop it when the command's database work is complete.
pub struct NodeDatabase {
    inner: RedbDatabase,
}

impl NodeDatabase {
    /// Open an existing database or create and initialize a new one.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("could not create data directory {}", parent.display()))?;
            set_private_directory_permissions(parent)?;
        }

        let inner = if path.exists() {
            RedbDatabase::open(path)
                .with_context(|| format!("could not open database {}", path.display()))?
        } else {
            RedbDatabase::create(path)
                .with_context(|| format!("could not create database {}", path.display()))?
        };

        set_private_file_permissions(path)?;
        let database = Self { inner };
        database.initialize_schema()?;
        Ok(database)
    }

    fn initialize_schema(&self) -> anyhow::Result<()> {
        let write_txn = self.inner.begin_write()?;
        {
            let mut metadata = write_txn.open_table(METADATA)?;
            let current_version = metadata.get("schema_version")?.map(|value| value.value());

            if current_version.is_some_and(|version| version > SCHEMA_VERSION) {
                bail!(
                    "database schema version {} is newer than supported version {}",
                    current_version.unwrap_or_default(),
                    SCHEMA_VERSION
                );
            }

            if current_version.unwrap_or_default() < SCHEMA_VERSION {
                metadata.insert("schema_version", &SCHEMA_VERSION)?;
            }
            if metadata.get("next_node_id")?.is_none() {
                metadata.insert("next_node_id", &1)?;
            }
        }
        {
            let _ = write_txn.open_table(NODES)?;
            let _ = write_txn.open_table(NODE_FINGERPRINTS)?;
            let _ = write_txn.open_table(BENCHMARK_RUNS)?;
            let _ = write_txn.open_table(BENCHMARK_SAMPLES)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Add a node atomically, returning the existing ID if its fingerprint is already stored.
    pub fn add_node(&self, node: &ProxyNode) -> anyhow::Result<AddNodeOutcome> {
        let fingerprint = node.fingerprint();
        let write_txn = self.inner.begin_write()?;

        {
            let fingerprints = write_txn.open_table(NODE_FINGERPRINTS)?;
            if let Some(existing) = fingerprints.get(fingerprint.as_str())? {
                return Ok(AddNodeOutcome::Duplicate(existing.value()));
            }
        }

        let id = {
            let mut metadata = write_txn.open_table(METADATA)?;
            let next_id = metadata
                .get("next_node_id")?
                .map(|value| value.value())
                .unwrap_or(1);
            let following_id = next_id
                .checked_add(1)
                .context("node ID space is exhausted")?;
            metadata.insert("next_node_id", &following_id)?;
            next_id
        };

        let record = NodeRecord {
            id,
            node: node.clone(),
            created_at: unix_timestamp(),
            deleted_at: None,
        };
        let encoded = serde_json::to_vec(&record)?;

        {
            let mut nodes = write_txn.open_table(NODES)?;
            nodes.insert(id, encoded.as_slice())?;
        }
        {
            let mut fingerprints = write_txn.open_table(NODE_FINGERPRINTS)?;
            fingerprints.insert(fingerprint.as_str(), &id)?;
        }

        write_txn.commit()?;
        Ok(AddNodeOutcome::Added(id))
    }

    pub fn get_node(&self, id: u64) -> anyhow::Result<Option<NodeRecord>> {
        let read_txn = self.inner.begin_read()?;
        let nodes = read_txn.open_table(NODES)?;
        let Some(value) = nodes.get(id)? else {
            return Ok(None);
        };
        let record = serde_json::from_slice(value.value())?;
        Ok(Some(record))
    }

    pub fn list_nodes(&self, include_deleted: bool) -> anyhow::Result<Vec<NodeRecord>> {
        let read_txn = self.inner.begin_read()?;
        let nodes = read_txn.open_table(NODES)?;
        let mut records = Vec::new();

        for entry in nodes.iter()? {
            let (key, value) = entry?;
            let record: NodeRecord = serde_json::from_slice(value.value())?;
            debug_assert_eq!(record.id, key.value());
            if include_deleted || !record.is_deleted() {
                records.push(record);
            }
        }

        records.sort_by_key(|record| record.id);
        Ok(records)
    }

    pub fn soft_delete(&self, id: u64) -> anyhow::Result<bool> {
        self.update_deleted_at(id, Some(unix_timestamp()))
    }

    pub fn restore(&self, id: u64) -> anyhow::Result<bool> {
        self.update_deleted_at(id, None)
    }

    fn update_deleted_at(&self, id: u64, deleted_at: Option<u64>) -> anyhow::Result<bool> {
        let write_txn = self.inner.begin_write()?;
        let mut nodes = write_txn.open_table(NODES)?;

        let Some(existing) = nodes.get(id)? else {
            return Ok(false);
        };
        let mut record: NodeRecord = serde_json::from_slice(existing.value())?;
        drop(existing);

        if record.deleted_at == deleted_at {
            return Ok(false);
        }

        record.deleted_at = deleted_at;
        let encoded = serde_json::to_vec(&record)?;
        nodes.insert(id, encoded.as_slice())?;
        drop(nodes);
        write_txn.commit()?;
        Ok(true)
    }
}

/// Resolve the default per-user database location, honoring XDG_DATA_HOME.
pub fn default_database_path() -> anyhow::Result<PathBuf> {
    let data_home = if let Some(value) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(value)
    } else {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        PathBuf::from(home).join(".local/share")
    };

    Ok(data_home.join("proxyctl").join("proxyctl.redb"))
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("could not secure data directory {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("could not secure database file {}", path.display()))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::parser::parse_proxy_url;

    use super::*;

    #[test]
    fn adds_and_deduplicates_nodes() {
        let directory = tempdir().unwrap();
        let database = NodeDatabase::open(directory.path().join("proxyctl.redb")).unwrap();
        let node = sample_node();

        assert_eq!(database.add_node(&node).unwrap(), AddNodeOutcome::Added(1));
        assert_eq!(
            database.add_node(&node).unwrap(),
            AddNodeOutcome::Duplicate(1)
        );
        assert_eq!(database.list_nodes(false).unwrap().len(), 1);
    }

    #[test]
    fn records_survive_close_and_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("proxyctl.redb");
        {
            let database = NodeDatabase::open(&path).unwrap();
            database.add_node(&sample_node()).unwrap();
        }

        let database = NodeDatabase::open(&path).unwrap();
        assert_eq!(
            database.get_node(1).unwrap().unwrap().node.server,
            "example.com"
        );
    }

    #[test]
    fn soft_deleted_nodes_can_be_restored() {
        let directory = tempdir().unwrap();
        let database = NodeDatabase::open(directory.path().join("proxyctl.redb")).unwrap();
        database.add_node(&sample_node()).unwrap();

        assert!(database.soft_delete(1).unwrap());
        assert!(database.list_nodes(false).unwrap().is_empty());
        assert_eq!(database.list_nodes(true).unwrap().len(), 1);
        assert!(database.restore(1).unwrap());
        assert_eq!(database.list_nodes(false).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn database_permissions_are_restricted() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let path = directory.path().join("proxyctl.redb");
        let _database = NodeDatabase::open(&path).unwrap();

        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fn sample_node() -> ProxyNode {
        parse_proxy_url("vless://uuid@example.com:443?security=tls").unwrap()
    }
}
