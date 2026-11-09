use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail, ensure};
use redb::{Database as RedbDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::domain::{
    BenchmarkRun, BenchmarkRunStatus, BenchmarkSample, ProxyNode,
};

const SCHEMA_VERSION: u64 = 2;
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

            let mut version = current_version.unwrap_or_default();
            if version < 1 {
                metadata.insert("schema_version", &1)?;
                version = 1;
            }
            if metadata.get("next_node_id")?.is_none() {
                metadata.insert("next_node_id", &1)?;
            }

            // Version 2 adds independent ID sequences for benchmark run and sample records.
            // The benchmark tables themselves were created in schema version 1.
            if version < 2 {
                if metadata.get("next_benchmark_run_id")?.is_none() {
                    metadata.insert("next_benchmark_run_id", &1)?;
                }
                if metadata.get("next_benchmark_sample_id")?.is_none() {
                    metadata.insert("next_benchmark_sample_id", &1)?;
                }
                metadata.insert("schema_version", &2)?;
            } else {
                if metadata.get("next_benchmark_run_id")?.is_none() {
                    metadata.insert("next_benchmark_run_id", &1)?;
                }
                if metadata.get("next_benchmark_sample_id")?.is_none() {
                    metadata.insert("next_benchmark_sample_id", &1)?;
                }
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

    /// Create a running run record and allocate its persistent ID.
    pub fn start_benchmark_run(&self, mut run: BenchmarkRun) -> anyhow::Result<u64> {
        ensure!(run.id == 0, "new benchmark run must not already have an ID");
        ensure!(
            run.status == BenchmarkRunStatus::Running,
            "new benchmark run must have running status"
        );
        ensure!(
            !run.node_ids.is_empty(),
            "benchmark run must select at least one node"
        );
        ensure!(
            !run.cores.is_empty(),
            "benchmark run must select at least one core"
        );

        let write_txn = self.inner.begin_write()?;
        let id = {
            let mut metadata = write_txn.open_table(METADATA)?;
            let next_id = metadata
                .get("next_benchmark_run_id")?
                .map(|value| value.value())
                .unwrap_or(1);
            let following_id = next_id
                .checked_add(1)
                .context("benchmark run ID space is exhausted")?;
            metadata.insert("next_benchmark_run_id", &following_id)?;
            next_id
        };
        run.id = id;
        let encoded = serde_json::to_vec(&run)?;
        {
            let mut runs = write_txn.open_table(BENCHMARK_RUNS)?;
            runs.insert(id, encoded.as_slice())?;
        }
        write_txn.commit()?;
        Ok(id)
    }

    /// Persist one completed sample in its own short write transaction.
    pub fn record_benchmark_sample(&self, mut sample: BenchmarkSample) -> anyhow::Result<u64> {
        ensure!(
            sample.id == 0,
            "new benchmark sample must not already have an ID"
        );
        sample.validate().map_err(anyhow::Error::msg)?;

        let write_txn = self.inner.begin_write()?;
        {
            let runs = write_txn.open_table(BENCHMARK_RUNS)?;
            let run = runs
                .get(sample.run_id)?
                .context("benchmark run was not found")?;
            let run: BenchmarkRun = serde_json::from_slice(run.value())?;
            ensure!(
                run.status == BenchmarkRunStatus::Running,
                "cannot append a sample to a finalized benchmark run"
            );
            ensure!(
                run.node_ids.contains(&sample.node_id),
                "benchmark sample references a node outside the run scope"
            );
            ensure!(
                run.cores.iter().any(|core| core == &sample.core),
                "benchmark sample references a core outside the run scope"
            );
        }
        {
            let nodes = write_txn.open_table(NODES)?;
            ensure!(
                nodes.get(sample.node_id)?.is_some(),
                "benchmark sample references an unknown node"
            );
        }
        let id = {
            let mut metadata = write_txn.open_table(METADATA)?;
            let next_id = metadata
                .get("next_benchmark_sample_id")?
                .map(|value| value.value())
                .unwrap_or(1);
            let following_id = next_id
                .checked_add(1)
                .context("benchmark sample ID space is exhausted")?;
            metadata.insert("next_benchmark_sample_id", &following_id)?;
            next_id
        };
        sample.id = id;
        let encoded = serde_json::to_vec(&sample)?;
        {
            let mut samples = write_txn.open_table(BENCHMARK_SAMPLES)?;
            samples.insert(id, encoded.as_slice())?;
        }
        write_txn.commit()?;
        Ok(id)
    }

    /// Finalize a running benchmark. Returns false when the run is already finalized.
    pub fn finish_benchmark_run(
        &self,
        id: u64,
        status: BenchmarkRunStatus,
        completed_at: u64,
        summary: Option<String>,
    ) -> anyhow::Result<bool> {
        ensure!(
            status != BenchmarkRunStatus::Running,
            "final benchmark status cannot be running"
        );
        let write_txn = self.inner.begin_write()?;
        let mut runs = write_txn.open_table(BENCHMARK_RUNS)?;
        let Some(existing) = runs.get(id)? else {
            return Ok(false);
        };
        let mut run: BenchmarkRun = serde_json::from_slice(existing.value())?;
        drop(existing);
        if run.status != BenchmarkRunStatus::Running {
            return Ok(false);
        }
        run.status = status;
        run.completed_at = Some(completed_at);
        run.summary = summary;
        let encoded = serde_json::to_vec(&run)?;
        runs.insert(id, encoded.as_slice())?;
        drop(runs);
        write_txn.commit()?;
        Ok(true)
    }

    pub fn get_benchmark_run(&self, id: u64) -> anyhow::Result<Option<BenchmarkRun>> {
        let read_txn = self.inner.begin_read()?;
        let runs = read_txn.open_table(BENCHMARK_RUNS)?;
        let Some(value) = runs.get(id)? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_slice(value.value())?))
    }

    pub fn list_benchmark_runs(&self) -> anyhow::Result<Vec<BenchmarkRun>> {
        let read_txn = self.inner.begin_read()?;
        let runs = read_txn.open_table(BENCHMARK_RUNS)?;
        let mut records = Vec::new();
        for entry in runs.iter()? {
            let (key, value) = entry?;
            let run: BenchmarkRun = serde_json::from_slice(value.value())?;
            debug_assert_eq!(run.id, key.value());
            records.push(run);
        }
        records.sort_by_key(|run| run.id);
        Ok(records)
    }

    pub fn list_benchmark_samples(&self, run_id: u64) -> anyhow::Result<Vec<BenchmarkSample>> {
        let read_txn = self.inner.begin_read()?;
        let samples = read_txn.open_table(BENCHMARK_SAMPLES)?;
        let mut records = Vec::new();
        for entry in samples.iter()? {
            let (key, value) = entry?;
            let sample: BenchmarkSample = serde_json::from_slice(value.value())?;
            debug_assert_eq!(sample.id, key.value());
            if sample.run_id == run_id {
                records.push(sample);
            }
        }
        records.sort_by_key(|sample| sample.id);
        Ok(records)
    }

    /// Mark runs left in the running state by an uncatchable termination as interrupted.
    pub fn recover_interrupted_benchmark_runs(&self) -> anyhow::Result<usize> {
        let stale = self
            .list_benchmark_runs()?
            .into_iter()
            .filter(|run| run.status == BenchmarkRunStatus::Running)
            .map(|run| run.id)
            .collect::<Vec<_>>();
        if stale.is_empty() {
            return Ok(0);
        }

        let write_txn = self.inner.begin_write()?;
        let mut runs = write_txn.open_table(BENCHMARK_RUNS)?;
        for id in &stale {
            let Some(existing) = runs.get(*id)? else {
                continue;
            };
            let mut run: BenchmarkRun = serde_json::from_slice(existing.value())?;
            drop(existing);
            if run.status == BenchmarkRunStatus::Running {
                run.status = BenchmarkRunStatus::Interrupted;
                run.completed_at = Some(unix_timestamp());
                run.summary = Some("interrupted before the run could be finalized".into());
                let encoded = serde_json::to_vec(&run)?;
                runs.insert(*id, encoded.as_slice())?;
            }
        }
        drop(runs);
        write_txn.commit()?;
        Ok(stale.len())
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
    use std::collections::BTreeMap;

    use tempfile::tempdir;

    use crate::{
        domain::{
            BenchmarkMetric, BenchmarkRun, BenchmarkRunStatus, BenchmarkSample,
            BenchmarkSampleStatus, BenchmarkSettings,
        },
        parser::parse_proxy_url,
    };

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

    #[test]
    fn benchmark_run_and_samples_persist_incrementally() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("proxyctl.redb");
        let run_id;
        {
            let database = NodeDatabase::open(&path).unwrap();
            database.add_node(&sample_node()).unwrap();
            run_id = database.start_benchmark_run(sample_run()).unwrap();
            assert_eq!(run_id, 1);
            let sample_id = database
                .record_benchmark_sample(sample_value(run_id))
                .unwrap();
            assert_eq!(sample_id, 1);
        }

        let database = NodeDatabase::open(&path).unwrap();
        let samples = database.list_benchmark_samples(run_id).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].value, Some(25.0));
        assert!(
            database
                .finish_benchmark_run(run_id, BenchmarkRunStatus::Completed, 2, None)
                .unwrap()
        );
        assert_eq!(
            database.get_benchmark_run(run_id).unwrap().unwrap().status,
            BenchmarkRunStatus::Completed
        );
        assert!(
            !database
                .finish_benchmark_run(run_id, BenchmarkRunStatus::Completed, 3, None)
                .unwrap()
        );
    }

    #[test]
    fn schema_v1_database_migrates_benchmark_id_counters() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("proxyctl.redb");
        {
            let database = NodeDatabase::open(&path).unwrap();
            database.add_node(&sample_node()).unwrap();
        }
        {
            let database = RedbDatabase::open(&path).unwrap();
            let write_txn = database.begin_write().unwrap();
            {
                let mut metadata = write_txn.open_table(METADATA).unwrap();
                metadata.insert("schema_version", &1).unwrap();
                drop(metadata.remove("next_benchmark_run_id").unwrap());
                drop(metadata.remove("next_benchmark_sample_id").unwrap());
            }
            write_txn.commit().unwrap();
        }

        let database = NodeDatabase::open(&path).unwrap();
        assert_eq!(
            database.get_node(1).unwrap().unwrap().node.server,
            "example.com"
        );
        assert_eq!(database.start_benchmark_run(sample_run()).unwrap(), 1);
    }

    #[test]
    fn interrupted_benchmark_runs_are_recovered() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("proxyctl.redb");
        let run_id = {
            let database = NodeDatabase::open(&path).unwrap();
            database.add_node(&sample_node()).unwrap();
            database.start_benchmark_run(sample_run()).unwrap()
        };
        let database = NodeDatabase::open(&path).unwrap();
        assert_eq!(database.recover_interrupted_benchmark_runs().unwrap(), 1);
        let run = database.get_benchmark_run(run_id).unwrap().unwrap();
        assert_eq!(run.status, BenchmarkRunStatus::Interrupted);
        assert!(run.completed_at.is_some());
    }

    #[test]
    fn rejects_samples_for_finalized_runs() {
        let directory = tempdir().unwrap();
        let database = NodeDatabase::open(directory.path().join("proxyctl.redb")).unwrap();
        database.add_node(&sample_node()).unwrap();
        let run_id = database.start_benchmark_run(sample_run()).unwrap();
        database
            .finish_benchmark_run(run_id, BenchmarkRunStatus::Completed, 2, None)
            .unwrap();
        assert!(
            database
                .record_benchmark_sample(sample_value(run_id))
                .is_err()
        );
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

    fn sample_run() -> BenchmarkRun {
        BenchmarkRun {
            id: 0,
            status: BenchmarkRunStatus::Running,
            started_at: 1,
            completed_at: None,
            node_ids: vec![1],
            cores: vec!["sing-box".into()],
            settings: BenchmarkSettings {
                methodology: "proxyctl-benchmark-v1".into(),
                latency_url: "https://speed.cloudflare.com/__down".into(),
                download_url: "https://speed.cloudflare.com/__down".into(),
                upload_url: "https://speed.cloudflare.com/__up".into(),
                download_bytes: 1_048_576,
                upload_bytes: 1_048_576,
                request_timeout_ms: 15_000,
                startup_timeout_ms: 10_000,
            },
            core_versions: BTreeMap::new(),
            summary: None,
        }
    }

    fn sample_value(run_id: u64) -> BenchmarkSample {
        BenchmarkSample {
            id: 0,
            run_id,
            node_id: 1,
            core: "sing-box".into(),
            core_version: Some("1.14.4".into()),
            metric: BenchmarkMetric::Latency,
            sample_index: 1,
            status: BenchmarkSampleStatus::Success,
            value: Some(25.0),
            unit: "ms".into(),
            failure_category: None,
            failure_reason: None,
            timestamp: 1,
            duration_ms: Some(25),
        }
    }

    fn sample_node() -> ProxyNode {
        parse_proxy_url("vless://uuid@example.com:443?security=tls").unwrap()
    }
}
