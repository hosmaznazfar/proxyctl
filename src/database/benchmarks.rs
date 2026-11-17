//! redb persistence operations for benchmark runs, samples, and history.
//!
//! These methods share the node database handle so cross-record validation and
//! each write transaction retain their existing atomicity guarantees.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, ensure};
use redb::{ReadableDatabase, ReadableTable};

use crate::domain::{BenchmarkRun, BenchmarkRunStatus, BenchmarkSample};

use super::{
    NodeDatabase,
    nodes::{BENCHMARK_RUNS, BENCHMARK_SAMPLES, METADATA, NODES, unix_timestamp},
};

impl NodeDatabase {
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
            let next_id: u64 = metadata
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
            let next_id: u64 = metadata
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

    /// List all persisted benchmark samples in stable insertion order.
    pub fn list_all_benchmark_samples(&self) -> anyhow::Result<Vec<BenchmarkSample>> {
        let read_txn = self.inner.begin_read()?;
        let samples = read_txn.open_table(BENCHMARK_SAMPLES)?;
        let mut records = Vec::new();
        for entry in samples.iter()? {
            let (key, value) = entry?;
            let sample: BenchmarkSample = serde_json::from_slice(value.value())?;
            debug_assert_eq!(sample.id, key.value());
            records.push(sample);
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

    /// Retain the newest `limit` finalized runs independently for each node/target pair.
    /// Samples for expired pairs are removed even when a multi-node run remains for another pair.
    /// Running runs are never modified.
    pub fn prune_benchmark_history(&self, limit: usize) -> anyhow::Result<usize> {
        ensure!(
            limit > 0,
            "benchmark history retention limit must be at least one"
        );

        let write_txn = self.inner.begin_write()?;
        let run_records = {
            let runs = write_txn.open_table(BENCHMARK_RUNS)?;
            runs.iter()?
                .map(|entry| {
                    let (key, value) = entry?;
                    let run: BenchmarkRun = serde_json::from_slice(value.value())?;
                    debug_assert_eq!(run.id, key.value());
                    Ok(run)
                })
                .collect::<anyhow::Result<Vec<_>>>()?
        };
        let sample_records = {
            let samples = write_txn.open_table(BENCHMARK_SAMPLES)?;
            samples
                .iter()?
                .map(|entry| {
                    let (key, value) = entry?;
                    let sample: BenchmarkSample = serde_json::from_slice(value.value())?;
                    debug_assert_eq!(sample.id, key.value());
                    Ok(sample)
                })
                .collect::<anyhow::Result<Vec<_>>>()?
        };

        let run_by_id = run_records
            .iter()
            .map(|run| (run.id, run))
            .collect::<BTreeMap<_, _>>();
        let mut histories: BTreeMap<(u64, String), Vec<(u64, u64)>> = BTreeMap::new();
        for run in &run_records {
            if run.status == BenchmarkRunStatus::Running {
                continue;
            }
            for node_id in &run.node_ids {
                for target in &run.cores {
                    histories
                        .entry((*node_id, target.clone()))
                        .or_default()
                        .push((run.id, run.started_at));
                }
            }
        }

        let mut retained_pairs = BTreeSet::new();
        for ((node_id, target), history) in &mut histories {
            history.sort_by_key(|(run_id, started_at)| (*started_at, *run_id));
            for (run_id, _) in history.iter().rev().take(limit) {
                retained_pairs.insert((*run_id, *node_id, target.clone()));
            }
        }

        let expired_sample_ids = sample_records
            .iter()
            .filter(|sample| {
                run_by_id
                    .get(&sample.run_id)
                    .is_some_and(|run| run.status != BenchmarkRunStatus::Running)
                    && !retained_pairs.contains(&(
                        sample.run_id,
                        sample.node_id,
                        sample.core.clone(),
                    ))
            })
            .map(|sample| sample.id)
            .collect::<Vec<_>>();

        let expired_set = expired_sample_ids.iter().copied().collect::<BTreeSet<_>>();
        let remaining_run_ids = sample_records
            .iter()
            .filter(|sample| !expired_set.contains(&sample.id))
            .map(|sample| sample.run_id)
            .collect::<BTreeSet<_>>();
        let expired_run_ids = run_records
            .iter()
            .filter(|run| {
                run.status != BenchmarkRunStatus::Running && !remaining_run_ids.contains(&run.id)
            })
            .map(|run| run.id)
            .collect::<Vec<_>>();

        if expired_sample_ids.is_empty() && expired_run_ids.is_empty() {
            return Ok(0);
        }

        {
            let mut samples = write_txn.open_table(BENCHMARK_SAMPLES)?;
            for id in expired_sample_ids {
                drop(samples.remove(id)?);
            }
        }
        {
            let mut runs = write_txn.open_table(BENCHMARK_RUNS)?;
            for id in &expired_run_ids {
                drop(runs.remove(*id)?);
            }
        }
        write_txn.commit()?;
        Ok(expired_run_ids.len())
    }
}
