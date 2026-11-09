//! Benchmark-backed node sorting and comparison.

use std::{cmp::Ordering, path::Path};

use anyhow::Context;

use crate::{
    cores::CoreId,
    database::{NodeDatabase, NodeRecord},
    domain::{
        BenchmarkMetric, BenchmarkRun, BenchmarkRunStatus, BenchmarkSample,
        median_successful_samples,
    },
};

const DIRECT_TARGET: &str = "direct";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortMetric {
    Ping,
    TcpPing,
    Download,
    Upload,
}

impl SortMetric {
    pub const fn benchmark_metric(self) -> BenchmarkMetric {
        match self {
            Self::Ping => BenchmarkMetric::Latency,
            Self::TcpPing => BenchmarkMetric::TcpPing,
            Self::Download => BenchmarkMetric::Download,
            Self::Upload => BenchmarkMetric::Upload,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Ping => "real ping",
            Self::TcpPing => "TCP ping",
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }

    const fn ascending(self) -> bool {
        matches!(self, Self::Ping | Self::TcpPing)
    }
}

impl std::str::FromStr for SortMetric {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> anyhow::Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ping" => Ok(Self::Ping),
            "tcp-ping" => Ok(Self::TcpPing),
            "download" => Ok(Self::Download),
            "upload" => Ok(Self::Upload),
            _ => anyhow::bail!("unknown sort metric '{value}'; use ping, tcp-ping, download, or upload"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct RankedNode {
    pub node: NodeRecord,
    pub value: Option<f64>,
    pub unit: &'static str,
    pub cores: String,
}

/// Sort active nodes using each node/core pair's latest completed run.
///
/// Cross-core comparisons take the median of the per-core medians, so every
/// compatible core with a successful result contributes equal weight. A newer
/// completed run supersedes an older one even when its measurements failed.
pub fn sort_nodes(
    database_path: &Path,
    nodes: Vec<NodeRecord>,
    metric: SortMetric,
    selected_core: Option<CoreId>,
) -> anyhow::Result<Vec<RankedNode>> {
    let (runs, samples) = {
        let database = NodeDatabase::open(database_path)?;
        (database.list_benchmark_runs()?, database.list_all_benchmark_samples()?)
    };
    let completed = runs
        .into_iter()
        .filter(|run| run.status == BenchmarkRunStatus::Completed)
        .collect::<Vec<_>>();
    let mut ranked = nodes
        .into_iter()
        .map(|node| {
            let (value, cores) = aggregate_node(
                node.id,
                &completed,
                &samples,
                metric,
                selected_core.as_ref().map(CoreId::as_str),
            );
            RankedNode {
                node,
                value,
                unit: metric.benchmark_metric().unit(),
                cores,
            }
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| {
        match (left.value, right.value) {
            (Some(a), Some(b)) => {
                let order = a.total_cmp(&b);
                let order = if metric.ascending() { order } else { order.reverse() };
                order.then_with(|| left.node.id.cmp(&right.node.id))
            }
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => left.node.id.cmp(&right.node.id),
        }
    });
    Ok(ranked)
}

fn aggregate_node(
    node_id: u64,
    runs: &[BenchmarkRun],
    samples: &[BenchmarkSample],
    metric: SortMetric,
    selected_core: Option<&str>,
) -> (Option<f64>, String) {
    let benchmark_metric = metric.benchmark_metric();
    if metric == SortMetric::TcpPing {
        let latest = latest_run(runs, node_id, DIRECT_TARGET);
        let Some(run) = latest else { return (None, "-".into()) };
        let values = samples_for(samples, run.id, node_id, DIRECT_TARGET, benchmark_metric);
        return (median_successful_samples(&values), DIRECT_TARGET.into());
    }

    let targets = if let Some(core) = selected_core {
        vec![core.to_owned()]
    } else {
        let mut cores = runs
            .iter()
            .filter(|run| run.node_ids.contains(&node_id))
            .flat_map(|run| run.cores.iter())
            .filter(|core| core.as_str() != DIRECT_TARGET)
            .cloned()
            .collect::<Vec<_>>();
        cores.sort();
        cores.dedup();
        cores
    };

    let mut per_core = Vec::new();
    for core in targets {
        let Some(run) = latest_run(runs, node_id, &core) else { continue };
        let values = samples_for(samples, run.id, node_id, &core, benchmark_metric);
        if let Some(value) = median_successful_samples(&values) {
            per_core.push((core, value));
        }
    }
    if per_core.is_empty() {
        return (None, "-".into());
    }

    let mut values = per_core.iter().map(|(_, value)| *value).collect::<Vec<_>>();
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    let aggregate = if values.len() % 2 == 1 {
        values[middle]
    } else {
        (values[middle - 1] + values[middle]) / 2.0
    };
    let cores = per_core.into_iter().map(|(core, _)| core).collect::<Vec<_>>().join(", ");
    (Some(aggregate), cores)
}

fn latest_run<'a>(runs: &'a [BenchmarkRun], node_id: u64, target: &str) -> Option<&'a BenchmarkRun> {
    runs.iter()
        .filter(|run| run.node_ids.contains(&node_id) && run.cores.iter().any(|core| core == target))
        .max_by_key(|run| (run.completed_at.unwrap_or(run.started_at), run.id))
}

fn samples_for(
    samples: &[BenchmarkSample],
    run_id: u64,
    node_id: u64,
    target: &str,
    metric: BenchmarkMetric,
) -> Vec<BenchmarkSample> {
    samples
        .iter()
        .filter(|sample| {
            sample.run_id == run_id
                && sample.node_id == node_id
                && sample.core == target
                && sample.metric == metric
                && sample.sample_index > 0
        })
        .cloned()
        .collect()
}
