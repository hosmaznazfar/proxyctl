//! Benchmark-backed node sorting and comparison.

use std::{cmp::Ordering, path::Path};

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
            _ => anyhow::bail!(
                "unknown sort metric '{value}'; use ping, tcp-ping, download, or upload"
            ),
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
        (
            database.list_benchmark_runs()?,
            database.list_all_benchmark_samples()?,
        )
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
                selected_core.as_ref().map(|core| core.as_str()),
            );
            RankedNode {
                node,
                value,
                unit: metric.benchmark_metric().unit(),
                cores,
            }
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| match (left.value, right.value) {
        (Some(a), Some(b)) => {
            let order = a.total_cmp(&b);
            let order = if metric.ascending() {
                order
            } else {
                order.reverse()
            };
            order.then_with(|| left.node.id.cmp(&right.node.id))
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => left.node.id.cmp(&right.node.id),
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
        let Some(run) = latest else {
            return (None, "-".into());
        };
        let values = samples_for(samples, run.id, node_id, DIRECT_TARGET, benchmark_metric);
        let median = median_successful_samples(&values);
        return match median {
            Some(value) => (Some(value), DIRECT_TARGET.into()),
            None => (None, "-".into()),
        };
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
        let Some(run) = latest_run(runs, node_id, &core) else {
            continue;
        };
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
    let cores = per_core
        .into_iter()
        .map(|(core, _)| core)
        .collect::<Vec<_>>()
        .join(", ");
    (Some(aggregate), cores)
}

fn latest_run<'a>(
    runs: &'a [BenchmarkRun],
    node_id: u64,
    target: &str,
) -> Option<&'a BenchmarkRun> {
    runs.iter()
        .filter(|run| {
            run.node_ids.contains(&node_id) && run.cores.iter().any(|core| core == target)
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{BenchmarkSampleStatus, BenchmarkSettings};

    fn run(id: u64, status: BenchmarkRunStatus, completed_at: u64, cores: &[&str]) -> BenchmarkRun {
        BenchmarkRun {
            id,
            status,
            started_at: id * 10,
            completed_at: Some(completed_at),
            node_ids: vec![1],
            cores: cores.iter().map(|core| (*core).to_owned()).collect(),
            settings: BenchmarkSettings {
                methodology: "test".into(),
                latency_url: "https://example.test/ping".into(),
                download_url: "https://example.test/file".into(),
                upload_url: "https://example.test/upload".into(),
                download_bytes: 1024,
                upload_bytes: 1024,
                request_timeout_ms: 1000,
                startup_timeout_ms: 1000,
            },
            core_versions: Default::default(),
            summary: None,
        }
    }

    fn sample(
        run_id: u64,
        core: &str,
        metric: BenchmarkMetric,
        index: u8,
        value: f64,
    ) -> BenchmarkSample {
        BenchmarkSample {
            id: run_id * 10 + u64::from(index),
            run_id,
            node_id: 1,
            core: core.into(),
            core_version: None,
            metric,
            sample_index: index,
            status: BenchmarkSampleStatus::Success,
            value: Some(value),
            unit: metric.unit().into(),
            failure_category: None,
            failure_reason: None,
            timestamp: run_id * 10,
            duration_ms: Some(10),
        }
    }

    #[test]
    fn cross_core_ranking_uses_equal_weight_median_of_latest_core_medians() {
        let runs = [
            run(
                1,
                BenchmarkRunStatus::Completed,
                100,
                &["direct", "sing-box"],
            ),
            run(2, BenchmarkRunStatus::Completed, 200, &["direct", "xray"]),
            run(
                3,
                BenchmarkRunStatus::Cancelled,
                300,
                &["direct", "sing-box"],
            ),
        ];
        let samples = [
            sample(1, "sing-box", BenchmarkMetric::Latency, 1, 100.0),
            sample(1, "sing-box", BenchmarkMetric::Latency, 2, 200.0),
            sample(1, "sing-box", BenchmarkMetric::Latency, 3, 300.0),
            sample(2, "xray", BenchmarkMetric::Latency, 1, 400.0),
            sample(2, "xray", BenchmarkMetric::Latency, 2, 500.0),
            sample(2, "xray", BenchmarkMetric::Latency, 3, 600.0),
            sample(3, "sing-box", BenchmarkMetric::Latency, 1, 1.0),
        ];
        let (value, cores) = aggregate_node(1, &runs, &samples, SortMetric::Ping, None);
        assert_eq!(value, Some(350.0));
        assert_eq!(cores, "sing-box, xray");
    }

    #[test]
    fn latest_completed_failed_run_does_not_fall_back_to_stale_success() {
        let runs = [
            run(1, BenchmarkRunStatus::Completed, 100, &["direct", "mihomo"]),
            run(2, BenchmarkRunStatus::Completed, 200, &["direct", "mihomo"]),
        ];
        let samples = [sample(
            1,
            "mihomo",
            BenchmarkMetric::Download,
            1,
            8_000_000.0,
        )];
        let (value, _) = aggregate_node(1, &runs, &samples, SortMetric::Download, Some("mihomo"));
        assert_eq!(value, None);
    }

    #[test]
    fn unmeasured_direct_tcp_ping_has_no_contributing_target() {
        let runs = [run(1, BenchmarkRunStatus::Completed, 100, &["direct", "sing-box"])];
        let samples = [sample(
            1,
            "sing-box",
            BenchmarkMetric::Latency,
            1,
            250.0,
        )];
        let (value, target) =
            aggregate_node(1, &runs, &samples, SortMetric::TcpPing, None);
        assert_eq!(value, None);
        assert_eq!(target, "-");
    }

    #[test]
    fn direct_tcp_ping_uses_only_the_direct_target() {
        let runs = [run(
            1,
            BenchmarkRunStatus::Completed,
            100,
            &["direct", "sing-box"],
        )];
        let samples = [
            sample(1, "direct", BenchmarkMetric::TcpPing, 1, 25.0),
            sample(1, "direct", BenchmarkMetric::TcpPing, 2, 15.0),
            sample(1, "sing-box", BenchmarkMetric::Latency, 1, 1.0),
        ];
        let (value, target) = aggregate_node(1, &runs, &samples, SortMetric::TcpPing, None);
        assert_eq!(value, Some(20.0));
        assert_eq!(target, "direct");
    }
}
