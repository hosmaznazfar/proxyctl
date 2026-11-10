//! Read-only benchmark history and per-core comparison reports.

use std::path::Path;

use anyhow::ensure;

use crate::{
    cores::CoreId,
    database::{NodeDatabase, NodeRecord},
    domain::{
        BenchmarkMetric, BenchmarkRun, BenchmarkRunStatus, BenchmarkSample, BenchmarkSampleStatus,
        median_successful_samples,
    },
};

const DIRECT_TARGET: &str = "direct";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportMode {
    Latest,
    History,
    Compare,
}

#[derive(Clone, Copy, Debug)]
pub struct ReportOptions {
    pub mode: ReportMode,
    pub node_id: Option<u64>,
    pub core: Option<CoreId>,
}

#[derive(Clone, Debug)]
pub struct BenchmarkReport {
    pub mode: ReportMode,
    pub nodes: Vec<NodeReport>,
    pub comparisons: Vec<CoreComparison>,
}

#[derive(Clone, Debug)]
pub struct NodeReport {
    pub node: NodeRecord,
    /// Newest first. Latest mode contains at most one run.
    pub runs: Vec<RunReport>,
}

#[derive(Clone, Debug)]
pub struct RunReport {
    pub run: BenchmarkRun,
    pub targets: Vec<TargetReport>,
}

#[derive(Clone, Debug)]
pub struct TargetReport {
    pub target: String,
    pub core_version: Option<String>,
    pub metrics: Vec<MetricSummary>,
}

#[derive(Clone, Debug)]
pub struct MetricSummary {
    pub metric: BenchmarkMetric,
    pub successful: usize,
    pub attempted: usize,
    pub median: Option<f64>,
    pub failures: Vec<FailureCount>,
    pub preflight: Option<BenchmarkSampleStatus>,
}

#[derive(Clone, Debug)]
pub struct FailureCount {
    pub status: BenchmarkSampleStatus,
    pub count: usize,
}

#[derive(Clone, Debug)]
pub struct CoreComparison {
    pub node: NodeRecord,
    /// A managed core name, or "direct" for TCP ping.
    pub target: String,
    pub run_id: u64,
    pub core_version: Option<String>,
    pub metrics: Vec<MetricSummary>,
}

/// Build a read-only report from persisted runs and samples.
pub fn build_report(path: &Path, options: ReportOptions) -> anyhow::Result<BenchmarkReport> {
    ensure!(
        options.mode == ReportMode::Compare || options.core.is_none(),
        "--core is only valid with --compare"
    );

    let (nodes, runs, samples) = {
        let database = NodeDatabase::open(path)?;
        let nodes = if let Some(node_id) = options.node_id {
            vec![
                database
                    .get_node(node_id)?
                    .ok_or_else(|| anyhow::anyhow!("node #{node_id} was not found"))?,
            ]
        } else {
            database.list_nodes(false)?
        };
        (
            nodes,
            database.list_benchmark_runs()?,
            database.list_all_benchmark_samples()?,
        )
    };

    if options.mode == ReportMode::Compare {
        let comparisons = build_comparisons(&nodes, &runs, &samples, options.core);
        return Ok(BenchmarkReport {
            mode: options.mode,
            nodes: Vec::new(),
            comparisons,
        });
    }

    let node_reports = nodes
        .into_iter()
        .map(|node| {
            let mut node_runs = runs
                .iter()
                .filter(|run| run.node_ids.contains(&node.id))
                .collect::<Vec<_>>();
            node_runs.sort_by_key(|run| (run.completed_at.unwrap_or(run.started_at), run.id));
            node_runs.reverse();
            if options.mode == ReportMode::Latest {
                node_runs.truncate(1);
            }
            let runs = node_runs
                .into_iter()
                .map(|run| build_run_report(run, node.id, &samples))
                .collect();
            NodeReport { node, runs }
        })
        .collect();

    Ok(BenchmarkReport {
        mode: options.mode,
        nodes: node_reports,
        comparisons: Vec::new(),
    })
}

fn build_run_report(run: &BenchmarkRun, node_id: u64, samples: &[BenchmarkSample]) -> RunReport {
    let targets = run
        .cores
        .iter()
        .map(|target| {
            let metrics = metrics_for_target(target);
            let target_samples = samples
                .iter()
                .filter(|sample| sample.run_id == run.id && sample.node_id == node_id)
                .filter(|sample| sample.core == *target)
                .collect::<Vec<_>>();
            let core_version = run.core_versions.get(target).cloned().or_else(|| {
                target_samples
                    .iter()
                    .find_map(|sample| sample.core_version.clone())
            });
            TargetReport {
                target: target.clone(),
                core_version,
                metrics: metrics
                    .into_iter()
                    .map(|metric| summarize_metric(metric, &target_samples))
                    .collect(),
            }
        })
        .collect();

    RunReport {
        run: run.clone(),
        targets,
    }
}

fn build_comparisons(
    nodes: &[NodeRecord],
    runs: &[BenchmarkRun],
    samples: &[BenchmarkSample],
    selected_core: Option<CoreId>,
) -> Vec<CoreComparison> {
    let mut comparisons = Vec::new();

    for node in nodes {
        let node_runs = runs
            .iter()
            .filter(|run| {
                run.status == BenchmarkRunStatus::Completed && run.node_ids.contains(&node.id)
            })
            .collect::<Vec<_>>();

        let mut targets = node_runs
            .iter()
            .flat_map(|run| run.cores.iter())
            .filter(|target| target.as_str() != DIRECT_TARGET)
            .cloned()
            .collect::<Vec<_>>();
        targets.sort();
        targets.dedup();
        if let Some(core) = selected_core {
            targets.retain(|target| target.as_str() == core.as_str());
        }

        for target in targets {
            let Some(run) = latest_completed_run(&node_runs, &target) else {
                continue;
            };
            comparisons.push(comparison_for(node, run, &target, samples));
        }

        if selected_core.is_none()
            && let Some(run) = latest_completed_run(&node_runs, DIRECT_TARGET)
        {
            comparisons.push(comparison_for(node, run, DIRECT_TARGET, samples));
        }
    }

    comparisons.sort_by(|left, right| {
        left.node
            .id
            .cmp(&right.node.id)
            .then_with(|| left.target.cmp(&right.target))
    });
    comparisons
}

fn latest_completed_run<'a>(runs: &[&'a BenchmarkRun], target: &str) -> Option<&'a BenchmarkRun> {
    runs.iter()
        .copied()
        .filter(|run| run.cores.iter().any(|core| core == target))
        .max_by_key(|run| (run.completed_at.unwrap_or(run.started_at), run.id))
}

fn comparison_for(
    node: &NodeRecord,
    run: &BenchmarkRun,
    target: &str,
    samples: &[BenchmarkSample],
) -> CoreComparison {
    let target_samples = samples
        .iter()
        .filter(|sample| sample.run_id == run.id)
        .filter(|sample| sample.node_id == node.id && sample.core == target)
        .collect::<Vec<_>>();
    let core_version = run.core_versions.get(target).cloned().or_else(|| {
        target_samples
            .iter()
            .find_map(|sample| sample.core_version.clone())
    });

    CoreComparison {
        node: node.clone(),
        target: target.to_owned(),
        run_id: run.id,
        core_version,
        metrics: metrics_for_target(target)
            .into_iter()
            .map(|metric| summarize_metric(metric, &target_samples))
            .collect(),
    }
}

fn metrics_for_target(target: &str) -> Vec<BenchmarkMetric> {
    if target == DIRECT_TARGET {
        vec![BenchmarkMetric::TcpPing]
    } else {
        vec![
            BenchmarkMetric::Latency,
            BenchmarkMetric::Download,
            BenchmarkMetric::Upload,
        ]
    }
}

fn summarize_metric(metric: BenchmarkMetric, samples: &[&BenchmarkSample]) -> MetricSummary {
    let metric_samples = samples
        .iter()
        .copied()
        .filter(|sample| sample.metric == metric)
        .collect::<Vec<_>>();
    let preflight = metric_samples
        .iter()
        .find(|sample| sample.sample_index == 0)
        .map(|sample| sample.status);
    let attempted_samples = metric_samples
        .iter()
        .copied()
        .filter(|sample| sample.sample_index > 0)
        .collect::<Vec<_>>();
    let successful = attempted_samples
        .iter()
        .filter(|sample| sample.status == BenchmarkSampleStatus::Success)
        .count();
    let mut failures = Vec::<FailureCount>::new();
    for sample in &attempted_samples {
        if sample.status == BenchmarkSampleStatus::Success {
            continue;
        }
        if let Some(existing) = failures
            .iter_mut()
            .find(|item| item.status == sample.status)
        {
            existing.count += 1;
        } else {
            failures.push(FailureCount {
                status: sample.status,
                count: 1,
            });
        }
    }
    let values = metric_samples
        .iter()
        .filter(|sample| sample.sample_index > 0)
        .map(|sample| (**sample).clone())
        .collect::<Vec<_>>();

    MetricSummary {
        metric,
        successful,
        attempted: attempted_samples.len(),
        median: median_successful_samples(&values),
        failures,
        preflight,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tempfile::tempdir;

    use super::*;
    use crate::{
        domain::{BenchmarkSettings, ProxyNode},
        parser::parse_proxy_url,
    };

    fn run(id: u64, status: BenchmarkRunStatus, completed_at: Option<u64>) -> BenchmarkRun {
        BenchmarkRun {
            id,
            status,
            started_at: id * 10,
            completed_at,
            node_ids: vec![1],
            cores: vec!["direct".into(), "sing-box".into()],
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
            core_versions: BTreeMap::new(),
            summary: None,
        }
    }

    fn sample(
        run_id: u64,
        metric: BenchmarkMetric,
        index: u8,
        status: BenchmarkSampleStatus,
        value: Option<f64>,
    ) -> BenchmarkSample {
        BenchmarkSample {
            id: run_id * 10 + u64::from(index),
            run_id,
            node_id: 1,
            core: "sing-box".into(),
            core_version: Some("1.0.0".into()),
            metric,
            sample_index: index,
            status,
            value,
            unit: metric.unit().into(),
            failure_category: (status != BenchmarkSampleStatus::Success)
                .then(|| "test_failure".into()),
            failure_reason: (status != BenchmarkSampleStatus::Success)
                .then(|| "test failure".into()),
            timestamp: run_id * 10,
            duration_ms: Some(10),
        }
    }

    #[test]
    fn report_summarizes_partial_samples_without_treating_them_as_complete() {
        let samples = [
            sample(
                1,
                BenchmarkMetric::Download,
                1,
                BenchmarkSampleStatus::Success,
                Some(8_000_000.0),
            ),
            sample(
                1,
                BenchmarkMetric::Download,
                2,
                BenchmarkSampleStatus::Timeout,
                None,
            ),
        ];
        let refs = samples.iter().collect::<Vec<_>>();
        let summary = summarize_metric(BenchmarkMetric::Download, &refs);
        assert_eq!(summary.successful, 1);
        assert_eq!(summary.attempted, 2);
        assert_eq!(summary.median, Some(8_000_000.0));
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(summary.failures[0].status, BenchmarkSampleStatus::Timeout);
    }

    #[test]
    fn compare_uses_latest_completed_run_and_does_not_fall_back_after_failure() {
        let old = run(1, BenchmarkRunStatus::Completed, Some(100));
        let latest = run(2, BenchmarkRunStatus::Completed, Some(200));
        let cancelled = run(3, BenchmarkRunStatus::Cancelled, Some(300));
        let samples = [
            sample(
                1,
                BenchmarkMetric::Latency,
                1,
                BenchmarkSampleStatus::Success,
                Some(100.0),
            ),
            sample(
                2,
                BenchmarkMetric::Latency,
                1,
                BenchmarkSampleStatus::Timeout,
                None,
            ),
            sample(
                3,
                BenchmarkMetric::Latency,
                1,
                BenchmarkSampleStatus::Success,
                Some(1.0),
            ),
        ];
        let node = NodeRecord {
            id: 1,
            node: parse_proxy_url("vless://uuid@example.test:443").unwrap(),
            created_at: 1,
            deleted_at: None,
        };
        let rows = build_comparisons(&[node], &[old, latest, cancelled], &samples, None);
        let sing_box = rows.iter().find(|row| row.target == "sing-box").unwrap();
        let ping = sing_box
            .metrics
            .iter()
            .find(|metric| metric.metric == BenchmarkMetric::Latency)
            .unwrap();
        assert_eq!(ping.median, None);
        assert_eq!(ping.successful, 0);
        assert_eq!(sing_box.run_id, 2);
    }

    #[test]
    fn history_includes_interrupted_and_cancelled_runs() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("proxyctl.redb");
        let database = NodeDatabase::open(&path).unwrap();
        let node: ProxyNode = parse_proxy_url("vless://uuid@example.test:443").unwrap();
        database.add_node(&node).unwrap();

        let mut cancelled = run(0, BenchmarkRunStatus::Running, None);
        cancelled.id = 0;
        let cancelled_id = database.start_benchmark_run(cancelled).unwrap();
        database
            .finish_benchmark_run(cancelled_id, BenchmarkRunStatus::Cancelled, 20, None)
            .unwrap();

        let mut interrupted = run(0, BenchmarkRunStatus::Running, None);
        interrupted.id = 0;
        let interrupted_id = database.start_benchmark_run(interrupted).unwrap();
        database
            .finish_benchmark_run(interrupted_id, BenchmarkRunStatus::Interrupted, 30, None)
            .unwrap();
        drop(database);

        let report = build_report(
            &path,
            ReportOptions {
                mode: ReportMode::History,
                node_id: Some(1),
                core: None,
            },
        )
        .unwrap();
        let statuses = report.nodes[0]
            .runs
            .iter()
            .map(|run| run.run.status)
            .collect::<Vec<_>>();
        assert_eq!(
            statuses,
            [
                BenchmarkRunStatus::Interrupted,
                BenchmarkRunStatus::Cancelled
            ]
        );
    }
}
