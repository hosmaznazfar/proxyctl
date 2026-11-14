//! Prune nodes that have no successful real-ping path through any managed core.

use std::path::Path;

use crate::{
    cores::{CoreId, adapters, adapters::CompatibilityStatus},
    database::{NodeDatabase, NodeRecord},
    domain::{
        BenchmarkMetric, BenchmarkRun, BenchmarkRunStatus, BenchmarkSample, BenchmarkSampleStatus,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PruneScope {
    AllCompatible,
    Core(CoreId),
}

#[derive(Clone, Copy, Debug)]
pub struct PruneOptions {
    pub scope: PruneScope,
    pub apply: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PruneDecision {
    Candidate,
    Reachable,
    InsufficientEvidence,
    NoCompatibleCore,
}

#[derive(Clone, Debug)]
pub struct NodePruneResult {
    pub node: NodeRecord,
    pub decision: PruneDecision,
    pub detail: String,
    pub deleted: bool,
}

#[derive(Clone, Debug)]
pub struct PruneReport {
    pub results: Vec<NodePruneResult>,
    pub applied: bool,
}

/// Preview or apply soft-deletion using only persisted benchmark evidence.
///
/// All-core mode evaluates sing-box, Xray, and Mihomo, including adapter-level Unsupported
/// and Invalid outcomes. A node is eligible only when every core is proven unusable and no
/// core has a successful real-ping sample. Missing runs and cancelled/incomplete evidence
/// remain inconclusive. No core is started and no network request is made.
pub fn prune_nodes(path: &Path, options: PruneOptions) -> anyhow::Result<PruneReport> {
    let (nodes, runs, samples, cores) = {
        let database = NodeDatabase::open(path)?;
        let nodes = database.list_nodes(false)?;
        let cores = match options.scope {
            PruneScope::AllCompatible => CoreId::ALL.to_vec(),
            PruneScope::Core(core) => vec![core],
        };
        (
            nodes,
            database.list_benchmark_runs()?,
            database.list_all_benchmark_samples()?,
            cores,
        )
    };

    let mut results = nodes
        .into_iter()
        .map(|node| {
            let evaluation = evaluate_node(&node, &cores, &runs, &samples);
            NodePruneResult {
                node,
                decision: evaluation.0,
                detail: evaluation.1,
                deleted: false,
            }
        })
        .collect::<Vec<_>>();

    if options.apply {
        let database = NodeDatabase::open(path)?;
        for result in &mut results {
            if result.decision == PruneDecision::Candidate {
                result.deleted = database.soft_delete(result.node.id)?;
            }
        }
    }

    Ok(PruneReport {
        results,
        applied: options.apply,
    })
}

fn evaluate_node(
    node: &NodeRecord,
    cores: &[CoreId],
    runs: &[BenchmarkRun],
    samples: &[BenchmarkSample],
) -> (PruneDecision, String) {
    let mut unavailable = 0usize;
    let mut reachable = false;
    let mut incomplete = Vec::new();
    let mut reasons = Vec::new();

    for core in cores {
        let compatibility = adapters::adapter(*core).compatibility(&node.node);
        match compatibility.status {
            CompatibilityStatus::Unsupported => {
                unavailable += 1;
                reasons.push(format!("{core}: unsupported by this core"));
                continue;
            }
            CompatibilityStatus::Invalid => {
                unavailable += 1;
                reasons.push(format!("{core}: node configuration is invalid"));
                continue;
            }
            CompatibilityStatus::Supported => {}
        }

        match evaluate_core(node.id, *core, runs, samples) {
            CoreConnectivity::Reachable => reachable = true,
            CoreConnectivity::Unreachable => {
                unavailable += 1;
                reasons.push(format!("{core}: no successful real-ping sample"));
            }
            CoreConnectivity::Unsupported => {
                unavailable += 1;
                reasons.push(format!("{core}: stored preflight marked unsupported"));
            }
            CoreConnectivity::Incomplete(reason) => {
                incomplete.push(format!("{core}: {reason}"));
            }
        }
    }

    if reachable {
        return (
            PruneDecision::Reachable,
            "at least one compatible core has a successful real-ping sample".into(),
        );
    }
    if !incomplete.is_empty() {
        return (
            PruneDecision::InsufficientEvidence,
            format!(
                "{unavailable}/{} core(s) proven unusable; {}",
                cores.len(),
                incomplete.join("; ")
            ),
        );
    }
    if unavailable == cores.len() {
        return (
            PruneDecision::Candidate,
            format!(
                "no successful real-ping path through any of the {} managed cores ({})",
                cores.len(),
                reasons.join("; ")
            ),
        );
    }

    (
        PruneDecision::InsufficientEvidence,
        format!(
            "{unavailable}/{} core(s) proven unusable; at least one core has no complete failure evidence",
            cores.len()
        ),
    )
}

enum CoreConnectivity {
    Reachable,
    Unreachable,
    Unsupported,
    Incomplete(String),
}

fn evaluate_core(
    node_id: u64,
    core: CoreId,
    runs: &[BenchmarkRun],
    samples: &[BenchmarkSample],
) -> CoreConnectivity {
    let target = core.as_str();
    let Some(run) = runs
        .iter()
        .filter(|run| {
            run.status == BenchmarkRunStatus::Completed
                && run.node_ids.contains(&node_id)
                && run.cores.iter().any(|candidate| candidate == target)
        })
        .max_by_key(|run| (run.completed_at.unwrap_or(run.started_at), run.id))
    else {
        return CoreConnectivity::Incomplete("no completed benchmark run".into());
    };

    let latency = samples
        .iter()
        .filter(|sample| {
            sample.run_id == run.id
                && sample.node_id == node_id
                && sample.core == target
                && sample.metric == BenchmarkMetric::Latency
        })
        .collect::<Vec<_>>();

    match latency
        .iter()
        .find(|sample| sample.sample_index == 0)
        .map(|sample| sample.status)
    {
        Some(BenchmarkSampleStatus::Unsupported) => return CoreConnectivity::Unsupported,
        Some(BenchmarkSampleStatus::Invalid)
        | Some(BenchmarkSampleStatus::Unavailable)
        | Some(BenchmarkSampleStatus::Timeout)
        | Some(BenchmarkSampleStatus::Unreachable) => return CoreConnectivity::Unreachable,
        Some(BenchmarkSampleStatus::Skipped) => {
            return CoreConnectivity::Incomplete("latency sample was skipped".into());
        }
        Some(BenchmarkSampleStatus::Cancelled) => {
            return CoreConnectivity::Incomplete("preflight was cancelled".into());
        }
        Some(BenchmarkSampleStatus::Success) => {
            return CoreConnectivity::Incomplete("invalid successful preflight record".into());
        }
        None => {}
    }

    let attempts = latency
        .iter()
        .filter(|sample| (1..=3).contains(&sample.sample_index))
        .collect::<Vec<_>>();
    if attempts.len() != 3
        || [1, 2, 3].iter().any(|index| {
            attempts
                .iter()
                .filter(|sample| sample.sample_index == *index)
                .count()
                != 1
        })
    {
        return CoreConnectivity::Incomplete(
            "three distinct real-ping samples are required".into(),
        );
    }

    if attempts
        .iter()
        .any(|sample| sample.status == BenchmarkSampleStatus::Success)
    {
        return CoreConnectivity::Reachable;
    }
    if attempts
        .iter()
        .all(|sample| sample.status != BenchmarkSampleStatus::Cancelled)
    {
        return CoreConnectivity::Unreachable;
    }

    CoreConnectivity::Incomplete("one or more real-ping samples were cancelled".into())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{domain::BenchmarkSettings, parser::parse_proxy_url};

    fn node() -> NodeRecord {
        NodeRecord {
            id: 1,
            node: parse_proxy_url("hysteria2://password@example.test:443").unwrap(),
            created_at: 1,
            active_order: 0,
            deleted_at: None,
        }
    }

    fn run(id: u64, status: BenchmarkRunStatus, completed_at: u64) -> BenchmarkRun {
        BenchmarkRun {
            id,
            status,
            started_at: id * 10,
            completed_at: Some(completed_at),
            node_ids: vec![1],
            cores: vec!["sing-box".into()],
            settings: BenchmarkSettings {
                methodology: "test".into(),
                latency_url: "https://example.test/ping".into(),
                download_url: "https://example.test/file".into(),
                upload_url: "https://example.test/upload".into(),
                download_bytes: 1024,
                upload_bytes: 1024,
                request_timeout_ms: 1000,
                latency_timeout_ms: 5_000,
                probe_concurrency: 3,
                startup_timeout_ms: 1000,
            },
            core_versions: BTreeMap::new(),
            summary: None,
        }
    }

    fn sample(run_id: u64, index: u8, status: BenchmarkSampleStatus) -> BenchmarkSample {
        BenchmarkSample {
            id: run_id * 10 + u64::from(index),
            run_id,
            node_id: 1,
            core: "sing-box".into(),
            core_version: Some("1.0.0".into()),
            metric: BenchmarkMetric::Latency,
            sample_index: index,
            status,
            value: (status == BenchmarkSampleStatus::Success).then_some(25.0),
            unit: "ms".into(),
            failure_category: (status != BenchmarkSampleStatus::Success).then(|| "test".into()),
            failure_reason: (status != BenchmarkSampleStatus::Success).then(|| "test".into()),
            timestamp: run_id * 10,
            duration_ms: Some(10),
        }
    }

    fn evidence(run_id: u64, statuses: [BenchmarkSampleStatus; 3]) -> Vec<BenchmarkSample> {
        statuses
            .into_iter()
            .enumerate()
            .map(|(index, status)| sample(run_id, index as u8 + 1, status))
            .collect()
    }

    #[test]
    fn three_unreachable_samples_confirm_a_core_unavailable() {
        let runs = [run(1, BenchmarkRunStatus::Completed, 20)];
        let samples = evidence(1, [BenchmarkSampleStatus::Unreachable; 3]);
        assert!(matches!(
            evaluate_core(1, CoreId::SingBox, &runs, &samples),
            CoreConnectivity::Unreachable
        ));
    }

    #[test]
    fn non_cancelled_timeout_unavailable_and_invalid_samples_confirm_unusable_core() {
        for status in [
            BenchmarkSampleStatus::Timeout,
            BenchmarkSampleStatus::Unavailable,
            BenchmarkSampleStatus::Invalid,
        ] {
            let runs = [run(1, BenchmarkRunStatus::Completed, 20)];
            let samples = evidence(1, [status; 3]);
            assert!(
                matches!(
                    evaluate_core(1, CoreId::SingBox, &runs, &samples),
                    CoreConnectivity::Unreachable
                ),
                "{status:?} should count as no working real-ping path"
            );
        }
    }

    #[test]
    fn one_successful_sample_keeps_the_node() {
        let runs = [run(1, BenchmarkRunStatus::Completed, 20)];
        let samples = evidence(
            1,
            [
                BenchmarkSampleStatus::Unreachable,
                BenchmarkSampleStatus::Success,
                BenchmarkSampleStatus::Timeout,
            ],
        );
        assert!(matches!(
            evaluate_core(1, CoreId::SingBox, &runs, &samples),
            CoreConnectivity::Reachable
        ));
    }

    #[test]
    fn incomplete_or_ambiguous_failures_never_confirm_unavailability() {
        let runs = [run(1, BenchmarkRunStatus::Completed, 20)];
        let partial = evidence(
            1,
            [
                BenchmarkSampleStatus::Unreachable,
                BenchmarkSampleStatus::Unreachable,
                BenchmarkSampleStatus::Cancelled,
            ],
        );
        assert!(matches!(
            evaluate_core(1, CoreId::SingBox, &runs, &partial),
            CoreConnectivity::Incomplete(_)
        ));

        let missing = evidence(
            1,
            [
                BenchmarkSampleStatus::Unreachable,
                BenchmarkSampleStatus::Unreachable,
                BenchmarkSampleStatus::Unreachable,
            ],
        );
        let mut missing = missing;
        let _ = missing.pop();
        assert!(matches!(
            evaluate_core(1, CoreId::SingBox, &runs, &missing),
            CoreConnectivity::Incomplete(_)
        ));
    }

    #[test]
    fn latest_completed_run_supersedes_older_success_or_failure() {
        let runs = [
            run(1, BenchmarkRunStatus::Completed, 20),
            run(2, BenchmarkRunStatus::Completed, 30),
            run(3, BenchmarkRunStatus::Cancelled, 40),
        ];
        let mut samples = evidence(1, [BenchmarkSampleStatus::Success; 3]);
        samples.extend(evidence(2, [BenchmarkSampleStatus::Unreachable; 3]));
        samples.extend(evidence(3, [BenchmarkSampleStatus::Success; 3]));
        assert!(matches!(
            evaluate_core(1, CoreId::SingBox, &runs, &samples),
            CoreConnectivity::Unreachable
        ));
    }

    #[test]
    fn adapter_unsupported_counts_as_a_core_that_cannot_use_the_node() {
        let node = node();
        let result = evaluate_node(&node, &[CoreId::Xray], &[], &[]);
        assert_eq!(result.0, PruneDecision::Candidate);
        assert!(result.1.contains("unsupported"));
    }

    #[test]
    fn invalid_current_compatibility_counts_as_unusable() {
        let mut node = node();
        node.node = parse_proxy_url("vless://uuid@example.test:443?type=ws&type=grpc").unwrap();
        let result = evaluate_node(&node, &[CoreId::SingBox], &[], &[]);
        assert_eq!(result.0, PruneDecision::Candidate);
        assert!(result.1.contains("invalid"));
    }

    #[test]
    fn invalid_cores_plus_one_unreachable_core_make_node_a_candidate() {
        let mut node = node();
        node.node = parse_proxy_url("vless://uuid@example.test:443?type=ws&type=grpc").unwrap();
        let runs = [run(1, BenchmarkRunStatus::Completed, 20)];
        let samples = evidence(1, [BenchmarkSampleStatus::Timeout; 3]);
        let result = evaluate_node(
            &node,
            &[CoreId::SingBox, CoreId::Xray, CoreId::Mihomo],
            &runs,
            &samples,
        );
        assert_eq!(result.0, PruneDecision::Candidate);
    }

    #[test]
    fn any_successful_core_keeps_node_even_when_other_cores_are_unusable() {
        let node = node();
        let runs = [run(1, BenchmarkRunStatus::Completed, 20)];
        let samples = evidence(1, [BenchmarkSampleStatus::Success; 3]);
        let result = evaluate_node(&node, &[CoreId::SingBox, CoreId::Xray], &runs, &samples);
        assert_eq!(result.0, PruneDecision::Reachable);
    }

    #[test]
    fn cancelled_runs_do_not_replace_latest_completed_evidence() {
        let runs = [
            run(1, BenchmarkRunStatus::Completed, 20),
            run(2, BenchmarkRunStatus::Cancelled, 30),
        ];
        let samples = [
            evidence(1, [BenchmarkSampleStatus::Unreachable; 3]),
            evidence(2, [BenchmarkSampleStatus::Success; 3]),
        ]
        .concat();
        assert!(matches!(
            evaluate_core(1, CoreId::SingBox, &runs, &samples),
            CoreConnectivity::Unreachable
        ));
    }
}
