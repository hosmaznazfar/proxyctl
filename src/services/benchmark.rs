//! Sequential benchmark orchestration. Database handles are never held during network work.

use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use anyhow::{Context, ensure};

use crate::{
    benchmark::{
        http::{BenchmarkHttpClient, Measurement, MeasurementFailure, validate_settings},
        process::ManagedCoreProcess,
        tcp,
    },
    cores::{CoreId, adapters, core_binary_path, installer::current_version},
    database::{NodeDatabase, NodeRecord},
    domain::{
        BenchmarkMetric, BenchmarkRun, BenchmarkRunStatus, BenchmarkSample, BenchmarkSampleStatus,
        BenchmarkSettings,
    },
};

static CANCELLED: AtomicBool = AtomicBool::new(false);
const SAMPLES_PER_METRIC: u8 = 3;
const BENCHMARK_HISTORY_LIMIT: usize = 3;
const METHODOLOGY: &str = "proxyctl-benchmark-v2";
const DIRECT_TARGET: &str = "direct";
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PROBE_CONCURRENCY: usize = 3;
const LATENCY_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct BenchmarkOptions {
    pub all_cores: bool,
    pub node_id: Option<u64>,
    pub core: Option<CoreId>,
    pub settings: BenchmarkSettings,
    pub metric_selection: BenchmarkMetricSelection,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BenchmarkMetricSelection {
    #[default]
    All,
    Latency,
    Download,
    Upload,
}

impl BenchmarkMetricSelection {
    fn metrics(self) -> &'static [BenchmarkMetric] {
        match self {
            Self::All => &[
                BenchmarkMetric::Latency,
                BenchmarkMetric::Download,
                BenchmarkMetric::Upload,
            ],
            Self::Latency => &[BenchmarkMetric::Latency],
            Self::Download => &[BenchmarkMetric::Download],
            Self::Upload => &[BenchmarkMetric::Upload],
        }
    }

    fn includes_direct_tcp(self) -> bool {
        matches!(self, Self::All)
    }
}

impl Default for BenchmarkOptions {
    fn default() -> Self {
        Self {
            all_cores: true,
            node_id: None,
            core: None,
            settings: default_settings(),
            metric_selection: BenchmarkMetricSelection::All,
        }
    }
}

pub fn default_settings() -> BenchmarkSettings {
    BenchmarkSettings {
        methodology: METHODOLOGY.into(),
        latency_url: "https://www.google.com/generate_204".into(),
        download_url: "https://cachefly.cachefly.net/10mb.test".into(),
        upload_url: "https://speed.cloudflare.com/__up".into(),
        download_bytes: 2 * 1024 * 1024,
        upload_bytes: 262_144,
        request_timeout_ms: 15_000,
        startup_timeout_ms: 10_000,
    }
}

/// Run the requested benchmark scope and persist each node/core sample batch after its core exits.
pub fn run_benchmark(database_path: &Path, options: BenchmarkOptions) -> anyhow::Result<u64> {
    ensure!(
        (options.all_cores && options.core.is_none())
            || (!options.all_cores && options.node_id.is_some() && options.core.is_some()),
        "choose --all-cores (optionally with --node), or both --node and --core"
    );
    validate_settings(&options.settings)?;
    install_cancellation_handler();
    CANCELLED.store(false, Ordering::Relaxed);

    let (nodes, cores) = load_scope(database_path, &options)?;
    let core_versions = installed_core_versions(&cores);
    let mut targets = vec![DIRECT_TARGET.to_owned()];
    targets.extend(cores.iter().map(|core| core.as_str().to_owned()));
    let run = BenchmarkRun {
        id: 0,
        status: BenchmarkRunStatus::Running,
        started_at: unix_timestamp(),
        completed_at: None,
        node_ids: nodes.iter().map(|record| record.id).collect(),
        cores: targets,
        settings: options.settings.clone(),
        core_versions: core_versions.clone(),
        summary: None,
    };

    let run_id = {
        let database = NodeDatabase::open(database_path)?;
        database.recover_interrupted_benchmark_runs()?;
        database.start_benchmark_run(run)?
    };

    println!(
        "Benchmark run #{run_id}: {} node(s), {} core(s)",
        nodes.len(),
        cores.len()
    );
    match options.metric_selection {
        BenchmarkMetricSelection::All => println!(
            "Direct TCP ping runs once per node; all HTTP metrics run through each compatible core."
        ),
        BenchmarkMetricSelection::Latency => {
            println!("Latency-only mode: HTTP latency runs through each compatible core.")
        }
        BenchmarkMetricSelection::Download => {
            println!("Download-only mode: download tests run through each compatible core.")
        }
        BenchmarkMetricSelection::Upload => {
            println!("Upload-only mode: upload tests run through each compatible core.")
        }
    }
    let execution = execute_run(
        database_path,
        run_id,
        &nodes,
        &cores,
        &core_versions,
        &options.settings,
        options.metric_selection,
    );
    let cancelled = CANCELLED.load(Ordering::Relaxed);
    let (status, summary) = if cancelled {
        (
            BenchmarkRunStatus::Cancelled,
            Some("cancelled by user; completed samples were retained".to_owned()),
        )
    } else if execution.is_ok() {
        (BenchmarkRunStatus::Completed, None)
    } else {
        (
            BenchmarkRunStatus::Interrupted,
            Some("benchmark orchestration stopped after an internal error".to_owned()),
        )
    };

    let database = NodeDatabase::open(database_path)?;
    database
        .finish_benchmark_run(run_id, status, unix_timestamp(), summary)
        .context("could not finalize benchmark run")?;
    database
        .prune_benchmark_history(BENCHMARK_HISTORY_LIMIT)
        .context("could not enforce benchmark history retention")?;

    execution?;
    if cancelled {
        println!("Benchmark run #{run_id} cancelled; completed samples were retained.");
    } else {
        println!("Benchmark run #{run_id} completed.");
    }
    Ok(run_id)
}

fn load_scope(
    database_path: &Path,
    options: &BenchmarkOptions,
) -> anyhow::Result<(Vec<NodeRecord>, Vec<CoreId>)> {
    let database = NodeDatabase::open(database_path)?;
    if options.all_cores {
        let nodes = if let Some(node_id) = options.node_id {
            let record = database
                .get_node(node_id)?
                .with_context(|| format!("node #{node_id} was not found"))?;
            ensure!(
                !record.is_deleted(),
                "node #{node_id} is deleted; restore it before benchmarking"
            );
            vec![record]
        } else {
            database.list_nodes(false)?
        };
        ensure!(!nodes.is_empty(), "there are no active nodes to benchmark");
        let cores = CoreId::ALL
            .into_iter()
            .filter(|core| core_binary_path(*core).is_ok_and(|path| path.is_file()))
            .collect::<Vec<_>>();
        ensure!(
            !cores.is_empty(),
            "no Proxyctl-managed core is installed; run proxyctl setup first"
        );
        Ok((nodes, cores))
    } else {
        let node_id = options.node_id.expect("validated node selector");
        let core = options.core.expect("validated core selector");
        let record = database
            .get_node(node_id)?
            .with_context(|| format!("node #{node_id} was not found"))?;
        ensure!(
            !record.is_deleted(),
            "node #{node_id} is deleted; restore it before benchmarking"
        );
        Ok((vec![record], vec![core]))
    }
}

fn installed_core_versions(cores: &[CoreId]) -> BTreeMap<String, String> {
    cores
        .iter()
        .filter_map(|core| {
            let path = core_binary_path(*core).ok()?;
            if !path.is_file() {
                return None;
            }
            current_version(*core, &path)
                .ok()
                .map(|version| (core.as_str().to_owned(), version))
        })
        .collect()
}

#[derive(Clone)]
struct SampleContext {
    run_id: u64,
    node_id: u64,
    target: String,
    version: Option<String>,
}

fn execute_run(
    database_path: &Path,
    run_id: u64,
    nodes: &[NodeRecord],
    cores: &[CoreId],
    core_versions: &BTreeMap<String, String>,
    settings: &BenchmarkSettings,
    metric_selection: BenchmarkMetricSelection,
) -> anyhow::Result<()> {
    let latency_concurrency = MAX_PROBE_CONCURRENCY;
    let active_nodes = NodeDatabase::open(database_path)?.list_nodes(false)?;
    let display_numbers = nodes
        .iter()
        .map(|record| {
            let number = active_nodes
                .iter()
                .position(|active| active.id == record.id)
                .map(|index| index + 1)
                .unwrap_or(record.id as usize);
            (record.id, number)
        })
        .collect::<BTreeMap<_, _>>();

    // Direct TCP is independent of a core and uses the same bounded worker limit.
    if metric_selection.includes_direct_tcp() {
        execute_tcp_ping_batch(database_path, run_id, nodes, &display_numbers, latency_concurrency)?;
    }

    // Core-first scheduling means one managed process per selected core, never multiple cores
    // at once. Unsupported/invalid nodes are persisted and excluded before batch generation.
    for core in cores {
        if CANCELLED.load(Ordering::Relaxed) {
            return Ok(());
        }
        let executable = core_binary_path(*core)?;
        let mut eligible = Vec::new();
        for record in nodes {
            let display_number = display_numbers[&record.id];
            let context = SampleContext {
                run_id,
                node_id: record.id,
                target: core.as_str().to_owned(),
                version: core_versions.get(core.as_str()).cloned(),
            };
            if !executable.is_file() {
                record_preflight(
                    database_path,
                    &context,
                    metric_selection.metrics(),
                    BenchmarkSampleStatus::Unavailable,
                    "core_missing",
                    "the selected managed core is not installed",
                )?;
                continue;
            }
            let compatibility = adapters::adapter(*core).compatibility(&record.node);
            if !compatibility.is_supported() {
                let (status, category, reason) = match compatibility.status {
                    crate::cores::adapters::CompatibilityStatus::Unsupported => (
                        BenchmarkSampleStatus::Unsupported,
                        "unsupported",
                        "the node options are not supported by this core",
                    ),
                    crate::cores::adapters::CompatibilityStatus::Invalid => (
                        BenchmarkSampleStatus::Invalid,
                        "invalid",
                        "the node configuration is invalid for this core",
                    ),
                    crate::cores::adapters::CompatibilityStatus::Supported => unreachable!(),
                };
                record_preflight(database_path, &context, metric_selection.metrics(), status, category, reason)?;
                println!("run #{run_id} node #{display_number} {core}: {category}");
                continue;
            }
            if let Err(error) = ManagedCoreProcess::validate_node_config(*core, &record.node, &executable) {
                let (status, category, reason) = classify_core_start_failure(&error);
                record_preflight(database_path, &context, metric_selection.metrics(), status, category, reason)?;
                println!("run #{run_id} node #{display_number} {core}: {reason}");
                continue;
            }
            eligible.push((record, display_number, context));
        }
        if eligible.is_empty() {
            continue;
        }

        println!(
            "run #{run_id}: preparing one {core} process for {} compatible node(s)...",
            eligible.len()
        );
        let mut targets = Vec::with_capacity(eligible.len());
        let mut ports = Vec::with_capacity(eligible.len());
        for (record, _, _) in &eligible {
            let port = crate::benchmark::process::reserve_loopback_port()?;
            ports.push(port);
            targets.push(adapters::BenchmarkTarget {
                node_id: record.id,
                node: &record.node,
                listen_port: port,
            });
        }

        let process = match ManagedCoreProcess::start_batch(
            *core,
            &targets,
            &executable,
            Duration::from_millis(settings.startup_timeout_ms),
        ) {
            Ok(process) => process,
            Err(error) => {
                let (status, category, reason) = classify_core_start_failure(&error);
                for (_, display_number, context) in &eligible {
                    record_preflight(database_path, context, metric_selection.metrics(), status, category, reason)?;
                    println!("run #{run_id} node #{display_number} {core}: {reason}");
                }
                continue;
            }
        };

        let entries = eligible
            .into_iter()
            .zip(ports)
            .map(|((_, display_number, context), port)| LatencyBatchEntry {
                display_number,
                context,
                port,
            })
            .collect::<Vec<_>>();
        let mut process = Some(process);
        let mut completed_samples = Vec::new();
        let latency_succeeded = if metric_selection.metrics().contains(&BenchmarkMetric::Latency) {
            execute_latency_batch(
                *core,
                run_id,
                &entries,
                settings,
                latency_concurrency,
                &mut process,
                &mut completed_samples,
            )?
        } else {
            vec![false; entries.len()]
        };

        // Throughput transfers stay sequential. A full run's per-node gate is based on any
        // successful real-latency sample; metric-only modes intentionally bypass that gate.
        for (index, entry) in entries.iter().enumerate() {
            if CANCELLED.load(Ordering::Relaxed) {
                break;
            }
            let client = match BenchmarkHttpClient::new(entry.port, settings) {
                Ok(client) => client,
                Err(_) => {
                    for &metric in metric_selection.metrics() {
                        if matches!(metric, BenchmarkMetric::Download | BenchmarkMetric::Upload) {
                            completed_samples.push(failed_sample(
                                &entry.context,
                                metric,
                                0,
                                BenchmarkSampleStatus::Invalid,
                                "measurement_settings",
                                "the configured measurement endpoint settings are invalid",
                            ));
                        }
                    }
                    continue;
                }
            };
            for &metric in [BenchmarkMetric::Download, BenchmarkMetric::Upload].iter() {
                if !metric_selection.metrics().contains(&metric) {
                    continue;
                }
                if !throughput_allowed(metric, metric_selection, latency_succeeded[index]) {
                    let reason = "throughput test skipped because all real-latency samples failed";
                    println!(
                        "run #{run_id} node #{} {core} {}: skipped — {reason}",
                        entry.display_number,
                        metric.label()
                    );
                    completed_samples.push(failed_sample(
                        &entry.context,
                        metric,
                        0,
                        BenchmarkSampleStatus::Unavailable,
                        "latency_gate",
                        reason,
                    ));
                    continue;
                }
                for sample_index in 1..=SAMPLES_PER_METRIC {
                    let label = format!(
                        "run #{run_id} node #{} {core} {} sample {sample_index}/{SAMPLES_PER_METRIC}",
                        entry.display_number,
                        metric.label()
                    );
                    println!("{label}: starting...");
                    let outcome = measure_interruptibly(
                        &client,
                        metric,
                        settings,
                        &mut process,
                        &label,
                    );
                    if metric == BenchmarkMetric::Download {
                        println!();
                    }
                    let sample = match outcome {
                        Ok(measurement) if !CANCELLED.load(Ordering::Relaxed) => {
                            println!(
                                "{label}: {:.2} {} ({:.2}s)",
                                measurement.value,
                                metric.unit(),
                                measurement.duration.as_secs_f64()
                            );
                            successful_sample(&entry.context, metric, sample_index, measurement)
                        }
                        Ok(_) | Err(MeasurementFailure::Cancelled) => {
                            println!("{label}: cancelled");
                            failed_sample(
                                &entry.context,
                                metric,
                                sample_index,
                                BenchmarkSampleStatus::Cancelled,
                                "cancelled",
                                "measurement cancelled by user",
                            )
                        }
                        Err(error) => {
                            let reason = error.reason();
                            println!("{label}: {reason}");
                            failed_sample(
                                &entry.context,
                                metric,
                                sample_index,
                                status_for_failure(error),
                                error.category(),
                                &reason,
                            )
                        }
                    };
                    completed_samples.push(sample);
                    if CANCELLED.load(Ordering::Relaxed) {
                        break;
                    }
                }
            }
        }

        if let Some(process) = process.as_ref()
            && let Some(diagnostic) = process.runtime_diagnostic()
        {
            println!("run #{run_id} {core}: runtime diagnostic: {diagnostic}");
        }
        let stop_result = if let Some(process) = process {
            process.stop()
        } else {
            Ok(())
        };
        // redb remains closed for the entire core process and all its network work.
        for sample in completed_samples {
            persist_sample(database_path, sample)?;
        }
        stop_result?;
    }
    Ok(())
}

fn execute_latency_batch(
    core: CoreId,
    run_id: u64,
    entries: &[LatencyBatchEntry],
    settings: &BenchmarkSettings,
    concurrency: usize,
    process: &mut Option<ManagedCoreProcess>,
    samples: &mut Vec<BenchmarkSample>,
) -> anyhow::Result<Vec<bool>> {
    let mut succeeded = vec![false; entries.len()];
    let timeout = LATENCY_REQUEST_TIMEOUT;
    for sample_index in 1..=SAMPLES_PER_METRIC {
        if CANCELLED.load(Ordering::Relaxed) {
            break;
        }
        for (base, chunk) in probe_chunks(entries, concurrency).enumerate() {
            let offset = base * concurrency.max(1);
            let (sender, receiver) = mpsc::channel();
            thread::scope(|scope| {
                for (local_index, entry) in chunk.iter().enumerate() {
                    let sender = sender.clone();
                    scope.spawn(move || {
                        let result = BenchmarkHttpClient::new_with_timeout(
                            entry.port,
                            settings,
                            timeout,
                        )
                        .map_err(|_| MeasurementFailure::Unavailable)
                        .and_then(|client| client.latency());
                        let _ = sender.send((offset + local_index, result));
                    });
                }
                drop(sender);
                let mut received = 0;
                let mut stopped = false;
                while received < chunk.len() {
                    if CANCELLED.load(Ordering::Relaxed) && !stopped {
                        if let Some(process) = process.take() {
                            let _ = process.stop();
                        }
                        stopped = true;
                    }
                    match receiver.recv_timeout(Duration::from_millis(50)) {
                        Ok((index, result)) => {
                            received += 1;
                            let entry = &entries[index];
                            let label = format!(
                                "run #{run_id} node #{} {core} real latency sample {sample_index}/{SAMPLES_PER_METRIC}",
                                entry.display_number
                            );
                            let sample = match result {
                                Ok(measurement) if !CANCELLED.load(Ordering::Relaxed) => {
                                    println!("{label}: {:.2} ms", measurement.value);
                                    succeeded[index] = true;
                                    successful_sample(&entry.context, BenchmarkMetric::Latency, sample_index, measurement)
                                }
                                Ok(_) | Err(MeasurementFailure::Cancelled) => failed_sample(
                                    &entry.context,
                                    BenchmarkMetric::Latency,
                                    sample_index,
                                    BenchmarkSampleStatus::Cancelled,
                                    "cancelled",
                                    "measurement cancelled by user",
                                ),
                                Err(error) => {
                                    let reason = error.reason();
                                    println!("{label}: {reason}");
                                    failed_sample(
                                        &entry.context,
                                        BenchmarkMetric::Latency,
                                        sample_index,
                                        status_for_failure(error),
                                        error.category(),
                                        &reason,
                                    )
                                }
                            };
                            samples.push(sample);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });
            if CANCELLED.load(Ordering::Relaxed) {
                break;
            }
        }
    }
    Ok(succeeded)
}

struct LatencyBatchEntry {
    display_number: usize,
    context: SampleContext,
    port: u16,
}

fn execute_tcp_ping_batch(
    database_path: &Path,
    run_id: u64,
    nodes: &[NodeRecord],
    display_numbers: &BTreeMap<u64, usize>,
    concurrency: usize,
) -> anyhow::Result<()> {
    for sample_index in 1..=SAMPLES_PER_METRIC {
        if CANCELLED.load(Ordering::Relaxed) {
            break;
        }
        for chunk in probe_chunks(nodes, concurrency) {
            let batch_samples = thread::scope(|scope| {
                let (sender, receiver) = mpsc::channel();
                for record in chunk {
                    let sender = sender.clone();
                    scope.spawn(move || {
                        let result = tcp::ping(
                            &record.node.server,
                            record.node.port,
                            TCP_CONNECT_TIMEOUT,
                        );
                        let _ = sender.send((record.id, result));
                    });
                }
                drop(sender);
                let mut batch_samples = Vec::with_capacity(chunk.len());
                for _ in 0..chunk.len() {
                    if let Ok((node_id, result)) = receiver.recv() {
                        let context = SampleContext {
                            run_id,
                            node_id,
                            target: DIRECT_TARGET.to_owned(),
                            version: None,
                        };
                        let display_number = display_numbers[&node_id];
                        let label = format!(
                            "run #{run_id} node #{display_number} direct TCP ping sample {sample_index}/{SAMPLES_PER_METRIC}"
                        );
                        let sample = match result {
                            Ok(measurement) => {
                                println!("{label}: {:.2} ms", measurement.value);
                                successful_sample(&context, BenchmarkMetric::TcpPing, sample_index, measurement)
                            }
                            Err(error) => {
                                let reason = error.reason();
                                println!("{label}: {reason}");
                                failed_sample(
                                    &context,
                                    BenchmarkMetric::TcpPing,
                                    sample_index,
                                    status_for_failure(error),
                                    error.category(),
                                    &reason,
                                )
                            }
                        };
                        batch_samples.push(sample);
                    }
                }
                batch_samples
            });
            for sample in batch_samples {
                persist_sample(database_path, sample)?;
            }
        }
    }
    Ok(())
}

fn probe_chunks<T>(items: &[T], requested_concurrency: usize) -> std::slice::Chunks<'_, T> {
    items.chunks(requested_concurrency.clamp(1, MAX_PROBE_CONCURRENCY))
}

fn throughput_allowed(
    metric: BenchmarkMetric,
    selection: BenchmarkMetricSelection,
    latency_succeeded: bool,
) -> bool {
    selection != BenchmarkMetricSelection::All
        || !matches!(metric, BenchmarkMetric::Download | BenchmarkMetric::Upload)
        || latency_succeeded
}

fn measure_interruptibly(
    client: &BenchmarkHttpClient,
    metric: BenchmarkMetric,
    settings: &BenchmarkSettings,
    process: &mut Option<ManagedCoreProcess>,
    label: &str,
) -> Result<Measurement, MeasurementFailure> {
    if CANCELLED.load(Ordering::Relaxed) {
        if let Some(process) = process.take() {
            let _ = process.stop();
        }
        return Err(MeasurementFailure::Cancelled);
    }
    let (sender, receiver) = mpsc::channel();
    let label = label.to_owned();

    thread::scope(|scope| {
        scope.spawn(move || {
            let result = match metric {
                BenchmarkMetric::TcpPing => Err(MeasurementFailure::InvalidResponse),
                BenchmarkMetric::Latency => client.latency(),
                BenchmarkMetric::Download => client.download(settings.download_bytes, |bytes| {
                    print!("\r{label}: {bytes} bytes received");
                    let _ = std::io::stdout().flush();
                }),
                BenchmarkMetric::Upload => client.upload(settings.upload_bytes),
            };
            let _ = sender.send(result);
        });

        loop {
            if CANCELLED.load(Ordering::Relaxed) {
                if let Some(process) = process.take() {
                    let _ = process.stop();
                }
                let _ = receiver.recv();
                return Err(MeasurementFailure::Cancelled);
            }

            match receiver.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => return result,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(MeasurementFailure::Unavailable);
                }
            }
        }
    })
}

/// Map process preparation failures to stable, credential-free benchmark outcomes.
fn classify_core_start_failure(
    error: &anyhow::Error,
) -> (BenchmarkSampleStatus, &'static str, &'static str) {
    let chain = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();

    if chain.contains("unrecognized configuration field") {
        (
            BenchmarkSampleStatus::Invalid,
            "core_config_field_invalid",
            "the selected core rejected a configuration field it does not recognize",
        )
    } else if chain.contains("loopback http inbound") {
        (
            BenchmarkSampleStatus::Invalid,
            "core_config_inbound_invalid",
            "the selected core rejected the generated loopback HTTP inbound",
        )
    } else if chain.contains("proxy outbound settings") {
        (
            BenchmarkSampleStatus::Invalid,
            "core_config_outbound_invalid",
            "the selected core rejected the generated proxy outbound settings",
        )
    } else if chain.contains("tls or certificate") {
        (
            BenchmarkSampleStatus::Invalid,
            "core_config_tls_invalid",
            "the selected core rejected the generated TLS or certificate settings",
        )
    } else if chain.contains("reality settings") {
        (
            BenchmarkSampleStatus::Invalid,
            "core_config_reality_invalid",
            "the selected core rejected the generated REALITY settings",
        )
    } else if chain.contains("rejected the benchmark configuration")
        || chain.contains("could not generate benchmark config")
    {
        (
            BenchmarkSampleStatus::Invalid,
            "core_config_invalid",
            "the adapter-generated configuration was rejected by the selected core",
        )
    } else if chain.contains("did not become ready")
        || chain.contains("local http listener readiness timed out")
    {
        (
            BenchmarkSampleStatus::Timeout,
            "core_readiness_timeout",
            "the core did not open its loopback HTTP listener before the startup deadline",
        )
    } else if chain.contains("could not run")
        || chain.contains("could not start managed")
        || chain.contains("could not create private")
        || chain.contains("could not write benchmark configuration")
    {
        (
            BenchmarkSampleStatus::Unavailable,
            "core_execution_unavailable",
            "the selected core could not be executed or its configuration could not be validated",
        )
    } else {
        (
            BenchmarkSampleStatus::Unavailable,
            "core_startup_failed",
            "the selected core could not be prepared or started",
        )
    }
}

fn status_for_failure(failure: MeasurementFailure) -> BenchmarkSampleStatus {
    match failure {
        MeasurementFailure::Timeout => BenchmarkSampleStatus::Timeout,
        MeasurementFailure::Unreachable => BenchmarkSampleStatus::Unreachable,
        MeasurementFailure::InvalidResponse => BenchmarkSampleStatus::Invalid,
        MeasurementFailure::Unavailable
        | MeasurementFailure::ProxyTunnelFailed
        | MeasurementFailure::TlsFailed
        | MeasurementFailure::HttpStatus(_)
        | MeasurementFailure::ProtocolFailed
        | MeasurementFailure::IncompleteResponse
        | MeasurementFailure::ReadFailed => BenchmarkSampleStatus::Unavailable,
        MeasurementFailure::Cancelled => BenchmarkSampleStatus::Cancelled,
    }
}

fn successful_sample(
    context: &SampleContext,
    metric: BenchmarkMetric,
    sample_index: u8,
    measurement: Measurement,
) -> BenchmarkSample {
    BenchmarkSample {
        id: 0,
        run_id: context.run_id,
        node_id: context.node_id,
        core: context.target.clone(),
        core_version: context.version.clone(),
        metric,
        sample_index,
        status: BenchmarkSampleStatus::Success,
        value: Some(measurement.value),
        unit: metric.unit().into(),
        failure_category: None,
        failure_reason: None,
        timestamp: unix_timestamp(),
        duration_ms: Some(duration_millis(measurement.duration)),
    }
}

fn failed_sample(
    context: &SampleContext,
    metric: BenchmarkMetric,
    sample_index: u8,
    status: BenchmarkSampleStatus,
    category: &str,
    reason: &str,
) -> BenchmarkSample {
    BenchmarkSample {
        id: 0,
        run_id: context.run_id,
        node_id: context.node_id,
        core: context.target.clone(),
        core_version: context.version.clone(),
        metric,
        sample_index,
        status,
        value: None,
        unit: metric.unit().into(),
        failure_category: Some(category.into()),
        failure_reason: Some(reason.into()),
        timestamp: unix_timestamp(),
        duration_ms: None,
    }
}

fn record_preflight(
    database_path: &Path,
    context: &SampleContext,
    metrics: &[BenchmarkMetric],
    status: BenchmarkSampleStatus,
    category: &str,
    reason: &str,
) -> anyhow::Result<()> {
    for &metric in metrics {
        persist_sample(
            database_path,
            failed_sample(context, metric, 0, status, category, reason),
        )?;
    }
    Ok(())
}

fn persist_sample(database_path: &Path, sample: BenchmarkSample) -> anyhow::Result<()> {
    NodeDatabase::open(database_path)?.record_benchmark_sample(sample)?;
    Ok(())
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn install_cancellation_handler() {
    #[cfg(unix)]
    {
        extern "C" fn handle_signal(_: libc::c_int) {
            CANCELLED.store(true, Ordering::Relaxed);
        }
        // The handler only performs an atomic store, which is signal-safe.
        unsafe {
            libc::signal(
                libc::SIGINT,
                handle_signal as *const () as libc::sighandler_t,
            );
            libc::signal(
                libc::SIGTERM,
                handle_signal as *const () as libc::sighandler_t,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_workers_are_hard_bounded_to_three() {
        let values = [0_u8; 8];
        let sizes = probe_chunks(&values, usize::MAX)
            .map(|chunk| chunk.len())
            .collect::<Vec<_>>();
        assert_eq!(sizes, vec![3, 3, 2]);
    }

    #[test]
    fn metric_selection_runs_only_the_requested_metric() {
        assert_eq!(
            BenchmarkMetricSelection::All.metrics(),
            &[
                BenchmarkMetric::Latency,
                BenchmarkMetric::Download,
                BenchmarkMetric::Upload
            ]
        );
        assert_eq!(
            BenchmarkMetricSelection::Latency.metrics(),
            &[BenchmarkMetric::Latency]
        );
        assert_eq!(
            BenchmarkMetricSelection::Download.metrics(),
            &[BenchmarkMetric::Download]
        );
        assert_eq!(
            BenchmarkMetricSelection::Upload.metrics(),
            &[BenchmarkMetric::Upload]
        );
        assert!(BenchmarkMetricSelection::All.includes_direct_tcp());
        assert!(!BenchmarkMetricSelection::Latency.includes_direct_tcp());
        assert!(!BenchmarkMetricSelection::Download.includes_direct_tcp());
        assert!(!BenchmarkMetricSelection::Upload.includes_direct_tcp());
    }

    #[test]
    fn full_benchmark_skips_throughput_until_latency_has_succeeded() {
        assert!(throughput_allowed(
            BenchmarkMetric::Latency,
            BenchmarkMetricSelection::All,
            false
        ));
        assert!(!throughput_allowed(
            BenchmarkMetric::Download,
            BenchmarkMetricSelection::All,
            false
        ));
        assert!(!throughput_allowed(
            BenchmarkMetric::Upload,
            BenchmarkMetricSelection::All,
            false
        ));
        assert!(throughput_allowed(
            BenchmarkMetric::Download,
            BenchmarkMetricSelection::All,
            true
        ));
        assert!(throughput_allowed(
            BenchmarkMetric::Upload,
            BenchmarkMetricSelection::All,
            true
        ));
        assert!(throughput_allowed(
            BenchmarkMetric::Download,
            BenchmarkMetricSelection::Download,
            false
        ));
        assert!(throughput_allowed(
            BenchmarkMetric::Upload,
            BenchmarkMetricSelection::Upload,
            false
        ));
    }

    #[test]
    fn core_start_failures_distinguish_invalid_config_from_runtime_startup() {
        let invalid = anyhow::anyhow!("native validator exit status 23")
            .context("mihomo rejected the benchmark configuration");
        assert_eq!(
            classify_core_start_failure(&invalid),
            (
                BenchmarkSampleStatus::Invalid,
                "core_config_invalid",
                "the adapter-generated configuration was rejected by the selected core",
            )
        );

        let startup = anyhow::anyhow!("the core did not open its local HTTP listener")
            .context("mihomo did not become ready after 3 attempts");
        assert_eq!(
            classify_core_start_failure(&startup),
            (
                BenchmarkSampleStatus::Timeout,
                "core_readiness_timeout",
                "the core did not open its loopback HTTP listener before the startup deadline",
            )
        );
    }

    #[test]
    fn measurement_failures_map_to_stable_sample_statuses() {
        let cases = [
            (MeasurementFailure::Timeout, BenchmarkSampleStatus::Timeout),
            (
                MeasurementFailure::Unreachable,
                BenchmarkSampleStatus::Unreachable,
            ),
            (
                MeasurementFailure::InvalidResponse,
                BenchmarkSampleStatus::Invalid,
            ),
            (
                MeasurementFailure::Unavailable,
                BenchmarkSampleStatus::Unavailable,
            ),
            (
                MeasurementFailure::ProxyTunnelFailed,
                BenchmarkSampleStatus::Unavailable,
            ),
            (
                MeasurementFailure::TlsFailed,
                BenchmarkSampleStatus::Unavailable,
            ),
            (
                MeasurementFailure::HttpStatus(502),
                BenchmarkSampleStatus::Unavailable,
            ),
            (
                MeasurementFailure::ProtocolFailed,
                BenchmarkSampleStatus::Unavailable,
            ),
            (
                MeasurementFailure::IncompleteResponse,
                BenchmarkSampleStatus::Unavailable,
            ),
            (
                MeasurementFailure::ReadFailed,
                BenchmarkSampleStatus::Unavailable,
            ),
            (
                MeasurementFailure::Cancelled,
                BenchmarkSampleStatus::Cancelled,
            ),
        ];

        for (failure, expected) in cases {
            assert_eq!(status_for_failure(failure), expected, "{failure:?}");
        }
    }

    #[test]
    fn default_settings_match_v2rayn_style_targets_and_are_bounded() {
        let settings = default_settings();
        assert_eq!(settings.latency_url, "https://www.google.com/generate_204");
        assert_eq!(
            settings.download_url,
            "https://cachefly.cachefly.net/10mb.test"
        );
        assert_eq!(settings.upload_url, "https://speed.cloudflare.com/__up");
        assert_eq!(settings.download_bytes, 2 * 1024 * 1024);
        assert_eq!(settings.upload_bytes, 262_144);
        assert_eq!(settings.request_timeout_ms, 15_000);
    }
}
