//! Sequential benchmark orchestration. Database handles are never held during network work.

use std::{
    collections::BTreeMap,
    io::Write,
    net::ToSocketAddrs,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
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
const METHODOLOGY: &str = "proxyctl-benchmark-v2";
const DIRECT_TARGET: &str = "direct";
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct BenchmarkOptions {
    pub all_cores: bool,
    pub node_id: Option<u64>,
    pub core: Option<CoreId>,
    pub settings: BenchmarkSettings,
}

impl Default for BenchmarkOptions {
    fn default() -> Self {
        Self {
            all_cores: true,
            node_id: None,
            core: None,
            settings: default_settings(),
        }
    }
}

pub fn default_settings() -> BenchmarkSettings {
    BenchmarkSettings {
        methodology: METHODOLOGY.into(),
        latency_url: "https://www.google.com/generate_204".into(),
        download_url: "https://cachefly.cachefly.net/10mb.test".into(),
        upload_url: "https://speed.cloudflare.com/__up".into(),
        download_bytes: 16 * 1024 * 1024,
        upload_bytes: 1_048_576,
        request_timeout_ms: 15_000,
        startup_timeout_ms: 10_000,
    }
}

/// Run the requested benchmark scope and persist each node/core sample batch after its core exits.
pub fn run_benchmark(database_path: &Path, options: BenchmarkOptions) -> anyhow::Result<u64> {
    ensure!(
        (options.all_cores && options.node_id.is_none() && options.core.is_none())
            || (!options.all_cores && options.node_id.is_some() && options.core.is_some()),
        "choose either --all-cores or both --node and --core"
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

    println!("Benchmark run #{run_id}: {} node(s), {} core(s)", nodes.len(), cores.len());
    println!("Direct TCP ping runs once per node; HTTP tests run through each compatible core.");
    let execution = execute_run(
        database_path,
        run_id,
        &nodes,
        &cores,
        &core_versions,
        &options.settings,
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

    NodeDatabase::open(database_path)?
        .finish_benchmark_run(run_id, status, unix_timestamp(), summary)
        .context("could not finalize benchmark run")?;

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
        let nodes = database.list_nodes(false)?;
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
) -> anyhow::Result<()> {
    for record in nodes {
        if CANCELLED.load(Ordering::Relaxed) {
            return Ok(());
        }
        execute_tcp_ping(database_path, run_id, record)?;

        for core in cores {
            if CANCELLED.load(Ordering::Relaxed) {
                return Ok(());
            }
            let executable = core_binary_path(*core)?;
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
                    BenchmarkSampleStatus::Unavailable,
                    "core_missing",
                    "the selected managed core is not installed",
                )?;
                continue;
            }

            println!("run #{run_id} node #{}: validating {core} configuration...", record.id);
            let adapter = adapters::adapter(*core);
            let compatibility = adapter.compatibility(&record.node);
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
                record_preflight(database_path, &context, status, category, reason)?;
                println!("run #{run_id} node #{} {core}: {category}", record.id);
                continue;
            }

            println!("run #{run_id} node #{}: starting {core}...", record.id);
            let process = match ManagedCoreProcess::start(
                *core,
                &record.node,
                &executable,
                Duration::from_millis(settings.startup_timeout_ms),
            ) {
                Ok(process) => process,
                Err(_) => {
                    record_preflight(
                        database_path,
                        &context,
                        BenchmarkSampleStatus::Unavailable,
                        "core_startup",
                        "the managed core failed to start or open its local listener",
                    )?;
                    println!("run #{run_id} node #{} {core}: startup failed", record.id);
                    continue;
                }
            };

            let client = match BenchmarkHttpClient::new(process.port(), settings) {
                Ok(client) => client,
                Err(_) => {
                    process.stop()?;
                    record_preflight(
                        database_path,
                        &context,
                        BenchmarkSampleStatus::Invalid,
                        "measurement_settings",
                        "the configured measurement endpoint settings are invalid",
                    )?;
                    continue;
                }
            };

            let mut process = Some(process);
            let mut completed_samples = Vec::with_capacity(usize::from(SAMPLES_PER_METRIC) * 3);
            for metric in [
                BenchmarkMetric::Latency,
                BenchmarkMetric::Download,
                BenchmarkMetric::Upload,
            ] {
                for sample_index in 1..=SAMPLES_PER_METRIC {
                    let label = format!(
                        "run #{run_id} node #{} {core} {} sample {sample_index}/{SAMPLES_PER_METRIC}",
                        record.id,
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
                    let sample = match outcome {
                        Ok(measurement) if !CANCELLED.load(Ordering::Relaxed) => {
                            println!(
                                "{label}: {:.2} {} ({:.2}s)",
                                measurement.value,
                                metric.unit(),
                                measurement.duration.as_secs_f64()
                            );
                            successful_sample(&context, metric, sample_index, measurement)
                        }
                        Ok(_) | Err(MeasurementFailure::Cancelled) => {
                            println!("{label}: cancelled");
                            failed_sample(
                                &context,
                                metric,
                                sample_index,
                                BenchmarkSampleStatus::Cancelled,
                                "cancelled",
                                "measurement cancelled by user",
                            )
                        }
                        Err(error) => {
                            println!("{label}: {}", error.reason());
                            failed_sample(
                                &context,
                                metric,
                                sample_index,
                                status_for_failure(error),
                                error.category(),
                                error.reason(),
                            )
                        }
                    };
                    completed_samples.push(sample);
                }
            }

            // Keep redb closed for the entire child-process lifetime. Flush this node/core
            // batch only after the child has exited, including when cancellation was requested.
            let stop_result = if let Some(process) = process {
                process.stop()
            } else {
                Ok(())
            };
            for sample in completed_samples {
                persist_sample(database_path, sample)?;
            }
            stop_result?;
        }
    }
    Ok(())
}

fn execute_tcp_ping(
    database_path: &Path,
    run_id: u64,
    record: &NodeRecord,
) -> anyhow::Result<()> {
    let context = SampleContext {
        run_id,
        node_id: record.id,
        target: DIRECT_TARGET.to_owned(),
        version: None,
    };
    for sample_index in 1..=SAMPLES_PER_METRIC {
        if CANCELLED.load(Ordering::Relaxed) {
            break;
        }
        let label = format!(
            "run #{run_id} node #{} direct TCP ping sample {sample_index}/{SAMPLES_PER_METRIC}",
            record.id
        );
        println!("{label}: connecting to {}:{}...", record.node.server, record.node.port);
        let sample = match tcp::ping(
            &record.node.server,
            record.node.port,
            TCP_CONNECT_TIMEOUT,
        ) {
            Ok(measurement) => {
                println!("{label}: {:.2} ms", measurement.value);
                successful_sample(&context, BenchmarkMetric::TcpPing, sample_index, measurement)
            }
            Err(error) => {
                println!("{label}: {}", error.reason());
                failed_sample(
                    &context,
                    BenchmarkMetric::TcpPing,
                    sample_index,
                    status_for_failure(error),
                    error.category(),
                    error.reason(),
                )
            }
        };
        persist_sample(database_path, sample)?;
    }
    Ok(())
}

fn measure_interruptibly(
    client: &BenchmarkHttpClient,
    metric: BenchmarkMetric,
    settings: &BenchmarkSettings,
    process: &mut Option<ManagedCoreProcess>,
    label: &str,
) -> Result<Measurement, MeasurementFailure> {
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

fn status_for_failure(failure: MeasurementFailure) -> BenchmarkSampleStatus {
    match failure {
        MeasurementFailure::Timeout => BenchmarkSampleStatus::Timeout,
        MeasurementFailure::Unreachable => BenchmarkSampleStatus::Unreachable,
        MeasurementFailure::InvalidResponse => BenchmarkSampleStatus::Invalid,
        MeasurementFailure::Unavailable => BenchmarkSampleStatus::Unavailable,
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
    status: BenchmarkSampleStatus,
    category: &str,
    reason: &str,
) -> anyhow::Result<()> {
    for metric in [
        BenchmarkMetric::Latency,
        BenchmarkMetric::Download,
        BenchmarkMetric::Upload,
    ] {
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
    fn default_settings_match_v2rayn_style_targets_and_are_bounded() {
        let settings = default_settings();
        assert_eq!(
            settings.latency_url,
            "https://www.google.com/generate_204"
        );
        assert_eq!(
            settings.download_url,
            "https://cachefly.cachefly.net/10mb.test"
        );
        assert_eq!(settings.upload_url, "https://speed.cloudflare.com/__up");
        assert_eq!(settings.download_bytes, 16 * 1024 * 1024);
        assert_eq!(settings.upload_bytes, 1_048_576);
        assert_eq!(settings.request_timeout_ms, 15_000);
    }
}
