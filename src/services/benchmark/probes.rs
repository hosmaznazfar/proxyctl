//! Bounded concurrent direct TCP and HTTP latency probes.
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{atomic::Ordering, mpsc},
    thread,
    time::Duration,
};

use crate::{
    benchmark::process::ManagedCoreProcess,
    benchmark::{
        http::{BenchmarkHttpClient, MeasurementFailure},
        tcp,
    },
    cores::CoreId,
    database::NodeRecord,
    domain::{BenchmarkMetric, BenchmarkSample, BenchmarkSampleStatus, BenchmarkSettings},
};

use super::{
    CANCELLED, DIRECT_TARGET, MAX_PROBE_CONCURRENCY, SAMPLES_PER_METRIC, SampleContext,
    TCP_CONNECT_TIMEOUT,
    samples::{failed_sample, persist_sample, status_for_failure, successful_sample},
};

pub(super) fn execute_latency_batch(
    core: CoreId,
    run_id: u64,
    entries: &[LatencyBatchEntry],
    settings: &BenchmarkSettings,
    concurrency: usize,
    process: &mut Option<ManagedCoreProcess>,
    samples: &mut Vec<BenchmarkSample>,
) -> anyhow::Result<Vec<bool>> {
    let mut succeeded = vec![false; entries.len()];
    let timeout = Duration::from_millis(settings.latency_timeout_ms);
    let batch_width = concurrency.clamp(1, MAX_PROBE_CONCURRENCY);
    for sample_index in 1..=SAMPLES_PER_METRIC {
        if CANCELLED.load(Ordering::Relaxed) {
            break;
        }
        for (base, chunk) in entries.chunks(batch_width).enumerate() {
            let offset = base * batch_width;
            let (sender, receiver) = mpsc::channel();
            thread::scope(|scope| {
                for (local_index, entry) in chunk.iter().enumerate() {
                    let sender = sender.clone();
                    scope.spawn(move || {
                        let result =
                            BenchmarkHttpClient::new_with_timeout(entry.port, settings, timeout)
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
                                    successful_sample(
                                        &entry.context,
                                        BenchmarkMetric::Latency,
                                        sample_index,
                                        measurement,
                                    )
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

pub(super) struct LatencyBatchEntry {
    pub(super) display_number: usize,
    pub(super) context: SampleContext,
    pub(super) port: u16,
}

pub(super) fn execute_tcp_ping_batch(
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
                        let result =
                            tcp::ping(&record.node.server, record.node.port, TCP_CONNECT_TIMEOUT);
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
                                successful_sample(
                                    &context,
                                    BenchmarkMetric::TcpPing,
                                    sample_index,
                                    measurement,
                                )
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

pub(super) fn probe_chunks<T>(
    items: &[T],
    requested_concurrency: usize,
) -> std::slice::Chunks<'_, T> {
    items.chunks(requested_concurrency.clamp(1, MAX_PROBE_CONCURRENCY))
}
