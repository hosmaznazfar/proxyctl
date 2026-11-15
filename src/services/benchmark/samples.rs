//! Benchmark sample construction, persistence, and cancellation plumbing.
use std::{path::Path, time::Duration};

use crate::{
    benchmark::http::{Measurement, MeasurementFailure},
    database::NodeDatabase,
    domain::{BenchmarkMetric, BenchmarkSample, BenchmarkSampleStatus},
};

use super::{CANCELLED, SampleContext};

pub(super) fn status_for_failure(failure: MeasurementFailure) -> BenchmarkSampleStatus {
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

pub(super) fn successful_sample(
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
        transferred_bytes: measurement.transferred_bytes,
        partial: measurement.partial,
    }
}

pub(super) fn failed_sample(
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
        transferred_bytes: None,
        partial: false,
    }
}

pub(super) fn record_preflight(
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

pub(super) fn persist_sample(database_path: &Path, sample: BenchmarkSample) -> anyhow::Result<()> {
    NodeDatabase::open(database_path)?.record_benchmark_sample(sample)?;
    Ok(())
}

pub(super) fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub(super) fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn install_cancellation_handler() {
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

