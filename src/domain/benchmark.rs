use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A benchmark metric and its canonical persisted unit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkMetric {
    TcpPing,
    Latency,
    Download,
    Upload,
}

impl BenchmarkMetric {
    pub const fn label(self) -> &'static str {
        match self {
            Self::TcpPing => "TCP ping",
            Self::Latency => "real ping",
            Self::Download => "download",
            Self::Upload => "upload",
        }
    }

    pub const fn unit(self) -> &'static str {
        match self {
            Self::TcpPing | Self::Latency => "ms",
            Self::Download | Self::Upload => "bps",
        }
    }
}

/// Lifecycle state of one benchmark run.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkRunStatus {
    Running,
    Completed,
    Interrupted,
    Cancelled,
}

/// Outcome of one metric sample or a preflight compatibility check.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkSampleStatus {
    Success,
    Unreachable,
    Unsupported,
    Invalid,
    Timeout,
    Unavailable,
    Skipped,
    Cancelled,
}

/// Local inbound protocol used by benchmark HTTP measurements.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkProxyType {
    #[default]
    Socks5,
    Http,
}

/// Effective, non-secret settings captured with every run.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchmarkSettings {
    #[serde(default)]
    pub proxy_type: BenchmarkProxyType,
    pub methodology: String,
    pub latency_url: String,
    pub download_url: String,
    pub upload_url: String,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub request_timeout_ms: u64,
    #[serde(default = "default_latency_timeout_ms")]
    pub latency_timeout_ms: u64,
    #[serde(default = "default_probe_concurrency")]
    pub probe_concurrency: u8,
    pub startup_timeout_ms: u64,
}

fn default_latency_timeout_ms() -> u64 {
    5_000
}

fn default_probe_concurrency() -> u8 {
    3
}

/// Persisted benchmark run metadata.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchmarkRun {
    pub id: u64,
    pub status: BenchmarkRunStatus,
    pub started_at: u64,
    pub completed_at: Option<u64>,
    pub node_ids: Vec<u64>,
    pub cores: Vec<String>,
    pub settings: BenchmarkSettings,
    pub core_versions: std::collections::BTreeMap<String, String>,
    pub summary: Option<String>,
}

/// One immutable metric sample. A preflight outcome uses sample_index 0; attempted
/// network measurements use indexes 1 through 3.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchmarkSample {
    pub id: u64,
    pub run_id: u64,
    pub node_id: u64,
    pub core: String,
    pub core_version: Option<String>,
    pub metric: BenchmarkMetric,
    pub sample_index: u8,
    pub status: BenchmarkSampleStatus,
    pub value: Option<f64>,
    pub unit: String,
    pub failure_category: Option<String>,
    pub failure_reason: Option<String>,
    pub timestamp: u64,
    pub duration_ms: Option<u64>,
    /// Number of body bytes actually received for transfer metrics.
    #[serde(default)]
    pub transferred_bytes: Option<u64>,
    /// True when a useful download sample ended before the configured byte cap.
    #[serde(default)]
    pub partial: bool,
}

impl BenchmarkSample {
    /// Check invariants before a sample is committed to persistent storage.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.core.trim().is_empty() {
            return Err("core identifier must not be empty");
        }
        if self.sample_index > 3 {
            return Err("sample index must be between 0 and 3");
        }
        if self.unit != self.metric.unit() {
            return Err("sample unit does not match its metric");
        }
        match (self.status, self.value) {
            (BenchmarkSampleStatus::Success, Some(value)) if value.is_finite() && value >= 0.0 => {}
            (BenchmarkSampleStatus::Success, _) => {
                return Err("successful samples require a finite non-negative value");
            }
            (_, None) => {}
            (_, Some(_)) => return Err("failed samples must not contain a numeric value"),
        }
        let is_transfer_metric =
            matches!(self.metric, BenchmarkMetric::Download | BenchmarkMetric::Upload);
        if self.transferred_bytes.is_some() && !is_transfer_metric {
            return Err("transfer byte metadata is only valid for download/upload samples");
        }
        if self.status != BenchmarkSampleStatus::Success
            && (self.transferred_bytes.is_some() || self.partial)
        {
            return Err("failed samples cannot contain transfer metadata");
        }
        if self.partial
            && (self.metric != BenchmarkMetric::Download
                || self.status != BenchmarkSampleStatus::Success)
        {
            return Err("only successful download samples can be partial");
        }
        if self.partial && self.transferred_bytes.is_none_or(|bytes| bytes == 0) {
            return Err("partial download samples require a positive transferred byte count");
        }
        if self.status == BenchmarkSampleStatus::Success && self.sample_index == 0 {
            return Err("preflight sample index 0 cannot be successful");
        }
        if self.status == BenchmarkSampleStatus::Success
            && (self.failure_category.is_some() || self.failure_reason.is_some())
        {
            return Err("successful samples cannot contain failure details");
        }
        if self.status != BenchmarkSampleStatus::Success
            && (self.failure_category.as_deref().is_none_or(str::is_empty)
                || self.failure_reason.as_deref().is_none_or(str::is_empty))
        {
            return Err("failed samples require a failure category and reason");
        }
        Ok(())
    }
}

/// Calculate the median of successful values, ignoring failed and missing samples.
pub fn median_successful_samples(samples: &[BenchmarkSample]) -> Option<f64> {
    let mut values = samples
        .iter()
        .filter(|sample| sample.status == BenchmarkSampleStatus::Success)
        .filter_map(|sample| sample.value)
        .filter(|value| value.is_finite() && *value >= 0.0)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        Some(values[middle])
    } else {
        Some((values[middle - 1] + values[middle]) / 2.0)
    }
}

/// Convert a transferred byte count and monotonic elapsed duration to bits per second.
pub fn throughput_bps(bytes: u64, elapsed: Duration) -> Option<f64> {
    let seconds = elapsed.as_secs_f64();
    if bytes == 0 || !seconds.is_finite() || seconds <= 0.0 {
        return None;
    }
    let value = (bytes as f64 * 8.0) / seconds;
    value.is_finite().then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(status: BenchmarkSampleStatus, value: Option<f64>) -> BenchmarkSample {
        BenchmarkSample {
            id: 0,
            run_id: 1,
            node_id: 1,
            core: "sing-box".into(),
            core_version: Some("1.0.0".into()),
            metric: BenchmarkMetric::Latency,
            sample_index: 1,
            status,
            value,
            unit: "ms".into(),
            failure_category: None,
            failure_reason: None,
            timestamp: 1,
            duration_ms: None,
            transferred_bytes: None,
            partial: false,
        }
    }

    #[test]
    fn legacy_benchmark_settings_receive_safe_optimization_defaults() {
        let settings: BenchmarkSettings = serde_json::from_str(
            r#"{
                "methodology":"proxyctl-benchmark-v2",
                "latency_url":"https://example.com/ping",
                "download_url":"https://example.com/down",
                "upload_url":"https://example.com/up",
                "download_bytes":1024,
                "upload_bytes":1024,
                "request_timeout_ms":15000,
                "startup_timeout_ms":10000
            }"#,
        )
        .unwrap();
        assert_eq!(settings.latency_timeout_ms, 5_000);
        assert_eq!(settings.probe_concurrency, 3);
    }

    #[test]
    fn legacy_samples_default_transfer_metadata() {
        let mut value = serde_json::to_value(sample(BenchmarkSampleStatus::Success, Some(12.0))).unwrap();
        value.as_object_mut().unwrap().remove("transferred_bytes");
        value.as_object_mut().unwrap().remove("partial");
        let restored: BenchmarkSample = serde_json::from_value(value).unwrap();
        assert_eq!(restored.transferred_bytes, None);
        assert!(!restored.partial);
    }

    #[test]
    fn only_download_successes_can_be_marked_partial() {
        let mut value = sample(BenchmarkSampleStatus::Success, Some(12.0));
        value.metric = BenchmarkMetric::Download;
        value.unit = BenchmarkMetric::Download.unit().into();
        value.partial = true;
        value.transferred_bytes = Some(16 * 1024);
        assert_eq!(value.validate(), Ok(()));
        value.metric = BenchmarkMetric::Latency;
        value.unit = BenchmarkMetric::Latency.unit().into();
        assert_eq!(value.validate(), Err("only successful download samples can be partial"));
    }

    #[test]
    fn transfer_byte_metadata_is_restricted_to_successful_transfer_samples() {
        let mut latency = sample(BenchmarkSampleStatus::Success, Some(12.0));
        latency.transferred_bytes = Some(1024);
        assert_eq!(
            latency.validate(),
            Err("transfer byte metadata is only valid for download/upload samples")
        );

        let mut failed_download = sample(BenchmarkSampleStatus::Timeout, None);
        failed_download.metric = BenchmarkMetric::Download;
        failed_download.unit = BenchmarkMetric::Download.unit().into();
        failed_download.failure_category = Some("timeout".into());
        failed_download.failure_reason = Some("request timed out".into());
        failed_download.transferred_bytes = Some(1024);
        assert_eq!(
            failed_download.validate(),
            Err("failed samples cannot contain transfer metadata")
        );
    }

    #[test]
    fn median_uses_successful_samples_only() {
        let samples = [
            sample(BenchmarkSampleStatus::Success, Some(40.0)),
            sample(BenchmarkSampleStatus::Timeout, None),
            sample(BenchmarkSampleStatus::Success, Some(10.0)),
            sample(BenchmarkSampleStatus::Success, Some(30.0)),
        ];
        assert_eq!(median_successful_samples(&samples), Some(30.0));
    }

    #[test]
    fn median_averages_the_two_middle_values() {
        let samples = [
            sample(BenchmarkSampleStatus::Success, Some(10.0)),
            sample(BenchmarkSampleStatus::Success, Some(30.0)),
        ];
        assert_eq!(median_successful_samples(&samples), Some(20.0));
    }

    #[test]
    fn median_is_absent_when_no_sample_succeeded() {
        let samples = [sample(BenchmarkSampleStatus::Timeout, None)];
        assert_eq!(median_successful_samples(&samples), None);
    }

    #[test]
    fn throughput_uses_bits_and_rejects_zero_duration() {
        assert_eq!(throughput_bps(1_000, Duration::from_secs(2)), Some(4_000.0));
        assert_eq!(throughput_bps(1_000, Duration::ZERO), None);
        assert_eq!(throughput_bps(0, Duration::from_secs(1)), None);
    }

    #[test]
    fn failed_sample_cannot_contain_a_numeric_value() {
        let mut value = sample(BenchmarkSampleStatus::Timeout, None);
        value.value = Some(0.0);
        assert_eq!(
            value.validate(),
            Err("failed samples must not contain a numeric value")
        );
    }

    #[test]
    fn sample_unit_must_match_metric() {
        let mut value = sample(BenchmarkSampleStatus::Success, Some(12.0));
        value.metric = BenchmarkMetric::Download;
        assert_eq!(
            value.validate(),
            Err("sample unit does not match its metric")
        );
    }
}
