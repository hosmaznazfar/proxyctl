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
    Cancelled,
}

/// Effective, non-secret settings captured with every run.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct BenchmarkSettings {
    pub methodology: String,
    pub latency_url: String,
    pub download_url: String,
    pub upload_url: String,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub request_timeout_ms: u64,
    pub startup_timeout_ms: u64,
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
        }
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
