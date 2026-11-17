//! User-selectable benchmark scope and default measurement settings.

use crate::{
    cores::CoreId,
    domain::{BenchmarkMetric, BenchmarkProfile, BenchmarkProxyType, BenchmarkSettings},
};

pub const METHODOLOGY: &str = "proxyctl-benchmark-v16";

#[derive(Clone, Debug)]
pub struct BenchmarkOptions {
    pub all_cores: bool,
    pub node_id: Option<u64>,
    pub node_ids: Vec<u64>,
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
    pub(super) fn metrics(self) -> &'static [BenchmarkMetric] {
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

    pub(super) fn includes_direct_tcp(self) -> bool {
        matches!(self, Self::All)
    }
}

impl Default for BenchmarkOptions {
    fn default() -> Self {
        Self {
            all_cores: true,
            node_id: None,
            node_ids: Vec::new(),
            core: None,
            settings: default_settings(),
            metric_selection: BenchmarkMetricSelection::All,
        }
    }
}

pub fn default_settings() -> BenchmarkSettings {
    default_settings_for(BenchmarkProfile::Quick)
}

/// Build profile defaults before applying explicit CLI overrides.
pub fn default_settings_for(profile: BenchmarkProfile) -> BenchmarkSettings {
    let (download_bytes, download_duration_ms, download_streams, warmup_bytes) = match profile {
        BenchmarkProfile::Quick => (1_048_576, 5_000, 1, 0),
        BenchmarkProfile::Accurate => (8 * 1_048_576, 20_000, 3, 64 * 1_024),
    };
    BenchmarkSettings {
        proxy_type: BenchmarkProxyType::default(),
        profile,
        methodology: METHODOLOGY.into(),
        latency_url: "https://www.google.com/generate_204".into(),
        download_url: "https://cachefly.cachefly.net/10mb.test".into(),
        upload_url: "https://speed.cloudflare.com/__up".into(),
        download_bytes,
        upload_bytes: 1_048_576,
        download_duration_ms,
        download_streams,
        warmup_bytes,
        request_timeout_ms: 60_000,
        latency_timeout_ms: 5_000,
        probe_concurrency: 3,
        startup_timeout_ms: 10_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_profile_is_small_and_single_stream() {
        let settings = default_settings_for(BenchmarkProfile::Quick);
        assert_eq!(settings.download_bytes, 1_048_576);
        assert_eq!(settings.download_duration_ms, 5_000);
        assert_eq!(settings.download_streams, 1);
        assert_eq!(settings.warmup_bytes, 0);
    }

    #[test]
    fn accurate_profile_is_bounded_and_multi_stream() {
        let settings = default_settings_for(BenchmarkProfile::Accurate);
        assert_eq!(settings.download_bytes, 8 * 1_048_576);
        assert_eq!(settings.download_duration_ms, 20_000);
        assert_eq!(settings.download_streams, 3);
        assert_eq!(settings.warmup_bytes, 64 * 1_024);
        assert!(settings.download_bytes <= 32 * 1_048_576);
    }
}
