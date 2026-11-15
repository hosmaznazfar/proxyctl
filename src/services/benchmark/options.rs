//! User-selectable benchmark scope and default measurement settings.

use crate::{
    cores::CoreId,
    domain::{BenchmarkMetric, BenchmarkProxyType, BenchmarkSettings},
};

pub const METHODOLOGY: &str = "proxyctl-benchmark-v14";

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
    BenchmarkSettings {
        proxy_type: BenchmarkProxyType::default(),
        methodology: METHODOLOGY.into(),
        latency_url: "https://www.google.com/generate_204".into(),
        download_url: "https://cachefly.cachefly.net/10mb.test".into(),
        upload_url: "https://speed.cloudflare.com/__up".into(),
        download_bytes: 1_048_576,
        upload_bytes: 1_048_576,
        request_timeout_ms: 60_000,
        latency_timeout_ms: 5_000,
        probe_concurrency: 3,
        startup_timeout_ms: 10_000,
    }
}


