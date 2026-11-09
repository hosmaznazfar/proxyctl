//! Bounded HTTP measurements routed through the benchmark's explicit local proxy.

use std::{
    io::Read,
    time::{Duration, Instant},
};

use anyhow::{Context, ensure};
use url::Url;
use ureq::{Agent, Proxy};

use crate::domain::BenchmarkSettings;

/// A successful, timed HTTP measurement.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Measurement {
    pub value: f64,
    pub duration: Duration,
}

/// Safe failure classification; deliberately excludes raw URLs and library diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeasurementFailure {
    Timeout,
    Unreachable,
    InvalidResponse,
    Unavailable,
}

impl MeasurementFailure {
    pub const fn category(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unreachable => "unreachable",
            Self::InvalidResponse => "invalid_response",
            Self::Unavailable => "unavailable",
        }
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::Timeout => "the measurement request exceeded its time limit",
            Self::Unreachable => "the measurement endpoint could not be reached",
            Self::InvalidResponse => "the measurement endpoint returned an invalid payload",
            Self::Unavailable => "the measurement request failed",
        }
    }
}

/// HTTP client pinned to the selected core's loopback inbound.
pub struct BenchmarkHttpClient {
    agent: Agent,
    latency_url: Url,
    download_url: Url,
    upload_url: Url,
}

impl BenchmarkHttpClient {
    pub fn new(port: u16, settings: &BenchmarkSettings) -> anyhow::Result<Self> {
        let latency_url = validate_endpoint(&settings.latency_url)?;
        let download_url = validate_endpoint(&settings.download_url)?;
        let upload_url = validate_endpoint(&settings.upload_url)?;
        let proxy = Proxy::new(format!("http://127.0.0.1:{port}"))
            .context("could not configure the local benchmark HTTP proxy")?;
        let config = Agent::config_builder()
            .proxy(Some(proxy))
            .timeout_global(Some(Duration::from_millis(settings.request_timeout_ms)))
            .build();
        let agent: Agent = config.into();
        Ok(Self {
            agent,
            latency_url,
            download_url,
            upload_url,
        })
    }

    /// Measure time until response headers arrive from the zero-byte latency endpoint.
    pub fn latency(&self) -> Result<Measurement, MeasurementFailure> {
        let started = Instant::now();
        let response = self
            .agent
            .get(self.latency_url.as_str())
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(classify_error)?;
        let duration = started.elapsed();
        drop(response);
        Ok(Measurement {
            value: duration.as_secs_f64() * 1_000.0,
            duration,
        })
    }

    /// Download exactly the requested number of bytes through the local proxy.
    pub fn download(&self, bytes: u64) -> Result<Measurement, MeasurementFailure> {
        let url = with_bytes_parameter(&self.download_url, bytes);
        let started = Instant::now();
        let mut response = self
            .agent
            .get(url.as_str())
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(classify_error)?;
        let body = response
            .body_mut()
            .with_config()
            .limit(bytes.saturating_add(1))
            .read_to_vec()
            .map_err(classify_error)?;
        let duration = started.elapsed();
        if body.len() as u64 != bytes {
            return Err(MeasurementFailure::InvalidResponse);
        }
        Ok(Measurement {
            value: throughput_bps(bytes, duration)
                .ok_or(MeasurementFailure::InvalidResponse)?,
            duration,
        })
    }

    /// Upload a deterministic in-memory payload and wait for the response body.
    pub fn upload(&self, bytes: u64) -> Result<Measurement, MeasurementFailure> {
        let size = usize::try_from(bytes).map_err(|_| MeasurementFailure::InvalidResponse)?;
        let body = vec![0x5a; size];
        let started = Instant::now();
        let mut response = self
            .agent
            .post(self.upload_url.as_str())
            .header("Content-Type", "application/octet-stream")
            .header("Accept-Encoding", "identity")
            .send(body.as_slice())
            .map_err(classify_error)?;
        response
            .body_mut()
            .with_config()
            .limit(64 * 1024)
            .read_to_vec()
            .map_err(classify_error)?;
        let duration = started.elapsed();
        Ok(Measurement {
            value: throughput_bps(bytes, duration)
                .ok_or(MeasurementFailure::InvalidResponse)?,
            duration,
        })
    }
}

fn validate_endpoint(value: &str) -> anyhow::Result<Url> {
    let url = Url::parse(value).context("benchmark endpoint URL is invalid")?;
    ensure!(
        url.scheme() == "https",
        "benchmark endpoints must use HTTPS"
    );
    ensure!(
        url.host_str().is_some(),
        "benchmark endpoint must include a host"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "benchmark endpoint must not contain URL credentials"
    );
    ensure!(
        url.fragment().is_none(),
        "benchmark endpoint must not contain a fragment"
    );
    Ok(url)
}

fn with_bytes_parameter(base: &Url, bytes: u64) -> Url {
    let mut url = base.clone();
    let retained = url
        .query_pairs()
        .filter(|(key, _)| key != "bytes")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.set_query(None);
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in retained {
            query.append_pair(&key, &value);
        }
        query.append_pair("bytes", &bytes.to_string());
    }
    url
}

fn throughput_bps(bytes: u64, duration: Duration) -> Option<f64> {
    let seconds = duration.as_secs_f64();
    if bytes == 0 || !seconds.is_finite() || seconds <= 0.0 {
        return None;
    }
    let value = (bytes as f64 * 8.0) / seconds;
    value.is_finite().then_some(value)
}

fn classify_error(error: ureq::Error) -> MeasurementFailure {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("timeout") || message.contains("timed out") {
        MeasurementFailure::Timeout
    } else if message.contains("dns")
        || message.contains("connection refused")
        || message.contains("connection reset")
        || message.contains("failed to connect")
    {
        MeasurementFailure::Unreachable
    } else {
        MeasurementFailure::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_https_and_credential_bearing_endpoints() {
        assert!(validate_endpoint("http://speed.example/test").is_err());
        assert!(validate_endpoint("https://user:pass@speed.example/test").is_err());
        assert!(validate_endpoint("https://speed.example/test#fragment").is_err());
    }

    #[test]
    fn accepts_https_endpoint_without_credentials() {
        assert!(validate_endpoint("https://speed.cloudflare.com/__down").is_ok());
    }

    #[test]
    fn download_size_parameter_is_replaced_not_duplicated() {
        let base = Url::parse("https://speed.example/__down?token=public&bytes=10").unwrap();
        let result = with_bytes_parameter(&base, 1024);
        let pairs = result.query_pairs().collect::<Vec<_>>();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("token".into(), "public".into()));
        assert_eq!(pairs[1], ("bytes".into(), "1024".into()));
    }

    #[test]
    fn throughput_is_bits_per_second() {
        assert_eq!(
            throughput_bps(1_000, Duration::from_secs(2)),
            Some(4_000.0)
        );
        assert_eq!(throughput_bps(0, Duration::from_secs(1)), None);
    }
}
