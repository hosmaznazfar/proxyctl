//! Bounded HTTP measurements routed through the benchmark's explicit local proxy.

use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use ureq::{Agent, Proxy};
use url::Url;

use crate::domain::{BenchmarkSettings, throughput_bps};

const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

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
        validate_settings(settings)?;
        let latency_url = validate_endpoint(&settings.latency_url)?;
        let download_url = validate_endpoint(&settings.download_url)?;
        let upload_url = validate_endpoint(&settings.upload_url)?;
        let proxy_url = format!("http://127.0.0.1:{port}");
        let proxy =
            Proxy::new(&proxy_url).context("could not configure the local benchmark HTTP proxy")?;
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
        let url = with_bytes_parameter(&self.latency_url, 0);
        let mut response = self
            .agent
            .get(url.as_str())
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(classify_error)?;
        let duration = started.elapsed();
        let response_body = response
            .body_mut()
            .with_config()
            .limit(1_024)
            .read_to_vec()
            .map_err(classify_error)?;
        if !response_body.is_empty() {
            return Err(MeasurementFailure::InvalidResponse);
        }
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
            value: throughput_bps(bytes, duration).ok_or(MeasurementFailure::InvalidResponse)?,
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
        let response_body = response
            .body_mut()
            .with_config()
            .limit(64 * 1024 + 1)
            .read_to_vec()
            .map_err(classify_error)?;
        if response_body.len() > 64 * 1024 {
            return Err(MeasurementFailure::InvalidResponse);
        }
        let duration = started.elapsed();
        Ok(Measurement {
            value: throughput_bps(bytes, duration).ok_or(MeasurementFailure::InvalidResponse)?,
            duration,
        })
    }
}

pub fn validate_settings(settings: &BenchmarkSettings) -> anyhow::Result<()> {
    validate_endpoint(&settings.latency_url)?;
    validate_endpoint(&settings.download_url)?;
    validate_endpoint(&settings.upload_url)?;
    ensure!(
        settings.download_bytes > 0 && settings.download_bytes <= MAX_PAYLOAD_BYTES,
        "download payload must be between 1 byte and 64 MiB"
    );
    ensure!(
        settings.upload_bytes > 0 && settings.upload_bytes <= MAX_PAYLOAD_BYTES,
        "upload payload must be between 1 byte and 64 MiB"
    );
    ensure!(
        settings.request_timeout_ms > 0,
        "request timeout must be positive"
    );
    ensure!(
        settings.startup_timeout_ms > 0,
        "startup timeout must be positive"
    );
    Ok(())
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
    ensure!(
        url.query().is_none(),
        "benchmark endpoint must not contain query parameters; payload settings are added by Proxyctl"
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
        assert!(validate_endpoint("https://speed.example/test?token=secret").is_err());
    }

    #[test]
    fn accepts_https_endpoint_without_credentials() {
        assert!(validate_endpoint("https://speed.cloudflare.com/__down").is_ok());
    }

    #[test]
    fn download_size_parameter_is_replaced_not_duplicated() {
        let base = Url::parse("https://speed.example/__down").unwrap();
        let result = with_bytes_parameter(&base, 1024);
        let pairs = result.query_pairs().collect::<Vec<_>>();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("bytes".into(), "1024".into()));
    }

    #[test]
    fn measurements_work_through_a_local_fake_http_proxy() {
        use std::{
            io::{BufRead, BufReader, Read, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream);
                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();
                let mut content_length = 0usize;
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" || header.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = header.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().unwrap();
                    }
                }
                let mut request_body = vec![0; content_length];
                reader.read_exact(&mut request_body).unwrap();

                let target = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(target).unwrap();
                let response_body = match url.path() {
                    "/__down" => {
                        let bytes = url
                            .query_pairs()
                            .find(|(key, _)| key == "bytes")
                            .unwrap()
                            .1
                            .parse::<usize>()
                            .unwrap();
                        vec![0x33; bytes]
                    }
                    "/__up" => {
                        assert_eq!(request_body, vec![0x5a; 8]);
                        b"ok".to_vec()
                    }
                    path => panic!("unexpected fake endpoint path: {path}"),
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response_body.len()
                );
                let stream = reader.get_mut();
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(&response_body).unwrap();
                stream.flush().unwrap();
            }
        });

        let proxy_url = format!("http://127.0.0.1:{proxy_port}");
        let proxy = Proxy::new(&proxy_url).unwrap();
        let config = Agent::config_builder()
            .proxy(Some(proxy))
            .timeout_global(Some(Duration::from_secs(2)))
            .build();
        let client = BenchmarkHttpClient {
            agent: config.into(),
            latency_url: Url::parse("http://measurement.invalid/__down").unwrap(),
            download_url: Url::parse("http://measurement.invalid/__down").unwrap(),
            upload_url: Url::parse("http://measurement.invalid/__up").unwrap(),
        };

        assert!(client.latency().unwrap().value >= 0.0);
        assert!(client.download(8).unwrap().value > 0.0);
        assert!(client.upload(8).unwrap().value > 0.0);
        server.join().unwrap();
    }

    #[test]
    fn throughput_is_bits_per_second() {
        assert_eq!(throughput_bps(1_000, Duration::from_secs(2)), Some(4_000.0));
        assert_eq!(throughput_bps(0, Duration::from_secs(1)), None);
    }
}
