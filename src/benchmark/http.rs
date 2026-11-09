//! Bounded HTTP measurements routed through the benchmark's explicit local proxy.

use std::{
    io::Read,
    time::{Duration, Instant},
};

use anyhow::{Context, ensure};
use ureq::{Agent, Proxy};
use url::Url;

use crate::domain::{BenchmarkSettings, throughput_bps};

const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(200);

/// A successful, timed HTTP measurement.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Measurement {
    pub value: f64,
    pub duration: Duration,
    pub transferred_bytes: Option<u64>,
}

/// Safe failure classification; deliberately excludes raw URLs and library diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeasurementFailure {
    Timeout,
    Unreachable,
    InvalidResponse,
    Unavailable,
    IncompleteResponse,
    ReadFailed,
    Cancelled,
}

impl MeasurementFailure {
    pub const fn category(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unreachable => "unreachable",
            Self::InvalidResponse => "invalid_response",
            Self::Unavailable => "unavailable",
            Self::IncompleteResponse => "incomplete_response",
            Self::ReadFailed => "read_failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::Timeout => "the measurement request exceeded its time limit",
            Self::Unreachable => "the measurement endpoint could not be reached",
            Self::InvalidResponse => "the measurement endpoint returned an invalid payload",
            Self::Unavailable => "the measurement request failed",
            Self::IncompleteResponse => "the download connection closed before the response completed",
            Self::ReadFailed => "the response stream could not be read",
            Self::Cancelled => "measurement cancelled by user",
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

    /// Measure a real HTTP response through the proxy; 204 No Content is valid.
    pub fn latency(&self) -> Result<Measurement, MeasurementFailure> {
        let started = Instant::now();
        let mut response = self
            .agent
            .get(self.latency_url.as_str())
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(classify_error)?;
        let duration = started.elapsed();
        // Some configurable ping endpoints return a small body; discard it with a strict cap.
        response
            .body_mut()
            .with_config()
            .limit(64 * 1024)
            .read_to_vec()
            .map_err(classify_error)?;
        Ok(Measurement {
            value: duration.as_secs_f64() * 1_000.0,
            duration,
            transferred_bytes: None,
        })
    }

    /// Stream a download until EOF, reporting throttled byte progress.
    ///
    /// `max_bytes` is a safety ceiling. Different providers may return different object sizes.
    pub fn download<F>(
        &self,
        max_bytes: u64,
        mut progress: F,
    ) -> Result<Measurement, MeasurementFailure>
    where
        F: FnMut(u64),
    {
        let started = Instant::now();
        let mut response = self
            .agent
            .get(self.download_url.as_str())
            .header("Accept-Encoding", "identity")
            .call()
            .map_err(classify_error)?;
        let mut reader = response
            .body_mut()
            .with_config()
            .limit(max_bytes)
            .reader()
            .take(max_bytes);
        let mut buffer = [0_u8; DOWNLOAD_CHUNK_BYTES];
        let mut received = 0_u64;
        let mut last_progress = Instant::now();

        loop {
            let count = reader.read(&mut buffer).map_err(classify_io_error)?;
            if count == 0 {
                break;
            }
            received = received.saturating_add(count as u64);
            if received > max_bytes {
                return Err(MeasurementFailure::InvalidResponse);
            }
            if last_progress.elapsed() >= PROGRESS_INTERVAL {
                progress(received);
                last_progress = Instant::now();
            }
        }

        let duration = started.elapsed();
        progress(received);
        if received == 0 {
            return Err(MeasurementFailure::InvalidResponse);
        }
        Ok(Measurement {
            value: throughput_bps(received, duration).ok_or(MeasurementFailure::InvalidResponse)?,
            duration,
            transferred_bytes: Some(received),
        })
    }

    /// Upload a deterministic in-memory payload and wait for a successful response.
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
            transferred_bytes: Some(bytes),
        })
    }
}

pub fn validate_settings(settings: &BenchmarkSettings) -> anyhow::Result<()> {
    validate_endpoint(&settings.latency_url)?;
    validate_endpoint(&settings.download_url)?;
    validate_endpoint(&settings.upload_url)?;
    ensure!(
        settings.download_bytes > 0 && settings.download_bytes <= MAX_PAYLOAD_BYTES,
        "download safety limit must be between 1 byte and 64 MiB"
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
        "benchmark endpoint must not contain query parameters"
    );
    Ok(url)
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
    } else if message.contains("status code: 4") || message.contains("status code: 5") {
        MeasurementFailure::InvalidResponse
    } else {
        MeasurementFailure::Unavailable
    }
}

fn classify_io_error(error: std::io::Error) -> MeasurementFailure {
    if error.kind() == std::io::ErrorKind::TimedOut {
        MeasurementFailure::Timeout
    } else if matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
    ) {
        MeasurementFailure::Unreachable
    } else if error.kind() == std::io::ErrorKind::UnexpectedEof {
        MeasurementFailure::IncompleteResponse
    } else {
        MeasurementFailure::ReadFailed
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
    fn accepts_v2rayn_style_https_endpoints() {
        assert!(validate_endpoint("https://www.google.com/generate_204").is_ok());
        assert!(validate_endpoint("https://cachefly.cachefly.net/10mb.test").is_ok());
        assert!(validate_endpoint("https://speed.cloudflare.com/__up").is_ok());
    }

    #[test]
    fn measurements_work_through_a_local_fake_http_proxy() {
        use std::{
            io::{BufReader, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream);
                let (method, target, request_body) = read_fake_request(&mut reader);
                let (method, target, request_body) = if method == "CONNECT" {
                    reader
                        .get_mut()
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .unwrap();
                    reader.get_mut().flush().unwrap();
                    read_fake_request(&mut reader)
                } else {
                    (method, target, request_body)
                };
                let target = if target.starts_with("http://") {
                    target
                } else {
                    format!("http://measurement.invalid{target}")
                };
                let url = Url::parse(&target).unwrap();
                let response_body = match (method.as_str(), url.path()) {
                    ("GET", "/ping") => Vec::new(),
                    ("GET", "/download") => vec![0x33; 32],
                    ("POST", "/upload") => {
                        assert_eq!(request_body, vec![0x5a; 8]);
                        b"ok".to_vec()
                    }
                    other => panic!("unexpected fake request: {other:?}"),
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
            latency_url: Url::parse("http://measurement.invalid/ping").unwrap(),
            download_url: Url::parse("http://measurement.invalid/download").unwrap(),
            upload_url: Url::parse("http://measurement.invalid/upload").unwrap(),
        };

        assert!(client.latency().unwrap().value >= 0.0);
        let mut progress = Vec::new();
        let download = client.download(8, |bytes| progress.push(bytes)).unwrap();
        assert_eq!(download.transferred_bytes, Some(8));
        assert_eq!(progress.last(), Some(&8));
        assert!(client.upload(8).unwrap().value > 0.0);
        server.join().unwrap();
    }

    fn read_fake_request(
        reader: &mut std::io::BufReader<std::net::TcpStream>,
    ) -> (String, String, Vec<u8>) {
        use std::io::{BufRead, Read};

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
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).unwrap();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap().to_owned();
        let target = parts.next().unwrap().to_owned();
        (method, target, body)
    }

    #[test]
    fn classifies_interrupted_download_streams_separately() {
        assert_eq!(
            classify_io_error(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            MeasurementFailure::IncompleteResponse
        );
        assert_eq!(
            classify_io_error(std::io::Error::other("socket read failed")),
            MeasurementFailure::ReadFailed
        );
    }

    #[test]
    fn throughput_is_bits_per_second() {
        assert_eq!(throughput_bps(1_000, Duration::from_secs(2)), Some(4_000.0));
        assert_eq!(throughput_bps(0, Duration::from_secs(1)), None);
    }
}
