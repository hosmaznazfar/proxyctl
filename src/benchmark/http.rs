//! Bounded HTTP measurements routed through the benchmark's explicit local proxy.

use std::{
    io::Read,
    time::{Duration, Instant},
};

use anyhow::{Context, ensure};
use ureq::{Agent, Proxy};
use url::Url;

use crate::domain::{BenchmarkSettings, throughput_bps};

const MAX_PAYLOAD_BYTES: u64 = 1024 * 1024;
const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;
/// Ignore tiny fragments that do not provide a useful throughput measurement.
const MIN_PARTIAL_DOWNLOAD_BYTES: u64 = 16 * 1024;
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
    ProxyTunnelFailed,
    TlsFailed,
    HttpStatus(u16),
    ProtocolFailed,
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
            Self::ProxyTunnelFailed => "proxy_tunnel_failed",
            Self::TlsFailed => "tls_failed",
            Self::HttpStatus(_) => "http_status",
            Self::ProtocolFailed => "protocol_failed",
            Self::IncompleteResponse => "incomplete_response",
            Self::ReadFailed => "read_failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn reason(self) -> String {
        match self {
            Self::Timeout => "the measurement request exceeded its time limit".into(),
            Self::Unreachable => "the measurement endpoint could not be reached".into(),
            Self::InvalidResponse => "the measurement endpoint returned an invalid payload".into(),
            Self::Unavailable => "the measurement request failed for an unclassified reason".into(),
            Self::ProxyTunnelFailed => {
                "the selected core could not establish the outbound HTTPS tunnel to the measurement endpoint".into()
            },
            Self::TlsFailed => "the TLS connection to the measurement endpoint failed".into(),
            Self::HttpStatus(status) => format!("the measurement endpoint returned HTTP status {status}"),
            Self::ProtocolFailed => "the measurement endpoint returned an invalid HTTP response".into(),
            Self::IncompleteResponse => "the connection closed before the HTTP exchange completed".into(),
            Self::ReadFailed => "the response stream could not be read".into(),
            Self::Cancelled => "measurement cancelled by user".into(),
        }
    }
}

/// Throttled progress snapshot for one bounded download sample.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TransferProgress {
    pub transferred_bytes: u64,
    pub target_bytes: u64,
    pub elapsed: Duration,
    pub bits_per_second: Option<f64>,
}

impl TransferProgress {
    fn new(transferred_bytes: u64, target_bytes: u64, elapsed: Duration) -> Self {
        Self {
            transferred_bytes,
            target_bytes,
            elapsed,
            bits_per_second: crate::domain::throughput_bps(transferred_bytes, elapsed),
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
        Self::new_with_timeout(
            port,
            settings,
            Duration::from_millis(settings.request_timeout_ms),
        )
    }

    /// Build an isolated local-proxy client with a metric-specific request deadline.
    pub fn new_with_timeout(
        port: u16,
        settings: &BenchmarkSettings,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        validate_settings(settings)?;
        ensure!(port != 0, "benchmark proxy port must be non-zero");
        ensure!(!timeout.is_zero(), "benchmark request timeout must be non-zero");
        let latency_url = validate_endpoint(&settings.latency_url)?;
        let download_url = validate_endpoint(&settings.download_url)?;
        let upload_url = validate_endpoint(&settings.upload_url)?;
        let proxy_url = format!("http://127.0.0.1:{port}");
        let proxy =
            Proxy::new(&proxy_url).context("could not configure the local benchmark HTTP proxy")?;
        let config = Agent::config_builder()
            .proxy(Some(proxy))
            .timeout_global(Some(timeout))
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
            .map_err(classify_response_error)?;
        Ok(Measurement {
            value: duration.as_secs_f64() * 1_000.0,
            duration,
            transferred_bytes: None,
        })
    }

    /// Measure exactly `max_bytes` from a download response, reporting throttled progress.
    ///
    /// Larger remote objects are intentionally cut short. A complete target is a normal sample;
    /// a truncated body can still provide a useful partial measurement after the minimum byte
    /// threshold, matching v2rayN's behavior of retaining observed speed after a transfer error.
    pub fn download<F>(
        &self,
        max_bytes: u64,
        mut progress: F,
    ) -> Result<Measurement, MeasurementFailure>
    where
        F: FnMut(TransferProgress),
    {
        if max_bytes == 0 {
            return Err(MeasurementFailure::InvalidResponse);
        }
        let started = Instant::now();
        let mut response = self
            .agent
            .get(self.download_url.as_str())
            .header("Accept-Encoding", "identity")
            .call()
            // Download responses can fail protocol parsing after the server has
            // begun sending a response (for example, a truncated Content-Length).
            .map_err(classify_response_error)?;
        let mut reader = response.body_mut().as_reader().take(max_bytes);
        let mut buffer = [0_u8; DOWNLOAD_CHUNK_BYTES];
        let mut received = 0_u64;
        let mut last_progress = Instant::now();

        loop {
            let count = match reader.read(&mut buffer) {
                Ok(count) => count,
                Err(error) => {
                    let duration = started.elapsed();
                    progress(TransferProgress::new(received, max_bytes, duration));
                    if received >= MIN_PARTIAL_DOWNLOAD_BYTES {
                        return partial_download_measurement(received, duration);
                    }
                    return Err(classify_body_io_error(error));
                }
            };
            if count == 0 {
                break;
            }
            received = received.saturating_add(count as u64);
            if received > max_bytes {
                return Err(MeasurementFailure::InvalidResponse);
            }
            if last_progress.elapsed() >= PROGRESS_INTERVAL {
                let elapsed = started.elapsed();
                progress(TransferProgress::new(received, max_bytes, elapsed));
                last_progress = Instant::now();
            }
        }

        let duration = started.elapsed();
        progress(TransferProgress::new(received, max_bytes, duration));
        if received < max_bytes {
            if received >= MIN_PARTIAL_DOWNLOAD_BYTES {
                return partial_download_measurement(received, duration);
            }
            return Err(MeasurementFailure::IncompleteResponse);
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
            .map_err(classify_response_error)?;
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


fn partial_download_measurement(
    received: u64,
    duration: Duration,
) -> Result<Measurement, MeasurementFailure> {
    Ok(Measurement {
        value: throughput_bps(received, duration).ok_or(MeasurementFailure::InvalidResponse)?,
        duration,
        transferred_bytes: Some(received),
    })
}

pub fn validate_settings(settings: &BenchmarkSettings) -> anyhow::Result<()> {
    validate_endpoint(&settings.latency_url)?;
    validate_endpoint(&settings.download_url)?;
    validate_endpoint(&settings.upload_url)?;
    ensure!(
        settings.download_bytes > 0 && settings.download_bytes <= MAX_PAYLOAD_BYTES,
        "download sample must be between 1 byte and 1 MiB"
    );
    ensure!(
        settings.upload_bytes > 0 && settings.upload_bytes <= MAX_PAYLOAD_BYTES,
        "upload payload must be between 1 byte and 1 MiB"
    );
    ensure!(
        settings.request_timeout_ms > 0,
        "throughput request timeout must be positive"
    );
    ensure!(
        settings.latency_timeout_ms > 0,
        "latency request timeout must be positive"
    );
    ensure!(
        (1..=3).contains(&settings.probe_concurrency),
        "probe concurrency must be between 1 and 3"
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
    match error {
        ureq::Error::Timeout(_) => MeasurementFailure::Timeout,
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => {
            MeasurementFailure::Unreachable
        }
        ureq::Error::ConnectProxyFailed(_) => MeasurementFailure::ProxyTunnelFailed,
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => MeasurementFailure::TlsFailed,
        ureq::Error::StatusCode(status) => MeasurementFailure::HttpStatus(status),
        ureq::Error::Protocol(_) => MeasurementFailure::ProtocolFailed,
        ureq::Error::Io(error) => classify_request_io_error(error),
        _ => MeasurementFailure::Unavailable,
    }
}

fn classify_response_error(error: ureq::Error) -> MeasurementFailure {
    match error {
        ureq::Error::Io(error) => classify_body_io_error(error),
        // ureq can surface a truncated Content-Length body as a protocol error
        // rather than an UnexpectedEof I/O error. Headers have already arrived,
        // so this is an incomplete exchange, not a request/setup failure.
        ureq::Error::Protocol(_) => MeasurementFailure::IncompleteResponse,
        other => classify_error(other),
    }
}

/// Errors before response headers are received are connection/request failures.
fn classify_request_io_error(error: std::io::Error) -> MeasurementFailure {
    match error.kind() {
        std::io::ErrorKind::TimedOut => MeasurementFailure::Timeout,
        std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::NotConnected
        | std::io::ErrorKind::AddrNotAvailable => MeasurementFailure::Unreachable,
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::BrokenPipe => MeasurementFailure::IncompleteResponse,
        _ => MeasurementFailure::ReadFailed,
    }
}

/// Once a response has started, a reset/EOF means that the HTTP exchange was truncated,
/// not that the endpoint was unreachable.
fn classify_body_io_error(error: std::io::Error) -> MeasurementFailure {
    match error.kind() {
        std::io::ErrorKind::TimedOut => MeasurementFailure::Timeout,
        std::io::ErrorKind::UnexpectedEof
        | std::io::ErrorKind::ConnectionAborted
        | std::io::ErrorKind::ConnectionReset
        | std::io::ErrorKind::BrokenPipe => MeasurementFailure::IncompleteResponse,
        _ => MeasurementFailure::ReadFailed,
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
        let download = client.download(8, |snapshot| progress.push(snapshot)).unwrap();
        assert_eq!(download.transferred_bytes, Some(8));
        assert_eq!(progress.last().map(|value| value.transferred_bytes), Some(8));
        assert_eq!(progress.last().map(|value| value.target_bytes), Some(8));
        assert!(client.upload(8).unwrap().value > 0.0);
        server.join().unwrap();
    }

    #[test]
    fn download_keeps_a_useful_partial_transfer_after_body_truncation() {
        use std::{
            io::{BufReader, Write},
            net::TcpListener,
            thread,
        };

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let _ = read_fake_request(&mut reader);
            let body = vec![0x33; 32 * 1024];
            let stream = reader.get_mut();
            // A truncated chunked stream lets ureq expose bytes already read before
            // reporting the missing terminal chunk to the body reader.
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n8000\r\n",
                )
                .unwrap();
            stream.write_all(&body).unwrap();
            stream.flush().unwrap();
        });
        let proxy = Proxy::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let agent: Agent = Agent::config_builder()
            .proxy(Some(proxy))
            .timeout_global(Some(Duration::from_secs(2)))
            .build()
            .into();
        let client = BenchmarkHttpClient {
            agent,
            latency_url: Url::parse("http://measurement.invalid/ping").unwrap(),
            download_url: Url::parse("http://measurement.invalid/download").unwrap(),
            upload_url: Url::parse("http://measurement.invalid/upload").unwrap(),
        };

        let measurement = client.download(64 * 1024, |_| {}).unwrap();
        assert_eq!(measurement.transferred_bytes, Some(32 * 1024));
        assert!(measurement.value > 0.0);
        server.join().unwrap();
    }

    #[test]
    fn download_rejects_early_eof_instead_of_scoring_a_short_sample() {
        use std::{io::{BufReader, Write}, net::TcpListener, thread};

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let _ = read_fake_request(&mut reader);
            let stream = reader.get_mut();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata").unwrap();
            stream.flush().unwrap();
        });
        let proxy = Proxy::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let agent: Agent = Agent::config_builder()
            .proxy(Some(proxy))
            .timeout_global(Some(Duration::from_secs(2)))
            .build()
            .into();
        let client = BenchmarkHttpClient {
            agent,
            latency_url: Url::parse("http://measurement.invalid/ping").unwrap(),
            download_url: Url::parse("http://measurement.invalid/download").unwrap(),
            upload_url: Url::parse("http://measurement.invalid/upload").unwrap(),
        };
        assert_eq!(
            client.download(8, |_| {}),
            Err(MeasurementFailure::IncompleteResponse)
        );
        server.join().unwrap();
    }

    #[test]
    fn download_preserves_http_status_failures_after_response_headers() {
        use std::{io::{BufReader, Write}, net::TcpListener, thread};

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let (method, _, _) = read_fake_request(&mut reader);
            assert_eq!(method, "CONNECT");
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();
            reader.get_mut().flush().unwrap();
            let (method, _, _) = read_fake_request(&mut reader);
            assert_eq!(method, "GET");
            let stream = reader.get_mut();
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let proxy = Proxy::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let agent: Agent = Agent::config_builder()
            .proxy(Some(proxy))
            .timeout_global(Some(Duration::from_secs(2)))
            .build()
            .into();
        let client = BenchmarkHttpClient {
            agent,
            latency_url: Url::parse("http://measurement.invalid/ping").unwrap(),
            download_url: Url::parse("http://measurement.invalid/download").unwrap(),
            upload_url: Url::parse("http://measurement.invalid/upload").unwrap(),
        };

        assert_eq!(
            client.download(8, |_| {}),
            Err(MeasurementFailure::HttpStatus(503))
        );
        server.join().unwrap();
    }

    #[test]
    fn upload_rejects_unsuccessful_http_response() {
        use std::{io::{BufReader, Write}, net::TcpListener, thread};

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let (method, _, _) = read_fake_request(&mut reader);
            assert_eq!(method, "CONNECT");
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();
            reader.get_mut().flush().unwrap();
            let (method, _, body) = read_fake_request(&mut reader);
            assert_eq!(method, "POST");
            assert_eq!(body, vec![0x5a; 8]);
            let stream = reader.get_mut();
            stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let proxy = Proxy::new(&format!("http://127.0.0.1:{port}")).unwrap();
        let agent: Agent = Agent::config_builder()
            .proxy(Some(proxy))
            .timeout_global(Some(Duration::from_secs(2)))
            .build()
            .into();
        let client = BenchmarkHttpClient {
            agent,
            latency_url: Url::parse("http://measurement.invalid/ping").unwrap(),
            download_url: Url::parse("http://measurement.invalid/download").unwrap(),
            upload_url: Url::parse("http://measurement.invalid/upload").unwrap(),
        };

        assert_eq!(client.upload(8), Err(MeasurementFailure::HttpStatus(500)));
        server.join().unwrap();
    }

    #[test]
    fn transfer_progress_reports_exact_target_and_monotonic_rate() {
        let progress = TransferProgress::new(1_024, 2_048, Duration::from_secs(2));
        assert_eq!(progress.transferred_bytes, 1_024);
        assert_eq!(progress.target_bytes, 2_048);
        assert_eq!(progress.elapsed, Duration::from_secs(2));
        assert_eq!(progress.bits_per_second, Some(4_096.0));
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
    fn classifies_request_and_response_failures_by_phase() {
        assert_eq!(
            classify_request_io_error(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            MeasurementFailure::Unreachable
        );
        assert_eq!(
            classify_body_io_error(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            MeasurementFailure::IncompleteResponse
        );
        assert_eq!(
            classify_body_io_error(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            MeasurementFailure::IncompleteResponse
        );
        assert_eq!(
            classify_body_io_error(std::io::Error::other("socket read failed")),
            MeasurementFailure::ReadFailed
        );
    }

    #[test]
    fn classifies_ureq_transport_failures_without_exposing_diagnostics() {
        assert_eq!(
            classify_error(ureq::Error::Timeout(ureq::Timeout::Global)),
            MeasurementFailure::Timeout
        );
        assert_eq!(
            classify_error(ureq::Error::HostNotFound),
            MeasurementFailure::Unreachable
        );
        assert_eq!(
            classify_error(ureq::Error::ConnectProxyFailed(
                "secret proxy detail".into()
            )),
            MeasurementFailure::ProxyTunnelFailed
        );
        assert_eq!(
            classify_error(ureq::Error::Tls("secret tls detail")),
            MeasurementFailure::TlsFailed
        );
        assert_eq!(
            classify_error(ureq::Error::StatusCode(502)),
            MeasurementFailure::HttpStatus(502)
        );
    }

    #[test]
    fn throughput_is_bits_per_second() {
        assert_eq!(throughput_bps(1_000, Duration::from_secs(2)), Some(4_000.0));
        assert_eq!(throughput_bps(0, Duration::from_secs(1)), None);
    }
}
