//! Direct TCP reachability measurements, independent of any proxy core.

use std::{
    net::{TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

use crate::benchmark::http::{Measurement, MeasurementFailure};

/// Measure TCP connection establishment to the node's advertised endpoint.
///
/// DNS resolution is performed by the operating system. The timeout bounds each
/// address connection attempt; it does not alter resolver or network settings.
pub fn ping(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Measurement, MeasurementFailure> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| MeasurementFailure::Unreachable)?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(MeasurementFailure::Unreachable);
    }

    let mut timed_out = false;
    for address in addresses {
        let started = Instant::now();
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                let duration = started.elapsed();
                drop(stream);
                return Ok(Measurement {
                    value: duration.as_secs_f64() * 1_000.0,
                    duration,
                    transferred_bytes: None,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => timed_out = true,
            Err(_) => {}
        }
    }

    if timed_out {
        Err(MeasurementFailure::Timeout)
    } else {
        Err(MeasurementFailure::Unreachable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::TcpListener, thread};

    #[test]
    fn measures_a_loopback_tcp_listener() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let _ = listener.accept().unwrap();
        });

        let result = ping("127.0.0.1", port, Duration::from_secs(1)).unwrap();
        assert!(result.value >= 0.0);
        server.join().unwrap();
    }

    #[test]
    fn rejects_an_unresolvable_host() {
        assert_eq!(
            ping("invalid.invalid", 443, Duration::from_millis(100))
                .unwrap_err(),
            MeasurementFailure::Unreachable
        );
    }
}
