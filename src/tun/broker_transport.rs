//! Bounded one-frame Unix-stream transport for broker responses.
//!
//! The caller owns connection authentication and lifecycle. This module only transfers one
//! validated response frame with a monotonic deadline and strict pre-allocation length checks.

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};

#[cfg(target_os = "linux")]
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use super::privilege_broker::{
    MAX_SOCKET_MARK_RESPONSE_BYTES, SocketMarkBrokerResponse, decode_socket_mark_response,
    encode_socket_mark_response,
};

#[cfg(target_os = "linux")]
pub const MAX_BROKER_RESPONSE_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Write exactly one validated response frame before the supplied bounded deadline.
///
/// The stream is not reused for another message. The caller should shut down its write side
/// after this succeeds so the peer observes an unambiguous one-response connection.
#[cfg(target_os = "linux")]
pub fn write_socket_mark_response(
    stream: &mut UnixStream,
    response: &SocketMarkBrokerResponse,
    timeout: Duration,
) -> Result<()> {
    ensure!(
        !timeout.is_zero() && timeout <= MAX_BROKER_RESPONSE_IO_TIMEOUT,
        "broker response write timeout is outside the permitted bound"
    );
    let frame = encode_socket_mark_response(response)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("broker response write deadline overflow")?;
    let mut remaining_bytes = frame.as_slice();
    while !remaining_bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "broker response write exceeded its deadline");
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(remaining_bytes) {
            Ok(0) => anyhow::bail!("broker response stream closed during write"),
            Ok(count) => remaining_bytes = &remaining_bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                anyhow::bail!("broker response write exceeded its deadline")
            }
            Err(error) => return Err(error).context("cannot write broker response frame"),
        }
    }
    stream.flush().context("cannot flush broker response frame")?;
    Ok(())
}

/// Read exactly one bounded response frame before a monotonic deadline.
///
/// The four-byte length is checked before allocating the payload. Truncated, oversized,
/// malformed, unknown-field, invalid-record, and trailing-frame bytes are rejected.
#[cfg(target_os = "linux")]
pub fn read_socket_mark_response(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<SocketMarkBrokerResponse> {
    ensure!(
        !timeout.is_zero() && timeout <= MAX_BROKER_RESPONSE_IO_TIMEOUT,
        "broker response read timeout is outside the permitted bound"
    );
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("broker response read deadline overflow")?;
    let mut header = [0u8; 4];
    read_exact_before_deadline(stream, &mut header, deadline)?;
    let length = u32::from_le_bytes(header) as usize;
    ensure!(
        length > 0 && length <= MAX_SOCKET_MARK_RESPONSE_BYTES,
        "broker response frame length is invalid"
    );
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&header);
    frame.resize(4 + length, 0);
    read_exact_before_deadline(stream, &mut frame[4..], deadline)?;
    decode_socket_mark_response(&frame)
}

#[cfg(target_os = "linux")]
fn read_exact_before_deadline(
    stream: &mut UnixStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<()> {
    while !buffer.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "broker response read exceeded its deadline");
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(buffer) {
            Ok(0) => anyhow::bail!("broker response frame ended before completion"),
            Ok(count) => buffer = &mut buffer[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                anyhow::bail!("broker response read exceeded its deadline")
            }
            Err(error) => return Err(error).context("cannot read broker response frame"),
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn read_socket_mark_response(
    _stream: &mut (),
    _timeout: std::time::Duration,
) -> anyhow::Result<()> {
    anyhow::bail!("socket-mark broker transport is supported only on Linux");
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::tun::{
        privilege_broker::{BrokerSocketTransport, BROKER_REQUEST_VERSION},
        socket_diag_records::{SocketAddressFamily, SocketDiagnosticRecord},
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        os::unix::net::UnixStream,
        thread,
    };

    fn response() -> SocketMarkBrokerResponse {
        SocketMarkBrokerResponse {
            version: BROKER_REQUEST_VERSION,
            expected_peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)), 443),
            transport: BrokerSocketTransport::Tcp,
            expected_mark: 0x42,
            mark_mask: 0xff,
            records: vec![SocketDiagnosticRecord {
                family: SocketAddressFamily::Ipv4,
                state: 1,
                local_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                local_port: 41000,
                remote_address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8)),
                remote_port: 443,
                inode: 77,
                mark: 0x42,
            }],
        }
    }

    #[test]
    fn transfers_one_validated_response_over_a_unix_stream() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let expected = response();
        let sender = thread::spawn(move || {
            write_socket_mark_response(&mut writer, &expected, Duration::from_secs(1)).unwrap();
        });
        let actual = read_socket_mark_response(&mut reader, Duration::from_secs(1)).unwrap();
        sender.join().unwrap();
        assert_eq!(actual, response());
    }

    #[test]
    fn rejects_invalid_timeouts_before_io() {
        let (_writer, mut reader) = UnixStream::pair().unwrap();
        assert!(read_socket_mark_response(&mut reader, Duration::ZERO).is_err());
        assert!(
            read_socket_mark_response(
                &mut reader,
                MAX_BROKER_RESPONSE_IO_TIMEOUT + Duration::from_millis(1)
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_truncated_response_frames() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&[8, 0, 0, 0, b'{']).unwrap();
        drop(writer);
        assert!(read_socket_mark_response(&mut reader, Duration::from_secs(1)).is_err());
    }
}
