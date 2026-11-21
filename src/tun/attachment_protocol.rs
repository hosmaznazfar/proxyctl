//! Generation-bound attachment offer/acknowledgement protocol for a core-side adapter.
//!
//! This protocol authenticates the connected peer using SO_PEERCRED and binds a
//! descriptor handoff to an activation UUID, generation, interface, and random nonce.
//! The receiver must call its real core-specific adoption function before acknowledging.
#![cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::{fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd}, unix::net::UnixStream},
    time::Duration,
};
use super::{descriptor_transfer, process::ProcessIdentity};

const VERSION: u8 = 1;
const MAX_FRAME: usize = 4096;
const HANDOFF_IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentOffer {
    pub version: u8,
    pub activation_id: String,
    pub generation: u64,
    pub interface_name: String,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentAck {
    version: u8,
    activation_id: String,
    generation: u64,
    interface_name: String,
    nonce: [u8; 32],
    adopted: bool,
}

impl AttachmentOffer {
    pub fn create(activation_id: String, generation: u64, interface_name: String) -> Result<Self> {
        validate_identity(&activation_id, generation, &interface_name)?;
        let mut nonce = [0u8; 32];
        File::open("/dev/urandom")
            .context("cannot open kernel random source for attachment nonce")?
            .read_exact(&mut nonce)
            .context("cannot read attachment nonce")?;
        ensure!(nonce.iter().any(|byte| *byte != 0), "kernel returned an all-zero attachment nonce");
        Ok(Self { version: VERSION, activation_id, generation, interface_name, nonce })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == VERSION, "unsupported attachment protocol version");
        validate_identity(&self.activation_id, self.generation, &self.interface_name)?;
        ensure!(self.nonce.iter().any(|byte| *byte != 0), "attachment nonce is invalid");
        Ok(())
    }
}

/// Verify that the connected socket peer is the exact expected process instance.
pub fn verify_peer_process(stream: &UnixStream, expected: &ProcessIdentity) -> Result<()> {
    expected.validate()?;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    ensure!(result == 0, "SO_PEERCRED failed: {}", std::io::Error::last_os_error());
    ensure!(length as usize == std::mem::size_of::<libc::ucred>(), "SO_PEERCRED returned an invalid credential size");
    ensure!(credentials.pid > 0 && credentials.pid as u32 == expected.pid, "attachment peer PID does not match the expected child");
    ensure!(credentials.uid == unsafe { libc::geteuid() }, "attachment peer UID does not match the current user");
    let actual = ProcessIdentity::capture(credentials.pid as u32)?;
    ensure!(actual == *expected && actual.verify()?, "attachment peer process identity changed");
    Ok(())
}

/// Send offer metadata before the descriptor so the receiver can validate the generation first.
pub fn send_offer(stream: &mut UnixStream, offer: &AttachmentOffer) -> Result<()> {
    offer.validate()?;
    configure_handoff_timeouts(stream)?;
    write_frame(stream, offer)
}

/// Receive and validate one bounded attachment offer.
pub fn receive_offer(stream: &mut UnixStream) -> Result<AttachmentOffer> {
    configure_handoff_timeouts(stream)?;
    let offer: AttachmentOffer = read_frame(stream)?;
    offer.validate()?;
    Ok(offer)
}

/// Send a positive adoption receipt only after the caller's core-specific attach operation succeeds.
pub fn send_adoption_ack(stream: &mut UnixStream, offer: &AttachmentOffer) -> Result<()> {
    offer.validate()?;
    configure_handoff_timeouts(stream)?;
    let ack = AttachmentAck {
        version: VERSION,
        activation_id: offer.activation_id.clone(),
        generation: offer.generation,
        interface_name: offer.interface_name.clone(),
        nonce: offer.nonce,
        adopted: true,
    };
    write_frame(stream, &ack)
}

/// Require a positive acknowledgement matching every offer field.
pub fn receive_adoption_ack(stream: &mut UnixStream, offer: &AttachmentOffer) -> Result<()> {
    offer.validate()?;
    configure_handoff_timeouts(stream)?;
    let ack: AttachmentAck = read_frame(stream)?;
    ensure!(ack.version == VERSION, "unsupported attachment acknowledgement version");
    validate_identity(&ack.activation_id, ack.generation, &ack.interface_name)?;
    ensure!(ack.nonce.iter().any(|byte| *byte != 0), "acknowledgement nonce is invalid");
    ensure!(ack.adopted, "core-side adapter rejected descriptor adoption");
    ensure!(
        ack.activation_id == offer.activation_id
            && ack.generation == offer.generation
            && ack.interface_name == offer.interface_name
            && ack.nonce == offer.nonce,
        "attachment acknowledgement does not match the outstanding offer"
    );
    Ok(())
}


/// Send an offer, transfer the descriptor, and require a matching adoption receipt.
/// The socket peer must be the exact expected child process.
pub fn send_attachment(
    stream: &mut UnixStream,
    descriptor: BorrowedFd<'_>,
    offer: &AttachmentOffer,
    expected_child: &ProcessIdentity,
) -> Result<()> {
    configure_handoff_timeouts(stream)?;
    verify_peer_process(stream, expected_child)?;
    send_offer(stream, offer)?;
    descriptor_transfer::send_descriptor(stream, descriptor)?;
    receive_adoption_ack(stream, offer)
}

/// Receive an offer and descriptor, acknowledging only after real adapter adoption.
pub fn receive_and_adopt<F>(
    stream: &mut UnixStream,
    expected_parent: &ProcessIdentity,
    expected_offer: &AttachmentOffer,
    adopt: F,
) -> Result<()>
where
    F: FnOnce(&AttachmentOffer, OwnedFd) -> Result<()>,
{
    configure_handoff_timeouts(stream)?;
    verify_peer_process(stream, expected_parent)?;
    let received_offer = receive_offer(stream)?;
    ensure!(&received_offer == expected_offer, "received attachment offer differs from expected activation");
    let descriptor = descriptor_transfer::receive_descriptor(stream)?;
    adopt(&received_offer, descriptor).context("core-specific descriptor adoption failed")?;
    send_adoption_ack(stream, &received_offer)
}

/// Receiver-side helper. The callback must transfer ownership to the real core adapter;
/// the acknowledgement is emitted only after that callback returns success.
pub fn adopt_and_ack<F>(
    stream: &mut UnixStream,
    descriptor: OwnedFd,
    expected: &AttachmentOffer,
    adopt: F,
) -> Result<()>
where
    F: FnOnce(&AttachmentOffer, OwnedFd) -> Result<()>,
{
    configure_handoff_timeouts(stream)?;
    let received = receive_offer(stream)?;
    ensure!(&received == expected, "received attachment offer differs from the expected activation");
    adopt(&received, descriptor).context("core-specific descriptor adoption failed")?;
    send_adoption_ack(stream, &received)
}


fn configure_handoff_timeouts(stream: &UnixStream) -> Result<()> {
    stream.set_read_timeout(Some(HANDOFF_IO_TIMEOUT))
        .context("cannot set attachment protocol read deadline")?;
    stream.set_write_timeout(Some(HANDOFF_IO_TIMEOUT))
        .context("cannot set attachment protocol write deadline")?;
    Ok(())
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    configure_handoff_timeouts(stream)?;
    let payload = serde_json::to_vec(value).context("cannot encode attachment protocol frame")?;
    ensure!(!payload.is_empty() && payload.len() <= MAX_FRAME, "attachment frame exceeds its size bound");
    stream.write_all(&(payload.len() as u32).to_le_bytes()).context("cannot write attachment frame length")?;
    stream.write_all(&payload).context("cannot write attachment frame payload")?;
    stream.flush().context("cannot flush attachment frame")
}

fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
    let deadline = std::time::Instant::now() + HANDOFF_IO_TIMEOUT;
    let mut header = [0u8; 4];
    read_exact_until(stream, &mut header, deadline).context("cannot read attachment frame length")?;
    let length = u32::from_le_bytes(header) as usize;
    ensure!(length >= 2 && length <= MAX_FRAME, "attachment frame length is invalid");
    let mut payload = vec![0u8; length];
    read_exact_until(stream, &mut payload, deadline).context("cannot read attachment frame payload")?;
    serde_json::from_slice(&payload).context("attachment frame is malformed or contains unknown fields")
}

fn read_exact_until(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: std::time::Instant) -> Result<()> {
    use std::io::ErrorKind;
    while !bytes.is_empty() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        ensure!(!remaining.is_zero(), "attachment frame exceeded its deadline");
        stream.set_read_timeout(Some(remaining))?;
        match stream.read(bytes) {
            Ok(0) => anyhow::bail!("attachment frame ended before completion"),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => anyhow::bail!("attachment frame exceeded its deadline"),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate_identity(activation_id: &str, generation: u64, interface_name: &str) -> Result<()> {
    ensure!(
        activation_id.len() == 36
            && activation_id.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) { byte == b'-' }
                else { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() }
            }),
        "attachment activation ID must be a canonical lowercase UUID"
    );
    ensure!(generation > 0, "attachment generation must be positive");
    ensure!(
        !interface_name.is_empty()
            && interface_name.len() < 16
            && interface_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
        "attachment interface name is invalid"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::fd::AsFd, os::unix::net::UnixStream};

    fn offer() -> AttachmentOffer {
        AttachmentOffer::create(
            "12345678-1234-4234-8234-123456789abc".into(),
            7,
            "tun-proxyctl".into(),
        ).unwrap()
    }

    #[test]
    fn rejects_tiny_frame_length_before_json_decode() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(&1u32.to_le_bytes()).unwrap();
        sender.write_all(b"x").unwrap();
        assert!(read_frame::<AttachmentOffer>(&mut receiver).is_err());
    }

    #[test]
    fn offer_round_trips_with_nonce_and_generation() {
        let expected = offer();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        send_offer(&mut sender, &expected).unwrap();
        assert_eq!(receive_offer(&mut receiver).unwrap(), expected);
    }

    #[test]
    fn acknowledgement_is_bound_to_exact_offer() {
        let expected = offer();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        send_adoption_ack(&mut sender, &expected).unwrap();
        receive_adoption_ack(&mut receiver, &expected).unwrap();
    }

    #[test]
    fn rejects_ack_for_different_generation() {
        let expected = offer();
        let mut other = expected.clone();
        other.generation += 1;
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        send_adoption_ack(&mut sender, &other).unwrap();
        assert!(receive_adoption_ack(&mut receiver, &expected).is_err());
    }

    #[test]
    fn acknowledgement_follows_successful_adoption_callback() {
        let expected = offer();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let descriptor = std::fs::File::open("/dev/null").unwrap().into();
        let offer_copy = expected.clone();
        let worker = std::thread::spawn(move || adopt_and_ack(&mut receiver, descriptor, &offer_copy, |_offer, fd| {
            ensure!(fd.as_fd().as_raw_fd() >= 0, "invalid received descriptor");
            Ok(())
        }));
        send_offer(&mut sender, &expected).unwrap();
        worker.join().unwrap().unwrap();
        receive_adoption_ack(&mut sender, &expected).unwrap();
    }
}
