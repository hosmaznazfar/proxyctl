//! Bounded, typed replies from the privileged TUN supervisor.
//!
//! The handoff's stdout pipe is a dedicated one-way acknowledgement channel. Human-readable
//! diagnostics remain on stderr, and a successful sudo spawn is never treated as activation.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[cfg(target_os = "linux")]
use super::session_record::SessionRecord;

pub const REPLY_VERSION: u16 = 1;
pub const MAX_REPLY_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum SupervisorOutcome {
    /// The request was understood, but no core/session was started.
    NotStarted { reason: String },
    /// The supervisor has durably committed the exact privileged process identity.
    #[cfg(target_os = "linux")]
    Started { session: SessionRecord },
    /// The supervisor rejected the request or encountered an error before startup.
    Failed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorReply {
    pub version: u16,
    pub outcome: SupervisorOutcome,
}

impl SupervisorReply {
    pub fn not_started(reason: impl AsRef<str>) -> Self {
        Self {
            version: REPLY_VERSION,
            outcome: SupervisorOutcome::NotStarted {
                reason: bounded_reason(reason.as_ref()),
            },
        }
    }

    pub fn failed(reason: impl AsRef<str>) -> Self {
        Self {
            version: REPLY_VERSION,
            outcome: SupervisorOutcome::Failed {
                reason: bounded_reason(reason.as_ref()),
            },
        }
    }

    #[cfg(target_os = "linux")]
    pub fn started(session: SessionRecord) -> Result<Self> {
        session.validate()?;
        Ok(Self {
            version: REPLY_VERSION,
            outcome: SupervisorOutcome::Started { session },
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == REPLY_VERSION,
            "unsupported supervisor reply version"
        );
        match &self.outcome {
            SupervisorOutcome::NotStarted { reason } | SupervisorOutcome::Failed { reason } => {
                validate_reason(reason)?;
            }
            #[cfg(target_os = "linux")]
            SupervisorOutcome::Started { session } => session.validate()?,
        }
        Ok(())
    }
}

/// Keep diagnostics safe for the single-line acknowledgement protocol.
fn bounded_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|character| !character.is_control())
        .take(1024)
        .collect()
}

fn validate_reason(reason: &str) -> Result<()> {
    ensure!(!reason.is_empty(), "supervisor reply reason is empty");
    ensure!(
        reason.chars().count() <= 1024,
        "supervisor reply reason exceeds size limit"
    );
    ensure!(
        !reason.chars().any(char::is_control),
        "supervisor reply reason contains control characters"
    );
    Ok(())
}

/// Write exactly one bounded JSON reply and flush the acknowledgement pipe.
pub fn write_reply<W: Write>(mut writer: W, reply: &SupervisorReply) -> Result<()> {
    reply.validate()?;
    let mut bytes = serde_json::to_vec(reply).context("cannot encode supervisor reply")?;
    ensure!(
        bytes.len() < MAX_REPLY_BYTES,
        "supervisor reply exceeds size limit"
    );
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .context("cannot write supervisor reply")?;
    writer.flush().context("cannot flush supervisor reply")
}

/// Read exactly one bounded newline-delimited reply frame without waiting for pipe EOF.
///
/// The privileged supervisor closes its acknowledgement descriptor and then remains alive
/// monitoring the TUN session. A core or launcher descendant may still hold an inherited
/// descriptor, so EOF is not a valid startup-frame delimiter.
pub fn read_reply<R: Read>(mut reader: R) -> Result<SupervisorReply> {
    let mut bytes = Vec::with_capacity(512);
    loop {
        ensure!(
            bytes.len() < MAX_REPLY_BYTES,
            "supervisor reply size is invalid"
        );
        let mut byte = [0u8; 1];
        let count = reader
            .read(&mut byte)
            .context("cannot read supervisor acknowledgement")?;
        ensure!(
            count != 0,
            "supervisor acknowledgement ended before its frame delimiter"
        );
        match byte[0] {
            b'\n' => break,
            b'\r' => anyhow::bail!("supervisor reply contains a carriage return"),
            value => bytes.push(value),
        }
    }
    ensure!(!bytes.is_empty(), "supervisor reply is empty");
    let reply: SupervisorReply =
        serde_json::from_slice(&bytes).context("supervisor reply is malformed")?;
    reply.validate()?;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_round_trips_over_the_acknowledgement_stream() {
        let reply = SupervisorReply::not_started("validation only");
        let mut bytes = Vec::new();
        write_reply(&mut bytes, &reply).unwrap();
        assert_eq!(read_reply(bytes.as_slice()).unwrap(), reply);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn started_acknowledgement_carries_the_validated_session_identity() {
        use crate::tun::{
            launch_spec::CoreKind, process::ProcessIdentity, session_record::SessionRecord,
        };
        use std::path::PathBuf;

        let session = SessionRecord {
            schema_version: 2,
            invoking_uid: 1000,
            session_nonce: "12345678-1234-4234-8234-123456789abc".into(),
            activation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            generation: 4,
            core: CoreKind::Xray,
            resolved_family: Some(crate::tun::address_family::ResolvedTunAddressFamily::DualStack),
            process: ProcessIdentity {
                pid: 42,
                start_ticks: 99,
                executable: PathBuf::from("/home/user/.local/share/proxyctl/cores/xray/xray"),
            },
        };
        let reply = SupervisorReply::started(session.clone()).unwrap();
        let mut bytes = Vec::new();
        write_reply(&mut bytes, &reply).unwrap();
        assert_eq!(read_reply(bytes.as_slice()).unwrap(), reply);
        assert!(matches!(
            reply.outcome,
            SupervisorOutcome::Started { session: returned } if returned == session
        ));
    }

    #[test]
    fn reads_frame_without_waiting_for_stream_eof() {
        struct FrameOnlyReader {
            bytes: Vec<u8>,
            offset: usize,
        }

        impl std::io::Read for FrameOnlyReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                assert!(
                    self.offset < self.bytes.len(),
                    "reader attempted to wait for EOF after the complete frame"
                );
                buffer[0] = self.bytes[self.offset];
                self.offset += 1;
                Ok(1)
            }
        }

        let reply = SupervisorReply::not_started("frame complete");
        let mut bytes = Vec::new();
        write_reply(&mut bytes, &reply).unwrap();
        let reader = FrameOnlyReader { bytes, offset: 0 };
        assert_eq!(read_reply(reader).unwrap(), reply);
    }

    #[test]
    fn rejects_unknown_fields_and_versions() {
        let unknown = br#"{"version":1,"outcome":"failed","reason":"no","extra":true}"#;
        assert!(read_reply(unknown.as_slice()).is_err());
        let unsupported = br#"{"version":9,"outcome":"failed","reason":"no"}"#;
        assert!(read_reply(unsupported.as_slice()).is_err());
    }

    #[test]
    fn rejects_empty_oversized_and_trailing_garbage_replies() {
        assert!(read_reply([].as_slice()).is_err());
        assert!(read_reply(vec![b'x'; MAX_REPLY_BYTES + 1].as_slice()).is_err());
        assert!(read_reply(b"{} trailing".as_slice()).is_err());
        assert!(
            read_reply(b"{\"version\":1,\"outcome\":\"failed\",\"reason\":\"no\"}\n\n".as_slice())
                .is_err()
        );
    }

    #[test]
    fn bounds_and_sanitizes_supervisor_failure_text() {
        let reply = SupervisorReply::failed(format!("bad\\n{}", "x".repeat(2000)));
        reply.validate().unwrap();
        let SupervisorOutcome::Failed { reason } = reply.outcome else {
            panic!("expected failed reply");
        };
        assert_eq!(reason.len(), 1024);
        assert!(!reason.chars().any(char::is_control));
    }
}
