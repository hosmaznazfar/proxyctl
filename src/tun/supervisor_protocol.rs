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
        ensure!(self.version == REPLY_VERSION, "unsupported supervisor reply version");
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

/// Write exactly one bounded JSON reply and flush the acknowledgement pipe.
pub fn write_reply<W: Write>(mut writer: W, reply: &SupervisorReply) -> Result<()> {
    reply.validate()?;
    let mut bytes = serde_json::to_vec(reply).context("cannot encode supervisor reply")?;
    ensure!(bytes.len() < MAX_REPLY_BYTES, "supervisor reply exceeds size limit");
    bytes.push(b'\n');
    writer.write_all(&bytes).context("cannot write supervisor reply")?;
    writer.flush().context("cannot flush supervisor reply")
}

/// Read one reply through EOF. The caller must bound the underlying pipe before trusting it.
pub fn read_reply<R: Read>(reader: R) -> Result<SupervisorReply> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REPLY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("cannot read supervisor acknowledgement")?;
    ensure!(!bytes.is_empty() && bytes.len() <= MAX_REPLY_BYTES, "supervisor reply size is invalid");
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    ensure!(!bytes.is_empty(), "supervisor reply is empty");
    let reply: SupervisorReply =
        serde_json::from_slice(&bytes).context("supervisor reply is malformed")?;
    reply.validate()?;
    Ok(reply)
}

fn bounded_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|character| !character.is_control())
        .take(1024)
        .collect()
}

fn validate_reason(reason: &str) -> Result<()> {
    ensure!(!reason.is_empty(), "supervisor reply reason must not be empty");
    ensure!(reason.len() <= 4096, "supervisor reply reason exceeds size limit");
    ensure!(
        !reason.chars().any(char::is_control),
        "supervisor reply reason contains control characters"
    );
    Ok(())
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
