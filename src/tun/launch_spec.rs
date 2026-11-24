//! Bounded, versioned data contract for the future privileged TUN supervisor.
//! This module validates data only; it does not launch cores or mutate networking.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{io::Read, str::FromStr};

pub const VERSION: u16 = 1;
pub const MAX_SPEC_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CoreKind {
    SingBox,
    Xray,
    Mihomo,
}
impl FromStr for CoreKind {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "sing-box" => Ok(Self::SingBox),
            "xray" => Ok(Self::Xray),
            "mihomo" => Ok(Self::Mihomo),
            _ => anyhow::bail!("unsupported core"),
        }
    }
}
impl CoreKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingBox => "sing-box",
            Self::Xray => "xray",
            Self::Mihomo => "mihomo",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaunchSpec {
    pub version: u16,
    pub node_id: u64,
    pub core: CoreKind,
    pub listen_port: u16,
}
/// Read one launch specification from a stream, rejecting input beyond the protocol limit.
///
/// The reader is consumed through EOF so trailing bytes cannot be left for a later parser.
pub fn read_bounded<R: Read>(reader: R) -> Result<LaunchSpec> {
    let mut bytes = Vec::with_capacity(MAX_SPEC_BYTES.min(1024));
    reader
        .take(MAX_SPEC_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_SPEC_BYTES,
        "launch specification size is invalid"
    );
    LaunchSpec::decode_bounded(&bytes)
}

impl LaunchSpec {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION,
            "unsupported launch specification version"
        );
        ensure!(self.node_id > 0, "node ID must be non-zero");
        ensure!(self.listen_port > 0, "listener port must be non-zero");
        Ok(())
    }
    pub fn encode_bounded(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_SPEC_BYTES,
            "launch specification exceeds size limit"
        );
        Ok(bytes)
    }
    pub fn decode_bounded(bytes: &[u8]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_SPEC_BYTES,
            "launch specification size is invalid"
        );
        let spec: Self = serde_json::from_slice(bytes)?;
        spec.validate()?;
        Ok(spec)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> LaunchSpec {
        LaunchSpec {
            version: VERSION,
            node_id: 5,
            core: CoreKind::Xray,
            listen_port: 1080,
        }
    }
    #[test]
    fn round_trip_and_bounds() {
        let s = sample();
        assert_eq!(
            LaunchSpec::decode_bounded(&s.encode_bounded().unwrap()).unwrap(),
            s
        );
        assert!(LaunchSpec::decode_bounded(&vec![0; MAX_SPEC_BYTES + 1]).is_err());
    }
    #[test]
    fn reads_one_bounded_specification_from_a_stream() {
        use std::io::Cursor;

        let encoded = sample().encode_bounded().unwrap();
        assert_eq!(read_bounded(Cursor::new(encoded)).unwrap(), sample());
        assert!(read_bounded(Cursor::new(Vec::<u8>::new())).is_err());
        assert!(read_bounded(Cursor::new(vec![b' '; MAX_SPEC_BYTES + 1])).is_err());
    }

    #[test]
    fn rejects_invalid_version_and_zero_values() {
        let mut s = sample();
        s.version = 99;
        assert!(s.validate().is_err());
        s.version = VERSION;
        s.node_id = 0;
        assert!(s.validate().is_err());
        s.node_id = 5;
        s.listen_port = 0;
        assert!(s.validate().is_err());
    }
    #[test]
    fn rejects_unknown_fields_and_invalid_core() {
        assert!(
            LaunchSpec::decode_bounded(
                br#"{"version":1,"node_id":1,"core":"xray","listen_port":80,"path":"/tmp"}"#
            )
            .is_err()
        );
        assert!(
            LaunchSpec::decode_bounded(
                br#"{"version":1,"node_id":1,"core":"root","listen_port":80}"#
            )
            .is_err()
        );
    }
}
