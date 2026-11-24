//! Bounded, versioned data contract for the future privileged TUN supervisor.
//! This module validates data only; it does not launch cores or mutate networking.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{io::Read, str::FromStr};

pub const VERSION: u16 = 2;
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
/// JSON string escaping can expand the generated document, so the wire limit allows
/// up to twice the config byte limit plus bounded request metadata.
pub const MAX_SPEC_BYTES: usize = (MAX_CONFIG_BYTES * 2) + (16 * 1024);

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
    /// Generated native core configuration, transferred as data rather than a filesystem path.
    pub generated_config: String,
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
        ensure!(
            self.listen_port >= 1024,
            "listener port must be between 1024 and 65535"
        );
        ensure!(
            !self.generated_config.is_empty() && self.generated_config.len() <= MAX_CONFIG_BYTES,
            "generated configuration size is invalid"
        );
        let document: Value = serde_json::from_str(&self.generated_config)
            .context("generated configuration must be valid JSON")?;
        ensure!(
            document.is_object(),
            "generated configuration must be a JSON object"
        );
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
            generated_config: r#"{"inbounds":[],"outbounds":[]}"#.to_owned(),
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
        s.listen_port = 80;
        assert!(s.validate().is_err());
    }
    #[test]
    fn rejects_unknown_fields_and_invalid_core() {
        assert!(
            LaunchSpec::decode_bounded(
                br#"{"version":2,"node_id":1,"core":"xray","listen_port":1080,"generated_config":"{}","path":"/tmp"}"#
            )
            .is_err()
        );
        assert!(
            LaunchSpec::decode_bounded(
                br#"{"version":2,"node_id":1,"core":"root","listen_port":1080,"generated_config":"{}"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_empty_oversized_non_json_and_non_object_configs() {
        let mut spec = sample();
        spec.generated_config.clear();
        assert!(spec.validate().is_err());
        spec.generated_config = "[]".to_owned();
        assert!(spec.validate().is_err());
        spec.generated_config = "not-json".to_owned();
        assert!(spec.validate().is_err());
        spec.generated_config = " ".repeat(MAX_CONFIG_BYTES + 1);
        assert!(spec.validate().is_err());
    }

    #[test]
    fn request_limit_accounts_for_json_string_escaping() {
        let mut spec = sample();
        spec.generated_config = format!(r#"{{"payload":"{}"}}"#, "\\".repeat(4096));
        assert!(spec.validate().is_ok());
        assert!(spec.encode_bounded().is_ok());
    }
}
