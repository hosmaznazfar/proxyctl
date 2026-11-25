//! Bounded, versioned data contract for the privileged TUN supervisor.
//! This module validates and transports data only; it does not launch cores or mutate networking.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{io::Read, path::PathBuf, str::FromStr};

use super::privilege_broker::BrokerSocketTransport;

pub const VERSION: u16 = 5;
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
/// JSON string escaping can expand the generated document, so the wire limit allows
/// up to twice the config byte limit plus bounded request metadata.
pub const MAX_SPEC_BYTES: usize = (MAX_CONFIG_BYTES * 2) + (24 * 1024);

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
    /// Keep core diagnostics attached to the invoking terminal until the session exits.
    pub foreground: bool,
    /// Transport used by the selected node's outbound peer socket.
    pub peer_transport: BrokerSocketTransport,
    /// Kernel-generated activation identity; also binds the generated socket mark to recovery.
    pub activation_id: String,
    /// Untrusted hint; the supervisor validates this tree and derives the executable from CoreKind.
    pub managed_core_root: PathBuf,
    /// Generated native core configuration, transferred as data rather than a filesystem path.
    pub generated_config: String,
    /// Generation identifier created before privilege escalation and bound to every durable record.
    pub generation: u64,
    /// Resolved selected-node endpoints used to prove the core's marked outbound socket bypass.
    pub expected_peers: Vec<std::net::SocketAddr>,
    /// Bounded numeric IPv4 and IPv6 HTTP destinations used for end-to-end TUN readiness.
    pub traffic_targets: Vec<crate::tun::readiness::HttpProbeTarget>,
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

/// Build a supervisor request from the already generated native config.
///
/// This is a pure handoff constructor: it neither resolves user state nor starts
/// a process, creates runtime files, or mutates host networking.
pub fn from_generated_config(
    node_id: u64,
    core: CoreKind,
    listen_port: u16,
    foreground: bool,
    peer_transport: BrokerSocketTransport,
    activation_id: String,
    managed_core_root: PathBuf,
    generated_config: &[u8],
    generation: u64,
    expected_peers: Vec<std::net::SocketAddr>,
    traffic_targets: Vec<crate::tun::readiness::HttpProbeTarget>,
) -> Result<LaunchSpec> {
    let generated_config = std::str::from_utf8(generated_config)
        .context("generated configuration must be UTF-8 JSON")?
        .to_owned();
    let spec = LaunchSpec {
        version: VERSION,
        node_id,
        core,
        listen_port,
        foreground,
        peer_transport,
        activation_id,
        managed_core_root,
        generated_config,
        generation,
        expected_peers,
        traffic_targets,
    };
    spec.validate()?;
    Ok(spec)
}

impl LaunchSpec {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION,
            "unsupported launch specification version"
        );
        ensure!(self.node_id > 0, "node ID must be non-zero");
        ensure!(self.generation > 0, "TUN generation must be non-zero");
        ensure!(
            !self.expected_peers.is_empty()
                && self.expected_peers.len() <= 8
                && self.expected_peers.iter().all(|peer| {
                    !peer.ip().is_unspecified()
                        && !peer.ip().is_multicast()
                        && peer.port() != 0
                }),
            "expected proxy peers must contain one to eight usable unicast endpoints"
        );
        let unique_peers = self.expected_peers.iter().copied().collect::<std::collections::BTreeSet<_>>();
        ensure!(
            unique_peers.len() == self.expected_peers.len(),
            "expected proxy peers must not contain duplicates"
        );
        super::readiness::validate_dual_stack_probe_targets(&self.traffic_targets)
            .context("invalid dual-stack TUN readiness targets")?;
        ensure!(
            self.activation_id.len() == 36
                && self.activation_id.bytes().enumerate().all(|(index, byte)| {
                    if [8, 13, 18, 23].contains(&index) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                    }
                }),
            "activation ID must be a canonical lowercase UUID"
        );
        ensure!(
            self.managed_core_root.is_absolute()
                && self.managed_core_root.as_os_str().len() <= 4096
                && self
                    .managed_core_root
                    .components()
                    .all(|component| matches!(
                        component,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    ))
                && self
                    .managed_core_root
                    .file_name()
                    .is_some_and(|name| name == "cores")
                && self
                    .managed_core_root
                    .parent()
                    .and_then(std::path::Path::file_name)
                    .is_some_and(|name| name == "proxyctl"),
            "managed core directory hint is invalid"
        );
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
            foreground: false,
            peer_transport: BrokerSocketTransport::Tcp,
            activation_id: "12345678-1234-4234-8234-123456789abc".to_owned(),
            managed_core_root: PathBuf::from("/home/user/.local/share/proxyctl/cores"),
            generated_config: r#"{"inbounds":[],"outbounds":[]}"#.to_owned(),
            generation: 1,
            expected_peers: vec!["198.51.100.10:443".parse().unwrap()],
            traffic_targets: vec![
                crate::tun::readiness::HttpProbeTarget {
                    destination: "192.0.2.10:80".parse().unwrap(),
                    host_header: "connectivity.example.test".into(),
                    path: "/generate_204".into(),
                    expected_status: 204,
                },
                crate::tun::readiness::HttpProbeTarget {
                    destination: "[2001:db8::10]:80".parse().unwrap(),
                    host_header: "connectivity.example.test".into(),
                    path: "/generate_204".into(),
                    expected_status: 204,
                },
            ],
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
                br#"{"version":5,"node_id":1,"core":"xray","listen_port":1080,"managed_core_root":"/home/user/.local/share/proxyctl/cores","generated_config":"{}","path":"/tmp"}"#
            )
            .is_err()
        );
        assert!(
            LaunchSpec::decode_bounded(
                br#"{"version":5,"node_id":1,"core":"root","listen_port":1080,"managed_core_root":"/home/user/.local/share/proxyctl/cores","generated_config":"{}"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_noncanonical_activation_ids() {
        let mut spec = sample();
        for invalid in [
            "",
            "not-a-uuid",
            "12345678-1234-4234-8234-123456789ABC",
            "12345678-1234-4234-8234-123456789abz",
        ] {
            spec.activation_id = invalid.to_owned();
            assert!(
                spec.validate().is_err(),
                "accepted activation ID {invalid:?}"
            );
        }
    }

    #[test]
    fn rejects_invalid_managed_core_root_hints() {
        let mut spec = sample();
        spec.managed_core_root = PathBuf::from("relative/proxyctl/cores");
        assert!(spec.validate().is_err());
        spec.managed_core_root = PathBuf::from("/home/user/proxyctl/other");
        assert!(spec.validate().is_err());
        spec.managed_core_root = PathBuf::from("/home/user/../other/proxyctl/cores");
        assert!(spec.validate().is_err());
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
    fn readiness_inputs_are_generation_bound_and_dual_stack() {
        let mut spec = sample();
        spec.generation = 0;
        assert!(spec.validate().is_err());

        spec = sample();
        spec.expected_peers.clear();
        assert!(spec.validate().is_err());

        spec = sample();
        spec.expected_peers = vec!["198.51.100.1:443".parse().unwrap(); 9];
        assert!(spec.validate().is_err());

        spec = sample();
        spec.expected_peers = vec![
            "198.51.100.1:443".parse().unwrap(),
            "198.51.100.1:443".parse().unwrap(),
        ];
        assert!(spec.validate().is_err());

        spec = sample();
        spec.traffic_targets.pop();
        assert!(spec.validate().is_err());

        spec = sample();
        spec.traffic_targets[1].destination = "192.0.2.11:80".parse().unwrap();
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
