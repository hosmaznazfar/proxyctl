//! Explicit native-core TUN attachment evidence contract.
use anyhow::{Result, ensure};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentMechanism {
    PassedDescriptor,
    NativeDeviceCreation,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentEvidence {
    pub activation_id: String,
    pub generation: u64,
    pub process_start_time: u64,
    pub interface_name: String,
    pub mechanism: AttachmentMechanism,
    pub descriptor_transfer_confirmed: bool,
    pub interface_index: u32,
}
impl AttachmentEvidence {
    /// Validate evidence against the activation request and pinned process instance.
    pub fn validate_binding(
        &self,
        request: &super::activation_orchestrator::ActivationRequest,
        process: &super::process::ProcessIdentity,
    ) -> Result<()> {
        self.validate()?;
        request.validate()?;
        process.validate()?;
        ensure!(
            self.activation_id == request.activation_id && self.generation == request.generation,
            "attachment evidence is from a different activation generation"
        );
        ensure!(
            self.interface_name == request.interface_name,
            "attachment evidence interface does not match activation request"
        );
        ensure!(
            self.process_start_time == process.start_ticks,
            "attachment evidence process identity does not match pinned process"
        );
        ensure!(process.verify()?, "managed core process identity is stale");
        Ok(())
    }
    /// Structural gate; evidence is caller supplied and not independent kernel proof.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            canonical_uuid(&self.activation_id),
            "attachment activation ID is invalid"
        );
        ensure!(
            self.generation > 0,
            "attachment generation must be positive"
        );
        ensure!(
            self.process_start_time > 0,
            "attachment process identity is missing"
        );
        ensure!(
            !self.interface_name.is_empty()
                && self.interface_name.len() < 16
                && self.interface_name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')),
            "attachment interface name is invalid"
        );
        ensure!(
            self.interface_index > 0,
            "attachment interface index must be positive"
        );
        ensure!(
            self.mechanism == AttachmentMechanism::PassedDescriptor,
            "native device creation is not accepted for broker-owned attachment"
        );
        ensure!(
            self.descriptor_transfer_confirmed,
            "descriptor transfer has not been confirmed"
        );
        Ok(())
    }
}
fn canonical_uuid(v: &str) -> bool {
    v.len() == 36
        && v.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn e() -> AttachmentEvidence {
        AttachmentEvidence {
            activation_id: "12345678-1234-4234-8234-123456789abc".into(),
            generation: 1,
            process_start_time: 123,
            interface_name: "tun-proxyctl".into(),
            mechanism: AttachmentMechanism::PassedDescriptor,
            descriptor_transfer_confirmed: true,
            interface_index: 7,
        }
    }
    #[test]
    fn accepts_valid() {
        assert!(e().validate().is_ok());
    }
    #[test]
    fn rejects_missing_transfer() {
        let mut x = e();
        x.descriptor_transfer_confirmed = false;
        assert!(x.validate().is_err());
    }
    #[test]
    fn rejects_native_creation() {
        let mut x = e();
        x.mechanism = AttachmentMechanism::NativeDeviceCreation;
        assert!(x.validate().is_err());
    }
    #[test]
    fn rejects_zero_index() {
        let mut x = e();
        x.interface_index = 0;
        assert!(x.validate().is_err());
    }
    #[test]
    fn rejects_bad_uuid() {
        let mut x = e();
        x.activation_id = "draft".into();
        assert!(x.validate().is_err());
    }
    #[test]
    fn rejects_zero_generation() {
        let mut x = e();
        x.generation = 0;
        assert!(x.validate().is_err());
    }
    #[test]
    fn rejects_invalid_ifname() {
        let mut x = e();
        x.interface_name = "tun/unsafe".into();
        assert!(x.validate().is_err());
    }
}
