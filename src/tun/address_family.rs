//! Address-family policy shared by TUN settings, launch preparation, and the supervisor.
//!
//! The preference is durable user configuration. Resolution is performed once, before
//! privilege escalation, and the resolved value is carried in the launch specification.
//! Core upstream socket egress is deliberately independent from application TUN families.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TunAddressFamily {
    /// Select every application address family for which a readiness target is available.
    #[default]
    Auto,
    Ipv4,
    Ipv6,
    DualStack,
}

impl TunAddressFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::DualStack => "dual-stack",
        }
    }

    /// Resolve the preference against the families for which the configured probe endpoint
    /// produced valid numeric targets. Explicit preferences never silently downgrade.
    pub fn resolve(self, has_ipv4: bool, has_ipv6: bool) -> Result<ResolvedTunAddressFamily> {
        let resolved = match self {
            Self::Auto if has_ipv4 && has_ipv6 => ResolvedTunAddressFamily::DualStack,
            Self::Auto if has_ipv4 => ResolvedTunAddressFamily::Ipv4,
            Self::Auto if has_ipv6 => ResolvedTunAddressFamily::Ipv6,
            Self::Auto => anyhow::bail!(
                "TUN auto family selection found no usable IPv4 or IPv6 readiness target"
            ),
            Self::Ipv4 if has_ipv4 => ResolvedTunAddressFamily::Ipv4,
            Self::Ipv6 if has_ipv6 => ResolvedTunAddressFamily::Ipv6,
            Self::DualStack if has_ipv4 && has_ipv6 => ResolvedTunAddressFamily::DualStack,
            Self::Ipv4 => anyhow::bail!(
                "IPv4 TUN mode was explicitly selected but no usable IPv4 readiness target is available"
            ),
            Self::Ipv6 => anyhow::bail!(
                "IPv6 TUN mode was explicitly selected but no usable IPv6 readiness target is available"
            ),
            Self::DualStack => anyhow::bail!(
                "dual-stack TUN mode was explicitly selected but both IPv4 and IPv6 readiness targets are required"
            ),
        };
        Ok(resolved)
    }
}

impl fmt::Display for TunAddressFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for TunAddressFamily {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            "dual-stack" | "dual" | "ipv4-ipv6" => Ok(Self::DualStack),
            _ => anyhow::bail!(
                "unknown TUN address family '{value}'; expected auto, ipv4, ipv6, or dual-stack"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolvedTunAddressFamily {
    Ipv4,
    Ipv6,
    DualStack,
}

impl ResolvedTunAddressFamily {
    pub const fn includes_ipv4(self) -> bool {
        matches!(self, Self::Ipv4 | Self::DualStack)
    }

    pub const fn includes_ipv6(self) -> bool {
        matches!(self, Self::Ipv6 | Self::DualStack)
    }

    pub fn validate_targets(self, has_ipv4: bool, has_ipv6: bool) -> Result<()> {
        ensure!(
            !self.includes_ipv4() || has_ipv4,
            "resolved TUN family requires an IPv4 readiness target"
        );
        ensure!(
            !self.includes_ipv6() || has_ipv6,
            "resolved TUN family requires an IPv6 readiness target"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_selects_all_available_application_families() {
        assert_eq!(
            TunAddressFamily::Auto.resolve(true, true).unwrap(),
            ResolvedTunAddressFamily::DualStack
        );
        assert_eq!(
            TunAddressFamily::Auto.resolve(true, false).unwrap(),
            ResolvedTunAddressFamily::Ipv4
        );
        assert_eq!(
            TunAddressFamily::Auto.resolve(false, true).unwrap(),
            ResolvedTunAddressFamily::Ipv6
        );
        assert!(TunAddressFamily::Auto.resolve(false, false).is_err());
    }

    #[test]
    fn explicit_modes_fail_closed_without_the_requested_target() {
        assert!(TunAddressFamily::Ipv4.resolve(false, true).is_err());
        assert!(TunAddressFamily::Ipv6.resolve(true, false).is_err());
        assert!(TunAddressFamily::DualStack.resolve(true, false).is_err());
        assert_eq!(
            TunAddressFamily::DualStack.resolve(true, true).unwrap(),
            ResolvedTunAddressFamily::DualStack
        );
    }

    #[test]
    fn parses_stable_setting_names_and_aliases() {
        assert_eq!(
            "auto".parse::<TunAddressFamily>().unwrap(),
            TunAddressFamily::Auto
        );
        assert_eq!(
            "ipv4".parse::<TunAddressFamily>().unwrap(),
            TunAddressFamily::Ipv4
        );
        assert_eq!(
            "ipv6".parse::<TunAddressFamily>().unwrap(),
            TunAddressFamily::Ipv6
        );
        assert_eq!(
            "ipv4-ipv6".parse::<TunAddressFamily>().unwrap(),
            TunAddressFamily::DualStack
        );
        assert_eq!(TunAddressFamily::DualStack.to_string(), "dual-stack");
    }
}
