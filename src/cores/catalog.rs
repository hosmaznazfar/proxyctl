//! Stable identity and upstream metadata for supported proxy cores.
use anyhow::Context;
use std::{fmt, str::FromStr};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CoreId {
    SingBox,
    Xray,
    Mihomo,
}

impl CoreId {
    pub const ALL: [Self; 3] = [Self::SingBox, Self::Xray, Self::Mihomo];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingBox => "sing-box",
            Self::Xray => "xray",
            Self::Mihomo => "mihomo",
        }
    }

    pub const fn executable_name(self) -> &'static str {
        self.as_str()
    }

    pub const fn release_api(self) -> &'static str {
        match self {
            Self::SingBox => "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=100",
            Self::Xray => "https://api.github.com/repos/XTLS/Xray-core/releases?per_page=100",
            Self::Mihomo => "https://api.github.com/repos/MetaCubeX/mihomo/releases?per_page=100",
        }
    }

    pub const fn version_argument(self) -> &'static str {
        match self {
            Self::SingBox | Self::Xray => "version",
            Self::Mihomo => "-v",
        }
    }
}

impl fmt::Display for CoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CoreId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|core| core.as_str() == normalized)
            .with_context(|| format!("unknown core '{value}'; expected sing-box, xray, or mihomo"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_core_names_without_case_sensitivity() {
        assert_eq!("sing-box".parse::<CoreId>().unwrap(), CoreId::SingBox);
        assert_eq!("XRAY".parse::<CoreId>().unwrap(), CoreId::Xray);
        assert_eq!("Mihomo".parse::<CoreId>().unwrap(), CoreId::Mihomo);
        assert!("unknown".parse::<CoreId>().is_err());
    }
}
