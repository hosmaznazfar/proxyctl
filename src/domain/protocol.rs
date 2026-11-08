use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// A proxy URL protocol understood by proxyctl.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
}

impl Protocol {
    /// Parse a URL scheme into a supported protocol.
    pub fn from_scheme(scheme: &str) -> Option<Self> {
        match scheme.to_ascii_lowercase().as_str() {
            "vless" => Some(Self::Vless),
            "vmess" => Some(Self::Vmess),
            "trojan" => Some(Self::Trojan),
            "ss" | "shadowsocks" => Some(Self::Shadowsocks),
            "hysteria2" | "hy2" => Some(Self::Hysteria2),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Vmess => "vmess",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::Hysteria2 => "hysteria2",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_scheme(value).ok_or(())
    }
}
