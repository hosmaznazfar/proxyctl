//! Operating-system and architecture asset naming.

use anyhow::bail;

/// Current proxyctl release workflow target. Additional targets can be added independently.
pub fn application_asset_name() -> anyhow::Result<String> {
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        (os, arch) => bail!(
            "automatic proxyctl updates are not supported on {os}/{arch}; download manually from https://github.com/hosmaznazfar/proxyctl/releases"
        ),
    };
    Ok(format!("proxyctl-{target}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_a_supported_asset_name_or_an_explicit_error() {
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            assert_eq!(
                application_asset_name().unwrap(),
                "proxyctl-x86_64-unknown-linux-gnu"
            );
        } else {
            assert!(application_asset_name().is_err());
        }
    }
}
