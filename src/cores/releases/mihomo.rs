//! Mihomo Linux x86_64 baseline (GOAMD64 v1) asset policy.
use super::CoreAsset;
use crate::cores::archive::ArchiveFormat;
use anyhow::Result;
pub fn resolve(tag: &str) -> Result<CoreAsset> {
    Ok(CoreAsset {
        name: format!("mihomo-linux-amd64-v1-{tag}.gz"),
        format: ArchiveFormat::Gzip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_baseline_linux_amd64_asset_with_tag_prefix() {
        let asset = resolve("v1.19.33").unwrap();
        assert_eq!(asset.name, "mihomo-linux-amd64-v1-v1.19.33.gz");
    }
}
