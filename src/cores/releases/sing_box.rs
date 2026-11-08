//! sing-box Linux x86_64 asset policy.
use super::{CoreAsset, version_from_tag};
use crate::cores::archive::ArchiveFormat;
use anyhow::Result;
pub fn resolve(tag: &str) -> Result<CoreAsset> {
    Ok(CoreAsset {
        name: format!("sing-box-{}-linux-amd64.tar.gz", version_from_tag(tag)?),
        format: ArchiveFormat::TarGz,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_linux_amd64_tarball() {
        let asset = resolve("v1.14.4").unwrap();
        assert_eq!(asset.name, "sing-box-1.14.4-linux-amd64.tar.gz");
    }
}
