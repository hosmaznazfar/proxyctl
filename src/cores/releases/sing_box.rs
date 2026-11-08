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
