//! Mihomo Linux x86_64 baseline (GOAMD64 v1) asset policy.
use anyhow::Result;
use super::{CoreAsset, version_from_tag};
use crate::cores::archive::ArchiveFormat;
pub fn resolve(tag: &str) -> Result<CoreAsset> {
    Ok(CoreAsset { name: format!("mihomo-linux-amd64-v1-{}.gz", version_from_tag(tag)?), format: ArchiveFormat::Gzip })
}
