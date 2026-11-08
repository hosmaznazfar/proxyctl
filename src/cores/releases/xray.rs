//! Xray Linux x86_64 asset policy.
use super::CoreAsset;
use crate::cores::archive::ArchiveFormat;
pub fn resolve() -> anyhow::Result<CoreAsset> {
    Ok(CoreAsset {
        name: "Xray-linux-64.zip".to_owned(),
        format: ArchiveFormat::Zip,
    })
}
