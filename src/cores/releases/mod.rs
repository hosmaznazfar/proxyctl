//! Upstream-specific asset naming and archive policy.
mod mihomo;
mod sing_box;
mod xray;
use super::archive::ArchiveFormat;
use crate::cores::CoreId;
use anyhow::bail;

pub struct CoreAsset {
    pub name: String,
    pub format: ArchiveFormat,
}
pub fn resolve(core: CoreId, tag: &str) -> anyhow::Result<CoreAsset> {
    match core {
        CoreId::SingBox => sing_box::resolve(tag),
        CoreId::Xray => xray::resolve(),
        CoreId::Mihomo => mihomo::resolve(tag),
    }
}
pub fn version_from_tag(tag: &str) -> anyhow::Result<&str> {
    let version = tag.strip_prefix('v').unwrap_or(tag);
    if version.is_empty()
        || !version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        bail!("upstream release tag has an unsupported version format");
    }
    Ok(version)
}
