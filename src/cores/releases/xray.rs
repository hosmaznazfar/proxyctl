//! Xray Linux x86_64 asset policy.
use super::CoreAsset;
use crate::cores::archive::ArchiveFormat;
pub fn resolve() -> anyhow::Result<CoreAsset> {
    Ok(CoreAsset {
        name: "Xray-linux-64.zip".to_owned(),
        format: ArchiveFormat::Zip,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_linux_64_zip() {
        let asset = resolve().unwrap();
        assert_eq!(asset.name, "Xray-linux-64.zip");
    }
}
