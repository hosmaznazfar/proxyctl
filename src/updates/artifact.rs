//! Download and checksum verification primitives shared by all components.

use anyhow::{Context, bail, ensure};
use sha2::{Digest, Sha256};

const USER_AGENT: &str = concat!("proxyctl/", env!("CARGO_PKG_VERSION"));
const MAX_ARTIFACT_SIZE: usize = 256 * 1024 * 1024;

/// Download an artifact from GitHub's release asset delivery infrastructure.
pub fn download(url: &str) -> anyhow::Result<Vec<u8>> {
    validate_github_download_url(url)?;
    let response = ureq::get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .context("could not download GitHub release asset")?;
    let bytes = response
        .into_body()
        .read_to_vec()
        .context("could not read downloaded release asset")?;
    ensure!(
        bytes.len() <= MAX_ARTIFACT_SIZE,
        "release asset exceeds the 256 MiB safety limit"
    );
    Ok(bytes)
}

/// Download a UTF-8 text artifact, such as a checksum manifest.
pub fn download_text(url: &str) -> anyhow::Result<String> {
    String::from_utf8(download(url)?).context("downloaded text artifact is not UTF-8")
}

/// Validate a checksum manifest entry in the common sha256sum format.
pub fn checksum_for_asset(manifest: &str, asset_name: &str) -> anyhow::Result<String> {
    for line in manifest.lines() {
        let mut fields = line.split_whitespace();
        let Some(hash) = fields.next() else { continue };
        let Some(name) = fields.next() else { continue };
        if name.trim_start_matches('*') != asset_name {
            continue;
        }
        ensure!(
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "checksum manifest contains an invalid SHA-256 value"
        );
        return Ok(hash.to_ascii_lowercase());
    }
    bail!("checksum manifest does not contain an entry for {asset_name}")
}

/// Verify bytes against a trusted SHA-256 digest.
pub fn verify_sha256(bytes: &[u8], expected: &str) -> anyhow::Result<()> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    ensure!(
        actual.eq_ignore_ascii_case(expected),
        "SHA-256 verification failed"
    );
    Ok(())
}

/// Accept only GitHub API/release delivery URLs; never follow arbitrary metadata URLs.
pub fn validate_github_download_url(url: &str) -> anyhow::Result<()> {
    let trusted = [
        "https://github.com/",
        "https://objects.githubusercontent.com/",
        "https://release-assets.githubusercontent.com/",
    ];
    ensure!(
        trusted.iter().any(|prefix| url.starts_with(prefix)),
        "release asset URL is outside trusted GitHub download domains"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_checksum_manifest() {
        let manifest = format!("{HASH}  proxyctl-test");
        assert_eq!(
            checksum_for_asset(&manifest, "proxyctl-test").unwrap(),
            HASH
        );
    }

    #[test]
    fn rejects_missing_and_malformed_checksums() {
        assert!(checksum_for_asset("abc  other", "proxyctl-test").is_err());
        assert!(checksum_for_asset("not-a-hash  proxyctl-test", "proxyctl-test").is_err());
    }

    #[test]
    fn rejects_untrusted_download_hosts() {
        assert!(validate_github_download_url("https://example.com/binary").is_err());
    }

    #[test]
    fn detects_checksum_mismatch() {
        assert!(verify_sha256(b"artifact", HASH).is_err());
    }
}
