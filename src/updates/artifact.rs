//! Download and checksum verification primitives shared by all components.
use std::io::Read;

use anyhow::{Context, bail, ensure};
use sha2::{Digest, Sha256};

const USER_AGENT: &str = concat!("proxyctl/", env!("CARGO_PKG_VERSION"));
const MAX_ARTIFACT_SIZE: u64 = 256 * 1024 * 1024;

/// Download an artifact from GitHub release delivery infrastructure with a hard read limit.
pub fn download(url: &str) -> anyhow::Result<Vec<u8>> {
    validate_github_download_url(url)?;
    let response = ureq::get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .context("could not download GitHub release asset")?;
    let reader = response.into_body().into_reader();
    let mut bytes = Vec::new();
    reader
        .take(MAX_ARTIFACT_SIZE + 1)
        .read_to_end(&mut bytes)
        .context("could not read downloaded release asset")?;
    ensure!(
        bytes.len() as u64 <= MAX_ARTIFACT_SIZE,
        "release asset exceeds the 256 MiB safety limit"
    );
    Ok(bytes)
}

pub fn download_text(url: &str) -> anyhow::Result<String> {
    String::from_utf8(download(url)?).context("downloaded text artifact is not UTF-8")
}

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

pub fn verify_sha256(bytes: &[u8], expected: &str) -> anyhow::Result<()> {
    ensure!(
        expected.len() == 64 && expected.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "expected SHA-256 digest is malformed"
    );
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    ensure!(
        actual.eq_ignore_ascii_case(expected),
        "SHA-256 verification failed"
    );
    Ok(())
}

pub fn validate_github_download_url(value: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(value).context("release asset URL is invalid")?;
    let host = url.host_str().unwrap_or_default();
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && matches!(
                host,
                "github.com"
                    | "objects.githubusercontent.com"
                    | "release-assets.githubusercontent.com"
            ),
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
        assert_eq!(
            checksum_for_asset(&format!("{HASH}  proxyctl-test"), "proxyctl-test").unwrap(),
            HASH
        );
    }

    #[test]
    fn rejects_missing_and_malformed_checksums() {
        assert!(checksum_for_asset("abc  other", "proxyctl-test").is_err());
        assert!(checksum_for_asset("not-a-hash  proxyctl-test", "proxyctl-test").is_err());
    }

    #[test]
    fn rejects_untrusted_download_hosts_and_host_suffix_spoofing() {
        assert!(validate_github_download_url("https://example.com/binary").is_err());
        assert!(validate_github_download_url("https://github.com.evil.invalid/binary").is_err());
    }

    #[test]
    fn detects_checksum_mismatch() {
        assert!(verify_sha256(b"artifact", HASH).is_err());
    }
}
