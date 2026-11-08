//! Verified self-update for the proxyctl executable.
//!
//! Release metadata and assets are accepted only from this repository's GitHub Releases.
//! The running executable is replaced only after checksum and version validation succeed.

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, bail, ensure};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const RELEASE_API: &str = "https://api.github.com/repos/hosmaznazfar/proxyctl/releases/latest";
const RELEASES_PAGE: &str = "https://github.com/hosmaznazfar/proxyctl/releases";
const USER_AGENT: &str = concat!("proxyctl/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateCheck {
    pub current: Version,
    pub latest: Version,
    pub asset_name: String,
}

pub fn update_application(check_only: bool) -> anyhow::Result<()> {
    let current = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let release = fetch_latest_release()?;
    ensure!(!release.draft && !release.prerelease, "GitHub returned a draft or prerelease; refusing to update");

    let latest_text = release.tag_name.strip_prefix('v').unwrap_or(&release.tag_name);
    let latest = Version::parse(latest_text)
        .with_context(|| format!("official release tag '{}' is not a semantic version", release.tag_name))?;
    let asset_name = platform_asset_name()?;
    let check = UpdateCheck { current: current.clone(), latest: latest.clone(), asset_name: asset_name.clone() };

    if latest <= current {
        println!("proxyctl is up to date ({}).", current);
        return Ok(());
    }

    println!("proxyctl update available: {} -> {}.", current, latest);
    if check_only {
        println!("Check only: no files were downloaded or changed.");
        return Ok(());
    }

    let asset = release.assets.iter().find(|asset| asset.name == asset_name)
        .with_context(|| format!("release {} has no asset for this platform ({asset_name}); see {RELEASES_PAGE}", release.tag_name))?;
    let sums = release.assets.iter().find(|asset| asset.name == "SHA256SUMS")
        .context("official release is missing SHA256SUMS; refusing to install an unverifiable binary")?;

    let checksum_text = download_text(&sums.browser_download_url)?;
    let expected = checksum_for_asset(&checksum_text, &asset_name)?;
    let bytes = download_bytes(&asset.browser_download_url)?;
    let actual = format!("{:x}", Sha256::digest(&bytes));
    ensure!(actual.eq_ignore_ascii_case(&expected), "SHA-256 verification failed for {asset_name}");

    replace_current_executable(&bytes, &latest)?;
    println!("Updated proxyctl to {latest}.");
    Ok(())
}

fn fetch_latest_release() -> anyhow::Result<Release> {
    let response = ureq::get(RELEASE_API)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/vnd.github+json")
        .call()
        .context("could not query the official proxyctl GitHub Releases API")?;
    let body = response.into_body().read_to_string()
        .context("could not read GitHub release metadata")?;
    let release: Release = serde_json::from_str(&body)
        .context("GitHub returned invalid release metadata")?;
    Ok(release)
}

fn download_text(url: &str) -> anyhow::Result<String> {
    let bytes = download_bytes(url)?;
    String::from_utf8(bytes).context("downloaded checksum manifest is not UTF-8")
}

fn download_bytes(url: &str) -> anyhow::Result<Vec<u8>> {
    ensure!(url.starts_with("https://github.com/") || url.starts_with("https://objects.githubusercontent.com/") || url.starts_with("https://release-assets.githubusercontent.com/"),
        "release asset URL is outside the trusted GitHub download domains");
    let response = ureq::get(url)
        .header("User-Agent", USER_AGENT)
        .call()
        .context("could not download a GitHub release asset")?;
    let bytes = response.into_body().read_to_vec()
        .context("could not read downloaded release asset")?;
    ensure!(bytes.len() <= 128 * 1024 * 1024, "release asset exceeds the 128 MiB safety limit");
    Ok(bytes)
}

fn checksum_for_asset(manifest: &str, asset_name: &str) -> anyhow::Result<String> {
    for line in manifest.lines() {
        let mut fields = line.split_whitespace();
        let Some(hash) = fields.next() else { continue };
        let Some(name) = fields.next() else { continue };
        let name = name.trim_start_matches('*');
        if name == asset_name {
            ensure!(hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "checksum manifest contains an invalid SHA-256 value");
            return Ok(hash.to_owned());
        }
    }
    bail!("SHA256SUMS does not contain an entry for {asset_name}")
}

fn platform_asset_name() -> anyhow::Result<String> {
    let target = match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        (os, arch) => bail!("automatic proxyctl updates are not yet supported on {os}/{arch}; use {RELEASES_PAGE}"),
    };
    Ok(format!("proxyctl-{target}"))
}

fn replace_current_executable(bytes: &[u8], version: &Version) -> anyhow::Result<()> {
    let executable = env::current_exe().context("could not locate the running proxyctl executable")?;
    let executable = fs::canonicalize(&executable).context("could not resolve the installed proxyctl executable path")?;
    let parent = executable.parent().context("installed executable has no parent directory")?;
    let staged = staged_path(parent);

    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&staged)
            .with_context(|| format!("cannot stage update beside {} (installation may require elevated permissions)", executable.display()))?;
        file.write_all(bytes).context("could not write staged proxyctl executable")?;
        file.sync_all().context("could not sync staged proxyctl executable")?;
        set_executable_permissions(&staged)?;

        let output = Command::new(&staged).arg("--version").output()
            .context("could not validate staged proxyctl executable")?;
        ensure!(output.status.success(), "staged proxyctl executable failed its --version check");
        let version_output = String::from_utf8_lossy(&output.stdout);
        ensure!(version_output.contains(&version.to_string()), "staged executable version does not match release {version}");

        fs::rename(&staged, &executable)
            .with_context(|| format!("could not safely replace {}; the existing executable was preserved", executable.display()))?;
        if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

fn staged_path(parent: &Path) -> PathBuf {
    parent.join(format!(".proxyctl-update-{}.tmp", std::process::id()))
}

#[cfg(unix)]
fn set_executable_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .context("could not set executable permissions on staged update")
}

#[cfg(not(unix))]
fn set_executable_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sha256_manifest_entries() {
        let manifest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  proxyctl-x86_64-unknown-linux-gnu\n";
        assert_eq!(
            checksum_for_asset(manifest, "proxyctl-x86_64-unknown-linux-gnu").unwrap(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn rejects_missing_checksum_entries() {
        assert!(checksum_for_asset("abc  other-file", "proxyctl-linux").is_err());
    }

    #[test]
    fn rejects_malformed_checksum_entries() {
        assert!(checksum_for_asset("not-a-hash  proxyctl-linux", "proxyctl-linux").is_err());
    }

    #[test]
    fn selects_supported_platform_assets() {
        assert!(platform_asset_name().unwrap().starts_with("proxyctl-"));
    }
}
