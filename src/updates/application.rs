//! Proxyctl-specific release policy and self-update use case.

use std::{env, fs};

use anyhow::Context;
use semver::Version;

use super::{
    artifact::{checksum_for_asset, download, download_text, verify_sha256},
    installer::replace_executable,
    platform::application_asset_name,
    release::latest_release,
};

const RELEASE_API: &str = "https://api.github.com/repos/hosmaznazfar/proxyctl/releases/latest";
const RELEASES_PAGE: &str = "https://github.com/hosmaznazfar/proxyctl/releases";

pub fn update_application(check_only: bool) -> anyhow::Result<()> {
    let current = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let release = latest_release(RELEASE_API)?;
    let latest_text = release.tag_name.strip_prefix('v').unwrap_or(&release.tag_name);
    let latest = Version::parse(latest_text).with_context(|| {
        format!("official release tag '{}' is not a semantic version", release.tag_name)
    })?;

    if latest <= current {
        println!("proxyctl is up to date ({current}).");
        return Ok(());
    }

    let asset_name = application_asset_name()?;
    let asset = release.asset(&asset_name)?;
    let sums = release.asset("SHA256SUMS")?;
    println!("proxyctl update available: {current} -> {latest}.");

    if check_only {
        println!("Compatible asset and checksum manifest are available.");
        println!("Check only: no files were downloaded or changed.");
        return Ok(());
    }

    let checksum_text = download_text(&sums.browser_download_url)?;
    let expected = checksum_for_asset(&checksum_text, &asset_name)?;
    let bytes = download(&asset.browser_download_url)?;
    verify_sha256(&bytes, &expected)?;

    let executable = env::current_exe().context("could not locate running proxyctl executable")?;
    let executable = fs::canonicalize(executable)
        .context("could not resolve running proxyctl executable path")?;
    if let Err(error) = replace_executable(&executable, &bytes, &latest.to_string(), "--version") {
        eprintln!(
            "Automatic replacement failed; the current executable was preserved. Download the verified asset manually from {RELEASES_PAGE}."
        );
        return Err(error);
    }

    println!("Updated proxyctl to {latest}.");
    Ok(())
}
