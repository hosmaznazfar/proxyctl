//! Shared core installation use case: resolve, verify, extract, validate, and install.
use anyhow::{Context, ensure};

use crate::{
    cores::{
        archive::extract_binary, core_binary_path, core_install_directory, releases, CoreId,
    },
    updates::{
        artifact::{download, verify_sha256},
        installer::replace_executable,
        release::latest_release,
    },
};

pub fn install_or_update(core: CoreId, check_only: bool) -> anyhow::Result<()> {
    ensure!(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "managed core installation currently supports Linux x86_64 only"
    );
    let release = latest_release(core.release_api())?;
    let spec = releases::resolve(core, &release.tag_name)?;
    let asset = release.asset(&spec.name)?;
    let digest = asset
        .digest
        .as_deref()
        .and_then(|value| value.strip_prefix("sha256:"))
        .context("official release asset has no SHA-256 digest; refusing installation")?;
    let version = releases::version_from_tag(&release.tag_name)?;
    let destination = core_binary_path(core)?;
    if destination.is_file() {
        let current = current_version(core, &destination).unwrap_or_else(|_| "unknown".to_owned());
        if current == version {
            println!("{core}: already up to date ({current}).");
            return Ok(());
        }
        println!("{core}: update available ({current} -> {version}).");
    } else {
        println!("{core}: installation available ({version}).");
    }
    if check_only {
        println!("{core}: compatible asset and SHA-256 digest available; no files changed.");
        return Ok(());
    }
    let archive = download(&asset.browser_download_url)?;
    verify_sha256(&archive, digest).context("upstream archive failed SHA-256 verification")?;
    let binary = extract_binary(&archive, spec.format, core.executable_name())?;
    let destination = core_install_directory(core)?.join(core.executable_name());
    replace_executable(&destination, &binary, version, core.version_argument())
        .with_context(|| format!("could not install verified {core} executable"))?;
    println!("{core}: installed version {version}.");
    Ok(())
}

pub fn current_version(core: CoreId, path: &std::path::Path) -> anyhow::Result<String> {
    let output = std::process::Command::new(path)
        .arg(core.version_argument())
        .output()
        .with_context(|| format!("could not query installed {core} version"))?;
    ensure!(output.status.success(), "installed {core} version command failed");
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    ensure!(!text.is_empty(), "installed {core} returned an empty version");
    Ok(text)
}
