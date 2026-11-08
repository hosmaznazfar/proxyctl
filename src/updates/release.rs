//! GitHub Releases metadata access.
use super::artifact::validate_github_download_url;
use anyhow::{Context, ensure};
use serde::Deserialize;
const USER_AGENT: &str = concat!("proxyctl/", env!("CARGO_PKG_VERSION"));
#[derive(Clone, Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub assets: Vec<ReleaseAsset>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    pub digest: Option<String>,
    pub size: u64,
}
impl Release {
    pub fn stable(&self) -> bool {
        !self.draft && !self.prerelease
    }
    pub fn asset(&self, name: &str) -> anyhow::Result<&ReleaseAsset> {
        self.assets
            .iter()
            .find(|asset| asset.name == name)
            .with_context(|| format!("release {} has no asset named {name}", self.tag_name))
    }
}
pub fn latest_release(api_url: &str) -> anyhow::Result<Release> {
    let endpoint = url::Url::parse(api_url).context("invalid release metadata endpoint")?;
    ensure!(
        endpoint.scheme() == "https"
            && endpoint.host_str() == Some("api.github.com")
            && endpoint.path().starts_with("/repos/")
            && endpoint.query().is_none(),
        "release metadata endpoint must use the official GitHub API"
    );
    let response = ureq::get(api_url)
        .header("User-Agent", USER_AGENT)
        .header("Accept", "application/vnd.github+json")
        .call()
        .context("could not query official GitHub release metadata")?;
    let body = response
        .into_body()
        .read_to_string()
        .context("could not read GitHub release metadata")?;
    let release: Release =
        serde_json::from_str(&body).context("GitHub returned invalid release metadata")?;
    ensure!(
        release.stable(),
        "latest GitHub release is a draft or prerelease"
    );
    for asset in &release.assets {
        validate_github_download_url(&asset.browser_download_url)?;
    }
    Ok(release)
}
