//! GitHub Releases metadata access.
use super::artifact::validate_github_download_url;
use anyhow::{Context, ensure};
use semver::Version;
use serde::Deserialize;

const USER_AGENT: &str = concat!("proxyctl/", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ReleaseChannel {
    #[default]
    Stable,
    Prerelease,
}

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

pub fn latest_release(api_url: &str, channel: ReleaseChannel) -> anyhow::Result<Release> {
    let endpoint = url::Url::parse(api_url).context("invalid release metadata endpoint")?;
    ensure!(
        endpoint.scheme() == "https"
            && endpoint.host_str() == Some("api.github.com")
            && endpoint.path().starts_with("/repos/")
            && endpoint.query() == Some("per_page=100")
            && endpoint.fragment().is_none(),
        "release metadata endpoint must use the official GitHub Releases API"
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
    let releases: Vec<Release> =
        serde_json::from_str(&body).context("GitHub returned invalid release metadata")?;
    let release = select_release(releases, channel)?;
    for asset in &release.assets {
        validate_github_download_url(&asset.browser_download_url)?;
    }
    Ok(release)
}

fn select_release(releases: Vec<Release>, channel: ReleaseChannel) -> anyhow::Result<Release> {
    releases
        .into_iter()
        .filter(|release| match channel {
            ReleaseChannel::Stable => release.stable(),
            ReleaseChannel::Prerelease => !release.draft,
        })
        .filter_map(|release| {
            let version = release
                .tag_name
                .strip_prefix('v')
                .unwrap_or(&release.tag_name);
            Version::parse(version).ok().map(|version| (version, release))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, release)| release)
        .context(match channel {
            ReleaseChannel::Stable => "no valid stable release was found",
            ReleaseChannel::Prerelease => "no valid non-draft release was found",
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(tag: &str, draft: bool, prerelease: bool) -> Release {
        Release {
            tag_name: tag.to_owned(),
            draft,
            prerelease,
            assets: Vec::new(),
        }
    }

    #[test]
    fn stable_is_the_default_release_channel() {
        let selected = select_release(
            vec![
                release("v1.15.0-alpha.13", false, true),
                release("v1.14.4", false, false),
                release("v1.16.0", true, false),
            ],
            ReleaseChannel::Stable,
        )
        .unwrap();
        assert_eq!(selected.tag_name, "v1.14.4");
    }

    #[test]
    fn prerelease_channel_can_select_a_newer_prerelease() {
        let selected = select_release(
            vec![
                release("v1.15.0-alpha.13", false, true),
                release("v1.14.4", false, false),
            ],
            ReleaseChannel::Prerelease,
        )
        .unwrap();
        assert_eq!(selected.tag_name, "v1.15.0-alpha.13");
    }

    #[test]
    fn drafts_are_never_selected() {
        assert!(select_release(
            vec![release("v2.0.0", true, false)],
            ReleaseChannel::Prerelease,
        )
        .is_err());
    }
}
