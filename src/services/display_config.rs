//! Persistent, user-editable table display profiles.
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io::Write, path::PathBuf};

const FILE_NAME: &str = "display.json";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum DisplayProfile {
    Compact,
    Normal,
    Full,
}
impl std::fmt::Display for DisplayProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Compact => "compact",
                Self::Normal => "normal",
                Self::Full => "full",
            }
        )
    }
}
impl std::str::FromStr for DisplayProfile {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "compact" => Ok(Self::Compact),
            "normal" => Ok(Self::Normal),
            "full" => Ok(Self::Full),
            _ => anyhow::bail!("unknown profile '{s}'; expected compact, normal, or full"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DisplayField {
    Node,
    Name,
    Server,
    Port,
    Protocol,
    Core,
    Version,
    Latency,
    TcpPing,
    Download,
    Upload,
    Status,
    Samples,
    Failures,
    Run,
    Tested,
}
impl std::fmt::Display for DisplayField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Node => "node",
                Self::Name => "name",
                Self::Server => "server",
                Self::Port => "port",
                Self::Protocol => "protocol",
                Self::Core => "core",
                Self::Version => "version",
                Self::Latency => "latency",
                Self::TcpPing => "tcp-ping",
                Self::Download => "download",
                Self::Upload => "upload",
                Self::Status => "status",
                Self::Samples => "samples",
                Self::Failures => "failures",
                Self::Run => "run",
                Self::Tested => "tested",
            }
        )
    }
}
impl std::str::FromStr for DisplayField {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "node" => Ok(Self::Node),
            "name" => Ok(Self::Name),
            "server" => Ok(Self::Server),
            "port" => Ok(Self::Port),
            "protocol" => Ok(Self::Protocol),
            "core" => Ok(Self::Core),
            "version" => Ok(Self::Version),
            "latency" | "ping" => Ok(Self::Latency),
            "tcp-ping" => Ok(Self::TcpPing),
            "download" => Ok(Self::Download),
            "upload" => Ok(Self::Upload),
            "status" => Ok(Self::Status),
            "samples" => Ok(Self::Samples),
            "failures" => Ok(Self::Failures),
            "run" => Ok(Self::Run),
            "tested" | "time" => Ok(Self::Tested),
            _ => anyhow::bail!("unknown display field '{s}'"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DisplayConfig {
    pub active_profile: DisplayProfile,
    pub profiles: BTreeMap<DisplayProfile, Vec<DisplayField>>,
}
impl Default for DisplayConfig {
    fn default() -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            DisplayProfile::Compact,
            vec![
                DisplayField::Node,
                DisplayField::Core,
                DisplayField::Latency,
                DisplayField::Download,
                DisplayField::Upload,
            ],
        );
        profiles.insert(
            DisplayProfile::Normal,
            vec![
                DisplayField::Node,
                DisplayField::Server,
                DisplayField::Protocol,
                DisplayField::Core,
                DisplayField::Latency,
                DisplayField::Download,
                DisplayField::Upload,
                DisplayField::Status,
            ],
        );
        profiles.insert(
            DisplayProfile::Full,
            vec![
                DisplayField::Node,
                DisplayField::Name,
                DisplayField::Server,
                DisplayField::Port,
                DisplayField::Protocol,
                DisplayField::Core,
                DisplayField::Version,
                DisplayField::Latency,
                DisplayField::TcpPing,
                DisplayField::Download,
                DisplayField::Upload,
                DisplayField::Status,
                DisplayField::Samples,
                DisplayField::Failures,
                DisplayField::Run,
                DisplayField::Tested,
            ],
        );
        Self {
            active_profile: DisplayProfile::Compact,
            profiles,
        }
    }
}
impl DisplayConfig {
    pub fn fields(&self) -> Vec<DisplayField> {
        self.profiles
            .get(&self.active_profile)
            .cloned()
            .unwrap_or_default()
    }
}
fn config_path() -> anyhow::Result<PathBuf> {
    let db = crate::database::default_database_path()?;
    Ok(db
        .parent()
        .context("Proxyctl data directory unavailable")?
        .join(FILE_NAME))
}
pub fn load() -> anyhow::Result<DisplayConfig> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(DisplayConfig::default());
    }
    let config: DisplayConfig =
        serde_json::from_slice(&fs::read(path)?).context("display configuration is invalid")?;
    for profile in [
        DisplayProfile::Compact,
        DisplayProfile::Normal,
        DisplayProfile::Full,
    ] {
        ensure!(
            config.profiles.contains_key(&profile),
            "display configuration is missing the {profile} profile"
        );
    }
    Ok(config)
}
pub fn save(config: &DisplayConfig) -> anyhow::Result<()> {
    let path = config_path()?;
    let parent = path.parent().context("display config path has no parent")?;
    fs::create_dir_all(parent)?;
    set_private_dir(parent)?;
    let bytes = serde_json::to_vec_pretty(config)?;
    let mut file = tempfile::Builder::new()
        .prefix(".proxyctl-display-")
        .tempfile_in(parent)?;
    set_private_file(file.as_file())?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .context("could not atomically save display configuration")?;
    Ok(())
}
pub fn add_field(
    config: &mut DisplayConfig,
    profile: DisplayProfile,
    field: DisplayField,
) -> anyhow::Result<()> {
    let fields = config
        .profiles
        .get_mut(&profile)
        .context("display profile missing")?;
    ensure!(
        !fields.contains(&field),
        "field '{field}' is already in {profile}"
    );
    fields.push(field);
    Ok(())
}
pub fn remove_field(
    config: &mut DisplayConfig,
    profile: DisplayProfile,
    field: DisplayField,
) -> anyhow::Result<()> {
    let fields = config
        .profiles
        .get_mut(&profile)
        .context("display profile missing")?;
    ensure!(
        fields.len() > 1,
        "a display profile must retain at least one field"
    );
    let before = fields.len();
    fields.retain(|item| *item != field);
    ensure!(
        fields.len() < before,
        "field '{field}' is not present in {profile}"
    );
    Ok(())
}
#[cfg(unix)]
fn set_private_dir(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_private_dir(_: &std::path::Path) -> anyhow::Result<()> {
    Ok(())
}
#[cfg(unix)]
fn set_private_file(file: &fs::File) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn set_private_file(_: &fs::File) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_is_the_default_and_profiles_are_independent() {
        let mut config = DisplayConfig::default();
        assert_eq!(config.active_profile, DisplayProfile::Compact);
        assert_eq!(
            config.fields(),
            vec![
                DisplayField::Node,
                DisplayField::Core,
                DisplayField::Latency,
                DisplayField::Download,
                DisplayField::Upload
            ]
        );
        add_field(&mut config, DisplayProfile::Compact, DisplayField::Server).unwrap();
        assert!(!config.profiles[&DisplayProfile::Normal].is_empty());
        assert!(config.profiles[&DisplayProfile::Full].contains(&DisplayField::Server));
        assert!(!config.profiles[&DisplayProfile::Normal].contains(&DisplayField::Failures));
    }
    #[test]
    fn parser_accepts_only_documented_fields() {
        assert_eq!(
            "ping".parse::<DisplayField>().unwrap(),
            DisplayField::Latency
        );
        assert!("fingerprint".parse::<DisplayField>().is_err());
    }
    #[test]
    fn profile_must_keep_at_least_one_field() {
        let mut config = DisplayConfig::default();
        for field in config.fields().into_iter().skip(1) {
            remove_field(&mut config, DisplayProfile::Compact, field).unwrap();
        }
        assert_eq!(config.fields(), vec![DisplayField::Node]);
        assert!(remove_field(&mut config, DisplayProfile::Compact, DisplayField::Node).is_err());
        assert_eq!(config.fields(), vec![DisplayField::Node]);
    }
}
