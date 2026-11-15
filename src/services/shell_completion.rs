//! Shell detection and per-user shell completion installation.
use std::{
    fs,
    io::Write,
    path::PathBuf,
};

use anyhow::{Context, bail};
use tempfile::NamedTempFile;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shell {
    Bash,
    Fish,
    Zsh,
}

impl Shell {
    pub fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "bash" => Ok(Self::Bash),
            "fish" => Ok(Self::Fish),
            "zsh" => Ok(Self::Zsh),
            _ => bail!("unsupported shell '{value}'; supported shells: bash, fish, zsh"),
        }
    }
}

/// Detect the active shell from shell-specific environment variables, then $SHELL.
pub fn detect_current() -> Option<Shell> {
    if std::env::var_os("FISH_VERSION").is_some() {
        return Some(Shell::Fish);
    }
    if std::env::var_os("ZSH_VERSION").is_some() {
        return Some(Shell::Zsh);
    }
    if std::env::var_os("BASH_VERSION").is_some() {
        return Some(Shell::Bash);
    }
    #[cfg(target_os = "linux")]
    {
        // Prefer the actual parent shell over $SHELL, which may name the login shell.
        let parent = unsafe { libc::getppid() };
        if let Ok(name) = fs::read_to_string(format!("/proc/{parent}/comm")) {
            if let Ok(shell) = Shell::parse(name.trim()) {
                return Some(shell);
            }
        }
    }
    std::env::var_os("SHELL")
        .and_then(|value| PathBuf::from(value).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().map(str::to_owned))
        .and_then(|name| Shell::parse(&name).ok())
}

pub fn fish_completion_path() -> anyhow::Result<PathBuf> {
    let config_home = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?)
            .join(".config"),
    };
    Ok(config_home.join("fish").join("completions").join("proxyctl.fish"))
}

pub fn install_fish(script: &str) -> anyhow::Result<PathBuf> {
    let destination = fish_completion_path()?;
    let directory = destination
        .parent()
        .context("Fish completion path has no parent directory")?;
    fs::create_dir_all(directory)
        .with_context(|| format!("could not create {}", directory.display()))?;

    let mut temporary = NamedTempFile::new_in(directory)
        .with_context(|| format!("could not create temporary file in {}", directory.display()))?;
    temporary.write_all(script.as_bytes())?;
    temporary.flush()?;
    temporary
        .persist(&destination)
        .map_err(|error| error.error)
        .with_context(|| format!("could not install Fish completion at {}", destination.display()))?;
    Ok(destination)
}

fn prompt_marker_path() -> anyhow::Result<PathBuf> {
    let data_home = match std::env::var_os("XDG_DATA_HOME") {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?)
            .join(".local")
            .join("share"),
    };
    Ok(data_home
        .join("proxyctl")
        .join("fish-completion-prompted"))
}

/// Returns true only until the first interactive setup prompt has been recorded.
pub fn should_offer_first_setup_prompt() -> anyhow::Result<bool> {
    Ok(!prompt_marker_path()?.exists())
}

pub fn mark_first_setup_prompted() -> anyhow::Result<()> {
    let marker = prompt_marker_path()?;
    let directory = marker.parent().context("prompt marker has no parent")?;
    fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    if !marker.exists() {
        fs::write(&marker, b"prompted\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Shell, fish_completion_path};

    #[test]
    fn shell_parser_accepts_supported_shells_only() {
        assert_eq!(Shell::parse("fish").unwrap(), Shell::Fish);
        assert_eq!(Shell::parse("bash").unwrap(), Shell::Bash);
        assert_eq!(Shell::parse("zsh").unwrap(), Shell::Zsh);
        assert!(Shell::parse("nu").is_err());
    }

    #[test]
    fn fish_completion_path_uses_the_expected_autoload_suffix() {
        // Path selection is exercised by the integration path in install_fish; this test
        // verifies the stable destination suffix without mutating process environment.
        let path = fish_completion_path();
        if let Ok(path) = path {
            assert!(path.ends_with("fish/completions/proxyctl.fish"));
        }
    }
}
