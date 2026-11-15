//! Shell detection and per-user shell completion installation.
use std::{fs, io::Write, path::PathBuf};

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

    pub fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Fish => "fish",
            Self::Zsh => "zsh",
        }
    }
}

/// Detect the active shell from shell-specific environment variables, then its parent process and $SHELL.
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
        let parent = unsafe { libc::getppid() };
        if let Ok(name) = fs::read_to_string(format!("/proc/{parent}/comm"))
            && let Ok(shell) = Shell::parse(name.trim())
        {
            return Some(shell);
        }
    }
    std::env::var_os("SHELL")
        .and_then(|value| PathBuf::from(value).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.to_str().map(str::to_owned))
        .and_then(|name| Shell::parse(&name).ok())
}

fn config_home() -> anyhow::Result<PathBuf> {
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(path) => Ok(PathBuf::from(path)),
        None => {
            Ok(PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"))
        }
    }
}

fn data_home() -> anyhow::Result<PathBuf> {
    match std::env::var_os("XDG_DATA_HOME") {
        Some(path) => Ok(PathBuf::from(path)),
        None => Ok(
            PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?)
                .join(".local")
                .join("share"),
        ),
    }
}

fn install_atomic(destination: &std::path::Path, script: &str) -> anyhow::Result<PathBuf> {
    let directory = destination
        .parent()
        .context("completion path has no parent directory")?;
    fs::create_dir_all(directory)
        .with_context(|| format!("could not create {}", directory.display()))?;
    let mut temporary = NamedTempFile::new_in(directory)
        .with_context(|| format!("could not create temporary file in {}", directory.display()))?;
    temporary.write_all(script.as_bytes())?;
    temporary.flush()?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)
        .with_context(|| format!("could not install completion at {}", destination.display()))?;
    Ok(destination.to_path_buf())
}

pub fn install(shell: Shell, script: &str) -> anyhow::Result<PathBuf> {
    match shell {
        Shell::Fish => install_atomic(
            &config_home()?
                .join("fish")
                .join("completions")
                .join("proxyctl.fish"),
            script,
        ),
        Shell::Bash => install_atomic(
            &data_home()?
                .join("bash-completion")
                .join("completions")
                .join("proxyctl"),
            script,
        ),
        Shell::Zsh => {
            let destination = data_home()?
                .join("zsh")
                .join("site-functions")
                .join("_proxyctl");
            let installed = install_atomic(&destination, script)?;
            ensure_zsh_fpath()?;
            Ok(installed)
        }
    }
}

fn ensure_zsh_fpath() -> anyhow::Result<()> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    let startup = home.join(".zshrc");
    let marker = "# proxyctl completion setup";
    let directory = data_home()?.join("zsh").join("site-functions");
    let snippet = format!(
        "\n{marker}\nfpath=({} $fpath)\nautoload -Uz compinit\ncompinit\n",
        shell_quote(&directory.to_string_lossy())
    );
    let existing = fs::read_to_string(&startup).unwrap_or_default();
    if existing.contains(marker) {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&startup)
        .with_context(|| format!("could not update {}", startup.display()))?;
    file.write_all(snippet.as_bytes())?;
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace(char::from(39), "'\\''"))
}

/// Returns true only until the first interactive setup prompt has been recorded for this shell.
pub fn should_offer_first_setup_prompt(shell: Shell) -> anyhow::Result<bool> {
    Ok(!prompt_marker_path(shell)?.exists())
}

pub fn mark_first_setup_prompted(shell: Shell) -> anyhow::Result<()> {
    let marker = prompt_marker_path(shell)?;
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

fn prompt_marker_path(shell: Shell) -> anyhow::Result<PathBuf> {
    Ok(data_home()?
        .join("proxyctl")
        .join(format!("{}-completion-prompted", shell.name())))
}

#[cfg(test)]
mod tests {
    use super::Shell;

    #[test]
    fn shell_parser_accepts_supported_shells_only() {
        assert_eq!(Shell::parse("fish").unwrap(), Shell::Fish);
        assert_eq!(Shell::parse("bash").unwrap(), Shell::Bash);
        assert_eq!(Shell::parse("zsh").unwrap(), Shell::Zsh);
        assert!(Shell::parse("nu").is_err());
    }

    #[test]
    fn shell_names_are_stable() {
        assert_eq!(Shell::Fish.name(), "fish");
        assert_eq!(Shell::Bash.name(), "bash");
        assert_eq!(Shell::Zsh.name(), "zsh");
    }
}
