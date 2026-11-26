//! Non-mutating runtime probe for nftables cgroup v2 socket matching.
//!
//! The candidate ruleset is checked inside a disposable network namespace. No rule is
//! committed, and the host's active nftables tables and hooks are never touched.

#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    env, fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use super::coexistence::{CgroupV2Target, inspect_process};

/// Inspect a process, then validate its exact cgroup selector using nftables check mode.
///
/// The privileged sudo invocation receives absolute paths for both commands it launches.
/// The nftables script uses a validated numeric kernel cgroup ID in a typed set and is
/// passed on stdin; no shell or path-string parsing is involved.
pub fn probe_process(pid: u32, expected_uid: u32) -> Result<CgroupV2Target> {
    let target = inspect_process(pid, expected_uid)
        .context("cannot resolve the selected process's cgroup v2 identity")?;
    ensure!(
        target.verify_current()?,
        "selected process or cgroup changed before the nftables probe"
    );

    let sudo = find_trusted_executable("sudo")?;
    let unshare = find_trusted_executable("unshare")?;
    let nft = find_trusted_executable("nft")?;
    let ruleset = candidate_ruleset(&target)?;

    let mut child = Command::new(&sudo)
        // Never allow sudo to read the ruleset pipe while trying to authenticate.
        // Authentication must already be cached; stdin belongs exclusively to nft.
        .arg("-n")
        .arg(&unshare)
        .args(["--net", "--"])
        .arg(&nft)
        .args(["--check", "--file", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context(
            "cannot start isolated nftables capability probe (sudo may require authentication)",
        )?;

    {
        let mut stdin = child
            .stdin
            .take()
            .context("nftables probe stdin was not available")?;
        stdin
            .write_all(ruleset.as_bytes())
            .context("cannot send the candidate ruleset to nftables check mode")?;
    }

    let output = child
        .wait_with_output()
        .context("cannot wait for the isolated nftables capability probe")?;
    if !output.status.success() {
        // Include both a readable escaped representation and the exact input bytes.
        // This distinguishes path-escaping problems from execution/environment issues.
        let ruleset_hex = ruleset
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        anyhow::bail!(
            "isolated nftables cgroup socket probe failed (exit {}); sudo={}, unshare={}, nft={}, ruleset_len={}, ruleset={:?}, ruleset_hex={}: stdout={}, stderr={}",
            output.status,
            sudo.display(),
            unshare.display(),
            nft.display(),
            ruleset.len(),
            ruleset,
            ruleset_hex,
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    ensure!(
        target.verify_current()?,
        "selected process or cgroup changed while the nftables probe was running"
    );
    Ok(target)
}

fn candidate_ruleset(target: &CgroupV2Target) -> Result<String> {
    target.validate()?;
    Ok(format!(
        "table inet proxyctl_probe {{\\n    set vpn_apps {{\\n        type cgroupsv2\\n        elements = {{ {} }}\\n    }}\\n    chain output {{\\n        type route hook output priority mangle; policy accept;\\n        socket cgroupv2 level {} @vpn_apps meta mark set 0x1\\n    }}\\n}}\\n",
        target.cgroup_id,
        target.hierarchy_level
    ))
}

/// Resolve only root-owned, non-writable executables from PATH. The privileged sudo
/// invocation receives absolute paths for both commands it launches.
fn find_trusted_executable(name: &str) -> Result<PathBuf> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "invalid system executable name"
    );
    let path = env::var_os("PATH").context("PATH is unavailable while locating system tools")?;
    for directory in env::split_paths(&path) {
        if directory.as_os_str().is_empty() {
            continue;
        }
        let candidate = directory.join(name);
        let Ok(canonical) = fs::canonicalize(&candidate) else {
            continue;
        };
        if trusted_executable(&canonical) {
            return Ok(canonical);
        }
    }
    anyhow::bail!(
        "could not find a trusted root-owned {name} executable in PATH; install the system tool or correct PATH"
    )
}

fn trusted_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return false;
    }

    let mut parent = path.parent();
    while let Some(directory) = parent {
        let Ok(metadata) = fs::metadata(directory) else {
            return false;
        };
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            return false;
        }
        if directory == Path::new("/") {
            break;
        }
        parent = directory.parent();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::process::ProcessIdentity;

    fn target(path: &str, level: u32) -> CgroupV2Target {
        CgroupV2Target {
            process: ProcessIdentity {
                pid: 1,
                start_ticks: 1,
                executable: PathBuf::from("/usr/bin/sleep"),
            },
            owner_uid: 1000,
            hierarchy_path: path.into(),
            hierarchy_level: level,
            mount_point: PathBuf::from("/sys/fs/cgroup"),
            directory_device: 1,
            directory_inode: 2,
        }
    }

    #[test]
    fn candidate_ruleset_uses_numeric_kernel_cgroup_id_set() {
        let target = target("user.slice/app.slice/app.scope", 3);
        let ruleset = candidate_ruleset(&target).unwrap();
        assert!(ruleset.contains("set vpn_apps"));
        assert!(ruleset.contains("type cgroupsv2"));
        assert!(ruleset.contains("elements = { 4242 }"));
        assert!(ruleset.contains("type route hook output priority mangle"));
        assert!(ruleset.contains("socket cgroupv2 level 3 @vpn_apps meta mark set 0x1"));
        assert!(ruleset.starts_with("table inet proxyctl_probe"));
    }

    #[test]
    fn candidate_ruleset_rejects_invalid_or_mismatched_target() {
        assert!(candidate_ruleset(&target("", 0)).is_err());
        assert!(candidate_ruleset(&target("user.slice/app.scope", 1)).is_err());
    }
}
