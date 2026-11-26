//! Read-only discovery of a process's exact cgroup v2 identity.
//!
//! This module does not move processes, create cgroups, invoke systemd, or modify networking.
//! Paths are resolved from procfs and the active cgroup2 mount rather than distro conventions.

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

use super::super::process::{
    ProcessHandle, ProcessIdentity, read_process_owner_uid,
};

const MAX_PROC_FILE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupV2Target {
    pub process: ProcessIdentity,
    pub owner_uid: u32,
    /// Absolute cgroup path relative to the unified hierarchy root, without a leading slash.
    pub hierarchy_path: String,
    /// Number of non-root path components; this is nftables' cgroupv2 level.
    pub hierarchy_level: u32,
    /// Resolved cgroup2 mount point in this process's mount namespace.
    pub mount_point: PathBuf,
    /// Stable directory identity used to detect deletion/recreation at the same path.
    pub directory_device: u64,
    pub directory_inode: u64,
}

impl CgroupV2Target {
    pub fn validate(&self) -> Result<()> {
        self.process.validate()?;
        validate_hierarchy_path(&self.hierarchy_path)?;
        ensure!(
            self.hierarchy_level as usize == self.hierarchy_path.split('/').count(),
            "cgroup hierarchy level does not match its path"
        );
        ensure!(
            self.directory_inode > 0 && self.mount_point.is_absolute(),
            "cgroup directory identity is incomplete"
        );
        Ok(())
    }

    /// Recheck PID identity, owner, cgroup membership, and cgroup directory identity.
    pub fn verify_current(&self) -> Result<bool> {
        self.validate()?;
        if !self.process.verify()? {
            return Ok(false);
        }
        let handle = match ProcessHandle::open(self.process.clone()) {
            Ok(handle) => handle,
            Err(_) => return Ok(false),
        };
        if read_process_owner_uid(&handle)? != self.owner_uid {
            return Ok(false);
        }
        let current_path = read_unified_cgroup_path(self.process.pid)?;
        if current_path != format!("/{}", self.hierarchy_path) {
            return Ok(false);
        }
        let directory = self.mount_point.join(&self.hierarchy_path);
        let metadata = match fs::metadata(&directory) {
            Ok(metadata) if metadata.is_dir() => metadata,
            _ => return Ok(false),
        };
        if metadata.dev() != self.directory_device || metadata.ino() != self.directory_inode {
            return Ok(false);
        }
        Ok(self.process.verify()? 
            && read_unified_cgroup_path(self.process.pid)?
                == format!("/{}", self.hierarchy_path))
    }

    /// Return the path syntax accepted by nftables' `socket cgroupv2 level` expression.
    pub fn nftables_path(&self) -> &str {
        &self.hierarchy_path
    }

    /// Quote the path as an nftables string, preserving literal backslashes and quotes.
    pub fn nftables_quoted_path(&self) -> String {
        let mut quoted = String::with_capacity(self.hierarchy_path.len() + 2);
        for character in self.hierarchy_path.chars() {
            match character {
                '\\' => quoted.push_str("\\\\"),
                '"' => quoted.push_str("\\\""),
                character => quoted.push(character),
            }
        }
        quoted
    }
}

/// Capture a process and its exact cgroup v2 scope, requiring it to belong to expected_uid.
pub fn inspect_process(pid: u32, expected_uid: u32) -> Result<CgroupV2Target> {
    ensure!(pid > 0, "process ID must be non-zero");
    let process = ProcessIdentity::capture(pid)?;
    let handle = ProcessHandle::open(process.clone())?;
    let owner_uid = read_process_owner_uid(&handle)?;
    ensure!(
        owner_uid == expected_uid,
        "selected VPN process belongs to UID {owner_uid}, not the invoking UID {expected_uid}"
    );

    let cgroup_path = read_unified_cgroup_path(pid)?;
    validate_absolute_cgroup_path(&cgroup_path)?;
    let mount_info = read_bounded("/proc/self/mountinfo")?;
    let (mount_point, mount_root) = find_cgroup2_mount(&mount_info)?;
    ensure!(
        mount_root == "/",
        "the initial cgroup v2 backend requires the unified hierarchy root to be mounted"
    );
    let hierarchy_path = cgroup_path
        .strip_prefix(&mount_root)
        .with_context(|| {
            format!(
                "process cgroup {cgroup_path:?} is outside cgroup2 mount root {mount_root:?}"
            )
        })?;
    let hierarchy_path = hierarchy_path.trim_start_matches('/');
    validate_hierarchy_path(hierarchy_path)?;

    let mount_point = fs::canonicalize(&mount_point)
        .with_context(|| format!("cannot resolve cgroup2 mount {}", mount_point.display()))?;
    let directory = mount_point.join(hierarchy_path);
    let canonical_directory = fs::canonicalize(&directory)
        .with_context(|| format!("cannot resolve process cgroup {}", directory.display()))?;
    ensure!(
        canonical_directory.starts_with(&mount_point),
        "resolved process cgroup escapes the cgroup2 mount"
    );
    let metadata = fs::metadata(&canonical_directory)?;
    ensure!(metadata.is_dir(), "process cgroup is not a directory");

    ensure!(
        process.verify()?,
        "process identity changed during cgroup discovery"
    );
    ensure!(
        read_unified_cgroup_path(pid)? == cgroup_path,
        "process cgroup changed during discovery"
    );
    ensure!(
        !handle.is_exited()?,
        "selected process exited during cgroup discovery"
    );
    ensure!(
        read_unified_cgroup_path(pid)? == cgroup_path,
        "process cgroup changed before discovery completed"
    );

    let target = CgroupV2Target {
        process,
        owner_uid,
        hierarchy_level: hierarchy_path.split('/').count() as u32,
        hierarchy_path: hierarchy_path.to_owned(),
        mount_point,
        directory_device: metadata.dev(),
        directory_inode: metadata.ino(),
    };
    target.validate()?;
    Ok(target)
}

fn read_unified_cgroup_path(pid: u32) -> Result<String> {
    let contents = read_bounded(&format!("/proc/{pid}/cgroup"))?;
    let mut unified = contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, ':');
            let hierarchy = fields.next()?;
            let controllers = fields.next()?;
            let path = fields.next()?;
            (hierarchy == "0" && controllers.is_empty()).then_some(path)
        });
    let path = unified
        .next()
        .context("process has no unified cgroup v2 membership")?;
    ensure!(
        unified.next().is_none(),
        "process has ambiguous unified cgroup v2 membership"
    );
    Ok(path.to_owned())
}

fn find_cgroup2_mount(contents: &str) -> Result<(PathBuf, String)> {
    let mut matches = contents.lines().filter_map(|line| {
        let (left, right) = line.split_once(" - ")?;
        let left = left.split_whitespace().collect::<Vec<_>>();
        let right = right.split_whitespace().collect::<Vec<_>>();
        if right.first().copied() != Some("cgroup2") || left.len() < 5 {
            return None;
        }
        let root = unescape_mount_field(left[3]).ok()?;
        let mount_point = unescape_mount_field(left[4]).ok()?;
        Some((PathBuf::from(mount_point), root))
    });
    let mount = matches
        .next()
        .context("no cgroup v2 mount was found in /proc/self/mountinfo")?;
    ensure!(
        matches.next().is_none(),
        "multiple cgroup v2 mounts are present; refusing ambiguous path resolution"
    );
    ensure!(
        mount.0.is_absolute() && Path::new(&mount.1).is_absolute(),
        "cgroup v2 mount metadata is not absolute"
    );
    Ok(mount)
}

fn unescape_mount_field(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            ensure!(index + 3 < bytes.len(), "truncated mountinfo escape");
            let escaped = &value[index + 1..index + 4];
            let decoded = match escaped {
                "040" => b' ',
                "011" => b'\t',
                "012" => b'\n',
                "134" => b'\\',
                _ => anyhow::bail!("unsupported mountinfo escape"),
            };
            output.push(decoded);
            index += 4;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).context("mountinfo path is not valid UTF-8")
}

fn validate_absolute_cgroup_path(path: &str) -> Result<()> {
    ensure!(
        path.starts_with('/') && path.len() <= 4096,
        "process cgroup path must be bounded and absolute"
    );
    ensure!(
        Path::new(path).components().all(|component| {
            matches!(component, Component::RootDir | Component::Normal(_))
        }),
        "process cgroup path contains an unsafe component"
    );
    Ok(())
}

fn validate_hierarchy_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= 4096,
        "the cgroup root or an empty cgroup path cannot be selected"
    );
    ensure!(
        Path::new(path).components().all(|component| {
            matches!(component, Component::Normal(_))
        }),
        "cgroup hierarchy path contains an unsafe component"
    );
    ensure!(
        !path.bytes().any(|byte| byte.is_ascii_control()),
        "cgroup hierarchy path contains control characters"
    );
    Ok(())
}

fn read_bounded(path: &str) -> Result<String> {
    use std::io::Read;

    let mut contents = String::new();
    fs::File::open(path)
        .with_context(|| format!("cannot read {path}"))?
        .take(MAX_PROC_FILE_BYTES as u64 + 1)
        .read_to_string(&mut contents)
        .with_context(|| format!("cannot read {path}"))?;
    ensure!(
        contents.len() <= MAX_PROC_FILE_BYTES,
        "{path} exceeds the bounded read limit"
    );
    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cgroup2_mount_from_mountinfo() {
        let input = "29 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw,nsdelegate,memory_recursiveprot";
        let (mount, root) = find_cgroup2_mount(input).unwrap();
        assert_eq!(mount, PathBuf::from("/sys/fs/cgroup"));
        assert_eq!(root, "/");
    }

    #[test]
    fn parses_cgroup2_mount_with_escaped_mountpoint_and_subtree_root() {
        let input = "29 23 0:26 /user.slice /run/cgroup\\040view rw - cgroup2 cgroup rw";
        let (mount, root) = find_cgroup2_mount(input).unwrap();
        assert_eq!(mount, PathBuf::from("/run/cgroup view"));
        assert_eq!(root, "/user.slice");
    }

    #[test]
    fn rejects_missing_or_ambiguous_cgroup2_mounts() {
        assert!(find_cgroup2_mount("1 0 0:1 / /sys rw - tmpfs tmpfs rw").is_err());
        let duplicate = "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n2 0 0:1 / /other rw - cgroup2 cgroup rw";
        assert!(find_cgroup2_mount(duplicate).is_err());
    }

    #[test]
    fn accepts_only_one_unified_cgroup_membership() {
        let contents = "12:cpu:/user.slice\n0::/user.slice/app.slice/app.scope\n";
        let path = contents
            .lines()
            .filter_map(|line| {
                let mut fields = line.splitn(3, ':');
                let hierarchy = fields.next()?;
                let controllers = fields.next()?;
                let path = fields.next()?;
                (hierarchy == "0" && controllers.is_empty()).then_some(path)
            })
            .collect::<Vec<_>>();
        assert_eq!(path, ["/user.slice/app.slice/app.scope"]);
    }

    #[test]
    fn rejects_root_and_traversal_cgroup_paths() {
        for path in ["", "/", "/user.slice/../app.scope", "user.slice/./app.scope"] {
            assert!(validate_hierarchy_path(path.trim_start_matches('/')).is_err()
                || validate_absolute_cgroup_path(path).is_err());
        }
    }

    #[test]
    fn quotes_literal_backslashes_and_quotes_for_nftables() {
        let target = CgroupV2Target {
            process: ProcessIdentity {
                pid: 1,
                start_ticks: 1,
                executable: PathBuf::from("/usr/bin/sleep"),
            },
            owner_uid: 1000,
            hierarchy_path: r#"user.slice/app-dms-v2rayN\x2dbin"scope"#.into(),
            hierarchy_level: 2,
            mount_point: PathBuf::from("/sys/fs/cgroup"),
            directory_device: 1,
            directory_inode: 2,
        };
        assert_eq!(
            target.nftables_quoted_path(),
            r#"user.slice/app-dms-v2rayN\\x2dbin\"scope"#
        );
    }

    #[test]
    fn validates_cgroup_level_against_component_count() {
        let mut target = CgroupV2Target {
            process: ProcessIdentity {
                pid: 1,
                start_ticks: 1,
                executable: PathBuf::from("/usr/bin/sleep"),
            },
            owner_uid: 1000,
            hierarchy_path: "user.slice/user-1000.slice/app.slice/app.scope".into(),
            hierarchy_level: 4,
            mount_point: PathBuf::from("/sys/fs/cgroup"),
            directory_device: 1,
            directory_inode: 2,
        };
        assert!(target.validate().is_ok());
        target.hierarchy_level = 3;
        assert!(target.validate().is_err());
    }
}
