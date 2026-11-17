//! Read-only attribution of process-owned socket inodes on Linux.
//!
//! INET_DIAG_MARK records expose socket inodes, not process IDs. This module maps those
//! inodes to the exact pidfd-pinned managed core process without requiring privileges.
//! It does not inspect or infer socket marks; that requires the privileged sock_diag broker.

use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
};

use super::process::{ProcessHandle, ProcessIdentity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSocketSnapshot {
    pub process: ProcessIdentity,
    pub socket_inodes: BTreeSet<u64>,
}

/// Snapshot socket inodes held by the exact process instance pinned by the handle.
///
/// Identity is checked before and after walking procfs to reject PID reuse and process-exit
/// races. The caller must still match returned inodes against privileged INET_DIAG records and
/// must not accept a mark unless the diagnostic record itself was successfully obtained.
#[cfg(target_os = "linux")]
pub fn inspect_process_sockets(handle: &ProcessHandle) -> Result<ProcessSocketSnapshot> {
    let identity = handle.identity();
    ensure!(
        identity.verify()?,
        "managed core process identity changed before socket inspection"
    );
    let fd_directory = Path::new("/proc").join(identity.pid.to_string()).join("fd");
    let socket_inodes = inspect_fd_directory(&fd_directory)?;
    ensure!(
        identity.verify()?,
        "managed core process identity changed during socket inspection"
    );
    ensure!(
        !handle.is_exited()?,
        "managed core process exited during socket inspection"
    );
    ensure!(
        !socket_inodes.is_empty(),
        "managed core process has no observable socket descriptors"
    );
    Ok(ProcessSocketSnapshot {
        process: identity.clone(),
        socket_inodes,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn inspect_process_sockets(_handle: &ProcessHandle) -> Result<ProcessSocketSnapshot> {
    anyhow::bail!("process socket ownership inspection is supported only on Linux");
}

fn inspect_fd_directory(directory: &Path) -> Result<BTreeSet<u64>> {
    let entries = fs::read_dir(directory)
        .with_context(|| format!("cannot inspect process file descriptors at {}", directory.display()))?;
    let mut inodes = BTreeSet::new();
    for entry in entries {
        let entry = entry?;
        let target = fs::read_link(entry.path())
            .with_context(|| format!("cannot read process descriptor {}", entry.path().display()))?;
        if let Some(inode) = parse_socket_link(&target)? {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

fn parse_socket_link(target: &Path) -> Result<Option<u64>> {
    let Some(target) = target.to_str() else {
        return Ok(None);
    };
    let Some(inode) = target.strip_prefix("socket:[") else {
        ensure!(
            !target.starts_with("socket:"),
            "process descriptor contains a malformed socket identity"
        );
        return Ok(None);
    };
    let inode = inode
        .strip_suffix(']')
        .context("process descriptor contains an unterminated socket identity")?
        .parse::<u64>()
        .context("process descriptor contains an invalid socket inode")?;
    ensure!(inode > 0, "process descriptor contains a zero socket inode");
    Ok(Some(inode))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn parses_only_valid_socket_inode_links() {
        assert_eq!(parse_socket_link(Path::new("socket:[12345]")).unwrap(), Some(12345));
        assert_eq!(parse_socket_link(Path::new("anon_inode:[eventpoll]")).unwrap(), None);
        assert_eq!(parse_socket_link(Path::new("/memfd:fixture")).unwrap(), None);
    }

    #[test]
    fn rejects_malformed_or_zero_socket_inodes() {
        for target in ["socket:[]", "socket:[0]", "socket:[abc]", "socket:[42"] {
            assert!(parse_socket_link(Path::new(target)).is_err(), "accepted {target}");
        }
    }

    #[test]
    fn inventories_socket_fds_and_deduplicates_repeated_descriptors() {
        let directory = tempfile::tempdir().unwrap();
        symlink("socket:[123]", directory.path().join("3")).unwrap();
        symlink("socket:[123]", directory.path().join("4")).unwrap();
        symlink("socket:[456]", directory.path().join("5")).unwrap();
        symlink("anon_inode:[eventpoll]", directory.path().join("6")).unwrap();
        assert_eq!(inspect_fd_directory(directory.path()).unwrap(), BTreeSet::from([123, 456]));
    }

    #[test]
    fn fails_closed_when_a_descriptor_cannot_be_resolved() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("3"), "not a symlink").unwrap();
        assert!(inspect_fd_directory(directory.path()).is_err());
    }
}
