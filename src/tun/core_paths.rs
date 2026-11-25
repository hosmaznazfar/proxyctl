//! Validate the invoking user's managed-core tree before privileged execution.
//!
//! The request carries only a directory hint (the user's effective XDG data root).
//! Core name and executable filename always come from the closed CoreKind catalog.
use anyhow::{Context, ensure};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

const PRIVATE_MODE: u32 = 0o700;
const EXECUTABLE_NAME: &str = "proxyctl";

/// Resolve and validate the fixed executable for a core under the supplied managed root.
///
/// The root must end in `proxyctl/cores`. Every component is inspected with
/// symlink_metadata; symlinked components, writable shared ancestors, unexpected
/// owners, and non-private Proxyctl directories are rejected.
pub fn resolve_managed_core(
    managed_root: &Path,
    uid: u32,
    core: crate::tun::launch_spec::CoreKind,
) -> anyhow::Result<PathBuf> {
    ensure!(uid != 0, "managed core owner UID must be non-zero");
    validate_managed_root(managed_root, uid)?;

    let core_directory = managed_root.join(core.as_str());
    let core_metadata = fs::symlink_metadata(&core_directory)
        .with_context(|| format!("cannot inspect managed {} directory", core.as_str()))?;
    ensure!(
        core_metadata.file_type().is_dir()
            && core_metadata.uid() == uid
            && core_metadata.permissions().mode() & 0o7777 == PRIVATE_MODE,
        "managed {} directory has unsafe type, owner, or permissions",
        core.as_str()
    );

    let executable = core_directory.join(core.as_str());
    let metadata = fs::symlink_metadata(&executable)
        .with_context(|| format!("cannot inspect managed {} executable", core.as_str()))?;
    let mode = metadata.permissions().mode() & 0o7777;
    ensure!(
        metadata.file_type().is_file(),
        "managed {} executable must be a regular file, not a symlink",
        core.as_str()
    );
    ensure!(
        metadata.uid() == uid,
        "managed {} executable has an unexpected owner",
        core.as_str()
    );
    ensure!(
        mode & 0o111 != 0 && mode & 0o022 == 0,
        "managed {} executable is not executable or is writable by group/other",
        core.as_str()
    );

    let canonical_root = fs::canonicalize(managed_root)?;
    let canonical_executable = fs::canonicalize(&executable)?;
    ensure!(
        canonical_executable.starts_with(&canonical_root),
        "managed core executable resolves outside Proxyctl's managed directory"
    );
    Ok(canonical_executable)
}

fn validate_managed_root(path: &Path, uid: u32) -> anyhow::Result<()> {
    ensure!(path.is_absolute(), "managed core directory must be absolute");
    ensure!(
        path.components().all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "managed core directory contains an unsafe path component"
    );
    ensure!(
        path.file_name().is_some_and(|name| name == "cores")
            && path.parent().and_then(Path::file_name).is_some_and(|name| name == EXECUTABLE_NAME),
        "managed core directory must end in proxyctl/cores"
    );

    let mut current = PathBuf::from("/");
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("cannot inspect managed-core path component {}", current.display()))?;
        ensure!(
            metadata.file_type().is_dir(),
            "managed-core path component {} is not a real directory",
            current.display()
        );
        let mode = metadata.permissions().mode() & 0o7777;
        ensure!(
            metadata.uid() == 0 || metadata.uid() == uid,
            "managed-core path component {} has an unexpected owner",
            current.display()
        );
        // A root-owned sticky ancestor such as /tmp is safe for traversal: the
        // sticky bit prevents unprivileged users replacing another user's entry.
        let safe_shared_write = metadata.uid() == 0 && mode & 0o1000 != 0;
        ensure!(
            mode & 0o022 == 0 || safe_shared_write,
            "managed-core path component {} is writable by other users",
            current.display()
        );
        if index + 2 >= components.len() {
            ensure!(
                metadata.uid() == uid && mode == PRIVATE_MODE,
                "Proxyctl managed directories must be owned by the invoking user with mode 0700"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};
    use tempfile::tempdir;

    fn managed_tree(root: &Path) -> PathBuf {
        let managed = root.join("proxyctl/cores");
        let core = managed.join("xray");
        fs::create_dir_all(&core).unwrap();
        for path in [root.join("proxyctl"), managed, core.clone()] {
            fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_MODE)).unwrap();
        }
        let executable = core.join("xray");
        fs::write(&executable, b"test executable").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        root.join("proxyctl/cores")
    }

    #[test]
    fn resolves_only_catalog_executable_from_private_user_tree() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("data");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let managed = managed_tree(&root);
        let resolved = resolve_managed_core(&managed, unsafe { libc::getuid() }, crate::tun::launch_spec::CoreKind::Xray).unwrap();
        assert_eq!(resolved, fs::canonicalize(managed.join("xray/xray")).unwrap());
    }

    #[test]
    fn rejects_wrong_suffix_and_symlinked_core_executable() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("data");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let managed = managed_tree(&root);
        assert!(resolve_managed_core(&root, unsafe { libc::getuid() }, crate::tun::launch_spec::CoreKind::Xray).is_err());

        let executable = managed.join("xray/xray");
        let target = managed.join("xray/real-xray");
        fs::rename(&executable, &target).unwrap();
        std::os::unix::fs::symlink(&target, &executable).unwrap();
        assert!(resolve_managed_core(&managed, unsafe { libc::getuid() }, crate::tun::launch_spec::CoreKind::Xray).is_err());
    }

    #[test]
    fn rejects_group_or_world_writable_proxyctl_directory() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("data");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let managed = managed_tree(&root);
        fs::set_permissions(root.join("proxyctl"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(resolve_managed_core(&managed, unsafe { libc::getuid() }, crate::tun::launch_spec::CoreKind::Xray).is_err());
    }
}
