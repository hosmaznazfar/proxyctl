//! Secure, validation-only execution of generated core configurations.
use std::{
    io::Write,
    path::Path,
};

use anyhow::Context;

use crate::{
    cores::{CoreId, adapters::{self, CoreAdapter}},
    domain::ProxyNode,
};

/// Generate a node config in a private temporary file and ask the selected core to parse it.
/// The core is never started; the temporary file is removed on every return path.
pub fn validate_node_config(
    core: CoreId,
    node: &ProxyNode,
    executable: &Path,
) -> anyhow::Result<()> {
    validate_node_config_in(core, node, executable, &std::env::temp_dir())
}

fn validate_node_config_in(
    core: CoreId,
    node: &ProxyNode,
    executable: &Path,
    temporary_directory: &Path,
) -> anyhow::Result<()> {
    let adapter = adapters::adapter(core);
    let generated = adapter.generate_config(node)
        .with_context(|| format!("could not generate {core} configuration"))?;

    let mut temporary_file = tempfile::Builder::new()
        .prefix("proxyctl-config-")
        .suffix(".json")
        .tempfile_in(temporary_directory)
        .context("could not create a private temporary core configuration")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary_file.as_file().set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("could not restrict temporary configuration permissions")?;
    }

    temporary_file.write_all(&generated.content)
        .context("could not write temporary core configuration")?;
    temporary_file.as_file().sync_all()
        .context("could not flush temporary core configuration")?;

    adapter.validate_config(executable, temporary_file.path())
        .with_context(|| format!("{core} rejected the generated configuration"))?;

    // NamedTempFile removes the secret-bearing config when it is dropped.
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::tempdir;

    use crate::{cores::CoreId, parser::parse_proxy_url};

    use super::*;

    #[test]
    fn validation_uses_a_private_file_and_removes_it_after_success() {
        let directory = tempdir().unwrap();
        let executable = directory.path().join("fake-core");
        let marker = directory.path().join("config-path");
        write_fake_core(&executable, &marker, 0);

        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443",
        ).unwrap();

        validate_node_config_in(
            CoreId::SingBox,
            &node,
            &executable,
            directory.path(),
        ).unwrap();

        let config_path = fs::read_to_string(marker).unwrap();
        assert!(!Path::new(&config_path).exists());
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            2,
            "only the fake executable and marker should remain"
        );
    }

    #[test]
    fn validation_removes_the_temporary_file_after_core_failure() {
        let directory = tempdir().unwrap();
        let executable = directory.path().join("fake-core");
        let marker = directory.path().join("config-path");
        write_fake_core(&executable, &marker, 42);

        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@example.com:443",
        ).unwrap();

        assert!(validate_node_config_in(
            CoreId::SingBox,
            &node,
            &executable,
            directory.path(),
        ).is_err());

        let config_path = fs::read_to_string(marker).unwrap();
        assert!(!Path::new(&config_path).exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    fn write_fake_core(executable: &Path, marker: &Path, exit_code: i32) {
        let script = format!(
            "#!/bin/sh\nfor arg in \"$@\"; do config=\"$arg\"; done\n[ -s \"$config\" ] || exit 20\n[ \"$(stat -c '%a' \"$config\")\" = 600 ] || exit 21\nprintf '%s' \"$config\" > '{}'\nexit {}\n",
            marker.display(),
            exit_code
        );
        fs::write(executable, script).unwrap();
        fs::set_permissions(executable, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
