//! Secure, validation-only execution of generated core configurations.
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;

const VALIDATOR_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_VALIDATOR_OUTPUT: u64 = 64 * 1024;

/// Run a native config validator with a hard deadline and bounded captured output.
/// Output is spooled to temporary files so a noisy child cannot block on a full pipe.
pub(crate) fn run_validator(mut command: Command, description: &str) -> anyhow::Result<Output> {
    let mut stdout = tempfile::tempfile().context("could not create validator stdout spool")?;
    let mut stderr = tempfile::tempfile().context("could not create validator stderr spool")?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));
    let mut child = command
        .spawn()
        .with_context(|| format!("{description}: could not start validator"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < VALIDATOR_TIMEOUT => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!(
                    "{description}: validator exceeded the 10-second deadline and was terminated"
                );
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error)
                    .with_context(|| format!("{description}: could not inspect validator"));
            }
        }
    };
    let stdout = read_validator_output(&mut stdout)?;
    let stderr = read_validator_output(&mut stderr)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn read_validator_output(file: &mut std::fs::File) -> anyhow::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut output = Vec::new();
    file.take(MAX_VALIDATOR_OUTPUT).read_to_end(&mut output)?;
    Ok(output)
}

use crate::{
    cores::{CoreId, adapters},
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
    let generated = adapter
        .generate_config(node)
        .with_context(|| format!("could not generate {core} configuration"))?;

    validate_generated_config_in(core, &generated, executable, temporary_directory)
}

/// Generate and validate a benchmark configuration with a loopback HTTP inbound.
pub fn validate_benchmark_config(
    core: CoreId,
    node: &ProxyNode,
    executable: &Path,
    listen_port: u16,
) -> anyhow::Result<()> {
    let generated = adapters::adapter(core)
        .generate_benchmark_config(node, listen_port)
        .with_context(|| format!("could not generate {core} benchmark configuration"))?;
    validate_generated_config(core, &generated, executable)
}

/// Validate an already generated native document using a private temporary file.
pub fn validate_generated_config(
    core: CoreId,
    generated: &super::GeneratedConfig,
    executable: &Path,
) -> anyhow::Result<()> {
    validate_generated_config_in(core, generated, executable, &std::env::temp_dir())
}

fn validate_generated_config_in(
    core: CoreId,
    generated: &super::GeneratedConfig,
    executable: &Path,
    temporary_directory: &Path,
) -> anyhow::Result<()> {
    let mut temporary_file = tempfile::Builder::new()
        .prefix("proxyctl-config-")
        .suffix(".json")
        .tempfile_in(temporary_directory)
        .context("could not create a private temporary core configuration")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        temporary_file
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("could not restrict temporary configuration permissions")?;
    }

    temporary_file
        .write_all(&generated.content)
        .context("could not write temporary core configuration")?;
    temporary_file
        .as_file()
        .sync_all()
        .context("could not flush temporary core configuration")?;

    adapters::adapter(core)
        .validate_config(executable, temporary_file.path())
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

        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();

        validate_node_config_in(CoreId::SingBox, &node, &executable, directory.path()).unwrap();

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

        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();

        assert!(
            validate_node_config_in(CoreId::SingBox, &node, &executable, directory.path()).is_err()
        );

        let config_path = fs::read_to_string(marker).unwrap();
        assert!(!Path::new(&config_path).exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn native_validator_is_terminated_after_its_deadline() {
        let directory = tempdir().unwrap();
        let executable = directory.path().join("hanging-core");
        fs::write(&executable, "#!/bin/sh\nexec sleep 30\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let started = std::time::Instant::now();
        let mut command = std::process::Command::new(&executable);
        command.arg("check");
        let error = run_validator(command, "test validator").unwrap_err();

        assert!(error.to_string().contains("10-second deadline"));
        assert!(started.elapsed() < std::time::Duration::from_secs(12));
    }

    #[test]
    fn validation_uses_each_cores_native_check_command() {
        let directory = tempdir().unwrap();
        let executable = directory.path().join("fake-core");
        let arguments = directory.path().join("arguments");
        let marker = directory.path().join("config-path");
        write_fake_core_with_arguments(&executable, &arguments, &marker);

        let node = parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@example.com:443")
            .unwrap();
        let cases = [
            (CoreId::SingBox, vec!["check", "-c"]),
            (CoreId::Xray, vec!["run", "-test", "-c"]),
            (CoreId::Mihomo, vec!["-t", "-f"]),
        ];

        for (core, expected_prefix) in cases {
            validate_node_config_in(core, &node, &executable, directory.path()).unwrap();

            let actual = fs::read_to_string(&arguments)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            assert_eq!(actual.len(), expected_prefix.len() + 1);
            assert_eq!(
                actual[..expected_prefix.len()]
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
                expected_prefix
            );
            let config_path = actual.last().expect("validator receives a config path");
            assert_eq!(fs::read_to_string(&marker).unwrap(), *config_path);
            assert!(
                !Path::new(config_path).exists(),
                "{core} validation must remove its temporary config"
            );
        }

        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            3,
            "only the fake executable, arguments, and marker should remain"
        );
    }

    fn write_fake_core_with_arguments(executable: &Path, arguments: &Path, marker: &Path) {
        let script = format!(
            r#"#!/bin/sh
printf '%s\n' "$@" > '{}'
for arg in "$@"; do config="$arg"; done
[ -s "$config" ] || exit 20
[ "$(stat -c '%a' "$config")" = 600 ] || exit 21
printf '%s' "$config" > '{}'
exit 0
"#,
            arguments.display(),
            marker.display()
        );
        fs::write(executable, script).unwrap();
        fs::set_permissions(executable, fs::Permissions::from_mode(0o700)).unwrap();
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
