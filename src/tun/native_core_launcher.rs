//! Capability-confined systemd launcher for native named-device TUN cores.
//!
//! Unlike Xray's external-fd launcher, sing-box and Mihomo attach to a persistent
//! interface by name. This launcher starts the exact core executable in a generation-bound
//! transient unit; the managed lifecycle stops that unit before broker cleanup.

#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use super::process::ProcessIdentity;
use crate::cores::CoreId;

const SUDO: &str = "/usr/bin/sudo";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const START_TIMEOUT: Duration = Duration::from_secs(10);
const INSPECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_COMMAND_OUTPUT: u64 = 4096;

/// Return the native command-line prefix for a generated config.
pub fn native_core_arguments(core: CoreId, config: &Path) -> Result<Vec<String>> {
    ensure!(
        config.is_absolute(),
        "native core config path must be absolute"
    );
    match core {
        CoreId::SingBox => Ok(vec![
            "run".into(),
            "-c".into(),
            config.display().to_string(),
        ]),
        CoreId::Mihomo => Ok(vec!["-f".into(), config.display().to_string()]),
        CoreId::Xray => {
            anyhow::bail!("Xray must use its generation-bound external descriptor launcher")
        }
    }
}

/// Start one native TUN core in a capability-confined transient systemd service.
///
/// The returned process identity is the service MainPID and is checked against the
/// canonical executable path. No broker descriptor is exported to this process.
pub fn spawn_native_core_service(
    core: CoreId,
    activation_id: &str,
    generation: u64,
    executable: &Path,
    config: &Path,
) -> Result<ProcessIdentity> {
    validate_activation_identity(activation_id, generation)?;
    ensure!(
        matches!(core, CoreId::SingBox | CoreId::Mihomo),
        "only sing-box and Mihomo use the native persistent-device launcher"
    );
    ensure!(
        Path::new("/run/systemd/system").is_dir(),
        "native TUN core activation requires the systemd system manager"
    );
    let executable_metadata =
        fs::symlink_metadata(executable).context("cannot inspect native core executable")?;
    ensure!(
        executable_metadata.file_type().is_file()
            && executable_metadata.permissions().mode() & 0o111 != 0
            && executable_metadata.permissions().mode() & 0o022 == 0,
        "native core executable must be a non-writable executable regular file"
    );
    let config_metadata =
        fs::symlink_metadata(config).context("cannot inspect native core configuration")?;
    ensure!(
        config_metadata.file_type().is_file()
            && config_metadata.uid() == unsafe { libc::geteuid() }
            && config_metadata.permissions().mode() & 0o777 == 0o600
            && config_metadata.permissions().mode() & 0o7000 == 0
            && config_metadata.nlink() == 1,
        "native core config must be a caller-owned, single-link 0600 regular file"
    );
    let executable = fs::canonicalize(executable)?;
    let config = fs::canonicalize(config)?;
    let arguments = native_core_arguments(core, &config)?;

    validate_root_executable(Path::new(SUDO), true)?;
    validate_root_executable(Path::new(SYSTEMD_RUN), false)?;
    validate_root_executable(Path::new(SYSTEMCTL), false)?;
    let authorization = Command::new(SUDO)
        .arg("-v")
        .status()
        .context("cannot request authorization for native TUN core service")?;
    ensure!(
        authorization.success(),
        "sudo authorization was not granted for native TUN core service"
    );

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let unit = core_service_unit(activation_id, generation)?;
    let mut command = Command::new(SUDO);
    command
        .args([
            "-n",
            "--",
            SYSTEMD_RUN,
            "--system",
            "--quiet",
            "--collect",
            "--no-block",
        ])
        .arg(format!("--unit={unit}"))
        .arg(format!("--property=User={uid}"))
        .arg(format!("--property=Group={gid}"))
        .args([
            "--property=Type=exec",
            "--property=CapabilityBoundingSet=CAP_NET_ADMIN",
            "--property=AmbientCapabilities=CAP_NET_ADMIN",
            "--property=NoNewPrivileges=yes",
            "--property=KillMode=control-group",
            "--property=KillSignal=SIGTERM",
            "--property=TimeoutStopSec=5s",
            "--property=SendSIGKILL=yes",
            "--property=Restart=no",
            "--property=UMask=0077",
            "--property=PrivateTmp=yes",
            "--property=StandardOutput=null",
            "--property=StandardError=null",
        ])
        .arg("--")
        .arg(&executable)
        .args(&arguments);
    let started = run_command(command, START_TIMEOUT, false)?;
    ensure!(
        started.success,
        "systemd refused to start the generation-bound native core service"
    );

    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        // A non-zero MainPID can briefly remain observable while a unit is stopping.
        // Require the service to be actively running before binding the lifecycle to it.
        let state = run_bounded(
            SUDO,
            &[
                "-n",
                "--",
                SYSTEMCTL,
                "show",
                "--property=ActiveState",
                "--property=SubState",
                "--value",
                &unit,
            ],
            INSPECT_TIMEOUT,
            true,
        )?;
        if is_active_running_state(state.success, &state.stdout) {
            let output = run_bounded(
                SUDO,
                &[
                    "-n",
                    "--",
                    SYSTEMCTL,
                    "show",
                    "--property=MainPID",
                    "--value",
                    &unit,
                ],
                INSPECT_TIMEOUT,
                true,
            )?;
            if output.success {
                if let Ok(pid) = std::str::from_utf8(&output.stdout)
                    .unwrap_or_default()
                    .trim()
                    .parse::<u32>()
                    && pid > 0
                {
                    let identity = ProcessIdentity::capture(pid)
                        .context("cannot capture native core systemd MainPID identity")?;
                    ensure!(
                        identity.executable == executable && identity.verify()?,
                        "native core systemd MainPID does not match the requested executable"
                    );
                    return Ok(identity);
                }
            }
        }
        ensure!(
            Instant::now() < deadline,
            "native core service did not reach active/running with a verified MainPID before its startup deadline"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn is_active_running_state(success: bool, output: &[u8]) -> bool {
    success
        && std::str::from_utf8(output)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>()
            == ["active", "running"]
}

pub fn core_service_unit(activation_id: &str, generation: u64) -> Result<String> {
    validate_activation_identity(activation_id, generation)?;
    Ok(format!(
        "proxyctl-tun-core-{activation_id}-{generation}.service"
    ))
}

fn validate_activation_identity(activation_id: &str, generation: u64) -> Result<()> {
    ensure!(
        generation > 0
            && activation_id.len() == 36
            && activation_id.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                }
            }),
        "invalid native core activation identity"
    );
    Ok(())
}

fn validate_root_executable(path: &Path, allow_setuid: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("required service executable is missing: {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o111 != 0
            && metadata.permissions().mode() & 0o022 == 0
            && (allow_setuid || metadata.permissions().mode() & 0o7000 == 0)
            && metadata.nlink() == 1,
        "service executable must be root-owned, non-writable, and a regular executable: {}",
        path.display()
    );
    Ok(())
}

struct BoundedOutput {
    success: bool,
    stdout: Vec<u8>,
}

fn run_bounded(
    program: &str,
    args: &[&str],
    timeout: Duration,
    capture: bool,
) -> Result<BoundedOutput> {
    let mut command = Command::new(program);
    command.args(args);
    run_command(command, timeout, capture)
}

fn run_command(mut command: Command, timeout: Duration, capture: bool) -> Result<BoundedOutput> {
    let mut output_file =
        tempfile::tempfile().context("cannot create bounded native-core launcher output file")?;
    command
        .stdin(Stdio::null())
        .stdout(if capture {
            Stdio::from(output_file.try_clone()?)
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .context("cannot spawn bounded native-core service command")?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("native core service command exceeded its deadline");
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("cannot inspect native core service command");
            }
        }
    };
    let mut stdout = Vec::new();
    if capture {
        let size = output_file.metadata()?.len();
        ensure!(
            size <= MAX_COMMAND_OUTPUT,
            "native core service command output exceeded its bound"
        );
        output_file.seek(SeekFrom::Start(0))?;
        output_file
            .take(MAX_COMMAND_OUTPUT + 1)
            .read_to_end(&mut stdout)?;
        ensure!(
            stdout.len() as u64 <= MAX_COMMAND_OUTPUT,
            "native core service command output exceeded its bound"
        );
    }
    Ok(BoundedOutput {
        success: status.success(),
        stdout,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_state_requires_exact_active_and_running_values() {
        assert!(is_active_running_state(true, b"active\nrunning\n"));
        assert!(!is_active_running_state(true, b"activating\nstart\n"));
        assert!(!is_active_running_state(true, b"active\nexited\n"));
        assert!(!is_active_running_state(false, b"active\nrunning\n"));
        assert!(!is_active_running_state(true, b"active\nrunning\nextra\n"));
        assert!(!is_active_running_state(true, b"\xff"));
    }

    #[test]
    fn native_command_arguments_are_core_specific_and_absolute() {
        let config = Path::new("/tmp/proxyctl-native.json");
        assert_eq!(
            native_core_arguments(CoreId::SingBox, config).unwrap(),
            ["run", "-c", "/tmp/proxyctl-native.json"]
        );
        assert_eq!(
            native_core_arguments(CoreId::Mihomo, config).unwrap(),
            ["-f", "/tmp/proxyctl-native.json"]
        );
        assert!(native_core_arguments(CoreId::Xray, config).is_err());
        assert!(native_core_arguments(CoreId::SingBox, Path::new("relative.json")).is_err());
    }

    #[test]
    fn native_service_unit_is_bound_to_canonical_generation() {
        assert_eq!(
            core_service_unit("12345678-1234-4234-8234-123456789abc", 9).unwrap(),
            "proxyctl-tun-core-12345678-1234-4234-8234-123456789abc-9.service"
        );
        assert!(core_service_unit("12345678-1234-4234-8234-123456789ABC", 9).is_err());
        assert!(core_service_unit("12345678-1234-4234-8234-123456789abc", 0).is_err());
    }
}
