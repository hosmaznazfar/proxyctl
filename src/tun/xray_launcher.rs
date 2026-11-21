//! Xray Linux launcher using a broker-owned TUN descriptor and a capability-confined systemd unit.
//!
//! The transient service receives only CAP_NET_ADMIN, accepts one authenticated descriptor
//! handoff, and keeps the Xray child in its control group. This module does not activate routes,
//! commit a lifecycle manifest, or prove traffic readiness.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::Read,
    os::unix::{fs::{MetadataExt, PermissionsExt}, net::UnixListener},
    os::fd::AsFd,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use super::descriptor_transfer;

use crate::{
    tun::{mutation_helper_launcher::MutationHelper, process::{ProcessHandle, ProcessIdentity}},
};

struct PrivateSocketCleanup(PathBuf);

impl Drop for PrivateSocketCleanup {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
        if let Ok(metadata) = fs::symlink_metadata(&self.0)
            && metadata.file_type().is_socket()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.nlink() == 1
        {
            let _ = fs::remove_file(&self.0);
        }
    }
}

/// Start Xray in a capability-confined transient service and pass its exact generation-bound TUN fd.
///
/// The service shim duplicates the descriptor for Xray and returns the identity of the actual
/// Xray child, not the shim or the systemd-run client.
pub fn spawn_xray_from_broker(
    helper: &MutationHelper,
    activation_id: &str,
    generation: u64,
    executable: &Path,
    config: &Path,
    interface_name: &str,
    expected_ifindex: u32,
) -> Result<(Child, ProcessIdentity)> {
    ensure!(executable.is_absolute(), "Xray executable path must be absolute");
    ensure!(config.is_absolute(), "Xray config path must be absolute");
    ensure!(generation > 0, "Xray activation generation must be positive");
    ensure!(activation_id.len() == 36 && activation_id.bytes().enumerate().all(|(i, byte)| {
        if [8, 13, 18, 23].contains(&i) { byte == b'-' }
        else { byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase() }
    }), "Xray activation ID is invalid");
    ensure!(!interface_name.is_empty() && interface_name.len() < 16
        && interface_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
        "Xray TUN interface name is invalid");
    ensure!(expected_ifindex > 0, "Xray TUN interface index must be positive");
    ensure!(Path::new("/run/systemd/system").is_dir(),
        "Xray TUN descriptor launch requires the systemd system manager");

    let executable_metadata = fs::symlink_metadata(executable)
        .context("cannot inspect Xray executable path")?;
    ensure!(executable_metadata.file_type().is_file(), "Xray executable must be a regular non-symlink file");
    ensure!(executable_metadata.permissions().mode() & 0o111 != 0,
        "Xray executable has no executable permission");
    let config_metadata = fs::symlink_metadata(config)
        .context("cannot inspect Xray config path")?;
    ensure!(config_metadata.file_type().is_file(), "Xray config must be a regular non-symlink file");
    ensure!(config_metadata.uid() == unsafe { libc::geteuid() }
        && config_metadata.permissions().mode() & 0o077 == 0,
        "Xray config must be owned by the current user and have private permissions");
    let executable = fs::canonicalize(executable).context("cannot canonicalize Xray executable")?;
    let config = fs::canonicalize(config).context("cannot canonicalize Xray config")?;

    const SUDO: &str = "/usr/bin/sudo";
    const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
    const SYSTEMCTL: &str = "/usr/bin/systemctl";
    const LAUNCHER: &str = "/usr/libexec/proxyctl-tun-core-launcher";
    let sudo_metadata = fs::symlink_metadata(SUDO)
        .context("required sudo executable is missing")?;
    ensure!(sudo_metadata.file_type().is_file() && sudo_metadata.uid() == 0
        && sudo_metadata.permissions().mode() & 0o111 != 0
        && sudo_metadata.permissions().mode() & 0o022 == 0
        && sudo_metadata.permissions().mode() & 0o3000 == 0,
        "sudo must be a root-owned, non-writable regular executable (the conventional setuid bit is permitted)");

    for path in [Path::new(SYSTEMD_RUN), Path::new(SYSTEMCTL), Path::new(LAUNCHER)] {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("required TUN service executable is missing: {}", path.display()))?;
        ensure!(metadata.file_type().is_file() && metadata.uid() == 0
            && metadata.permissions().mode() & 0o111 != 0
            && metadata.permissions().mode() & 0o022 == 0
            && metadata.permissions().mode() & 0o7000 == 0,
            "TUN service executable must be a root-owned, non-writable regular executable: {}", path.display());
    }

    let runtime = helper.socket_path().parent()
        .context("mutation helper socket has no runtime directory")?;
    let socket_path = runtime.join(format!("xray-{activation_id}-{generation}.sock"));
    ensure!(socket_path.as_os_str().len() < 108,
        "Xray descriptor socket path exceeds the Unix-domain socket limit");
    ensure!(matches!(fs::symlink_metadata(&socket_path),
        Err(ref error) if error.kind() == std::io::ErrorKind::NotFound),
        "Xray descriptor socket path already exists; refusing to replace it");
    let listener = UnixListener::bind(&socket_path)
        .context("cannot bind private Xray descriptor socket")?;
    let _socket_cleanup = PrivateSocketCleanup(socket_path.clone());
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .context("cannot restrict Xray descriptor socket permissions")?;
    let socket_metadata = fs::symlink_metadata(&socket_path)?;
    ensure!(socket_metadata.file_type().is_socket()
        && socket_metadata.uid() == unsafe { libc::geteuid() }
        && socket_metadata.permissions().mode() & 0o777 == 0o600
        && socket_metadata.nlink() == 1,
        "Xray descriptor socket identity or permissions are unsafe");
    listener.set_nonblocking(true)?;

    // Allow the system manager to create one capability-confined transient unit. The
    // subsequent systemd-run invocation is non-interactive and cannot prompt mid-launch.
    let authorization = Command::new(SUDO).arg("-v").status()
        .context("cannot request authorization for the isolated Xray TUN service")?;
    ensure!(authorization.success(), "sudo authorization was not granted for the Xray TUN service");

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let unit = format!("proxyctl-tun-core-{activation_id}-{generation}.service");
    let mut launcher = Command::new(SUDO);
    launcher.args(["-n", "--"]).arg(SYSTEMD_RUN)
        .args(["--system", "--quiet", "--collect"])
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
        .arg("--").arg(LAUNCHER)
        .arg("--socket").arg(&socket_path)
        .arg("--activation-id").arg(activation_id)
        .arg("--generation").arg(generation.to_string())
        .arg("--parent-pid").arg(std::process::id().to_string())
        .arg("--interface").arg(interface_name)
        .arg("--ifindex").arg(expected_ifindex.to_string())
        .arg("--executable").arg(&executable)
        .arg("--config").arg(&config)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    let mut service_command = launcher.spawn()
        .context("cannot start the capability-confined Xray TUN service")?;

    let start_deadline = std::time::Instant::now() + Duration::from_secs(10);
    let start_result = loop {
        match service_command.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(_)) => break Err(anyhow::anyhow!("systemd refused to start the Xray TUN service")),
            Ok(None) if std::time::Instant::now() >= start_deadline => {
                let _ = service_command.kill();
                let _ = service_command.wait();
                break Err(anyhow::anyhow!("systemd-run did not finish starting the Xray TUN service before its deadline"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                let _ = service_command.kill();
                let _ = service_command.wait();
                break Err(error.into());
            }
        }
    };
    if let Err(error) = start_result {
        let _ = Command::new(SUDO).args(["-n", "--", SYSTEMCTL, "stop"]).arg(&unit).status();
        return Err(error).context("Xray transient service startup failed");
    }

    let handoff_result = (|| -> Result<ProcessIdentity> {
        let accept_deadline = std::time::Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    ensure!(std::time::Instant::now() < accept_deadline,
                        "Xray core launcher did not connect before the descriptor handoff deadline");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error).context("cannot accept Xray core launcher connection"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let peer = super::privilege_broker::read_broker_peer_credentials(&stream)?;
        ensure!(peer.uid == uid && peer.gid == gid && peer.pid > 0,
            "Xray core launcher peer credentials do not match the activation user");
        let main_pid = Command::new(SUDO)
            .args(["-n", "--", SYSTEMCTL, "show", "--property=MainPID", "--value"])
            .arg(&unit)
            .output()
            .context("cannot verify Xray systemd service main process")?;
        ensure!(main_pid.status.success(), "cannot inspect the exact Xray systemd service");
        let main_pid = String::from_utf8_lossy(&main_pid.stdout).trim()
            .parse::<u32>().context("systemd returned an invalid Xray service MainPID")?;
        ensure!(main_pid == peer.pid,
            "descriptor socket peer is not the MainPID of the requested Xray service");
        let launcher_identity = ProcessIdentity::capture(peer.pid)
            .context("cannot capture Xray core launcher process identity")?;
        ensure!(launcher_identity.executable == fs::canonicalize(LAUNCHER)?
            && launcher_identity.verify()?,
            "descriptor socket peer is not the live installed Xray core launcher");

        let descriptor = helper.attach_descriptor(activation_id, generation)
            .context("cannot obtain the broker-owned TUN descriptor for Xray")?;
        descriptor_transfer::send_descriptor(&stream, descriptor.as_fd())
            .context("cannot transfer the broker-owned TUN descriptor to Xray")?;
        let identity = receive_process_identity(&mut stream)
            .context("Xray core launcher did not confirm the exec'd core identity")?;
        ensure!(identity.executable == executable,
            "Xray core launcher reported an unexpected executable identity");
        ensure!(identity.verify()?, "Xray process identity is not live after descriptor handoff");
        verify_xray_capability_boundary(&identity, uid)?;
        Ok(identity)
    })();

    match handoff_result {
        Ok(identity) => Ok((service_command, identity)),
        Err(error) => {
            let _ = Command::new(SUDO).args(["-n", "--", SYSTEMCTL, "stop", &unit]).status();
            let _ = service_command.wait();
            Err(error).context("Xray descriptor handoff failed; transient service stop was requested")
        }
    }
}

fn verify_xray_capability_boundary(identity: &ProcessIdentity, expected_uid: u32) -> Result<()> {
    const CAP_NET_ADMIN: u64 = 1 << 12;
    let status = fs::read_to_string(format!("/proc/{}/status", identity.pid))
        .context("cannot inspect managed Xray capability state")?;
    let field = |name: &str| status.lines()
        .find_map(|line| line.strip_prefix(name))
        .map(str::trim);
    let uid_values = field("Uid:")
        .context("managed Xray process status has no UID field")?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(uid_values.len() == 4 && uid_values.iter().all(|uid| *uid == expected_uid),
        "managed Xray process did not retain the activation user's UID");
    for name in ["CapEff:", "CapPrm:", "CapBnd:", "CapInh:", "CapAmb:"] {
        let value = field(name).context("managed Xray capability status is incomplete")?;
        ensure!(u64::from_str_radix(value, 16)? == CAP_NET_ADMIN,
            "managed Xray must have exactly CAP_NET_ADMIN in its effective, permitted, bounding, and ambient sets");
    }
    ensure!(field("NoNewPrivs:") == Some("1"),
        "managed Xray process must retain NoNewPrivileges");
    ensure!(identity.verify()?, "managed Xray process identity changed during capability verification");
    Ok(())
}

fn receive_process_identity(stream: &mut std::os::unix::net::UnixStream) -> Result<ProcessIdentity> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).context("cannot read Xray process identity frame length")?;
    let length = u32::from_le_bytes(header) as usize;
    ensure!(length > 0 && length <= 4096, "Xray process identity frame length is invalid");
    let mut payload = Vec::new();
    payload.try_reserve_exact(length).context("cannot reserve bounded Xray process identity frame")?;
    payload.resize(length, 0);
    stream.read_exact(&mut payload).context("cannot read Xray process identity frame")?;
    let identity: ProcessIdentity = serde_json::from_slice(&payload)
        .context("Xray process identity frame is malformed")?;
    identity.validate()?;
    Ok(identity)
}


/// Verify that the exact Xray process holds an open kernel TUN descriptor for this interface.
/// Linux exposes the bound interface name in /proc/PID/fdinfo as an `iff:` record.
pub fn verify_xray_tun_attachment(
    process: &ProcessIdentity,
    interface_name: &str,
    expected_ifindex: u32,
) -> Result<()> {
    ensure!(!interface_name.is_empty() && interface_name.len() < 16
        && interface_name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
        "Xray TUN interface name is invalid");
    ensure!(expected_ifindex > 0, "expected TUN interface index must be positive");
    ensure!(process.verify()?, "Xray process identity is not live before TUN attachment inspection");
    let handle = ProcessHandle::open(process.clone()).context("cannot pin Xray while inspecting TUN descriptor ownership")?;

    let interface = std::path::Path::new("/sys/class/net").join(interface_name);
    ensure!(interface.join("tun_flags").is_file(), "expected interface is not a kernel TUN device");
    let actual_ifindex = fs::read_to_string(interface.join("ifindex"))
        .context("cannot read TUN interface index")?.trim().parse::<u32>()
        .context("kernel returned an invalid TUN interface index")?;
    ensure!(actual_ifindex == expected_ifindex, "TUN interface index changed before Xray attachment verification");

    let fdinfo = std::path::Path::new("/proc").join(process.pid.to_string()).join("fdinfo");
    let entries = fs::read_dir(&fdinfo).context("cannot inspect Xray file-descriptor metadata")?;
    let mut attached = false;
    for entry in entries {
        let entry = entry.context("cannot enumerate Xray file-descriptor metadata")?;
        let metadata = match fs::read_to_string(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("cannot read Xray file-descriptor metadata"),
        };
        if fdinfo_names_interface(&metadata, interface_name) {
            attached = true;
            break;
        }
    }
    ensure!(attached, "Xray does not hold a TUN file descriptor bound to the expected interface");
    ensure!(process.verify()? && !handle.is_exited()?, "Xray process exited or changed during TUN attachment verification");
    Ok(())
}

fn fdinfo_names_interface(contents: &str, expected: &str) -> bool {
    contents.lines().any(|line| {
        line.strip_prefix("iff:").is_some_and(|value| value.trim() == expected)
    })
}

#[cfg(test)]
mod attachment_tests {
    use super::fdinfo_names_interface;

    #[test]
    fn fdinfo_interface_match_is_exact() {
        assert!(fdinfo_names_interface("pos:\t0\niff:\ttun-proxyctl\n", "tun-proxyctl"));
        assert!(!fdinfo_names_interface("iff:\ttun-proxyctl-extra\n", "tun-proxyctl"));
        assert!(!fdinfo_names_interface("pos:\t0\n", "tun-proxyctl"));
    }
}


/// Compose Xray's kernel-backed descriptor check with the shared live TUN readiness gate.
///
/// The caller must supply independently collected host-network, physical-egress, and socket-mark
/// evidence plus an application-level traffic observation. This function refreshes the process,
/// listener, interface, and route-policy evidence itself; it never infers traffic success from a
/// successful SOCKS handshake.
#[allow(clippy::too_many_arguments)]
pub fn verify_xray_readiness(
    process: &ProcessIdentity,
    interface_name: &str,
    expected: &super::readiness::ReadinessExpectation<'_>,
    evidence: &super::readiness::ReadinessEvidence,
    listener: std::net::SocketAddr,
    listener_timeout: std::time::Duration,
    plan: &super::route_policy::RoutingPolicyPlan,
    socket_mark_response: &super::privilege_broker::SocketMarkBrokerResponse,
    expected_peer: std::net::SocketAddr,
    expected_transport: super::privilege_broker::BrokerSocketTransport,
    traffic: &super::readiness::ProxyTrafficObservation,
    activation_id: &str,
    generation: u64,
    maximum_traffic_duration: std::time::Duration,
    maximum_response_bytes: usize,
) -> Result<()> {
    ensure!(expected.interface_name == interface_name, "Xray readiness interface differs from the manifest-bound expectation");
    ensure!(plan.interface_name == interface_name && plan.interface_index == expected.interface_index,
        "Xray routing plan does not match the expected TUN interface identity");
    ensure!(process.verify()?, "Xray process identity is not live before readiness verification");

    verify_xray_tun_attachment(process, interface_name, expected.interface_index)
        .context("Xray has not adopted the expected broker-owned TUN interface")?;
    let live_listener = super::readiness::probe_core_listener(process, listener, listener_timeout)?;
    let live_interface = super::readiness::probe_tun_interface(interface_name, expected.interface_index)?;
    super::readiness::probe_routing_policy(plan)?;

    super::readiness::validate_proxy_traffic_observation(
        traffic, activation_id, generation, process,
        maximum_traffic_duration, maximum_response_bytes,
    ).context("Xray proxied-traffic observation is invalid")?;

    let mut complete = evidence.clone();
    complete.core_process_verified = true;
    complete.local_listener = Some(live_listener);
    complete.tun_interface = Some(live_interface);
    complete.route_policy_verified = true;
    complete.proxied_traffic_verified = true;
    super::readiness::verify_readiness_with_socket_mark(
        expected, &complete, socket_mark_response, expected_peer, expected_transport,
    ).context("Xray readiness evidence failed the shared TUN readiness gate")?;
    ensure!(process.verify()?, "Xray process identity changed during readiness verification");
    Ok(())
}


/// Wait for Xray to expose the exact TUN attachment in kernel fdinfo.
///
/// This is a bounded startup wait (maximum five seconds), not a traffic-readiness check.
pub fn wait_for_xray_tun_attachment(
    process: &ProcessIdentity,
    interface_name: &str,
    expected_ifindex: u32,
    timeout: std::time::Duration,
) -> Result<()> {
    ensure!(!timeout.is_zero() && timeout <= std::time::Duration::from_secs(5),
        "Xray TUN attachment wait must be between zero and five seconds");
    let handle = ProcessHandle::open(process.clone())
        .context("cannot pin Xray while waiting for TUN attachment")?;
    let deadline = std::time::Instant::now() + timeout;
    let mut last_error = None;
    loop {
        ensure!(!handle.is_exited()?, "Xray exited before adopting its TUN descriptor");
        match verify_xray_tun_attachment(process, interface_name, expected_ifindex) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50).min(
            deadline.saturating_duration_since(std::time::Instant::now())
        ));
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Xray TUN attachment was not observed")))
        .context("Xray did not adopt the expected TUN interface before the startup deadline")
}


/// Spawn Xray and require kernel-confirmed attachment before returning the child handle.
///
/// On attachment timeout or early exit, this function terminates and reaps only the child it
/// created. The caller remains responsible for generation-scoped broker rollback and lifecycle
/// manifest cleanup.
pub fn spawn_xray_with_verified_attachment(
    helper: &MutationHelper,
    activation_id: &str,
    generation: u64,
    executable: &Path,
    config: &Path,
    interface_name: &str,
    expected_ifindex: u32,
    attachment_timeout: std::time::Duration,
) -> Result<(Child, ProcessIdentity)> {
    let (mut child, identity) = spawn_xray_from_broker(
        helper, activation_id, generation, executable, config, interface_name, expected_ifindex,
    )?;
    if let Err(error) = wait_for_xray_tun_attachment(
        &identity, interface_name, expected_ifindex, attachment_timeout,
    ) {
        if let Err(termination_error) = terminate_and_reap_xray(&mut child, &identity) {
            return Err(error).context(format!(
                "Xray failed TUN attachment and bounded child termination/reaping also failed: {termination_error:#}"
            ));
        }
        return Err(error).context("Xray did not attach the expected TUN device; child was terminated and reaped");
    }
    Ok((child, identity))
}


/// Terminate and reap the exact Xray child without an unbounded wait.
pub fn terminate_and_reap_xray(child: &mut Child, process: &ProcessIdentity) -> Result<()> {
    let handle = ProcessHandle::open(process.clone())
        .context("cannot pin Xray child for bounded termination")?;
    if !handle.is_exited()? {
        if let Err(signal_error) = handle.signal(libc::SIGKILL) {
            ensure!(handle.is_exited()?, "cannot terminate Xray child: {signal_error:#}");
        }
        ensure!(handle.wait_exit(std::time::Duration::from_secs(2))?,
            "Xray child did not exit within the two-second termination bound");
    }
    child.wait().context("cannot reap terminated Xray child")?;
    Ok(())
}
