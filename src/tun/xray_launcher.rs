//! Xray Linux launcher using the broker-owned TUN descriptor.
//!
//! This is a core-specific launch primitive. It does not activate routes, commit a lifecycle
//! manifest, or prove traffic readiness; the caller must compose those steps and keep public
//! activation gated until the full lifecycle is connected.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    os::fd::AsFd,
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
};

use crate::{
    cores::adapters::xray_tun_fd::XrayTunDescriptor,
    tun::{mutation_helper_launcher::MutationHelper, process::{ProcessHandle, ProcessIdentity}},
};

/// Spawn Xray with the descriptor retained by the exact broker activation generation.
///
/// Xray's documented Linux `XRAY_TUN_FD` input causes it to duplicate and consume this
/// externally supplied TUN descriptor. The broker's original descriptor remains owned by
/// the helper; this process receives a duplicate with close-on-exec cleared only in its child.
pub fn spawn_xray_from_broker(
    helper: &MutationHelper,
    activation_id: &str,
    generation: u64,
    executable: &Path,
    config: &Path,
) -> Result<(Child, ProcessIdentity)> {
    ensure!(executable.is_absolute(), "Xray executable path must be absolute");
    ensure!(config.is_absolute(), "Xray config path must be absolute");
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

    let broker_descriptor = helper.attach_descriptor(activation_id, generation)
        .context("cannot obtain the broker-owned TUN descriptor for Xray")?;
    let inherited = XrayTunDescriptor::duplicate(broker_descriptor.as_fd())
        .context("cannot prepare the Xray TUN descriptor for child inheritance")?;

    let mut command = Command::new(&executable);
    command.arg("run").arg("-c").arg(&config)
        .arg0("proxyctl-core")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    inherited.configure_command(&mut command)?;

    let mut child = command.spawn().context("cannot spawn Xray with the broker-owned TUN descriptor")?;
    drop(inherited);
    drop(broker_descriptor);

    let identity = match ProcessIdentity::capture(child.id()) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("cannot capture the spawned Xray process identity");
        }
    };
    Ok((child, identity))
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
        helper, activation_id, generation, executable, config,
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
