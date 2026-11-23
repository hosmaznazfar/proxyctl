//! Independent verification of process attachment to a kernel TUN interface.
//!
//! This module verifies live kernel state rather than trusting configuration or caller evidence.
//! A pidfd pins the process instance while /proc fdinfo and sysfs are inspected.

#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{fs, time::Duration};

use super::process::{ProcessHandle, ProcessIdentity};

/// Verify that a pinned process holds a descriptor for the exact named TUN interface.
pub fn verify_process_tun_attachment(
    process: &ProcessIdentity,
    interface_name: &str,
    expected_ifindex: u32,
) -> Result<()> {
    ensure!(
        !interface_name.is_empty()
            && interface_name.len() < 16
            && interface_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
        "native core TUN interface name is invalid"
    );
    ensure!(
        expected_ifindex > 0,
        "expected native TUN ifindex must be positive"
    );
    ensure!(
        process.verify()?,
        "native core process identity is not live"
    );
    let handle = ProcessHandle::open(process.clone())
        .context("cannot pin native core while inspecting TUN attachment")?;
    let interface = std::path::Path::new("/sys/class/net").join(interface_name);
    ensure!(
        interface.join("tun_flags").is_file(),
        "expected native interface is not a kernel TUN device"
    );
    let actual_ifindex = fs::read_to_string(interface.join("ifindex"))?
        .trim()
        .parse::<u32>()
        .context("kernel returned an invalid native TUN ifindex")?;
    ensure!(
        actual_ifindex == expected_ifindex,
        "native TUN interface index changed"
    );
    let fdinfo = std::path::Path::new("/proc")
        .join(process.pid.to_string())
        .join("fdinfo");
    let entries = fs::read_dir(&fdinfo).context("cannot inspect native core fdinfo")?;
    let mut attached = false;
    for entry in entries {
        let entry = entry.context("cannot enumerate native core fdinfo")?;
        let metadata = match fs::read_to_string(entry.path()) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("cannot read native core fdinfo"),
        };
        if fdinfo_names_interface(&metadata, interface_name) {
            attached = true;
            break;
        }
    }
    ensure!(
        attached,
        "native core does not hold a TUN descriptor for the requested interface"
    );
    ensure!(
        process.verify()? && !handle.is_exited()?,
        "native core exited or changed during attachment verification"
    );
    Ok(())
}

/// Wait at most five seconds for a native core to open the exact persistent TUN device.
pub fn wait_for_process_tun_attachment(
    process: &ProcessIdentity,
    interface_name: &str,
    expected_ifindex: u32,
    timeout: Duration,
) -> Result<()> {
    ensure!(
        !timeout.is_zero() && timeout <= Duration::from_secs(5),
        "native TUN attachment wait must be between zero and five seconds"
    );
    let handle = ProcessHandle::open(process.clone())
        .context("cannot pin native core while waiting for TUN attachment")?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        ensure!(
            !handle.is_exited()?,
            "native core exited before opening its TUN device"
        );
        if verify_process_tun_attachment(process, interface_name, expected_ifindex).is_ok() {
            return Ok(());
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "native core did not attach to the requested TUN device before timeout"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn fdinfo_names_interface(contents: &str, expected: &str) -> bool {
    contents.lines().any(|line| {
        line.strip_prefix("iff:")
            .is_some_and(|value| value.trim() == expected)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdinfo_interface_match_is_exact() {
        assert!(fdinfo_names_interface(
            "pos:\t0\niff:\ttun-proxyctl\n",
            "tun-proxyctl"
        ));
        assert!(!fdinfo_names_interface(
            "iff:\ttun-proxyctl-extra\n",
            "tun-proxyctl"
        ));
        assert!(!fdinfo_names_interface("pos:\t0\n", "tun-proxyctl"));
    }

    #[test]
    fn native_attachment_wait_is_strictly_bounded() {
        let process = ProcessIdentity {
            pid: 1,
            start_ticks: 1,
            executable: std::path::PathBuf::from("/usr/bin/true"),
        };
        assert!(
            wait_for_process_tun_attachment(
                &process,
                "tun-proxyctl",
                7,
                Duration::from_secs(6)
            )
            .is_err()
        );
        assert!(
            wait_for_process_tun_attachment(
                &process,
                "tun-proxyctl",
                7,
                Duration::ZERO
            )
            .is_err()
        );
    }
}
