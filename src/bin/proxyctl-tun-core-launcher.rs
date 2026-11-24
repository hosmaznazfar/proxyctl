//! Minimal systemd-launched Xray exec shim for broker-owned TUN descriptors.
//!
//! The service manager grants no Linux capabilities to this process. The broker creates
//! and configures the TUN device, then transfers its already-open descriptor. This launcher
//! validates the interface identity and starts Xray without network-administration privileges.
#[cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
#[cfg(target_os = "linux")]
use std::{
    env, fs,
    io::Write,
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("proxyctl-tun-core-launcher: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<()> {
    let mut args = env::args_os().skip(1);
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--socket")),
        "expected --socket PATH"
    );
    let socket_path = PathBuf::from(args.next().context("missing private socket path")?);
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--activation-id")),
        "expected --activation-id UUID"
    );
    let activation_id = args
        .next()
        .context("missing activation UUID")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("activation UUID must be UTF-8"))?;
    ensure!(
        activation_id.len() == 36
            && activation_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
                }
            }),
        "activation UUID is invalid"
    );
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--generation")),
        "expected --generation NUMBER"
    );
    let generation = args
        .next()
        .context("missing activation generation")?
        .to_str()
        .context("activation generation must be UTF-8")?
        .parse::<u64>()
        .context("activation generation is invalid")?;
    ensure!(generation > 0, "activation generation must be positive");
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--parent-pid")),
        "expected --parent-pid PID"
    );
    let parent_pid = args
        .next()
        .context("missing parent PID")?
        .to_str()
        .context("parent PID must be UTF-8")?
        .parse::<u32>()
        .context("parent PID is invalid")?;
    ensure!(parent_pid > 0, "parent PID must be positive");
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--interface")),
        "expected --interface NAME"
    );
    let interface = args
        .next()
        .context("missing TUN interface name")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("interface name must be UTF-8"))?;
    ensure!(
        !interface.is_empty()
            && interface.len() < 16
            && interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')),
        "TUN interface name is invalid"
    );
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--ifindex")),
        "expected --ifindex INDEX"
    );
    let ifindex = args
        .next()
        .context("missing TUN interface index")?
        .to_str()
        .context("TUN interface index must be UTF-8")?
        .parse::<u32>()
        .context("TUN interface index is invalid")?;
    ensure!(ifindex > 0, "TUN interface index must be positive");
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--executable")),
        "expected --executable PATH"
    );
    let executable = PathBuf::from(args.next().context("missing Xray executable path")?);
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new("--config")),
        "expected --config PATH"
    );
    let config = PathBuf::from(args.next().context("missing Xray config path")?);
    ensure!(args.next().is_none(), "unexpected extra launcher arguments");

    verify_capability_boundary()?;
    validate_private_runtime_socket(&socket_path)?;
    validate_xray_paths(&executable, &config)?;

    let mut stream = UnixStream::connect(&socket_path)
        .context("cannot connect to the private controller descriptor socket")?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    let peer = proxyctl::tun::privilege_broker::read_broker_peer_credentials(&stream)?;
    ensure!(
        peer.uid == unsafe { libc::geteuid() } && peer.pid == parent_pid,
        "descriptor socket peer does not match the expected controller process"
    );

    let descriptor: OwnedFd = proxyctl::tun::descriptor_transfer::receive_descriptor(&stream)
        .context("cannot receive the broker-owned TUN descriptor")?;
    validate_tun_descriptor(descriptor.as_raw_fd(), &interface, ifindex)?;

    let inherited =
        proxyctl::cores::adapters::xray_tun_fd::XrayTunDescriptor::duplicate(descriptor.as_fd())
            .context("cannot duplicate the received broker-owned TUN descriptor")?;
    let mut command = Command::new(&executable);
    command
        .arg("run")
        .arg("-c")
        .arg(&config)
        .arg0("proxyctl-core");
    inherited.configure_command(&mut command)?;
    let mut child = command
        .spawn()
        .context("cannot spawn managed Xray with the broker-owned TUN descriptor")?;
    drop(inherited);
    drop(descriptor);

    // Command::spawn returns only after exec succeeded. Capture the actual Xray executable,
    // not this shim, so the returned identity remains valid after the handoff. Any failure
    // before the identity receipt is delivered must terminate and reap this exact child.
    let startup = (|| -> Result<()> {
        // Neither the shim nor Xray has capabilities, so procfs identity checks remain
        // available to the unprivileged controller and supervisor.
        let identity = proxyctl::tun::process::ProcessIdentity::capture(child.id())
            .context("cannot capture the spawned Xray process identity")?;
        ensure!(
            identity.executable == fs::canonicalize(&executable)?,
            "spawned process did not become the expected managed Xray executable"
        );

        // Persist the exact Xray child while the manifest is still Prepared. This closes the
        // controller-crash window between descriptor handoff and readiness/Running commit.
        let runtime = socket_path
            .parent()
            .context("descriptor socket has no runtime directory")?;
        let store = proxyctl::tun::manifest_store::ManifestStore::open(runtime)?;
        let coordinator = proxyctl::tun::lifecycle_coordinator::LifecycleCoordinator::new(store)?;
        let current = coordinator
            .load_current()?
            .context("Prepared TUN manifest disappeared before Xray process binding")?;
        ensure!(
            current.token.activation_id() == activation_id
                && current.token.generation() == generation
                && current.snapshot.phase == proxyctl::tun::recovery::SupervisorPhase::Prepared,
            "Xray process binding does not match the active Prepared generation"
        );
        ensure!(
            current.snapshot.manifest.interface_name == interface
                && current.snapshot.manifest.interface_index == ifindex,
            "Xray process binding interface identity differs from the broker manifest"
        );
        coordinator
            .bind_core_process(&current.token, identity.clone())
            .context("cannot persist Xray process identity before readiness")?;
        send_process_identity(&mut stream, &identity)?;
        Ok(())
    })();
    if let Err(error) = startup {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error)
            .context("Xray startup identity handoff failed; child was terminated and reaped");
    }
    let status = child
        .wait()
        .context("cannot wait for the Xray child process")?;
    ensure!(status.success(), "managed Xray exited unsuccessfully");
    Ok(())
}

#[cfg(target_os = "linux")]
fn send_process_identity(
    stream: &mut UnixStream,
    identity: &proxyctl::tun::process::ProcessIdentity,
) -> Result<()> {
    let payload = serde_json::to_vec(identity).context("cannot encode Xray process identity")?;
    ensure!(
        !payload.is_empty() && payload.len() <= 4096,
        "Xray process identity frame exceeds its bound"
    );
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream
        .write_all(&(payload.len() as u32).to_le_bytes())
        .context("cannot write Xray process identity frame length")?;
    stream
        .write_all(&payload)
        .context("cannot write Xray process identity frame")?;
    stream
        .flush()
        .context("cannot flush Xray process identity frame")
}

#[cfg(target_os = "linux")]
fn verify_capability_boundary() -> Result<()> {
    let status = fs::read_to_string("/proc/self/status")
        .context("cannot inspect core launcher capability state")?;
    let mut effective = None;
    let mut permitted = None;
    let mut bounding = None;
    let mut inheritable = None;
    let mut ambient = None;
    let mut no_new_privileges = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("CapEff:") {
            effective = Some(u64::from_str_radix(value.trim(), 16)?);
        } else if let Some(value) = line.strip_prefix("CapPrm:") {
            permitted = Some(u64::from_str_radix(value.trim(), 16)?);
        } else if let Some(value) = line.strip_prefix("CapBnd:") {
            bounding = Some(u64::from_str_radix(value.trim(), 16)?);
        } else if let Some(value) = line.strip_prefix("CapInh:") {
            inheritable = Some(u64::from_str_radix(value.trim(), 16)?);
        } else if let Some(value) = line.strip_prefix("CapAmb:") {
            ambient = Some(u64::from_str_radix(value.trim(), 16)?);
        } else if let Some(value) = line.strip_prefix("NoNewPrivs:") {
            no_new_privileges = Some(value.trim() == "1");
        }
    }
    ensure!(
        effective == Some(0)
            && permitted == Some(0)
            && bounding == Some(0)
            && inheritable == Some(0)
            && ambient == Some(0)
            && no_new_privileges == Some(true),
        "core launcher and Xray must run without Linux capabilities and with NoNewPrivileges"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_private_runtime_socket(socket: &Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    ensure!(
        socket.is_absolute() && socket.as_os_str().len() < 108,
        "descriptor socket path must be a bounded absolute Unix socket path"
    );
    let parent = socket
        .parent()
        .context("descriptor socket has no parent directory")?;
    let directory = fs::symlink_metadata(parent)?;
    ensure!(
        directory.is_dir()
            && !directory.file_type().is_symlink()
            && directory.uid() == unsafe { libc::geteuid() }
            && directory.permissions().mode() & 0o077 == 0
            && directory.permissions().mode() & 0o7000 == 0
            && directory.permissions().mode() & 0o700 == 0o700,
        "descriptor socket parent must be a caller-owned private directory"
    );
    let metadata = fs::symlink_metadata(socket)?;
    ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o777 == 0o600
            && metadata.permissions().mode() & 0o7000 == 0
            && metadata.nlink() == 1,
        "descriptor socket must be a caller-owned 0600 Unix socket"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_xray_paths(executable: &Path, config: &Path) -> Result<()> {
    ensure!(
        executable.is_absolute() && config.is_absolute(),
        "Xray executable and config paths must be absolute"
    );
    let expected = proxyctl::cores::core_binary_path(proxyctl::cores::CoreId::Xray)?;
    ensure!(
        fs::canonicalize(executable)? == fs::canonicalize(expected)?,
        "core launcher may execute only Proxyctl's managed Xray binary"
    );
    let binary = fs::symlink_metadata(executable)?;
    ensure!(
        binary.file_type().is_file()
            && binary.uid() == unsafe { libc::geteuid() }
            && binary.permissions().mode() & 0o111 != 0
            && binary.permissions().mode() & 0o022 == 0
            && binary.permissions().mode() & 0o7000 == 0,
        "managed Xray executable must be a caller-owned regular executable"
    );
    let config_metadata = fs::symlink_metadata(config)?;
    ensure!(
        config_metadata.file_type().is_file()
            && config_metadata.uid() == unsafe { libc::geteuid() }
            && config_metadata.permissions().mode() & 0o700 == 0o600
            && config_metadata.permissions().mode() & 0o077 == 0
            && config_metadata.permissions().mode() & 0o7000 == 0
            && config_metadata.nlink() == 1,
        "Xray config must be a caller-owned, single-link 0600 regular file"
    );
    let runtime = config
        .parent()
        .context("Xray config has no runtime parent")?;
    let runtime_metadata = fs::symlink_metadata(runtime)?;
    ensure!(
        runtime_metadata.is_dir()
            && !runtime_metadata.file_type().is_symlink()
            && runtime_metadata.uid() == unsafe { libc::geteuid() }
            && runtime_metadata.permissions().mode() & 0o077 == 0
            && runtime_metadata.permissions().mode() & 0o7000 == 0
            && runtime_metadata.permissions().mode() & 0o700 == 0o700,
        "Xray config must reside in the caller-owned private runtime directory"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_tun_descriptor(fd: i32, interface: &str, expected_ifindex: u32) -> Result<()> {
    ensure!(fd >= 0, "received TUN descriptor is invalid");
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))
        .context("cannot inspect received TUN descriptor metadata")?;
    ensure!(
        fdinfo.lines().any(|line| line
            .strip_prefix("iff:")
            .is_some_and(|value| value.trim() == interface)),
        "received descriptor is not bound to the expected TUN interface"
    );

    // TUNGETIFF reports the kernel's actual device mode. Do not accept TAP, PI-enabled,
    // or vnet-header descriptors: the Xray TUN inbound contract expects packet-mode TUN.
    const TUNGETIFF: libc::c_ulong = 0x8004_54d2;
    const IFF_TUN: u16 = 0x0001;
    const IFF_TAP: u16 = 0x0002;
    const IFF_NO_PI: u16 = 0x1000;
    const IFF_VNET_HDR: u16 = 0x4000;
    let mut request = [0u8; 40];
    // SAFETY: request is a writable Linux ifreq-sized buffer and fd is a received live fd.
    let result = unsafe { libc::ioctl(fd, TUNGETIFF, request.as_mut_ptr()) };
    ensure!(
        result == 0,
        "received descriptor does not support TUNGETIFF"
    );
    let flags = u16::from_ne_bytes([request[16], request[17]]);
    validate_tun_mode_flags(flags, IFF_TUN, IFF_TAP, IFF_NO_PI, IFF_VNET_HDR)?;
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        status >= 0 && status & libc::O_ACCMODE == libc::O_RDWR,
        "received TUN descriptor must be open for read/write packet I/O"
    );

    const TUNGETOWNER: libc::c_ulong = 0x8004_54cc;
    const TUNGETGROUP: libc::c_ulong = 0x8004_54ce;
    let mut owner: libc::c_int = -1;
    let mut group: libc::c_int = -1;
    // SAFETY: TUNGETOWNER/TUNGETGROUP write one integer to the supplied live pointers.
    ensure!(
        unsafe { libc::ioctl(fd, TUNGETOWNER, &mut owner) } == 0
            && unsafe { libc::ioctl(fd, TUNGETGROUP, &mut group) } == 0,
        "cannot inspect TUN descriptor owner and group"
    );
    ensure!(
        owner >= 0
            && owner as u32 == unsafe { libc::getuid() }
            && group >= 0
            && group as u32 == unsafe { libc::getgid() },
        "received TUN descriptor owner/group does not match the isolated Xray service identity"
    );

    let interface_path = Path::new("/sys/class/net").join(interface);
    ensure!(
        interface_path.join("tun_flags").is_file(),
        "expected interface is not a kernel TUN device"
    );
    let actual = fs::read_to_string(interface_path.join("ifindex"))?
        .trim()
        .parse::<u32>()
        .context("kernel returned an invalid TUN interface index")?;
    ensure!(
        actual == expected_ifindex,
        "TUN interface index changed before Xray exec"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_tun_mode_flags(
    flags: u16,
    tun: u16,
    tap: u16,
    no_pi: u16,
    vnet_hdr: u16,
) -> Result<()> {
    ensure!(
        flags & tun != 0 && flags & tap == 0 && flags & no_pi != 0 && flags & vnet_hdr == 0,
        "received descriptor must be IFF_TUN|IFF_NO_PI without TAP or VNET_HDR"
    );
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tun_descriptor_contract_tests {
    use super::validate_tun_mode_flags;

    #[test]
    fn accepts_only_packet_mode_tun_without_tap_or_vnet_header() {
        assert!(validate_tun_mode_flags(0x1001, 0x0001, 0x0002, 0x1000, 0x4000).is_ok());
        assert!(validate_tun_mode_flags(0x1003, 0x0001, 0x0002, 0x1000, 0x4000).is_err());
        assert!(validate_tun_mode_flags(0x0001, 0x0001, 0x0002, 0x1000, 0x4000).is_err());
        assert!(validate_tun_mode_flags(0x5001, 0x0001, 0x0002, 0x1000, 0x4000).is_err());
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("proxyctl-tun-core-launcher is supported only on Linux");
    std::process::exit(1);
}
