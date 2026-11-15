//! Linux TUN activation preparation and service lifecycle helpers.
//!
//! This module only contains the already-gated activation implementation. The public
//! activation entry point continues to reject TUN until the production recovery stack is ready.
use super::*;

#[cfg(target_os = "linux")]
pub(super) fn ip_json_snapshot(arguments: &[&str]) -> anyhow::Result<Vec<String>> {
    let ip = find_program("ip")?;
    let output = Command::new(ip)
        .args(arguments)
        .output()
        .context("could not inspect Linux route tables")?;
    ensure!(
        output.status.success(),
        "could not capture the complete Linux route/rule baseline; TUN activation was not started"
    );
    let mut value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .context("iproute2 returned an invalid JSON route/rule snapshot")?;
    let entries = value
        .as_array_mut()
        .context("iproute2 route/rule snapshot was not a JSON array")?;
    // IPv6 route lifetimes count down continuously; they are not route-ownership changes.
    for entry in entries.iter_mut() {
        if let Some(object) = entry.as_object_mut() {
            object.remove("expires");
        }
    }
    let mut snapshot = entries
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?;
    snapshot.sort();
    Ok(snapshot)
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub(super) fn launch_tun_managed(
    runtime: &Path,
    state_path: &Path,
    managed_root: &Path,
    executable: &Path,
    config: &Path,
    config_content: &[u8],
    node_id: u64,
    core: CoreId,
    port: u16,
    mut context: TunLaunchContext,
    timeout: Duration,
) -> anyhow::Result<()> {
    ensure!(
        executable.starts_with(managed_root),
        "refusing to run a core outside Proxyctl's managed directory"
    );
    write_atomic(config, config_content)?;
    if let Err(error) = stop_locked(runtime, state_path, managed_root) {
        let _ = fs::remove_file(config);
        return Err(error);
    }
    // If replacing an existing TUN core, snapshot only after its owned routes are gone.
    context.baseline = match TunBaseline::capture() {
        Ok(baseline) if baseline.tun_interfaces.is_empty() => baseline,
        Ok(_) => {
            let _ = fs::remove_file(config);
            anyhow::bail!(
                "another TUN/TAP interface remains after stopping Proxyctl's previous activation; refusing to start a second TUN"
            );
        }
        Err(error) => {
            let _ = fs::remove_file(config);
            return Err(error);
        }
    };
    let mut state = ActiveProcess {
        pid: 0,
        start_ticks: 0,
        executable: executable.to_path_buf(),
        config: config.to_path_buf(),
        node_id,
        core: core.as_str().to_owned(),
        port,
        tun: Some(TunProcess {
            unit: context.unit.clone(),
            uid: context.uid,
            baseline: context.baseline.clone(),
        }),
    };
    if let Err(error) = write_atomic(state_path, &serde_json::to_vec(&state)?) {
        let _ = fs::remove_file(config);
        return Err(error);
    }
    let start_result = (|| {
        start_tun_service(&context, executable, core, config)?;
        let pid = await_systemd_main_pid(&context, timeout)?;
        let ticks = await_identity(pid, executable, timeout)?;
        ensure!(
            process_has_only_tun_capability(pid, context.uid),
            "TUN service did not start with the expected unprivileged UID and CAP_NET_ADMIN-only capability set"
        );
        state.pid = pid;
        state.start_ticks = ticks;
        write_atomic(state_path, &serde_json::to_vec(&state)?)?;
        await_listener(pid, ticks, port, timeout)?;
        await_tun_interface(pid, ticks, timeout)?;
        Ok(())
    })();
    if let Err(error) = start_result {
        return match stop_locked(runtime, state_path, managed_root) {
            Ok(()) => Err(error),
            Err(cleanup) => anyhow::bail!(
                "TUN activation failed ({error:#}); cleanup could not be verified ({cleanup:#}). State and config were retained."
            ),
        };
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn tun_interfaces_are_safe(interfaces: &[String], active_proxyctl_tun: bool) -> bool {
    interfaces.is_empty()
        || (active_proxyctl_tun && interfaces.iter().all(|name| name == "tun-proxyctl"))
}

#[cfg(target_os = "linux")]
pub(super) fn prepare_tun_launch(runtime: &Path, state_path: &Path) -> anyhow::Result<TunLaunchContext> {
    ensure!(
        Path::new("/run/systemd/system").is_dir(),
        "TUN activation requires a running systemd system manager; ordinary activation remains available"
    );
    let _tun_device = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context("TUN activation requires readable/writable /dev/net/tun")?;
    let active_proxyctl_tun = if state_path.exists() {
        let state: ActiveProcess = serde_json::from_slice(&fs::read(state_path)?)
            .context("activation state is corrupt; refusing TUN preflight")?;
        ensure!(
            state.config.parent() == Some(runtime),
            "activation state config path is outside the private runtime directory"
        );
        state.tun.is_some()
    } else {
        false
    };
    let status = crate::tun::inspect()?;
    ensure!(
        status.routes_inspected && status.dns_inspected,
        "TUN activation requires readable baseline route and DNS state; no changes were made"
    );
    ensure!(
        tun_interfaces_are_safe(&status.tun_interfaces, active_proxyctl_tun),
        "a foreign TUN/TAP interface is already present; stop that VPN before enabling Proxyctl TUN mode"
    );
    let baseline = TunBaseline::capture()?;
    let sudo = find_program("sudo")?;
    let systemd_run = find_program("systemd-run")?;
    let systemctl = find_program("systemctl")?;
    // Let sudo prompt through the user's terminal. Proxyctl never reads or stores the password.
    let authorization = Command::new(&sudo).arg("-v").status()?;
    ensure!(
        authorization.success(),
        "sudo authorization was not granted; no TUN service or network changes were made"
    );
    let mut token = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut token)?;
    let suffix = token
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let unit = format!("proxyctl-tun-{suffix}.service");
    let context = TunLaunchContext {
        sudo,
        systemd_run,
        systemctl,
        unit,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        baseline,
    };
    // Verify that systemd accepts the exact unprivileged-user/CAP_NET_ADMIN policy before
    // stopping any existing activation. The one-shot command is /usr/bin/true and changes no
    // interfaces, routes, DNS, or firewall state.
    let true_executable = find_program("true")?;
    preflight_tun_service(&context, &true_executable)?;
    Ok(context)
}

#[cfg(target_os = "linux")]
pub(super) fn build_tun_preflight_command(context: &TunLaunchContext, true_executable: &Path) -> Command {
    let unit = format!(
        "{}-preflight.service",
        context.unit.trim_end_matches(".service")
    );
    let mut command = Command::new(&context.sudo);
    command
        .args(["-n", "--"])
        .arg(&context.systemd_run)
        .arg("--system")
        .arg("--quiet")
        .arg("--wait")
        .arg("--collect")
        .arg(format!("--unit={unit}"))
        .arg(format!("--property=User={}", context.uid))
        .arg(format!("--property=Group={}", context.gid))
        .arg("--property=CapabilityBoundingSet=CAP_NET_ADMIN")
        .arg("--property=AmbientCapabilities=CAP_NET_ADMIN")
        .arg("--property=NoNewPrivileges=yes")
        .arg("--")
        .arg(true_executable);
    command
}

#[cfg(target_os = "linux")]
pub(super) fn preflight_tun_service(context: &TunLaunchContext, true_executable: &Path) -> anyhow::Result<()> {
    let output = build_tun_preflight_command(context, true_executable)
        .output()
        .context("could not preflight the isolated TUN systemd service")?;
    ensure!(
        output.status.success(),
        "systemd cannot create the required unprivileged CAP_NET_ADMIN service; existing activation was not stopped"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn find_program(name: &str) -> anyhow::Result<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return fs::canonicalize(candidate)
                .with_context(|| format!("could not resolve required utility {name}"));
        }
    }
    anyhow::bail!("required utility {name} was not found in PATH")
}

#[cfg(target_os = "linux")]
pub(super) fn build_tun_service_command(
    context: &TunLaunchContext,
    executable: &Path,
    core: CoreId,
    config: &Path,
) -> Command {
    let mut command = Command::new(&context.sudo);
    command
        .args(["-n", "--"])
        .arg(&context.systemd_run)
        .arg("--system")
        .arg("--quiet")
        .arg("--collect")
        .arg(format!("--unit={}", context.unit))
        .arg(format!("--property=User={}", context.uid))
        .arg(format!("--property=Group={}", context.gid))
        .arg("--property=CapabilityBoundingSet=CAP_NET_ADMIN")
        .arg("--property=AmbientCapabilities=CAP_NET_ADMIN")
        .arg("--property=NoNewPrivileges=yes")
        .arg("--property=KillMode=control-group")
        .arg("--property=KillSignal=SIGTERM")
        .arg("--property=TimeoutStopSec=5s")
        .arg("--property=SendSIGKILL=yes")
        .arg("--property=Restart=no")
        .arg("--property=UMask=0077")
        .arg("--property=PrivateTmp=yes")
        .arg("--property=StandardOutput=null")
        .arg("--property=StandardError=null")
        .arg("--")
        .arg(executable);
    match core {
        CoreId::SingBox | CoreId::Xray => {
            command.arg("run").arg("-c").arg(config);
        }
        CoreId::Mihomo => {
            command.arg("-f").arg(config);
        }
    }
    command
}

#[cfg(target_os = "linux")]
pub(super) fn start_tun_service(
    context: &TunLaunchContext,
    executable: &Path,
    core: CoreId,
    config: &Path,
) -> anyhow::Result<()> {
    let output = build_tun_service_command(context, executable, core, config)
        .output()
        .context("could not invoke systemd-run")?;
    ensure!(
        output.status.success(),
        "systemd refused to start the isolated TUN service; raw privileged command output withheld"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn systemd_property(context: &TunLaunchContext, property: &str) -> anyhow::Result<String> {
    let output = Command::new(&context.sudo)
        .args(["-n", "--"])
        .arg(&context.systemctl)
        .arg("show")
        .arg(format!("--property={property}"))
        .arg("--value")
        .arg(&context.unit)
        .output()
        .context("could not inspect the Proxyctl TUN service")?;
    ensure!(
        output.status.success(),
        "could not inspect the Proxyctl TUN service; refusing to signal a process"
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(target_os = "linux")]
pub(super) fn systemd_main_pid(context: &TunLaunchContext) -> anyhow::Result<Option<u32>> {
    let load_state = systemd_property(context, "LoadState")?;
    if load_state == "not-found" {
        return Ok(None);
    }
    ensure!(
        load_state == "loaded",
        "Proxyctl TUN service has an unexpected systemd state; refusing to signal a process"
    );
    let pid = systemd_property(context, "MainPID")?
        .parse::<u32>()
        .context("systemd returned an invalid TUN service PID")?;
    Ok((pid != 0).then_some(pid))
}

#[cfg(target_os = "linux")]
pub(super) fn await_systemd_main_pid(context: &TunLaunchContext, timeout: Duration) -> anyhow::Result<u32> {
    let start = Instant::now();
    loop {
        if let Some(pid) = systemd_main_pid(context)? {
            return Ok(pid);
        }
        ensure!(
            start.elapsed() < timeout,
            "TUN service did not publish a running core process"
        );
        thread::sleep(POLL);
    }
}

#[cfg(target_os = "linux")]
pub(super) fn process_status_has_only_tun_capability(status: &str, expected_uid: u32) -> bool {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
    };
    let uid_matches = field("Uid:").is_some_and(|value| {
        let values = value
            .split_whitespace()
            .filter_map(|uid| uid.parse::<u32>().ok())
            .collect::<Vec<_>>();
        values.len() == 4 && values.iter().all(|uid| *uid == expected_uid)
    });
    const NET_ADMIN: u64 = 1 << 12;
    let capability_matches = ["CapEff:", "CapPrm:", "CapBnd:", "CapAmb:"]
        .into_iter()
        .all(|name| {
            field(name).and_then(|value| u64::from_str_radix(value, 16).ok()) == Some(NET_ADMIN)
        });
    uid_matches && capability_matches
}

#[cfg(target_os = "linux")]
pub(super) fn process_has_only_tun_capability(pid: u32, expected_uid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .is_ok_and(|status| process_status_has_only_tun_capability(&status, expected_uid))
}

#[cfg(target_os = "linux")]
pub(super) fn await_tun_interface(pid: u32, ticks: u64, timeout: Duration) -> anyhow::Result<()> {
    let interface = Path::new("/sys/class/net/tun-proxyctl");
    let start = Instant::now();
    loop {
        ensure!(
            start_ticks(pid) == Some(ticks),
            "managed TUN core exited before its interface became ready"
        );
        if interface.join("tun_flags").exists() {
            return Ok(());
        }
        ensure!(
            start.elapsed() < timeout,
            "managed core did not create the expected tun-proxyctl interface"
        );
        thread::sleep(POLL);
    }
}

#[cfg(target_os = "linux")]
pub(super) fn stop_systemd_unit(context: &TunLaunchContext) -> anyhow::Result<()> {
    let output = Command::new(&context.sudo)
        .args(["-n", "--"])
        .arg(&context.systemctl)
        .arg("stop")
        .arg(&context.unit)
        .output()?;
    ensure!(
        output.status.success(),
        "systemd could not stop the exact Proxyctl TUN service"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn stop_tun_locked(runtime: &Path, state_path: &Path, state: &ActiveProcess) -> anyhow::Result<()> {
    let tun = state
        .tun
        .as_ref()
        .context("missing TUN ownership manifest")?;
    ensure!(
        tun.unit.starts_with("proxyctl-tun-") && tun.unit.ends_with(".service"),
        "recorded TUN service name is outside Proxyctl's namespace; refusing systemd operation"
    );
    let systemctl = find_program("systemctl")?;
    let load_output = Command::new(&systemctl)
        .arg("show")
        .arg("--property=LoadState")
        .arg("--value")
        .arg(&tun.unit)
        .output()
        .context("could not inspect the recorded Proxyctl TUN service")?;
    ensure!(
        load_output.status.success(),
        "could not inspect the recorded Proxyctl TUN service; refusing cleanup"
    );
    let load_state = String::from_utf8_lossy(&load_output.stdout)
        .trim()
        .to_owned();

    // Older TUN activation state stored only a whole-machine baseline, not exact
    // resource fingerprints. Retire it only when the service is absent, no
    // process was ever recorded, and the live snapshot proves no TUN interface
    // or route/rule additions exist. This path never mutates kernel networking.
    if load_state == "not-found" && state.pid == 0 && state.start_ticks == 0 {
        let current = TunBaseline::capture()?;
        ensure!(
            legacy_tun_snapshot_is_safe_to_retire(&tun.baseline, &current),
            "stale TUN state is not safe to retire: a TUN interface or route/rule resource may remain; state/config retained"
        );
        ensure!(
            state.config.parent() == Some(runtime),
            "TUN config path is outside the private runtime directory; refusing cleanup"
        );
        fs::remove_file(&state.config).or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        })?;
        fs::remove_file(state_path)?;
        println!(
            "Retired stale Proxyctl TUN runtime state for node #{}; no network resources were changed.",
            state.node_id
        );
        return Ok(());
    }

    let sudo = find_program("sudo")?;
    let context = TunLaunchContext {
        sudo,
        systemd_run: PathBuf::new(),
        systemctl,
        unit: tun.unit.clone(),
        uid: tun.uid,
        gid: unsafe { libc::getgid() },
        baseline: tun.baseline.clone(),
    };
    if load_state == "loaded" {
        let pid = systemd_property(&context, "MainPID")?
            .parse::<u32>()
            .context("systemd returned an invalid TUN service PID")?;
        let tracked = if pid == 0 {
            None
        } else {
            ensure!(
                state.pid == 0 || state.pid == pid,
                "TUN service PID differs from the recorded process; refusing to stop it"
            );
            let ticks = if state.start_ticks == 0 {
                await_identity(pid, &state.executable, WAIT)?
            } else {
                state.start_ticks
            };
            ensure!(
                matches_process(pid, &state.executable, ticks),
                "TUN process identity changed; refusing systemd stop"
            );
            Some((pid, ticks))
        };
        stop_systemd_unit(&context)?;
        if let Some((pid, ticks)) = tracked {
            wait_exit(pid, ticks, Duration::from_secs(10));
            ensure!(
                !matches_process(pid, &state.executable, ticks),
                "TUN core did not exit; activation state and config were retained"
            );
        }
        ensure!(
            systemd_main_pid(&context)?.is_none(),
            "TUN systemd service still has a running process after stop"
        );
        if state.pid != 0 && state.start_ticks != 0 {
            wait_exit(state.pid, state.start_ticks, Duration::from_secs(10));
            ensure!(
                !matches_process(state.pid, &state.executable, state.start_ticks),
                "the recorded TUN core process is still running after systemd stop"
            );
        }
    } else {
        ensure!(
            load_state == "not-found",
            "Proxyctl TUN service has an unexpected load state; refusing cleanup"
        );
        ensure!(
            state.pid == 0 || !matches_process(state.pid, &state.executable, state.start_ticks),
            "the recorded TUN core is still running but its systemd unit is unavailable; refusing to signal it directly"
        );
    }
    let current_baseline = TunBaseline::capture()?;
    let differences = tun.baseline.differences(&current_baseline);
    ensure!(
        differences.is_empty(),
        "TUN cleanup did not restore the baseline ({}) ; state/config retained for manual inspection, no routes or interfaces were deleted",
        differences.join(", ")
    );
    ensure!(
        state.config.parent() == Some(runtime),
        "TUN config path is outside the private runtime directory; refusing cleanup"
    );
    for path in [state.config.as_path(), state_path] {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    println!(
        "Stopped Proxyctl-managed TUN service for node #{}; network baseline restored.",
        state.node_id
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn legacy_tun_snapshot_is_safe_to_retire(baseline: &TunBaseline, current: &TunBaseline) -> bool {
    // Legacy state has no per-resource ownership fingerprints. It is safe to
    // discard only when the baseline itself had no TUN interface, none exists
    // now, and every current route/rule was already present in the baseline.
    // Removed baseline entries and unrelated interface/DNS changes are ignored;
    // any newly observed route/rule keeps recovery fail-closed.
    baseline.tun_interfaces.is_empty()
        && current.tun_interfaces.is_empty()
        && current
            .ipv4_routes
            .iter()
            .all(|entry| baseline.ipv4_routes.contains(entry))
        && current
            .ipv6_routes
            .iter()
            .all(|entry| baseline.ipv6_routes.contains(entry))
        && current
            .ipv4_rules
            .iter()
            .all(|entry| baseline.ipv4_rules.contains(entry))
        && current
            .ipv6_rules
            .iter()
            .all(|entry| baseline.ipv6_rules.contains(entry))
}


