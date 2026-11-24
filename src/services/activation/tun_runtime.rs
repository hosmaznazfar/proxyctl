//! Linux TUN recovery helpers retained for safely stopping legacy generations.
use super::*;

#[cfg(target_os = "linux")]
pub(super) struct TunStopContext {
    sudo: PathBuf,
    systemctl: PathBuf,
    unit: String,
}

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

pub(super) fn systemd_property(context: &TunStopContext, property: &str) -> anyhow::Result<String> {
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

pub(super) fn systemd_main_pid(context: &TunStopContext) -> anyhow::Result<Option<u32>> {
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

pub(super) fn stop_systemd_unit(context: &TunStopContext) -> anyhow::Result<()> {
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

pub(super) fn stop_tun_locked(
    runtime: &Path,
    state_path: &Path,
    state: &ActiveProcess,
) -> anyhow::Result<()> {
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
    let context = TunStopContext {
        sudo,
        systemctl,
        unit: tun.unit.clone(),
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

pub(super) fn legacy_tun_snapshot_is_safe_to_retire(
    baseline: &TunBaseline,
    current: &TunBaseline,
) -> bool {
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
