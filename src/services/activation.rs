//! Linux single-core activation with private state and identity-checked shutdown.
use crate::{
    cores::{CoreId, adapters, core_binary_path, managed_cores_path},
    database::{NodeDatabase, default_database_path},
};
use anyhow::{Context, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::TcpStream,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use std::{io::Read, os::unix::process::CommandExt};

const WAIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);
#[cfg(target_os = "linux")]
const PROCESS_NAME: &str = "proxyctl-core";

#[derive(Debug, Serialize, Deserialize)]
struct ActiveProcess {
    pid: u32,
    start_ticks: u64,
    executable: PathBuf,
    config: PathBuf,
    node_id: u64,
    core: String,
    port: u16,
    #[serde(default)]
    tun: Option<TunProcess>,
}
#[derive(Debug, Serialize, Deserialize)]
struct TunProcess {
    unit: String,
    uid: u32,
    baseline: TunBaseline,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TunBaseline {
    interfaces: Vec<String>,
    tun_interfaces: Vec<String>,
    default_routes: Vec<String>,
    dns_servers: Vec<String>,
    resolv_conf_target: Option<String>,
    ipv4_routes: Vec<String>,
    ipv6_routes: Vec<String>,
    ipv4_rules: Vec<String>,
    ipv6_rules: Vec<String>,
}

impl TunBaseline {
    #[cfg(target_os = "linux")]
    fn capture() -> anyhow::Result<Self> {
        let status = crate::tun::inspect()?;
        ensure!(
            status.routes_inspected && status.dns_inspected,
            "TUN activation requires readable baseline route and DNS state; no changes were made"
        );
        Ok(Self {
            interfaces: status.interfaces,
            tun_interfaces: status.tun_interfaces,
            default_routes: status.default_routes,
            dns_servers: status.dns_servers,
            resolv_conf_target: status.resolv_conf_target,
            ipv4_routes: ip_json_snapshot(&["-j", "-4", "route", "show", "table", "all"])?,
            ipv6_routes: ip_json_snapshot(&["-j", "-6", "route", "show", "table", "all"])?,
            ipv4_rules: ip_json_snapshot(&["-j", "-4", "rule", "show"])?,
            ipv6_rules: ip_json_snapshot(&["-j", "-6", "rule", "show"])?,
        })
    }
    #[cfg(target_os = "linux")]
    fn differences(&self, current: &Self) -> Vec<String> {
        let mut differences = Vec::new();
        macro_rules! compare {
            ($field:ident, $label:literal) => {
                if self.$field != current.$field {
                    differences.push($label.to_owned());
                }
            };
        }
        compare!(interfaces, "network interfaces");
        compare!(tun_interfaces, "TUN/TAP interfaces");
        compare!(default_routes, "default routes");
        compare!(dns_servers, "DNS nameservers");
        compare!(resolv_conf_target, "resolv.conf target");
        compare!(ipv4_routes, "IPv4 routing tables");
        compare!(ipv6_routes, "IPv6 routing tables");
        compare!(ipv4_rules, "IPv4 policy rules");
        compare!(ipv6_rules, "IPv6 policy rules");
        differences
    }
}
#[cfg(target_os = "linux")]
struct TunLaunchContext {
    sudo: PathBuf,
    systemd_run: PathBuf,
    systemctl: PathBuf,
    unit: String,
    uid: u32,
    gid: u32,
    baseline: TunBaseline,
}
struct RuntimeLock(File);
impl RuntimeLock {
    fn acquire(dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(dir)?;
        private_dir(dir)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(dir.join("activation.lock"))?;
        private_fd(file.as_raw_fd())?;
        // SAFETY: file is a live descriptor owned by this guard.
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0,
            "could not lock activation state"
        );
        Ok(Self(file))
    }
}
impl Drop for RuntimeLock {
    fn drop(&mut self) {
        // SAFETY: file remains open while this guard is dropped.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn activate(
    node_id: u64,
    core: CoreId,
    tun_enabled: bool,
    port_override: Option<u16>,
) -> anyhow::Result<()> {
    ensure_tun_mode_disabled(tun_enabled)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (node_id, core, tun_enabled, port_override);
        anyhow::bail!("activation currently requires Linux process-identity support");
    }
    #[cfg(target_os = "linux")]
    {
        let (runtime, state_path) = paths()?;
        let _lock = RuntimeLock::acquire(&runtime)?;
        let db = NodeDatabase::open(default_database_path()?)?;
        let record = db
            .get_node(node_id)?
            .with_context(|| format!("node #{node_id} not found"))?;
        ensure!(
            !record.is_deleted(),
            "node #{node_id} is deleted; restore it first"
        );
        let node = record.node;
        drop(db);

        let executable = core_binary_path(core)?;
        ensure!(
            executable.is_file(),
            "{core} is not installed by Proxyctl; run setup --core {core}"
        );
        let executable = fs::canonicalize(executable)?;
        let managed = fs::canonicalize(managed_cores_path()?)?;
        ensure!(
            executable.starts_with(&managed),
            "refusing to run a core outside Proxyctl's managed directory"
        );
        let adapter = adapters::adapter(core);
        let compatibility = adapter.compatibility(&node);
        ensure!(
            compatibility.is_supported(),
            "{core} does not support this node: {}",
            compatibility
                .reason
                .as_deref()
                .unwrap_or("unsupported configuration")
        );

        let port = match port_override {
            Some(port) => port,
            None => crate::services::listener_config::listen_port()?,
        };
        validate_listen_port(port)?;
        ensure_port_available(port)?;
        let generated = if tun_enabled {
            adapter.generate_tun_activation_config(&node, port)
        } else {
            adapter.generate_activation_config(&node, port)
        }
        .with_context(|| {
            if tun_enabled {
                format!(
                    "could not generate loopback mixed SOCKS5/HTTP plus native TUN {core} config"
                )
            } else {
                format!("could not generate loopback-only mixed SOCKS5/HTTP {core} config")
            }
        })?;
        adapters::validation::validate_generated_config(core, &generated, &executable)
            .with_context(|| format!("{core} rejected the activation config"))?;

        // Do not interrupt the existing activation until the replacement config validates.
        let config = runtime.join(format!("active-{node_id}-{}-{port}.json", core.as_str()));
        let mut command = Command::new(&executable);
        match core {
            CoreId::SingBox | CoreId::Xray => {
                command.arg("run").arg("-c").arg(&config);
            }
            CoreId::Mihomo => {
                command.arg("-f").arg(&config);
            }
        }
        if tun_enabled {
            let context = prepare_tun_launch(&runtime, &state_path)?;
            launch_tun_managed(
                &runtime,
                &state_path,
                &managed,
                &executable,
                &config,
                &generated.content,
                node_id,
                core,
                port,
                context,
                WAIT,
            )?;
        } else {
            launch_managed(
                &runtime,
                &state_path,
                &managed,
                &executable,
                &config,
                &generated.content,
                node_id,
                core.as_str(),
                port,
                command,
                WAIT,
            )?;
        }
        println!("Activated node #{node_id} with {core}.");
        println!(
            "Shared SOCKS5/HTTP proxy: 127.0.0.1:{port} (loopback only; configure applications manually)."
        );
        if tun_enabled {
            println!(
                "Native TUN interface tun-proxyctl is active; DNS and firewall settings were not changed."
            );
            println!(
                "The core runs as your user with only CAP_NET_ADMIN in a transient systemd service."
            );
        } else {
            println!("System proxy, DNS, routes, firewall, and TUN were not changed.");
        }
        Ok(())
    }
}

/// Stop the selected core before setup/update replaces its managed executable.
pub fn stop_if_active_core(core: CoreId) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("activation currently requires Linux process-identity support");
    #[cfg(target_os = "linux")]
    {
        let (runtime, state_path) = paths()?;
        let _lock = RuntimeLock::acquire(&runtime)?;
        if !state_path.exists() {
            return Ok(());
        }
        let state: ActiveProcess = serde_json::from_slice(&fs::read(&state_path)?)
            .context("activation state is corrupt; refusing to update a managed core")?;
        if state.core == core.as_str() {
            let managed = fs::canonicalize(managed_cores_path()?)
                .context("Proxyctl managed-core directory is unavailable; refusing to stop")?;
            stop_locked(&runtime, &state_path, &managed)?;
        }
        Ok(())
    }
}

pub fn stop() -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("activation currently requires Linux process-identity support");
    #[cfg(target_os = "linux")]
    {
        let (runtime, state) = paths()?;
        let _lock = RuntimeLock::acquire(&runtime)?;
        let managed = fs::canonicalize(managed_cores_path()?)
            .context("Proxyctl managed-core directory is unavailable; refusing to stop")?;
        stop_locked(&runtime, &state, &managed)
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn launch_managed(
    runtime: &Path,
    state_path: &Path,
    managed_root: &Path,
    executable: &Path,
    config: &Path,
    config_content: &[u8],
    node_id: u64,
    core: &str,
    port: u16,
    mut command: Command,
    timeout: Duration,
) -> anyhow::Result<()> {
    ensure!(
        executable.starts_with(managed_root),
        "refusing to run a core outside Proxyctl's managed directory"
    );
    let launch_executable =
        fs::canonicalize(executable).context("could not resolve the managed core executable")?;
    ensure!(
        launch_executable.starts_with(managed_root),
        "resolved core executable is outside Proxyctl's managed directory"
    );
    // Validate and prepare the replacement before stopping the current process.
    write_atomic(config, config_content)?;
    if let Err(error) = stop_locked(runtime, state_path, managed_root) {
        let _ = fs::remove_file(config);
        return Err(error);
    }
    configure_process_identity(&mut command);
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(config);
            return Err(error).context("could not start managed core");
        }
    };
    let pid = child.id();
    // argv[0] is always unified; procfs comm renaming is best-effort because
    // some kernels/container policies prohibit writing another process's comm.
    let _ = set_process_comm(pid);
    let start_ticks = match await_identity(pid, &launch_executable, timeout) {
        Ok(ticks) => ticks,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(config);
            return Err(error);
        }
    };
    let state = ActiveProcess {
        pid,
        start_ticks,
        executable: launch_executable,
        config: config.to_path_buf(),
        node_id,
        core: core.to_owned(),
        port,
        tun: None,
    };
    if let Err(error) = write_atomic(state_path, &serde_json::to_vec(&state)?) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(config);
        return Err(error);
    }
    // Persist ownership before readiness checks so failure can safely stop this exact process.
    drop(child);
    if let Err(error) = await_listener(pid, start_ticks, port, timeout) {
        let _ = stop_locked(runtime, state_path, managed_root);
        return Err(error);
    }
    Ok(())
}

fn ensure_tun_mode_disabled(tun_enabled: bool) -> anyhow::Result<()> {
    ensure!(
        !tun_enabled,
        "TUN activation is temporarily disabled: the current implementation can detect incomplete network cleanup but cannot safely restore Proxyctl-owned routes after a core exits or is force-killed. Ordinary loopback activation and 'proxyctl tun status' remain available."
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_process_identity(command: &mut Command) {
    // argv[0] is a stable user-facing identity. The real executable path is unchanged.
    command.arg0(PROCESS_NAME);
}

#[cfg(target_os = "linux")]
fn set_process_comm(pid: u32) -> anyhow::Result<()> {
    let path = format!("/proc/{pid}/comm");
    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .with_context(|| format!("could not set the Proxyctl process name for PID {pid}"))?;
    file.write_all(PROCESS_NAME.as_bytes())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn paths() -> anyhow::Result<(PathBuf, PathBuf)> {
    let db = default_database_path()?;
    let data = db.parent().context("Proxyctl data directory unavailable")?;
    let runtime = data.join("runtime");
    Ok((runtime.clone(), runtime.join("active.json")))
}
/// Validate and preflight the shared loopback HTTP/SOCKS listener port.
pub fn validate_listen_port(port: u16) -> anyhow::Result<()> {
    anyhow::ensure!((1024..=u16::MAX).contains(&port), "listen port must be between 1024 and 65535");
    Ok(())
}

/// Reject a port held by another process. The exact tracked Proxyctl process may
/// retain its current port while the replacement configuration is prepared.
pub fn ensure_port_available(port: u16) -> anyhow::Result<()> {
    validate_listen_port(port)?;
    #[cfg(target_os = "linux")]
    {
        if let Ok((_, state_path)) = paths()
            && let Ok(bytes) = fs::read(&state_path)
            && let Ok(state) = serde_json::from_slice::<ActiveProcess>(&bytes)
            && state.port == port
            && matches_process(state.pid, &state.executable, state.start_ticks)
        {
            return Ok(());
        }
    }
    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("127.0.0.1:{port} is already in use or cannot be bound"))?;
    drop(listener);
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().context("runtime file has no parent")?;
    fs::create_dir_all(parent)?;
    private_dir(parent)?;
    let mut file = tempfile::Builder::new()
        .prefix(".proxyctl-runtime-")
        .tempfile_in(parent)?;
    private_fd(file.as_file().as_raw_fd())?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .context("could not atomically publish private runtime file")?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn stop_locked(runtime: &Path, state_path: &Path, managed_root: &Path) -> anyhow::Result<()> {
    if !state_path.exists() {
        println!("No Proxyctl-managed core is active.");
        return Ok(());
    }
    let state: ActiveProcess = serde_json::from_slice(&fs::read(state_path)?)
        .context("activation state is corrupt; refusing to signal any process")?;
    ensure!(
        state.config.parent() == Some(runtime)
            && state
                .config
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("active-")),
        "activation config path is outside the private runtime directory; refusing cleanup"
    );
    ensure!(
        state.executable.starts_with(managed_root),
        "recorded executable is outside Proxyctl's managed-core directory; refusing to signal"
    );
    if state.tun.is_some() {
        return stop_tun_locked(runtime, state_path, &state);
    }
    if matches_process(state.pid, &state.executable, state.start_ticks) {
        signal_verified(
            state.pid,
            &state.executable,
            state.start_ticks,
            libc::SIGTERM,
        )?;
        wait_exit(state.pid, state.start_ticks, Duration::from_secs(5));
        if matches_process(state.pid, &state.executable, state.start_ticks) {
            signal_verified(
                state.pid,
                &state.executable,
                state.start_ticks,
                libc::SIGKILL,
            )?;
            wait_exit(state.pid, state.start_ticks, Duration::from_secs(5));
        }
        ensure!(
            !matches_process(state.pid, &state.executable, state.start_ticks),
            "tracked core did not exit; state/config retained"
        );
        println!(
            "Stopped Proxyctl-managed {} for node #{}.",
            state.core, state.node_id
        );
    } else {
        println!(
            "Recorded process is stale or has a different identity; no process was signalled."
        );
    }
    let _ = fs::remove_file(state.config);
    // Remove a launch alias left by older Proxyctl versions after its process has exited.
    if state
        .executable
        .file_name()
        .is_some_and(|name| name == PROCESS_NAME)
    {
        fs::remove_file(&state.executable)?;
    }
    fs::remove_file(state_path)?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn ip_json_snapshot(arguments: &[&str]) -> anyhow::Result<Vec<String>> {
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
fn launch_tun_managed(
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
fn tun_interfaces_are_safe(interfaces: &[String], active_proxyctl_tun: bool) -> bool {
    interfaces.is_empty()
        || (active_proxyctl_tun && interfaces.iter().all(|name| name == "tun-proxyctl"))
}

#[cfg(target_os = "linux")]
fn prepare_tun_launch(runtime: &Path, state_path: &Path) -> anyhow::Result<TunLaunchContext> {
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
fn build_tun_preflight_command(context: &TunLaunchContext, true_executable: &Path) -> Command {
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
fn preflight_tun_service(context: &TunLaunchContext, true_executable: &Path) -> anyhow::Result<()> {
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
fn find_program(name: &str) -> anyhow::Result<PathBuf> {
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
fn build_tun_service_command(
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
fn start_tun_service(
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
fn systemd_property(context: &TunLaunchContext, property: &str) -> anyhow::Result<String> {
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
fn systemd_main_pid(context: &TunLaunchContext) -> anyhow::Result<Option<u32>> {
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
fn await_systemd_main_pid(context: &TunLaunchContext, timeout: Duration) -> anyhow::Result<u32> {
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
fn process_status_has_only_tun_capability(status: &str, expected_uid: u32) -> bool {
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
fn process_has_only_tun_capability(pid: u32, expected_uid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .is_ok_and(|status| process_status_has_only_tun_capability(&status, expected_uid))
}

#[cfg(target_os = "linux")]
fn await_tun_interface(pid: u32, ticks: u64, timeout: Duration) -> anyhow::Result<()> {
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
fn stop_systemd_unit(context: &TunLaunchContext) -> anyhow::Result<()> {
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
fn stop_tun_locked(runtime: &Path, state_path: &Path, state: &ActiveProcess) -> anyhow::Result<()> {
    let tun = state
        .tun
        .as_ref()
        .context("missing TUN ownership manifest")?;
    ensure!(
        tun.unit.starts_with("proxyctl-tun-") && tun.unit.ends_with(".service"),
        "recorded TUN service name is outside Proxyctl's namespace; refusing systemd operation"
    );
    let sudo = find_program("sudo")?;
    let systemctl = find_program("systemctl")?;
    let authorization = Command::new(&sudo).arg("-v").status()?;
    ensure!(
        authorization.success(),
        "sudo authorization was not granted; TUN service was not stopped"
    );
    let context = TunLaunchContext {
        sudo,
        systemd_run: PathBuf::new(),
        systemctl,
        unit: tun.unit.clone(),
        uid: tun.uid,
        gid: unsafe { libc::getgid() },
        baseline: tun.baseline.clone(),
    };
    let load_state = systemd_property(&context, "LoadState")?;
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
fn start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat.get(stat.rfind(')')? + 2..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}
#[cfg(target_os = "linux")]
fn executable(pid: u32) -> Option<PathBuf> {
    fs::canonicalize(format!("/proc/{pid}/exe")).ok()
}
#[cfg(target_os = "linux")]
fn matches_process(pid: u32, expected: &Path, ticks: u64) -> bool {
    start_ticks(pid) == Some(ticks) && executable(pid).as_deref() == Some(expected)
}
#[cfg(target_os = "linux")]
fn await_identity(pid: u32, expected: &Path, timeout: Duration) -> anyhow::Result<u64> {
    let start = Instant::now();
    loop {
        if let (Some(ticks), Some(actual)) = (start_ticks(pid), executable(pid))
            && actual == expected
        {
            return Ok(ticks);
        }
        ensure!(
            start.elapsed() < timeout,
            "could not verify the managed process identity"
        );
        thread::sleep(POLL);
    }
}
#[cfg(target_os = "linux")]
fn await_listener(pid: u32, ticks: u64, port: u16, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        ensure!(
            start_ticks(pid) == Some(ticks),
            "managed core exited before listener readiness"
        );
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Ok(());
        }
        ensure!(
            start.elapsed() < timeout,
            "managed core did not open its loopback listener"
        );
        thread::sleep(POLL);
    }
}
#[cfg(target_os = "linux")]
fn wait_exit(pid: u32, ticks: u64, timeout: Duration) {
    let start = Instant::now();
    while start_ticks(pid) == Some(ticks) && start.elapsed() < timeout {
        thread::sleep(POLL);
    }
}
#[cfg(target_os = "linux")]
fn signal_verified(pid: u32, expected: &Path, ticks: u64, signal: i32) -> anyhow::Result<()> {
    ensure!(
        matches_process(pid, expected, ticks),
        "process identity changed; refusing signal"
    );
    // pidfd pins the signal target to this process instance and prevents PID-reuse races.
    // SAFETY: scalar PID/flags; successful result is an owned descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) as i32 };
    ensure!(fd >= 0, "could not obtain pidfd; refusing to signal by PID");
    // The PID could have been reused between the first identity check and pidfd_open.
    // Recheck while holding the pidfd; after this, signalling the pidfd cannot target a
    // later process that reuses the numeric PID.
    if !matches_process(pid, expected, ticks) {
        // SAFETY: fd was opened above and is owned here.
        unsafe {
            libc::close(fd);
        }
        anyhow::bail!("process identity changed after pidfd acquisition; refusing signal");
    }
    // SAFETY: fd is a valid pidfd and siginfo is unused for this syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    // SAFETY: fd was opened above and is owned here.
    unsafe {
        libc::close(fd);
    }
    ensure!(result == 0, "could not signal tracked process");
    Ok(())
}
#[cfg(unix)]
fn private_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
#[cfg(not(unix))]
fn private_dir(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}
#[cfg(unix)]
fn private_fd(fd: i32) -> anyhow::Result<()> {
    // SAFETY: fchmod receives a live descriptor and scalar permission bits.
    ensure!(
        unsafe { libc::fchmod(fd, 0o600) } == 0,
        "could not secure private runtime file"
    );
    Ok(())
}
#[cfg(not(unix))]
fn private_fd(_fd: i32) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    #[cfg(target_os = "linux")]
    #[test]
    fn tun_preflight_refuses_foreign_tun_interfaces_but_allows_its_own_for_switching() {
        assert!(tun_interfaces_are_safe(&[], false));
        assert!(tun_interfaces_are_safe(&["tun-proxyctl".into()], true));
        assert!(!tun_interfaces_are_safe(&["tun0".into()], false));
        assert!(!tun_interfaces_are_safe(&["tun-proxyctl".into()], false));
        assert!(!tun_interfaces_are_safe(
            &["tun-proxyctl".into(), "tun0".into()],
            true
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_baseline_reports_exact_changed_categories() {
        let baseline = TunBaseline {
            interfaces: vec!["lo".into()],
            tun_interfaces: vec![],
            default_routes: vec!["IPv4 default via wlan0".into()],
            dns_servers: vec!["127.0.0.53".into()],
            resolv_conf_target: Some("/run/systemd/resolve/stub-resolv.conf".into()),
            ipv4_routes: vec!["main-route".into()],
            ipv6_routes: vec!["main-v6-route".into()],
            ipv4_rules: vec!["main-rule".into()],
            ipv6_rules: vec!["main-v6-rule".into()],
        };
        let mut current = baseline.clone();
        current.ipv4_routes.push("unexpected-route".into());
        current.dns_servers = vec!["1.1.1.1".into()];
        assert_eq!(
            baseline.differences(&current),
            vec!["DNS nameservers", "IPv4 routing tables"]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_capability_check_accepts_only_unprivileged_net_admin_service() {
        let valid = concat!(
            "Uid:\t1000\t1000\t1000\t1000\n",
            "CapEff:\t0000000000001000\n",
            "CapPrm:\t0000000000001000\n",
            "CapBnd:\t0000000000001000\n",
            "CapAmb:\t0000000000001000\n"
        );
        assert!(process_status_has_only_tun_capability(valid, 1000));
        assert!(!process_status_has_only_tun_capability(
            &valid.replace("0000000000001000", "0000000000003000"),
            1000
        ));
        assert!(!process_status_has_only_tun_capability(valid, 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tun_service_command_limits_capabilities_and_keeps_user_identity() {
        let context = TunLaunchContext {
            sudo: PathBuf::from("/usr/bin/sudo"),
            systemd_run: PathBuf::from("/usr/bin/systemd-run"),
            systemctl: PathBuf::from("/usr/bin/systemctl"),
            unit: "proxyctl-tun-test.service".into(),
            uid: 1000,
            gid: 1000,
            baseline: TunBaseline {
                interfaces: vec![],
                tun_interfaces: vec![],
                default_routes: vec![],
                dns_servers: vec![],
                resolv_conf_target: None,
                ipv4_routes: vec![],
                ipv6_routes: vec![],
                ipv4_rules: vec![],
                ipv6_rules: vec![],
            },
        };
        let command = build_tun_service_command(
            &context,
            Path::new("/managed/sing-box"),
            CoreId::SingBox,
            Path::new("/runtime/active.json"),
        );
        let args = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for expected in [
            "--property=User=1000",
            "--property=Group=1000",
            "--property=CapabilityBoundingSet=CAP_NET_ADMIN",
            "--property=AmbientCapabilities=CAP_NET_ADMIN",
            "--property=NoNewPrivileges=yes",
            "--property=KillMode=control-group",
            "--",
            "/managed/sing-box",
            "run",
            "-c",
            "/runtime/active.json",
        ] {
            assert!(args.iter().any(|arg| arg == expected), "missing {expected}");
        }
        assert!(!args.iter().any(|arg| arg.contains("CAP_SYS_ADMIN")));
        assert!(!args.iter().any(|arg| arg.contains("CAP_NET_RAW")));

        let preflight = build_tun_preflight_command(&context, Path::new("/usr/bin/true"));
        let preflight_args = preflight
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for expected in [
            "--wait",
            "--collect",
            "--property=User=1000",
            "--property=CapabilityBoundingSet=CAP_NET_ADMIN",
            "--property=AmbientCapabilities=CAP_NET_ADMIN",
            "--property=NoNewPrivileges=yes",
            "/usr/bin/true",
        ] {
            assert!(
                preflight_args.iter().any(|arg| arg == expected),
                "missing preflight {expected}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn old_activation_state_without_tun_manifest_remains_readable() {
        let state = serde_json::json!({
            "pid": 10, "start_ticks": 20, "executable": "/managed/sing-box",
            "config": "/runtime/active-1-sing-box.json", "node_id": 1,
            "core": "sing-box", "port": 1080
        });
        let parsed: ActiveProcess = serde_json::from_value(state).unwrap();
        assert!(parsed.tun.is_none());
    }

    #[test]
    fn listen_port_preflight_rejects_an_occupied_loopback_port() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(ensure_port_available(port).is_err());
    }

    #[test]
    fn tun_activation_is_rejected_before_any_network_or_process_operation() {
        assert!(ensure_tun_mode_disabled(false).is_ok());
        let error = ensure_tun_mode_disabled(true).unwrap_err().to_string();
        assert!(error.contains("temporarily disabled"));
        assert!(error.contains("cannot safely restore"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn managed_process_uses_unified_proxyctl_argv0_without_changing_executable() {
        // tail keeps its original argv storage intact, unlike some utilities that
        // rewrite or clear argv after startup.
        let tail = find_program("tail").unwrap();
        let executable_path = fs::canonicalize(&tail).unwrap();
        let mut command = Command::new(&executable_path);
        command.args(["-f", "/dev/null"]);
        configure_process_identity(&mut command);
        let mut child = command.spawn().unwrap();
        let pid = child.id();
        let _ = set_process_comm(pid);
        await_identity(pid, &executable_path, Duration::from_secs(2)).unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        let argv0 = loop {
            let command_line = fs::read(format!("/proc/{pid}/cmdline")).unwrap();
            let argv0 = command_line
                .split(|byte| *byte == 0)
                .next()
                .unwrap_or_default();
            if argv0 == PROCESS_NAME.as_bytes() {
                break argv0.to_vec();
            }
            assert!(
                Instant::now() < deadline,
                "managed child did not retain the configured Proxyctl argv[0]"
            );
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(argv0, PROCESS_NAME.as_bytes());
        assert_eq!(executable(pid).as_deref(), Some(executable_path.as_path()));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_identity_includes_start_ticks_and_executable() {
        let pid = std::process::id();
        let exe = executable(pid).unwrap();
        let ticks = start_ticks(pid).unwrap();
        assert!(matches_process(pid, &exe, ticks));
        assert!(!matches_process(pid, &exe, ticks + 1));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_stop_signals_only_the_verified_fake_process_instance() {
        let mut child = Command::new("tail")
            .args(["-f", "/dev/null"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let exe = executable(pid).unwrap();
        let ticks = await_identity(pid, &exe, Duration::from_secs(2)).unwrap();

        assert!(signal_verified(pid, &exe, ticks.saturating_add(1), libc::SIGTERM).is_err());
        assert!(
            matches_process(pid, &exe, ticks),
            "a rejected identity must leave the verified child running"
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match signal_verified(pid, &exe, ticks, libc::SIGTERM) {
                Ok(()) => break,
                Err(error) if matches_process(pid, &exe, ticks) && Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(POLL);
                }
                Err(error) => panic!("could not signal the still-verified fake child: {error:#}"),
            }
        }
        child.wait().unwrap();
        assert!(!matches_process(pid, &exe, ticks));
    }

    #[cfg(target_os = "linux")]
    fn test_managed_root(directory: &Path) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let managed = directory.join("managed");
        fs::create_dir_all(&managed).unwrap();
        let source = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|path| path.join("tail"))
            .find(|path| path.is_file())
            .expect("sleep utility is required for process lifecycle tests");
        let fake = managed.join("sleep");
        fs::copy(source, &fake).unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        (managed, fake)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn activation_switches_managed_process_and_stop_cleans_state_and_config() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        let state_path = runtime.join("active.json");
        let (managed, fake) = test_managed_root(dir.path());
        let managed = fs::canonicalize(managed).unwrap();
        let fake = fs::canonicalize(fake).unwrap();
        let readiness = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = readiness.local_addr().unwrap().port();

        let mut previous_config: Option<PathBuf> = None;
        let mut previous_process: Option<(u32, PathBuf, u64)> = None;
        for (node_id, core) in [(1, "sing-box"), (2, "xray"), (3, "mihomo")] {
            let config = runtime.join(format!("active-{node_id}-{core}.json"));
            let mut command = Command::new(&fake);
            command.args(["-f", "/dev/null"]);
            launch_managed(
                &runtime,
                &state_path,
                &managed,
                &fake,
                &config,
                b"{}",
                node_id,
                core,
                port,
                command,
                Duration::from_secs(2),
            )
            .unwrap();
            let state: ActiveProcess =
                serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
            assert_eq!(state.node_id, node_id);
            assert_eq!(state.core, core);
            assert!(matches_process(
                state.pid,
                &state.executable,
                state.start_ticks
            ));
            if let Some((pid, executable, ticks)) = previous_process.take() {
                assert!(
                    !matches_process(pid, &executable, ticks),
                    "switching must stop the previously active process"
                );
            }
            previous_process = Some((state.pid, state.executable.clone(), state.start_ticks));
            if let Some(previous) = previous_config.take() {
                assert!(
                    !previous.exists(),
                    "previous activation config must be removed"
                );
            }
            previous_config = Some(config);
        }

        let final_state: ActiveProcess =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        stop_locked(&runtime, &state_path, &managed).unwrap();
        assert!(!matches_process(
            final_state.pid,
            &final_state.executable,
            final_state.start_ticks
        ));
        assert!(!state_path.exists());
        assert!(!runtime.join("active-3-mihomo.json").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn readiness_failure_stops_fake_process_and_removes_runtime_files() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        let state_path = runtime.join("active.json");
        let (managed, fake) = test_managed_root(dir.path());
        let managed = fs::canonicalize(managed).unwrap();
        let fake = fs::canonicalize(fake).unwrap();
        let unavailable = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = unavailable.local_addr().unwrap().port();
        drop(unavailable);
        let config = runtime.join("active-4-sing-box.json");
        let mut command = Command::new(fake.parent().unwrap().join(PROCESS_NAME));
        command.args(["-f", "/dev/null"]);

        assert!(
            launch_managed(
                &runtime,
                &state_path,
                &managed,
                &fake,
                &config,
                b"{}",
                4,
                "sing-box",
                port,
                command,
                Duration::from_millis(150),
            )
            .is_err()
        );
        assert!(!state_path.exists());
        assert!(!config.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_failure_removes_prepared_config_without_persisting_state() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        let managed = dir.path().join("managed");
        fs::create_dir_all(&runtime).unwrap();
        fs::create_dir_all(&managed).unwrap();
        let managed = fs::canonicalize(managed).unwrap();
        let state_path = runtime.join("active.json");
        let config = runtime.join("active-6-mihomo.json");
        let command = Command::new(dir.path().join("does-not-exist"));

        assert!(
            launch_managed(
                &runtime,
                &state_path,
                &managed,
                &managed.join("fake-core"),
                &config,
                b"{}",
                6,
                "mihomo",
                12347,
                command,
                Duration::from_millis(100),
            )
            .is_err()
        );
        assert!(!state_path.exists());
        assert!(!config.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn activation_refuses_fake_executable_outside_managed_directory() {
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let runtime = dir.path().join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        let state_path = runtime.join("active.json");
        let (managed, fake) = test_managed_root(dir.path());
        let managed = fs::canonicalize(managed).unwrap();
        let fake = fs::canonicalize(fake).unwrap();
        let outside = dir.path().join("outside");
        fs::copy(&fake, &outside).unwrap();
        let config = runtime.join("active-5-xray.json");
        let command = Command::new(&outside);

        assert!(
            launch_managed(
                &runtime,
                &state_path,
                &managed,
                &outside,
                &config,
                b"{}",
                5,
                "xray",
                12345,
                command,
                Duration::from_millis(100),
            )
            .is_err()
        );
        assert!(!state_path.exists());
        assert!(!config.exists());
    }

    #[test]
    fn persisted_state_contains_no_node_secret_fields() {
        let state = ActiveProcess {
            pid: 1,
            start_ticks: 2,
            executable: "/managed/xray".into(),
            config: "/runtime/active-1-xray.json".into(),
            node_id: 1,
            core: "xray".into(),
            port: 1234,
            tun: None,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("uuid"));
        assert!(!json.contains("password"));
    }
}
