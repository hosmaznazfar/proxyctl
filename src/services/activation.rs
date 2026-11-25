//! Linux single-core activation with private state and identity-checked shutdown.
use crate::{
    cores::{CoreId, adapters, core_binary_path, managed_cores_path},
    database::{NodeDatabase, default_database_path},
};
use anyhow::{Context, ensure};

#[cfg(target_os = "linux")]
mod identity;
#[cfg(target_os = "linux")]
mod tun_runtime;
#[cfg(target_os = "linux")]
use identity::*;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    net::TcpListener,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
#[cfg(test)]
use std::{thread, time::Instant};
#[cfg(target_os = "linux")]
use tun_runtime::*;

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
    foreground: bool,
) -> anyhow::Result<()> {
    activate_with_policy(node_id, core, tun_enabled, port_override, foreground, false)
}

/// Activate only when the loopback slot is still idle; used to restore a prior session after TUN.
pub fn activate_if_idle(
    node_id: u64,
    core: CoreId,
    port_override: Option<u16>,
    foreground: bool,
) -> anyhow::Result<()> {
    activate_with_policy(node_id, core, false, port_override, foreground, true)
}

fn activate_with_policy(
    node_id: u64,
    core: CoreId,
    tun_enabled: bool,
    port_override: Option<u16>,
    foreground: bool,
    require_idle: bool,
) -> anyhow::Result<()> {
    ensure_tun_mode_disabled(tun_enabled)?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (node_id, core, tun_enabled, port_override, foreground, require_idle);
        anyhow::bail!("activation currently requires Linux process-identity support");
    }
    #[cfg(target_os = "linux")]
    {
        let (foreground_child, state_path, port, foreground_identity) = {
            let (runtime, state_path) = paths()?;
            let _lock = RuntimeLock::acquire(&runtime)?;
            if require_idle {
                ensure!(
                    !state_path.exists(),
                    "another Proxyctl-managed session became active before loopback restoration"
                );
                ensure!(
                    !runtime.join("tun-session.json").exists(),
                    "privileged TUN recovery must finish before loopback restoration"
                );
            } else {
                ensure!(
                    !runtime.join("tun-previous.json").exists(),
                    "a previous loopback session is awaiting TUN recovery/restoration; run 'proxyctl tun stop' first"
                );
            }
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
            let generated = adapter
                .generate_activation_config(&node, port)
                .with_context(|| {
                    format!("could not generate loopback-only mixed SOCKS5/HTTP {core} config")
                })?;
            adapters::validation::validate_generated_config(core, &generated, &executable)
                .with_context(|| format!("{core} rejected the activation config"))?;

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
            let child = launch_managed(
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
                foreground,
            )?;
            let identity = if let Some(child) = &child {
                let state: ActiveProcess = serde_json::from_slice(&fs::read(&state_path)?)
                    .context("foreground activation state disappeared before handoff")?;
                ensure!(
                    state.pid == child.id()
                        && state.start_ticks > 0
                        && state.tun.is_none()
                        && state.executable == executable,
                    "foreground activation state does not match the launched core identity"
                );
                Some((state.start_ticks, state.executable))
            } else {
                None
            };
            (child, state_path, port, identity)
        };

        if let Some(mut child) = foreground_child {
            let pid = child.id();
            let (start_ticks, executable) =
                foreground_identity.context("foreground process identity was not retained")?;
            let status = child
                .wait()
                .context("could not wait for the foreground proxy core")?;
            finish_foreground(&state_path, pid, start_ticks, &executable, status.success())?;
            if !status.success() {
                anyhow::bail!("foreground {core} process exited with status {status}");
            }
            println!("Foreground {core} process exited successfully.");
            return Ok(());
        }
        println!("Activated node #{node_id} with {core}.");
        println!(
            "Shared SOCKS5/HTTP proxy: 127.0.0.1:{port} (loopback only; configure applications manually)."
        );
        println!("System proxy, DNS, routes, firewall, and TUN were not changed.");
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

/// Display the currently tracked Proxyctl session without mutating runtime or host state.
pub fn status() -> anyhow::Result<()> {
    let (runtime, state_path) = paths()?;
    if !state_path.exists() {
        let manifest_path = runtime.join("tun-manifest.json");
        let journal_path = runtime.join("tun-transaction-journal.json");
        if manifest_path.exists() || journal_path.exists() {
            println!("Proxyctl session: TUN state requires recovery/inspection.");
            println!(
                "Manifest: {}; transaction journal: {}",
                if manifest_path.exists() {
                    "present"
                } else {
                    "absent"
                },
                if journal_path.exists() {
                    "present"
                } else {
                    "absent"
                }
            );
            println!("Run 'proxyctl tun status' for read-only host-network details.");
        } else if runtime.join("tun-session.json").exists() {
            println!("Proxyctl session: privileged TUN session is active or recovery is pending.");
            println!("Run 'proxyctl tun stop' to stop/recover it.");
        } else if runtime.join("tun-previous.json").exists() {
            println!("Proxyctl session: native TUN transition or loopback restoration is pending.");
            println!("Previous loopback session metadata is saved; run 'proxyctl tun stop' to recover TUN state and restore it.");
        } else {
            println!("No active Proxyctl-managed session.");
        }
        return Ok(());
    }

    let state: ActiveProcess = serde_json::from_slice(&fs::read(&state_path)?)
        .context("Proxyctl activation state is corrupt; refusing to infer session ownership")?;
    let mode = if state.tun.is_some() {
        "TUN"
    } else {
        "loopback proxy"
    };
    println!("Proxyctl session: {mode}");
    println!("Node: #{}", state.node_id);
    println!("Core: {}", state.core);
    println!("PID: {}", state.pid);
    println!("Listener: 127.0.0.1:{}", state.port);

    #[cfg(target_os = "linux")]
    {
        if state.pid == 0 || state.start_ticks == 0 {
            println!("Process identity: not yet committed (startup/recovery may be incomplete)");
        } else if matches_process(state.pid, &state.executable, state.start_ticks) {
            println!("Process identity: matches the recorded PID, start time, and executable");
        } else {
            println!("Process identity: no longer matches the recorded process");
        }
    }
    #[cfg(not(target_os = "linux"))]
    println!("Process identity: verification is available only on Linux");
    Ok(())
}

pub fn stop() -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("activation currently requires Linux process-identity support");
    #[cfg(target_os = "linux")]
    {
        let (runtime, state) = paths()?;
        let _lock = RuntimeLock::acquire(&runtime)?;
        let store = crate::tun::manifest_store::ManifestStore::open(runtime.clone())?;
        let current_manifest = store.load()?;
        let transaction_journal = store.load_transaction_journal()?;
        if current_manifest.is_some() || transaction_journal.is_some() {
            let helper =
                crate::tun::mutation_helper_launcher::MutationHelper::ensure_started(&runtime)
                    .context("cannot connect to the TUN mutation helper for safe stop")?;
            if current_manifest.is_some() {
                let coordinator =
                    crate::tun::lifecycle_coordinator::LifecycleCoordinator::new(store)?;
                let orchestrator = crate::tun::activation_orchestrator::ActivationOrchestrator::new(
                    &helper,
                    &coordinator,
                );
                orchestrator
                    .stop_current_xray()
                    .context("cannot stop the active generation-bound TUN service")?;
            } else if let Some(journal) = transaction_journal {
                crate::tun::xray_launcher::stop_core_service_generation(
                    &journal.activation_id,
                    journal.generation,
                    None,
                )
                .context("cannot stop the Xray service associated with the orphaned TUN journal")?;
                let recovery = helper.recover(journal.activation_id, journal.generation);
                if !matches!(recovery.as_ref(), Ok(response) if response.success) {
                    let recovery_message = match &recovery {
                        Ok(response) => response.message.clone(),
                        Err(error) => format!("{error:#}"),
                    };
                    let remaining =
                        crate::tun::manifest_store::ManifestStore::open(runtime.clone())?;
                    ensure!(
                        remaining.load()?.is_none()
                            && remaining.load_transaction_journal()?.is_none(),
                        "orphaned TUN journal recovery is incomplete: {recovery_message}"
                    );
                }
            }
            println!("Stopped or recovered the Proxyctl-managed Xray TUN generation.");
            return Ok(());
        }
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
    foreground: bool,
) -> anyhow::Result<Option<std::process::Child>> {
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
    let output = if foreground {
        Stdio::inherit()
    } else {
        Stdio::null()
    };
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(if foreground {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
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
    if let Err(error) = await_listener(pid, start_ticks, port, timeout) {
        let _ = stop_locked(runtime, state_path, managed_root);
        let _ = child.wait();
        return Err(error);
    }
    if foreground {
        Ok(Some(child))
    } else {
        drop(child);
        Ok(None)
    }
}

/// Activate one managed Xray node through the generation-bound broker TUN lifecycle.
#[cfg(target_os = "linux")]
pub fn activate_tun_xray(
    node_id: u64,
    port_override: Option<u16>,
    probe_url: &str,
    expected_status: u16,
) -> anyhow::Result<()> {
    activate_tun_core(
        node_id,
        CoreId::Xray,
        port_override,
        probe_url,
        expected_status,
    )
}

/// Keep new TUN generations disabled while the legacy helper/systemd launcher is being
/// replaced by the single-executable privileged session owner.
fn ensure_tun_session_backend_ready() -> anyhow::Result<()> {
    anyhow::bail!(
        "TUN activation is temporarily disabled during the single-executable supervisor migration; existing generations can still be inspected and safely stopped"
    )
}

pub fn activate_tun_core(
    node_id: u64,
    core: CoreId,
    port_override: Option<u16>,
    probe_url: &str,
    expected_status: u16,
) -> anyhow::Result<()> {
    ensure_tun_session_backend_ready()?;
    use std::net::ToSocketAddrs;

    let (runtime, state_path) = paths()?;
    let _lock = RuntimeLock::acquire(&runtime)?;
    ensure!(
        !state_path.exists(),
        "a Proxyctl-managed core state file already exists; stop it before starting TUN mode"
    );

    let store = crate::tun::manifest_store::ManifestStore::open(runtime.clone())?;
    ensure!(
        store.load()?.is_none(),
        "a TUN activation manifest already exists; stop or recover it before starting another generation"
    );
    ensure!(
        store.load_transaction_journal()?.is_none(),
        "an unresolved TUN transaction journal exists; recover it before starting another generation"
    );

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

    ensure!(
        matches!(core, CoreId::Xray | CoreId::SingBox | CoreId::Mihomo),
        "unsupported TUN core"
    );
    ensure!(
        core == CoreId::Xray,
        "sing-box and Mihomo native TUN activation remain disabled until persistent-device crash recovery identity is fully hardened"
    );
    let executable = core_binary_path(core)?;
    ensure!(
        executable.is_file(),
        "selected core is not installed by Proxyctl; run setup for the selected core"
    );
    let executable = fs::canonicalize(executable)?;
    let managed_root = fs::canonicalize(managed_cores_path()?)?;
    ensure!(
        executable.starts_with(&managed_root),
        "refusing to run the selected core outside Proxyctl's managed-core directory"
    );
    let adapter = adapters::adapter(core);
    let compatibility = adapter.compatibility(&node);
    ensure!(
        compatibility.is_supported(),
        "selected core does not support this node: {}",
        compatibility
            .reason
            .as_deref()
            .unwrap_or("unsupported configuration")
    );

    let listen_port = match port_override {
        Some(port) => port,
        None => crate::services::listener_config::listen_port()?,
    };
    validate_listen_port(listen_port)?;
    ensure_port_available(listen_port)?;

    let expected_peers = (node.server.as_str(), node.port)
        .to_socket_addrs()
        .context("cannot resolve the selected proxy node endpoint before TUN activation")?
        .filter(|peer| !peer.ip().is_unspecified() && !peer.ip().is_multicast())
        .take(8)
        .collect::<Vec<_>>();
    ensure!(
        !expected_peers.is_empty(),
        "selected node did not resolve to a usable endpoint"
    );

    let probe = url::Url::parse(probe_url).context("TUN readiness probe URL is invalid")?;
    ensure!(
        probe.scheme() == "http"
            && probe.username().is_empty()
            && probe.password().is_none()
            && probe.query().is_none()
            && probe.fragment().is_none(),
        "TUN readiness probe must be a plain HTTP URL without credentials, query, or fragment"
    );
    let probe_host = probe
        .host()
        .context("TUN readiness probe URL has no host")?;
    let probe_port = probe
        .port_or_known_default()
        .context("TUN readiness probe URL has no usable port")?;
    let probe_addresses = match probe_host {
        url::Host::Ipv4(address) => vec![std::net::SocketAddr::from((address, probe_port))],
        url::Host::Ipv6(address) => vec![std::net::SocketAddr::from((address, probe_port))],
        url::Host::Domain(domain) => (domain, probe_port)
            .to_socket_addrs()
            .context("cannot resolve TUN readiness probe endpoint before activation")?
            .collect::<Vec<_>>(),
    };
    let traffic_targets = build_dual_stack_probe_targets(&probe, probe_addresses, expected_status)?;

    let activation_id = fs::read_to_string("/proc/sys/kernel/random/uuid")
        .context("cannot obtain a kernel-generated activation UUID")?
        .trim()
        .to_ascii_lowercase();
    let generation = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    )
    .context("system clock produced an activation generation outside the supported range")?;
    let (table_id, bypass_priority, proxy_priority) =
        crate::tun::route_policy::allocate_policy_identifiers(
            &crate::tun::kernel_inventory::inspect()?,
        )?;
    let (core_mark, core_mark_mask) =
        crate::tun::route_policy::mark_for_activation_id(&activation_id)?;

    let interface_name = match core {
        CoreId::Xray => crate::cores::adapters::XRAY_TUN_INTERFACE_NAME,
        CoreId::SingBox | CoreId::Mihomo => "tun-proxyctl",
    };
    let request = crate::tun::activation_orchestrator::ActivationRequest {
        activation_id,
        generation,
        interface_name: interface_name.to_owned(),
        owner_uid: unsafe { libc::getuid() },
        owner_gid: unsafe { libc::getgid() },
        table_id,
        bypass_priority,
        proxy_priority,
        core_mark,
        core_mark_mask,
    };
    let helper = crate::tun::mutation_helper_launcher::MutationHelper::ensure_started(&runtime)
        .context("cannot start or connect to the TUN mutation helper")?;
    let coordinator = crate::tun::lifecycle_coordinator::LifecycleCoordinator::new(store)?;
    let orchestrator =
        crate::tun::activation_orchestrator::ActivationOrchestrator::new(&helper, &coordinator);
    let activation = match core {
        CoreId::Xray => orchestrator
            .activate_xray_node_dual_stack_end_to_end(
                request,
                &node,
                listen_port,
                &executable,
                Duration::from_secs(5),
                expected_peers,
                traffic_targets,
                Duration::from_secs(10),
                64 * 1024,
            )
            .map(|activation| activation.managed),
        CoreId::SingBox | CoreId::Mihomo => orchestrator
            .activate_native_core_node_dual_stack_end_to_end(
                core,
                request,
                &node,
                listen_port,
                &executable,
                expected_peers,
                traffic_targets,
                Duration::from_secs(10),
                64 * 1024,
            ),
    }
    .with_context(|| {
        format!("{core} TUN activation failed its broker transaction or end-to-end readiness gate")
    })?;

    println!(
        "Activated Proxyctl {core} TUN for node #{node_id} on 127.0.0.1:{listen_port} (generation {}).",
        activation.token.generation()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn activate_tun_xray(
    _node_id: u64,
    _port_override: Option<u16>,
    _probe_url: &str,
    _expected_status: u16,
) -> anyhow::Result<()> {
    anyhow::bail!("managed Xray TUN activation is supported only on Linux");
}

#[cfg(not(target_os = "linux"))]
pub fn activate_tun_core(
    _node_id: u64,
    _core: CoreId,
    _port_override: Option<u16>,
    _probe_url: &str,
    _expected_status: u16,
) -> anyhow::Result<()> {
    anyhow::bail!("managed native TUN activation is supported only on Linux");
}

#[cfg(target_os = "linux")]
fn build_dual_stack_probe_targets(
    probe: &url::Url,
    addresses: impl IntoIterator<Item = std::net::SocketAddr>,
    expected_status: u16,
) -> anyhow::Result<Vec<crate::tun::readiness::HttpProbeTarget>> {
    let host_header = probe
        .host_str()
        .context("TUN readiness probe URL has no host")?
        .to_owned();
    let path = if probe.path().is_empty() {
        "/".to_owned()
    } else {
        probe.path().to_owned()
    };
    let mut ipv4 = None;
    let mut ipv6 = None;
    for address in addresses {
        let ip = address.ip();
        let is_link_local = match ip {
            std::net::IpAddr::V4(ip) => ip.is_link_local(),
            std::net::IpAddr::V6(ip) => ip.is_unicast_link_local(),
        };
        if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() || is_link_local {
            continue;
        }
        if address.is_ipv4() && ipv4.is_none() {
            ipv4 = Some(address);
        } else if address.is_ipv6() && ipv6.is_none() {
            ipv6 = Some(address);
        }
    }
    let targets = vec![
        crate::tun::readiness::HttpProbeTarget {
            destination: ipv4
                .context("TUN readiness endpoint must resolve to a usable IPv4 address")?,
            host_header: host_header.clone(),
            path: path.clone(),
            expected_status,
        },
        crate::tun::readiness::HttpProbeTarget {
            destination: ipv6
                .context("TUN readiness endpoint must resolve to a usable IPv6 address")?,
            host_header,
            path,
            expected_status,
        },
    ];
    crate::tun::readiness::validate_dual_stack_probe_targets(&targets)?;
    Ok(targets)
}

fn ensure_tun_mode_disabled(tun_enabled: bool) -> anyhow::Result<()> {
    ensure!(
        !tun_enabled,
        "TUN activation must use the dedicated generation-bound Xray broker lifecycle, which composes the broker-owned device, readiness, and recovery lifecycle; it is not the loopback activation path."
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
    anyhow::ensure!(
        (1024..=u16::MAX).contains(&port),
        "listen port must be between 1024 and 65535"
    );
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

/// Identity of the currently tracked unprivileged loopback session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveLoopbackSession {
    pub node_id: u64,
    pub core: CoreId,
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousLoopbackSession {
    node_id: u64,
    core: String,
    port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingTunSession {
    schema_version: u16,
    activation_id: String,
    generation: u64,
}

/// Read the active loopback session without changing it, for the explicit TUN transition.
#[cfg(target_os = "linux")]
pub fn active_loopback_session() -> anyhow::Result<ActiveLoopbackSession> {
    let (_, state_path) = paths()?;
    let state: ActiveProcess = serde_json::from_slice(
        &fs::read(&state_path).context("no Proxyctl-managed loopback session is active")?,
    )
    .context("Proxyctl activation state is corrupt; refusing to transition it to TUN")?;
    ensure!(
        state.tun.is_none(),
        "the tracked session is already a legacy TUN session; use 'proxyctl tun stop' to recover it"
    );
    ensure!(
        state.node_id != 0
            && state.port >= 1024
            && state.start_ticks > 0
            && matches_process(state.pid, &state.executable, state.start_ticks),
        "active loopback process identity does not match its recorded session"
    );
    let core = match state.core.as_str() {
        "sing-box" => CoreId::SingBox,
        "xray" => CoreId::Xray,
        "mihomo" => CoreId::Mihomo,
        _ => anyhow::bail!("active loopback state names an unsupported core"),
    };
    Ok(ActiveLoopbackSession {
        node_id: state.node_id,
        core,
        port: state.port,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn active_loopback_session() -> anyhow::Result<ActiveLoopbackSession> {
    anyhow::bail!("managed TUN activation is supported only on Linux")
}

/// Atomically verify and stop the active loopback core for a TUN transition.
///
/// The activation lock covers both identity validation and stop, so a concurrent activation
/// cannot cause this operation to stop a different node/core than the one it returns.
#[cfg(target_os = "linux")]
pub fn stop_active_loopback_for_tun() -> anyhow::Result<ActiveLoopbackSession> {
    let (runtime, state_path) = paths()?;
    let _lock = RuntimeLock::acquire(&runtime)?;
    ensure!(
        !runtime.join("tun-session.json").exists(),
        "a privileged TUN session or handoff is already pending"
    );
    let state: ActiveProcess = serde_json::from_slice(
        &fs::read(&state_path).context("no Proxyctl-managed loopback session is active")?,
    )
    .context("Proxyctl activation state is corrupt; refusing to transition it to TUN")?;
    ensure!(
        state.tun.is_none(),
        "the tracked session is already a legacy TUN session; use 'proxyctl tun stop' to recover it"
    );
    ensure!(
        state.node_id != 0
            && state.port >= 1024
            && state.start_ticks > 0
            && matches_process(state.pid, &state.executable, state.start_ticks),
        "active loopback process identity does not match its recorded session"
    );
    let core = match state.core.as_str() {
        "sing-box" => CoreId::SingBox,
        "mihomo" => CoreId::Mihomo,
        "xray" => anyhow::bail!(
            "the active Xray session uses a descriptor-backed TUN contract not yet wired into the native supervisor"
        ),
        _ => anyhow::bail!("active loopback state names an unsupported core"),
    };
    let active = ActiveLoopbackSession {
        node_id: state.node_id,
        core,
        port: state.port,
    };
    let previous_path = runtime.join("tun-previous.json");
    ensure!(
        !previous_path.exists(),
        "a previous loopback restoration is already pending; recover or restore it before another TUN transition"
    );
    let previous = PreviousLoopbackSession {
        node_id: active.node_id,
        core: active.core.as_str().to_owned(),
        port: active.port,
    };
    write_atomic(&previous_path, &serde_json::to_vec(&previous)?)?;
    if let Err(error) = stop_locked(&runtime, &state_path, &managed_cores_path()?) {
        // If the active state remains, the loopback process was not fully transitioned and
        // must not be restored over itself. If it disappeared, retain the marker for recovery.
        if state_path.exists() {
            let _ = fs::remove_file(&previous_path);
        }
        return Err(error).context("cannot stop the active loopback process for TUN transition");
    }
    Ok(active)
}

#[cfg(not(target_os = "linux"))]
pub fn stop_active_loopback_for_tun() -> anyhow::Result<ActiveLoopbackSession> {
    anyhow::bail!("managed TUN activation is supported only on Linux")
}

/// Persist an unprivileged hint that a privileged TUN session is being started.
///
/// The marker is written before sudo handoff so a front-end crash cannot make a live TUN
/// session invisible to `proxyctl stop`. It is never trusted for privileged recovery.
#[cfg(target_os = "linux")]
pub fn write_tun_session_marker(activation_id: &str, generation: u64) -> anyhow::Result<()> {
    ensure!(
        activation_id.len() == 36
            && activation_id.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                }
            }),
        "invalid TUN activation identity for user runtime marker"
    );
    ensure!(generation > 0, "TUN marker generation must be non-zero");
    let (runtime, state_path) = paths()?;
    let _lock = RuntimeLock::acquire(&runtime)?;
    ensure!(
        !state_path.exists(),
        "a loopback session became active before the TUN handoff"
    );
    let marker_path = runtime.join("tun-session.json");
    ensure!(
        !marker_path.exists(),
        "a TUN session marker already exists; recover it before starting another session"
    );
    let marker = PendingTunSession {
        schema_version: 1,
        activation_id: activation_id.to_owned(),
        generation,
    };
    write_atomic(&marker_path, &serde_json::to_vec(&marker)?)
}

#[cfg(not(target_os = "linux"))]
pub fn write_tun_session_marker(_activation_id: &str, _generation: u64) -> anyhow::Result<()> {
    anyhow::bail!("managed TUN activation is supported only on Linux")
}

/// Whether a TUN handoff or session is pending in the current user's runtime.
#[cfg(target_os = "linux")]
pub fn has_pending_tun_session() -> anyhow::Result<bool> {
    let (runtime, _) = paths()?;
    Ok(runtime.join("tun-session.json").exists())
}

#[cfg(not(target_os = "linux"))]
pub fn has_pending_tun_session() -> anyhow::Result<bool> {
    Ok(false)
}

/// Remove the user-owned TUN hint only after privileged recovery or session completion.
#[cfg(target_os = "linux")]
pub fn clear_tun_session_marker() -> anyhow::Result<bool> {
    let (runtime, _) = paths()?;
    let _lock = RuntimeLock::acquire(&runtime)?;
    let marker_path = runtime.join("tun-session.json");
    if !marker_path.exists() {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(&marker_path)
        .context("cannot inspect pending TUN session marker")?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.uid() == unsafe { libc::getuid() }
            && metadata.permissions().mode() & 0o7777 == 0o600
            && metadata.nlink() == 1,
        "pending TUN session marker has an unsafe identity or mode"
    );
    let marker: PendingTunSession = serde_json::from_slice(&fs::read(&marker_path)?)
        .context("pending TUN session marker is corrupt")?;
    ensure!(
        marker.schema_version == 1
            && marker.generation > 0
            && marker.activation_id.len() == 36
            && marker.activation_id.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
                }
            }),
        "pending TUN session marker contains invalid identity data"
    );
    fs::remove_file(&marker_path).context("cannot remove completed TUN session marker")?;
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
pub fn clear_tun_session_marker() -> anyhow::Result<bool> {
    Ok(false)
}

/// Report whether a prior loopback session is awaiting restoration after TUN mode.
#[cfg(target_os = "linux")]
pub fn has_pending_previous_loopback() -> anyhow::Result<bool> {
    let (runtime, _) = paths()?;
    Ok(runtime.join("tun-previous.json").exists())
}

#[cfg(not(target_os = "linux"))]
pub fn has_pending_previous_loopback() -> anyhow::Result<bool> {
    Ok(false)
}

/// Restore the saved loopback session after a TUN session has been stopped or failed.
///
/// The marker is user-owned and is used only to re-resolve the node through the ordinary
/// activation path. The activation lock enforces an idle-only start so this cannot replace
/// a session created concurrently by another Proxyctl process.
#[cfg(target_os = "linux")]
pub fn restore_previous_loopback_if_any() -> anyhow::Result<bool> {
    let (runtime, state_path) = paths()?;
    let previous_path = runtime.join("tun-previous.json");
    let previous = {
        let _lock = RuntimeLock::acquire(&runtime)?;
        if !previous_path.exists() {
            return Ok(false);
        }
        let metadata = fs::symlink_metadata(&previous_path)
            .context("cannot inspect pending loopback restoration metadata")?;
        ensure!(
            metadata.file_type().is_file()
                && metadata.uid() == unsafe { libc::getuid() }
                && metadata.permissions().mode() & 0o7777 == 0o600
                && metadata.nlink() == 1,
            "pending loopback restoration metadata has an unsafe identity or mode"
        );
        let previous: PreviousLoopbackSession =
            serde_json::from_slice(&fs::read(&previous_path)?)
                .context("pending loopback restoration metadata is corrupt")?;
        ensure!(
            previous.node_id != 0 && previous.port >= 1024,
            "pending loopback restoration metadata contains invalid values"
        );
        ensure!(
            matches!(previous.core.as_str(), "sing-box" | "mihomo"),
            "pending loopback restoration metadata names an unsupported core"
        );
        if state_path.exists() {
            let state: ActiveProcess = serde_json::from_slice(&fs::read(&state_path)?)
                .context("active Proxyctl session state is corrupt")?;
            ensure!(
                state.node_id == previous.node_id
                    && state.core == previous.core
                    && state.port == previous.port
                    && state.tun.is_none()
                    && matches_process(state.pid, &state.executable, state.start_ticks),
                "another Proxyctl-managed session is active; preserving the pending loopback restoration marker"
            );
            fs::remove_file(&previous_path)
                .context("cannot remove already-completed loopback restoration metadata")?;
            return Ok(true);
        }
        previous
    };

    let core = match previous.core.as_str() {
        "sing-box" => CoreId::SingBox,
        "mihomo" => CoreId::Mihomo,
        _ => anyhow::bail!("pending loopback restoration core is unsupported"),
    };
    activate_if_idle(previous.node_id, core, Some(previous.port), false)
        .context("cannot restore the previous loopback session")?;

    let _lock = RuntimeLock::acquire(&runtime)?;
    let state: ActiveProcess = serde_json::from_slice(&fs::read(&state_path)?)
        .context("restored loopback session state disappeared before marker cleanup")?;
    ensure!(
        state.node_id == previous.node_id
            && state.core == previous.core
            && state.port == previous.port
            && state.tun.is_none()
            && matches_process(state.pid, &state.executable, state.start_ticks),
        "restored loopback process does not match the saved session; preserving restoration marker"
    );
    fs::remove_file(&previous_path)
        .context("cannot remove completed loopback restoration metadata")?;
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
pub fn restore_previous_loopback_if_any() -> anyhow::Result<bool> {
    anyhow::bail!("managed TUN activation is supported only on Linux")
}

/// Require a clean unprivileged activation slot before handing a new TUN request to sudo.
#[cfg(target_os = "linux")]
pub fn ensure_tun_start_available(port: u16) -> anyhow::Result<()> {
    let (_, state_path) = paths()?;
    ensure!(
        !state_path.exists(),
        "a Proxyctl-managed core is already active; stop it before starting a separate TUN session"
    );
    ensure_port_available(port)
}

#[cfg(not(target_os = "linux"))]
pub fn ensure_tun_start_available(_port: u16) -> anyhow::Result<()> {
    anyhow::bail!("managed TUN activation is supported only on Linux")
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
/// Clear foreground state only when it still belongs to the exact process we waited for.
#[cfg(target_os = "linux")]
fn finish_foreground(
    state_path: &Path,
    pid: u32,
    start_ticks: u64,
    executable: &Path,
    exit_success: bool,
) -> anyhow::Result<()> {
    let (runtime, expected_state_path) = paths()?;
    ensure!(
        state_path == expected_state_path.as_path(),
        "foreground activation state path changed; refusing cleanup"
    );
    let _lock = RuntimeLock::acquire(&runtime)?;
    let bytes = match fs::read(state_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The top-level stop command may already have removed this child's state.
            return Ok(());
        }
        Err(error) => return Err(error).context("cannot read foreground activation state"),
    };
    let state: ActiveProcess = serde_json::from_slice(&bytes)
        .context("foreground activation state is corrupt; refusing cleanup")?;
    if state.pid != pid
        || state.start_ticks != start_ticks
        || state.executable.as_path() != executable
    {
        // A newer activation or a reused PID owns the shared state path.
        return Ok(());
    }
    ensure!(
        state.tun.is_none() && state.start_ticks > 0,
        "foreground activation state has an invalid process identity; refusing cleanup"
    );
    ensure!(
        state.config.parent() == Some(runtime.as_path())
            && state
                .config
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("active-")),
        "foreground config path is outside the private runtime directory; refusing cleanup"
    );
    ensure!(
        !matches_process(state.pid, &state.executable, state.start_ticks),
        "foreground process still matches its recorded identity; refusing to remove its state"
    );
    fs::remove_file(&state.config).context("could not remove exited foreground core config")?;
    fs::remove_file(state_path).context("could not remove exited foreground activation state")?;
    if !exit_success {
        eprintln!("The foreground core exited unsuccessfully; its exact stale state was cleaned.");
    }
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
    #[cfg(target_os = "linux")]
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
    fn legacy_tun_recovery_ignores_unrelated_interface_and_dns_changes() {
        let baseline = TunBaseline {
            interfaces: vec!["lo".into(), "docker0".into()],
            tun_interfaces: vec![],
            default_routes: vec!["IPv4 default via wlan0".into()],
            dns_servers: vec!["127.0.0.53".into()],
            resolv_conf_target: None,
            ipv4_routes: vec!["main-route".into(), "docker-route".into()],
            ipv6_routes: vec!["main-v6-route".into()],
            ipv4_rules: vec!["main-rule".into()],
            ipv6_rules: vec!["main-v6-rule".into()],
        };
        let mut current = baseline.clone();
        current.interfaces = vec!["lo".into(), "wlan0".into()];
        current.dns_servers = vec!["1.1.1.1".into()];
        current.ipv4_routes.retain(|route| route != "docker-route");
        assert!(legacy_tun_snapshot_is_safe_to_retire(&baseline, &current));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_tun_recovery_refuses_tun_interfaces_and_new_routes_or_rules() {
        let baseline = TunBaseline {
            interfaces: vec!["lo".into()],
            tun_interfaces: vec![],
            default_routes: vec![],
            dns_servers: vec![],
            resolv_conf_target: None,
            ipv4_routes: vec!["main-route".into()],
            ipv6_routes: vec![],
            ipv4_rules: vec!["main-rule".into()],
            ipv6_rules: vec![],
        };
        let mut current = baseline.clone();
        current.tun_interfaces.push("tun-proxyctl".into());
        assert!(!legacy_tun_snapshot_is_safe_to_retire(&baseline, &current));

        current = baseline.clone();
        current.ipv4_routes.push("new-route".into());
        assert!(!legacy_tun_snapshot_is_safe_to_retire(&baseline, &current));

        current = baseline.clone();
        current.ipv6_rules.push("new-rule".into());
        assert!(!legacy_tun_snapshot_is_safe_to_retire(&baseline, &current));
    }

    #[cfg(target_os = "linux")]
    #[cfg(target_os = "linux")]
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
        assert!(error.contains("dedicated generation-bound Xray broker lifecycle"));
        assert!(error.contains("not the loopback activation path"));
    }

    #[test]
    fn new_tun_activation_stays_fail_closed_during_supervisor_migration() {
        let error = ensure_tun_session_backend_ready().unwrap_err().to_string();
        assert!(error.contains("single-executable supervisor migration"));
        assert!(error.contains("existing generations"));
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
        // Use a bounded-duration sleeper rather than tail -f /dev/null. Some
        // environments or test runners can terminate follow-mode tail processes,
        // which makes the identity assertion flaky before the test sends a signal.
        let sleep = find_program("sleep").unwrap();
        let exe = fs::canonicalize(sleep).unwrap();
        let mut child = Command::new(&exe)
            .arg("3600")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        // Resolve the expected binary independently of /proc so the test cannot
        // accidentally pin the short-lived pre-exec image returned by spawn().
        let ticks = await_identity(pid, &exe, Duration::from_secs(2)).unwrap();

        assert!(signal_verified(pid, &exe, ticks.saturating_add(1), libc::SIGTERM).is_err());
        assert!(
            matches_process(pid, &exe, ticks),
            "a rejected identity must leave the verified child running"
        );

        let deadline = Instant::now() + Duration::from_secs(10);
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
            .map(|path| path.join("sleep"))
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
            command.arg("3600");
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
                false,
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
                false,
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
                false,
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
                false,
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

#[cfg(all(test, target_os = "linux"))]
mod tun_probe_target_tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn readiness_targets_require_one_usable_address_per_family() {
        let probe = url::Url::parse("http://connectivity.example.test/generate_204").unwrap();
        let targets = build_dual_stack_probe_targets(
            &probe,
            [
                SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 80)),
                SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10), 80)),
                SocketAddr::from((Ipv4Addr::new(192, 0, 2, 11), 80)),
            ],
            204,
        )
        .unwrap();

        assert_eq!(targets.len(), 2);
        assert!(targets[0].destination.is_ipv4());
        assert!(targets[1].destination.is_ipv6());
        assert_eq!(targets[0].host_header, "connectivity.example.test");
        assert_eq!(targets[1].host_header, "connectivity.example.test");
        assert_eq!(targets[0].path, "/generate_204");
        assert_eq!(targets[1].path, "/generate_204");
    }

    #[test]
    fn readiness_targets_reject_missing_address_family() {
        let probe = url::Url::parse("http://connectivity.example.test/generate_204").unwrap();
        let result = build_dual_stack_probe_targets(
            &probe,
            [SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 80))],
            204,
        );
        assert!(result.is_err());
    }

    #[test]
    fn readiness_targets_ignore_unspecified_and_multicast_addresses() {
        let probe = url::Url::parse("http://connectivity.example.test/").unwrap();
        let result = build_dual_stack_probe_targets(
            &probe,
            [
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 80)),
                SocketAddr::from((Ipv4Addr::new(224, 0, 0, 1), 80)),
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 80)),
                SocketAddr::from((Ipv6Addr::LOCALHOST, 80)),
            ],
            204,
        );
        assert!(result.is_err());
    }
}
