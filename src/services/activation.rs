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
    net::{TcpListener, TcpStream},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const WAIT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(100);

#[derive(Debug, Serialize, Deserialize)]
struct ActiveProcess {
    pid: u32,
    start_ticks: u64,
    executable: PathBuf,
    config: PathBuf,
    node_id: u64,
    core: String,
    port: u16,
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

pub fn activate(node_id: u64, core: CoreId) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("activation currently requires Linux process-identity support");
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
            executable.starts_with(managed),
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

        let port = reserve_port()?;
        let generated = adapter
            .generate_benchmark_config(&node, port)
            .with_context(|| format!("could not generate loopback-only {core} config"))?;
        adapters::validation::validate_generated_config(core, &generated, &executable)
            .with_context(|| format!("{core} rejected the activation config"))?;

        // Do not interrupt the existing activation until the replacement config validates.
        stop_locked(&runtime, &state_path)?;
        let config = runtime.join(format!("active-{node_id}-{}.json", core.as_str()));
        write_atomic(&config, &generated.content)?;
        let mut command = Command::new(&executable);
        match core {
            CoreId::SingBox | CoreId::Xray => {
                command.arg("run").arg("-c").arg(&config);
            }
            CoreId::Mihomo => {
                command.arg("-f").arg(&config);
            }
        }
        let mut child = match command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_file(&config);
                return Err(error).with_context(|| format!("could not start managed {core}"));
            }
        };
        let pid = child.id();
        let start_ticks = match await_identity(pid, &executable, WAIT) {
            Ok(ticks) => ticks,
            Err(error) => {
                // Child::kill targets the exact Child handle, so it is safe even when procfs
                // identity could not be established.
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(&config);
                return Err(error);
            }
        };
        let state = ActiveProcess {
            pid,
            start_ticks,
            executable,
            config,
            node_id,
            core: core.to_string(),
            port,
        };
        if let Err(error) = write_atomic(&state_path, &serde_json::to_vec(&state)?) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&state.config);
            return Err(error);
        }
        // Persist ownership before the readiness wait, so interruption cannot orphan an
        // untracked core during the full startup timeout.
        drop(child);
        if let Err(error) = await_listener(pid, start_ticks, port, WAIT) {
            let _ = stop_locked(&runtime, &state_path);
            return Err(error);
        }
        println!("Activated node #{node_id} with {core}.");
        println!(
            "Local HTTP proxy: 127.0.0.1:{port} (loopback only; configure applications manually)."
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
            stop_locked(&runtime, &state_path)?;
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
        stop_locked(&runtime, &state)
    }
}

fn paths() -> anyhow::Result<(PathBuf, PathBuf)> {
    let db = default_database_path()?;
    let data = db.parent().context("Proxyctl data directory unavailable")?;
    let runtime = data.join("runtime");
    Ok((runtime.clone(), runtime.join("active.json")))
}
fn reserve_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
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
fn stop_locked(runtime: &Path, state_path: &Path) -> anyhow::Result<()> {
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
    let managed_root = fs::canonicalize(managed_cores_path()?)
        .context("Proxyctl managed-core directory is unavailable; refusing to signal")?;
    ensure!(
        state.executable.starts_with(managed_root),
        "recorded executable is outside Proxyctl's managed-core directory; refusing to signal"
    );
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
    fs::remove_file(state_path)?;
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
        if let (Some(ticks), Some(actual)) = (start_ticks(pid), executable(pid)) {
            if actual == expected {
                return Ok(ticks);
            }
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
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let exe = executable(pid).unwrap();
        let ticks = start_ticks(pid).unwrap();

        assert!(signal_verified(pid, &exe, ticks.saturating_add(1), libc::SIGTERM).is_err());
        assert!(matches_process(pid, &exe, ticks));

        signal_verified(pid, &exe, ticks, libc::SIGTERM).unwrap();
        child.wait().unwrap();
        assert!(!matches_process(pid, &exe, ticks));
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
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("uuid"));
        assert!(!json.contains("password"));
    }
}
