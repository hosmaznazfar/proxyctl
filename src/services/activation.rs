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

        let port = reserve_port()?;
        let generated = adapter
            .generate_benchmark_config(&node, port)
            .with_context(|| format!("could not generate loopback-only {core} config"))?;
        adapters::validation::validate_generated_config(core, &generated, &executable)
            .with_context(|| format!("{core} rejected the activation config"))?;

        // Do not interrupt the existing activation until the replacement config validates.
        let config = runtime.join(format!("active-{node_id}-{}.json", core.as_str()));
        let mut command = Command::new(&executable);
        match core {
            CoreId::SingBox | CoreId::Xray => {
                command.arg("run").arg("-c").arg(&config);
            }
            CoreId::Mihomo => {
                command.arg("-f").arg(&config);
            }
        }
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
    // Validate and prepare the replacement before stopping the current process.
    write_atomic(config, config_content)?;
    stop_locked(runtime, state_path, managed_root)?;
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
    let start_ticks = match await_identity(pid, executable, timeout) {
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
        executable: executable.to_path_buf(),
        config: config.to_path_buf(),
        node_id,
        core: core.to_owned(),
        port,
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
            command.arg("30");
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
            assert!(matches_process(state.pid, &fake, state.start_ticks));
            if let Some((pid, executable, ticks)) = previous_process.take() {
                assert!(
                    !matches_process(pid, &executable, ticks),
                    "switching must stop the previously active process"
                );
            }
            previous_process = Some((state.pid, fake.clone(), state.start_ticks));
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
            &fake,
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
        let mut command = Command::new(&fake);
        command.arg("30");

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
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("uuid"));
        assert!(!json.contains("password"));
    }
}
