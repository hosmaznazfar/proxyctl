//! Isolated lifecycle for one Proxyctl-managed benchmark core process.

use std::{
    fs,
    io::Write,
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, bail, ensure};
use tempfile::NamedTempFile;

use crate::{
    cores::{CoreId, adapters},
    domain::ProxyNode,
};

const STARTUP_ATTEMPTS: usize = 3;
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Owns the child process and its secret-bearing temporary configuration.
pub struct ManagedCoreProcess {
    child: Child,
    _config: NamedTempFile,
    port: u16,
}

impl ManagedCoreProcess {
    /// Generate, validate, and start a core with a loopback-only HTTP inbound.
    pub fn start(
        core: CoreId,
        node: &ProxyNode,
        executable: &Path,
        startup_timeout: Duration,
    ) -> anyhow::Result<Self> {
        ensure!(
            executable.is_file(),
            "managed {core} executable is not installed"
        );
        let adapter = adapters::adapter(core);
        let mut last_failure = "the core did not open its local HTTP listener".to_owned();

        for _ in 0..STARTUP_ATTEMPTS {
            let port = reserve_loopback_port()?;
            let generated = adapter
                .generate_benchmark_config(node, port)
                .with_context(|| format!("could not generate benchmark config for {core}"))?;
            let mut config = NamedTempFile::new()
                .context("could not create private benchmark configuration")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                config
                    .as_file()
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .context("could not restrict benchmark config permissions")?;
            }
            config
                .write_all(&generated.content)
                .context("could not write benchmark configuration")?;
            config
                .as_file()
                .sync_all()
                .context("could not flush benchmark configuration")?;

            adapter
                .validate_config(executable, config.path())
                .with_context(|| format!("{core} rejected the benchmark configuration"))?;

            let mut child = spawn_core(core, executable, config.path())?;
            match wait_for_listener(&mut child, port, startup_timeout) {
                Ok(()) => {
                    return Ok(Self {
                        child,
                        _config: config,
                        port,
                    });
                }
                Err(reason) => {
                    last_failure = reason;
                    terminate_child(&mut child);
                }
            }
        }

        bail!("{core} did not become ready after {STARTUP_ATTEMPTS} attempts: {last_failure}")
    }

    /// Port of the loopback HTTP proxy listener.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Stop the child and wait for process exit before removing its config.
    pub fn stop(mut self) -> anyhow::Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill().context("could not stop managed benchmark core")?;
        }
        self.child
            .wait()
            .context("could not wait for managed benchmark core to exit")?;
        Ok(())
    }
}

impl Drop for ManagedCoreProcess {
    fn drop(&mut self) {
        terminate_child(&mut self.child);
        // The temporary config is removed after the child has been stopped.
    }
}

fn reserve_loopback_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .context("could not reserve a loopback benchmark port")?;
    let port = listener
        .local_addr()
        .context("could not read reserved benchmark port")?
        .port();
    drop(listener);
    Ok(port)
}

fn append_core_arguments(core: CoreId, command: &mut Command, config: &Path) {
    match core {
        CoreId::SingBox | CoreId::Xray => {
            command.arg("run").arg("-c").arg(config);
        }
        CoreId::Mihomo => {
            command.arg("-f").arg(config);
        }
    }
}

fn spawn_core(core: CoreId, executable: &Path, config: &Path) -> anyhow::Result<Child> {
    let mut command = Command::new(executable);
    append_core_arguments(core, &mut command, config);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("could not start managed {core} process"))
}

fn wait_for_listener(
    child: &mut Child,
    port: u16,
    timeout: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    let address = ("127.0.0.1", port);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!(
                    "core exited before readiness (exit status {:?})",
                    status.code()
                ));
            }
            Err(_) => return Err("could not inspect core process state".into()),
            Ok(None) => {}
        }

        if TcpStream::connect(address).is_ok() {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err("local HTTP listener readiness timed out".into());
        }
        thread::sleep(READINESS_POLL_INTERVAL);
    }
}

fn terminate_child(child: &mut Child) {
    if matches!(child.try_wait(), Ok(None)) {
        let _ = child.kill();
    }
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserves_only_loopback_ephemeral_ports() {
        let port = reserve_loopback_port().unwrap();
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        assert_eq!(listener.local_addr().unwrap().ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn command_arguments_are_core_specific() {
        let config = Path::new("/tmp/proxyctl-test.json");
        let mut sing_box = Command::new("sing-box");
        let mut xray = Command::new("xray");
        let mut mihomo = Command::new("mihomo");
        append_core_arguments(CoreId::SingBox, &mut sing_box, config);
        append_core_arguments(CoreId::Xray, &mut xray, config);
        append_core_arguments(CoreId::Mihomo, &mut mihomo, config);
        let sing_box_args = sing_box.get_args().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>();
        let xray_args = xray.get_args().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>();
        let mihomo_args = mihomo.get_args().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>();
        assert_eq!(sing_box_args, ["run", "-c", "/tmp/proxyctl-test.json"]);
        assert_eq!(xray_args, ["run", "-c", "/tmp/proxyctl-test.json"]);
        assert_eq!(mihomo_args, ["-f", "/tmp/proxyctl-test.json"]);
    }
}
