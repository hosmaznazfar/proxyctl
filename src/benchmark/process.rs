//! Isolated lifecycle for one Proxyctl-managed benchmark core process.

use std::{
    fs,
    io::{Read, Write},
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
        let overall_started = Instant::now();

        for attempt in 0..STARTUP_ATTEMPTS {
            let remaining = startup_timeout.saturating_sub(overall_started.elapsed());
            if remaining.is_zero() {
                break;
            }
            let attempts_left = u32::try_from(STARTUP_ATTEMPTS - attempt).unwrap_or(1);
            let attempt_timeout = remaining / attempts_left;
            let port = reserve_loopback_port()?;
            let generated = adapter
                .generate_benchmark_config(node, port)
                .with_context(|| format!("could not generate benchmark config for {core}"))?;
            let mut config = tempfile::Builder::new()
                .prefix("proxyctl-benchmark-")
                .suffix(".json")
                .tempfile()
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

            let log = NamedTempFile::new().context("could not create private core startup log")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                log.as_file()
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .context("could not restrict core startup log permissions")?;
            }
            let mut child = spawn_core(core, executable, config.path(), &log)?;
            match wait_for_listener(&mut child, port, attempt_timeout) {
                Ok(()) => {
                    return Ok(Self {
                        child,
                        _config: config,
                        port,
                    });
                }
                Err(reason) => {
                    terminate_child(&mut child);
                    last_failure = summarize_startup_failure(&reason, log.path());
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
            self.child
                .kill()
                .context("could not stop managed benchmark core")?;
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

fn spawn_core(
    core: CoreId,
    executable: &Path,
    config: &Path,
    log: &NamedTempFile,
) -> anyhow::Result<Child> {
    let mut command = Command::new(executable);
    append_core_arguments(core, &mut command, config);
    let stderr = log
        .reopen()
        .context("could not open private core startup log")?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .with_context(|| format!("could not start managed {core} process"))
}

fn summarize_startup_failure(fallback: &str, log_path: &Path) -> String {
    let Ok(mut file) = fs::File::open(log_path) else {
        return fallback.to_owned();
    };
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return fallback.to_owned();
    }
    let diagnostic = contents.to_ascii_lowercase();
    let category =
        if diagnostic.contains("address already in use") || diagnostic.contains("address in use") {
            Some("the local listener port is already in use")
        } else if diagnostic.contains("permission denied") {
            Some("the core was denied permission to open a required resource")
        } else if diagnostic.contains("failed to listen")
            || diagnostic.contains("listen tcp")
            || diagnostic.contains("bind:")
        {
            Some("the core could not bind its local listener")
        } else if diagnostic.contains("unknown field")
            || diagnostic.contains("invalid config")
            || diagnostic.contains("failed to parse")
        {
            Some("the core rejected a runtime configuration field")
        } else if diagnostic.contains("tls")
            || diagnostic.contains("certificate")
            || diagnostic.contains("x509")
        {
            Some("the core failed while initializing TLS or certificate settings")
        } else if diagnostic.contains("failed to initialize")
            || diagnostic.contains("failed to start")
            || diagnostic.contains("fatal")
        {
            Some("the core reported an initialization failure")
        } else {
            None
        };
    match category {
        Some(category) => format!("{fallback}; {category}"),
        None if contents.is_empty() => fallback.to_owned(),
        None => format!(
            "{fallback}; core emitted {} bytes of startup diagnostics (details withheld)",
            contents.len()
        ),
    }
}

fn wait_for_listener(child: &mut Child, port: u16, timeout: Duration) -> Result<(), String> {
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

    #[cfg(unix)]
    #[test]
    fn startup_timeout_stops_a_non_ready_fake_core() {
        use std::{fs, os::unix::fs::PermissionsExt};

        use tempfile::tempdir;

        let directory = tempdir().unwrap();
        let executable = directory.path().join("fake-sing-box");
        fs::write(
            &executable,
            "#!/bin/sh\nif [ \"$1\" = \"check\" ]; then exit 0; fi\nexec sleep 30\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let node = crate::parser::parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@proxy.local:443",
        )
        .unwrap();

        let started = Instant::now();
        let result = ManagedCoreProcess::start(
            CoreId::SingBox,
            &node,
            &executable,
            Duration::from_millis(200),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn startup_diagnostic_summary_never_exposes_raw_log_lines() {
        let log = NamedTempFile::new().unwrap();
        fs::write(
            log.path(),
            "failed to listen tcp 127.0.0.1:1234: address already in use; password=secret",
        )
        .unwrap();
        let summary = summarize_startup_failure("core exited", log.path());
        assert!(summary.contains("local listener port is already in use"));
        assert!(!summary.contains("secret"));
        assert!(!summary.contains("127.0.0.1"));
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
        let sing_box_args = sing_box
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let xray_args = xray
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let mihomo_args = mihomo
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            sing_box_args,
            vec![
                "run".to_owned(),
                "-c".to_owned(),
                "/tmp/proxyctl-test.json".to_owned()
            ]
        );
        assert_eq!(xray_args, vec!["run", "-c", "/tmp/proxyctl-test.json"]);
        assert_eq!(
            mihomo_args,
            vec!["-f".to_owned(), "/tmp/proxyctl-test.json".to_owned()]
        );
    }
}
