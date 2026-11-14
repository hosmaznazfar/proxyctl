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
    log: NamedTempFile,
    ports: Vec<u16>,
}

impl ManagedCoreProcess {
    /// Generate, validate, and start a core with one loopback-only HTTP inbound.
    pub fn start(
        core: CoreId,
        node: &ProxyNode,
        executable: &Path,
        startup_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let port = reserve_loopback_port()?;
        let target = adapters::BenchmarkTarget {
            node_id: 1,
            node,
            listen_port: port,
        };
        Self::start_batch(core, &[target], executable, startup_timeout)
    }

    /// Validate one node's ordinary benchmark configuration before admitting it to a batch.
    /// This isolates per-node native incompatibilities without starting a core process.
    pub fn validate_node_config(
        core: CoreId,
        node: &ProxyNode,
        executable: &Path,
    ) -> anyhow::Result<()> {
        ensure!(
            executable.is_file(),
            "managed {core} executable is not installed"
        );
        let port = reserve_loopback_port()?;
        let adapter = adapters::adapter(core);
        let generated = adapter
            .generate_benchmark_config(node, port)
            .with_context(|| format!("could not generate benchmark config for {core}"))?;
        let mut config = tempfile::Builder::new()
            .prefix("proxyctl-benchmark-preflight-")
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
            .with_context(|| format!("{core} rejected the node benchmark configuration"))?;
        Ok(())
    }

    /// Start one managed core with independently routed loopback listeners for a node batch.
    pub fn start_batch(
        core: CoreId,
        targets: &[adapters::BenchmarkTarget<'_>],
        executable: &Path,
        startup_timeout: Duration,
    ) -> anyhow::Result<Self> {
        ensure!(!targets.is_empty(), "benchmark batch must not be empty");
        ensure!(
            executable.is_file(),
            "managed {core} executable is not installed"
        );
        let ports = targets.iter().map(|target| target.listen_port).collect::<Vec<_>>();
        let adapter = adapters::adapter(core);
        let mut last_failure = "the core did not open every local HTTP listener".to_owned();
        let overall_started = Instant::now();

        for attempt in 0..STARTUP_ATTEMPTS {
            let remaining = startup_timeout.saturating_sub(overall_started.elapsed());
            if remaining.is_zero() {
                break;
            }
            let attempts_left = u32::try_from(STARTUP_ATTEMPTS - attempt).unwrap_or(1);
            let attempt_timeout = remaining / attempts_left;
            let generated = adapter
                .generate_benchmark_batch_config(targets)
                .with_context(|| format!("could not generate benchmark batch config for {core}"))?;
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
            match wait_for_listeners(&mut child, &ports, attempt_timeout) {
                Ok(()) => {
                    return Ok(Self {
                        child,
                        _config: config,
                        log,
                        ports,
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
    pub fn port(&self) -> u16 {
        self.ports[0]
    }

    /// Loopback listener ports in the same order as the batch targets.
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// Return a safe summary of recognized runtime failures from the private core log.
    /// Raw log lines are never returned or printed.
    pub fn runtime_diagnostic(&self) -> Option<&'static str> {
        let contents = fs::read_to_string(self.log.path()).ok()?;
        classify_runtime_diagnostic(&contents)
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

pub(crate) fn reserve_loopback_port() -> anyhow::Result<u16> {
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
    // Some cores emit runtime diagnostics on stdout while others use stderr.
    // Clone the same file handle so both streams are captured in one private log.
    let stderr = log
        .reopen()
        .context("could not open private core diagnostic log")?;
    let stdout = stderr
        .try_clone()
        .context("could not duplicate private core diagnostic log handle")?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
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

fn classify_runtime_diagnostic(contents: &str) -> Option<&'static str> {
    let diagnostic = contents.to_ascii_lowercase();
    if diagnostic.contains("websocket: bad handshake")
        || diagnostic.contains("bad websocket handshake")
    {
        Some("the remote server rejected the WebSocket handshake")
    } else if diagnostic.contains("certificate verify failed")
        || diagnostic.contains("failed to verify certificate")
        || diagnostic.contains("x509:")
    {
        Some("the core could not verify the remote TLS certificate")
    } else if diagnostic.contains("tls handshake") || diagnostic.contains("handshake failure") {
        Some("the outbound TLS handshake failed")
    } else if diagnostic.contains("no such host") {
        Some("the core could not resolve the remote server hostname")
    } else if diagnostic.contains("connection refused") {
        Some("the remote server refused the outbound connection")
    } else if diagnostic.contains("i/o timeout") || diagnostic.contains("context deadline exceeded")
    {
        Some("the outbound connection timed out")
    } else if diagnostic.contains("connection reset by peer") {
        Some("the remote server reset the outbound connection")
    } else if diagnostic.contains("unexpected eof") || diagnostic.contains("\"eof\"") {
        Some("the remote side closed the outbound connection unexpectedly")
    } else {
        None
    }
}

fn wait_for_listeners(child: &mut Child, ports: &[u16], timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    let mut ready = vec![false; ports.len()];
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

        for (index, port) in ports.iter().enumerate() {
            if !ready[index] && TcpStream::connect(("127.0.0.1", *port)).is_ok() {
                ready[index] = true;
            }
        }
        if ready.iter().all(|is_ready| *is_ready) {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            let missing = ready.iter().zip(ports).filter_map(|(is_ready, port)| (!is_ready).then_some(port.to_string())).collect::<Vec<_>>().join(", ");
            return Err(format!("local HTTP listener readiness timed out for port(s): {missing}"));
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
        // The reservation socket is intentionally dropped before the core binds.
        // Do not re-bind here: another process may legitimately win that port
        // between the reservation and this assertion (TOCTOU).
        let port = reserve_loopback_port().unwrap();
        assert_ne!(port, 0, "the OS must assign an ephemeral port");
    }

    #[cfg(unix)]
    #[test]
    fn startup_timeout_stops_a_non_ready_fake_core() {
        use std::{fs, os::unix::fs::PermissionsExt};

        use tempfile::tempdir;

        let directory = tempdir().unwrap();
        let executable = directory.path().join("fake-sing-box");
        let pid_file = directory.path().join("child.pid");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "check" ]; then exit 0; fi
printf '%s\\n' "$$" > '{}'
exec sleep 30
"#,
            pid_file.display()
        );
        fs::write(&executable, script).unwrap();
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
        let child_pid: u32 = fs::read_to_string(pid_file).unwrap().trim().parse().unwrap();
        assert!(
            !Path::new(&format!("/proc/{child_pid}")).exists(),
            "failed startup must stop and reap the exact fake child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn batch_readiness_requires_every_listener_and_identifies_missing_ports() {
        let first = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let second = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let first_port = first.local_addr().unwrap().port();
        let second_port = second.local_addr().unwrap().port();
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        assert!(wait_for_listeners(
            &mut child,
            &[first_port, second_port],
            Duration::from_millis(200)
        )
        .is_ok());
        terminate_child(&mut child);

        let missing_port = reserve_loopback_port().unwrap();
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let error = wait_for_listeners(
            &mut child,
            &[first_port, missing_port],
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(error.contains(&missing_port.to_string()));
        terminate_child(&mut child);
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
    fn runtime_diagnostics_are_allowlisted_and_never_return_raw_log_content() {
        let diagnostic = classify_runtime_diagnostic(
            "[error] websocket: bad handshake for user=secret url=https://example.invalid/path",
        );
        assert_eq!(
            diagnostic,
            Some("the remote server rejected the WebSocket handshake")
        );
        assert!(!diagnostic.unwrap().contains("secret"));
        assert_eq!(
            classify_runtime_diagnostic("dial tcp 203.0.113.1:443: i/o timeout"),
            Some("the outbound connection timed out")
        );
        assert_eq!(classify_runtime_diagnostic("normal startup message"), None);
    }

    #[test]
    fn runtime_diagnostic_patterns_cover_outbound_failures_without_leaking_details() {
        let cases = [
            (
                "sing-box: websocket: bad handshake; url=https://secret.invalid/path",
                "the remote server rejected the WebSocket handshake",
            ),
            (
                "xray: failed to verify certificate: certificate verify failed",
                "the core could not verify the remote TLS certificate",
            ),
            (
                "mihomo: x509: certificate signed by unknown authority",
                "the core could not verify the remote TLS certificate",
            ),
            (
                "sing-box: TLS handshake timeout",
                "the outbound TLS handshake failed",
            ),
            (
                "xray: handshake failure",
                "the outbound TLS handshake failed",
            ),
            (
                "mihomo: lookup proxy.example: no such host",
                "the core could not resolve the remote server hostname",
            ),
            (
                "sing-box: dial tcp proxy.example:443: connection refused",
                "the remote server refused the outbound connection",
            ),
            (
                "xray: dial tcp: i/o timeout",
                "the outbound connection timed out",
            ),
            (
                "mihomo: context deadline exceeded",
                "the outbound connection timed out",
            ),
            (
                "sing-box: read tcp: connection reset by peer",
                "the remote server reset the outbound connection",
            ),
            (
                "xray: read: unexpected EOF",
                "the remote side closed the outbound connection unexpectedly",
            ),
            (
                "mihomo: transport closed: \"EOF\"",
                "the remote side closed the outbound connection unexpectedly",
            ),
        ];

        for (log, expected) in cases {
            let summary = classify_runtime_diagnostic(log);
            assert_eq!(summary, Some(expected), "log pattern: {log}");
            assert!(!summary.unwrap().contains("secret"));
            assert!(!summary.unwrap().contains("proxy.example"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn captures_runtime_diagnostics_from_stdout_and_stderr() {
        use std::os::unix::fs::PermissionsExt;

        use tempfile::tempdir;

        let directory = tempdir().unwrap();
        let executable = directory.path().join("fake-mihomo");
        let config = directory.path().join("config.json");
        fs::write(&config, "{}").unwrap();
        fs::write(
            &executable,
            "#!/bin/sh\nprintf 'stdout diagnostic\\n'\nprintf 'stderr diagnostic\\n' >&2\n",
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();

        let log = NamedTempFile::new().unwrap();
        let mut child = spawn_core(CoreId::Mihomo, &executable, &config, &log).unwrap();
        assert!(child.wait().unwrap().success());

        let contents = fs::read_to_string(log.path()).unwrap();
        assert!(contents.contains("stdout diagnostic"));
        assert!(contents.contains("stderr diagnostic"));
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
