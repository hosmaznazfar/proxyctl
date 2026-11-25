//! Complete single-executable startup and monitoring for native persistent-device TUN cores.
//!
//! The privileged supervisor owns the staged config, kernel transaction, exact core child,
//! durable session receipt, and cleanup monitor for the full session lifetime. Xray attaches
//! through its native named-device mode; no descriptor broker or helper process is involved.
#![cfg(target_os = "linux")]

use anyhow::{Context, Result, ensure};
use std::{
    net::SocketAddr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::process::ExitStatusExt,
    process::ExitStatus,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering},
    },
    time::Duration,
};

/// Signal state is installed before privileged network preparation. Until a core pidfd is
/// attached, signals are latched and delivered/cancelled as soon as the child is available.
static FORWARDED_CORE_PIDFD: AtomicI32 = AtomicI32::new(-1);
static FOREGROUND_SIGNAL_GROUP: AtomicBool = AtomicBool::new(false);
static PENDING_STARTUP_SIGNALS: AtomicU64 = AtomicU64::new(0);
static SIGNAL_GUARD_ACTIVE: AtomicBool = AtomicBool::new(false);
// A handler may have loaded the pidfd immediately before Drop restores the dispositions.
// Retain retired duplicate descriptors until process exit so that in-flight handlers can
// never observe a closed/reused descriptor.
static RETIRED_SIGNAL_PIDFDS: OnceLock<Mutex<Vec<OwnedFd>>> = OnceLock::new();

fn signal_bit(signal: libc::c_int) -> Option<u64> {
    if (1..=64).contains(&signal) {
        Some(1u64 << (signal - 1))
    } else {
        None
    }
}

fn send_pidfd_signal(pidfd: libc::c_int, signal: libc::c_int) {
    // A pidfd continues to identify the original child after wait() reaps it; it can
    // never redirect a late signal to a process that reused the numeric PID.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        );
    }
}

extern "C" fn forward_supervisor_signal(signal: libc::c_int) {
    let foreground_terminal_signal = FOREGROUND_SIGNAL_GROUP.load(Ordering::Relaxed)
        && matches!(signal, libc::SIGINT | libc::SIGQUIT | libc::SIGHUP);
    let pidfd = FORWARDED_CORE_PIDFD.load(Ordering::Acquire);
    if pidfd >= 0 {
        // Foreground cores share the terminal process group, so terminal-generated signals
        // already reach the core directly. Do not deliver those a second time.
        if !foreground_terminal_signal {
            send_pidfd_signal(pidfd, signal);
        }
        return;
    }

    // There is no child yet. Latch the signal and recheck the pidfd to close the race with
    // attach_core(): exactly one side either drains the bit or forwards it after attachment.
    let Some(bit) = signal_bit(signal) else {
        return;
    };
    PENDING_STARTUP_SIGNALS.fetch_or(bit, Ordering::AcqRel);
    let pidfd = FORWARDED_CORE_PIDFD.load(Ordering::Acquire);
    if pidfd >= 0 && PENDING_STARTUP_SIGNALS.fetch_and(!bit, Ordering::AcqRel) & bit != 0 {
        send_pidfd_signal(pidfd, signal);
    }
}

/// Owns process-wide signal dispositions from before kernel preparation until session cleanup.
/// Signals received before a core is attached are latched; once attached, supervisor-only
/// signals are forwarded through its pinned pidfd.
pub struct SignalForwardingGuard {
    previous: Vec<(libc::c_int, libc::sighandler_t)>,
    process: Option<super::process::ProcessHandle>,
    signal_pidfd: Option<OwnedFd>,
}

impl SignalForwardingGuard {
    pub fn install(foreground: bool) -> Result<Self> {
        SIGNAL_GUARD_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("a TUN signal-forwarding guard is already active"))?;
        if FORWARDED_CORE_PIDFD.load(Ordering::Acquire) != -1 {
            SIGNAL_GUARD_ACTIVE.store(false, Ordering::Release);
            anyhow::bail!("a core signal-forwarding pidfd is unexpectedly still active");
        }
        PENDING_STARTUP_SIGNALS.store(0, Ordering::Release);
        FOREGROUND_SIGNAL_GROUP.store(foreground, Ordering::Release);

        let mut signals = vec![libc::SIGTERM, libc::SIGINT];
        if foreground {
            signals.extend([libc::SIGQUIT, libc::SIGHUP]);
        }
        let mut previous = Vec::with_capacity(signals.len());
        for signal in signals {
            let old = unsafe {
                libc::signal(
                    signal,
                    forward_supervisor_signal as *const () as libc::sighandler_t,
                )
            };
            if old == libc::SIG_ERR {
                let error = std::io::Error::last_os_error();
                for (installed, handler) in previous.iter().rev() {
                    unsafe {
                        libc::signal(*installed, *handler);
                    }
                }
                FOREGROUND_SIGNAL_GROUP.store(false, Ordering::Release);
                PENDING_STARTUP_SIGNALS.store(0, Ordering::Release);
                SIGNAL_GUARD_ACTIVE.store(false, Ordering::Release);
                return Err(error).context("cannot install TUN supervisor signal forwarding");
            }
            previous.push((signal, old));
        }
        Ok(Self {
            previous,
            process: None,
            signal_pidfd: None,
        })
    }

    /// Fail before further startup work if a termination signal arrived before child spawn.
    pub fn check_startup(&self) -> Result<()> {
        let pending = PENDING_STARTUP_SIGNALS.swap(0, Ordering::AcqRel);
        ensure!(
            pending == 0,
            "TUN supervisor received a termination signal during startup; activation will be recovered"
        );
        Ok(())
    }

    /// Bind signal forwarding to the exact child. A signal latched before attachment cancels
    /// startup instead of allowing readiness/commit to proceed after an interrupted handoff.
    pub fn attach_core(&mut self, identity: super::process::ProcessIdentity) -> Result<()> {
        let process = super::process::ProcessHandle::open(identity)
            .context("cannot pin the exact TUN core for signal forwarding")?;
        ensure!(
            !process.is_exited()?,
            "cannot install signal forwarding for an exited TUN core"
        );
        // Give the async signal handler a descriptor whose lifetime is independent from
        // ProcessHandle. Drop retires this duplicate until process exit to close the
        // handler-load-versus-close race without locking inside the signal handler.
        let duplicated = unsafe { libc::fcntl(process.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        ensure!(
            duplicated >= 0,
            "cannot duplicate the pinned TUN core pidfd for signal handling: {}",
            std::io::Error::last_os_error()
        );
        let signal_pidfd = unsafe { OwnedFd::from_raw_fd(duplicated) };
        FORWARDED_CORE_PIDFD
            .compare_exchange(
                -1,
                signal_pidfd.as_raw_fd(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| anyhow::anyhow!("a core signal-forwarding pidfd is already active"))?;
        // The local OwnedFd remains alive from publication until ownership is transferred.
        self.process = Some(process);
        self.signal_pidfd = Some(signal_pidfd);

        let pending = PENDING_STARTUP_SIGNALS.swap(0, Ordering::AcqRel);
        if pending != 0 {
            if let Some(process) = self.process.as_ref() {
                let _ = process.signal(libc::SIGTERM);
            }
            anyhow::bail!(
                "TUN supervisor received a termination signal before core attachment; startup was cancelled"
            );
        }
        Ok(())
    }
}

impl Drop for SignalForwardingGuard {
    fn drop(&mut self) {
        FORWARDED_CORE_PIDFD.store(-1, Ordering::Release);
        FOREGROUND_SIGNAL_GROUP.store(false, Ordering::Release);
        PENDING_STARTUP_SIGNALS.store(0, Ordering::Release);
        for (signal, handler) in self.previous.iter().rev() {
            unsafe {
                libc::signal(*signal, *handler);
            }
        }
        if let Some(pidfd) = self.signal_pidfd.take() {
            RETIRED_SIGNAL_PIDFDS
                .get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(pidfd);
        }
        SIGNAL_GUARD_ACTIVE.store(false, Ordering::Release);
    }
}

use super::{
    config_staging::{self, StagedConfig},
    direct_core_launcher::SupervisedCore,
    launch_spec::LaunchSpec,
    lifecycle_coordinator::{ActivationToken, LifecycleCoordinator},
    linux_journal_backend::LinuxJournalBackend,
    manifest_store::ManifestStore,
    native_session,
    recovery::SupervisorPhase,
    route_policy::RoutingPolicyPlan,
    session_record::{SessionRecord, SessionStore},
    supervisor_activation,
};

/// A committed native TUN session whose resources remain owned until this value is monitored
/// to core exit. Dropping it also drops the staged config, so callers must keep it alive.
pub struct RunningNativeSession {
    core: SupervisedCore,
    _staged_config: StagedConfig,
    store: ManifestStore,
    coordinator: LifecycleCoordinator,
    sessions: SessionStore,
    token: ActivationToken,
    _signal_guard: SignalForwardingGuard,
    pub record: SessionRecord,
}

impl RunningNativeSession {
    /// Wait for the exact launched child to exit, then recover only this activation generation.
    ///
    /// A concurrent `proxyctl tun stop` may already have completed recovery. In that case
    /// the absent manifest is treated as an already-finished session, never as permission to
    /// touch a newer generation.
    pub fn wait_and_recover(mut self) -> Result<ExitStatus> {
        let status = self.core.child.wait();
        let recovery = self.recover_if_current();
        match (status, recovery) {
            (Ok(status), Ok(())) => {
                let requested_stop = matches!(
                    status.signal(),
                    Some(libc::SIGINT) | Some(libc::SIGTERM) | Some(libc::SIGKILL)
                );
                ensure!(
                    status.success() || requested_stop,
                    "managed {} TUN core exited unexpectedly with {status}",
                    self.record.core.as_str()
                );
                Ok(status)
            }
            (Err(wait_error), Ok(())) => {
                Err(wait_error).context("native TUN core wait failed; session recovery completed")
            }
            (Ok(_), Err(recovery_error)) => Err(recovery_error),
            (Err(wait_error), Err(recovery_error)) => Err(wait_error).context(format!(
                "native TUN core wait failed; session recovery also failed ({recovery_error:#})"
            )),
        }
    }

    /// Abort a session if the startup acknowledgement cannot be delivered, then recover it.
    pub fn abort_and_recover(mut self) -> Result<()> {
        let termination = match self.core.child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => self.core.child.kill(),
            Err(error) => Err(error),
        };
        let reaping = self.core.child.wait();
        let recovery = self.recover_if_current();
        if let Err(error) = termination {
            return Err(error).context(format!(
                "could not terminate the core after supervisor handoff failure; reap result: {:?}; recovery result: {:?}",
                reaping.as_ref().map(|_| ()),
                recovery.as_ref().map(|_| ())
            ));
        }
        if let Err(error) = reaping {
            return Err(error).context(format!(
                "could not reap the core after supervisor handoff failure; recovery result: {:?}",
                recovery.as_ref().map(|_| ())
            ));
        }
        recovery
    }

    fn recover_if_current(&self) -> Result<()> {
        let Some(current) = self.coordinator.load_current()? else {
            ensure!(
                self.store.load_transaction_journal()?.is_none(),
                "TUN manifest is absent while its transaction journal remains; preserving recovery evidence"
            );
            ensure!(
                self.sessions.load()?.is_none(),
                "TUN manifest is absent while its privileged session receipt remains; preserving recovery evidence"
            );
            return Ok(());
        };
        ensure!(
            current.token == self.token,
            "TUN session changed before supervisor cleanup; preserving the newer generation"
        );
        if current.snapshot.phase == SupervisorPhase::Cleaned {
            return self
                .coordinator
                .finalize_session_cleanup(&self.token, &self.sessions)
                .context("cannot finish already-cleaned native TUN session records");
        }
        let mut backend = LinuxJournalBackend::open_for_recovery(
            self.store.clone(),
            self.token.activation_id(),
            self.token.generation(),
        )
        .context("cannot reopen the exact TUN journal after core exit")?;
        self.coordinator
            .recover_session(&self.token, &self.sessions, &mut backend)
            .map(|_| ())
            .context("cannot recover the completed native TUN session")
    }
}

/// Start a native persistent-device session after capturing an independent host baseline.
///
/// All node/database resolution has already happened in the unprivileged preparation process.
/// This function accepts only the bounded LaunchSpec data, derives every privileged path and
/// executable locally, and runs the complete end-to-end readiness gate before committing Running.
pub fn start(
    spec: &LaunchSpec,
    invoking_uid: u32,
    invoking_gid: u32,
    runtime: std::path::PathBuf,
) -> Result<RunningNativeSession> {
    ensure!(
        unsafe { libc::getuid() } == 0 && unsafe { libc::geteuid() } == 0,
        "native TUN startup must run inside the real/effective-root supervisor"
    );
    supervisor_activation::validate_native_device_core(spec.core)?;
    spec.validate()?;
    ensure!(invoking_uid != 0, "invoking TUN UID must be non-zero");
    ensure!(
        runtime == std::path::PathBuf::from("/run/proxyctl").join(invoking_uid.to_string()),
        "TUN runtime path does not match the authenticated invoking UID"
    );
    super::core_paths::resolve_managed_core(&spec.managed_core_root, invoking_uid, spec.core)
        .context("selected managed core failed privileged path validation before kernel setup")?;

    // Own termination signals before staging or any privileged network mutation.
    let mut signal_guard = SignalForwardingGuard::install(spec.foreground)?;
    signal_guard.check_startup()?;

    let baseline_host =
        crate::tun::inspect().context("cannot capture pre-activation host network baseline")?;
    ensure!(
        baseline_host.routes_inspected && baseline_host.dns_inspected,
        "native TUN startup requires complete pre-activation route and DNS inspection"
    );
    super::readiness::verify_host_network_unchanged(&baseline_host, &baseline_host)
        .context("pre-activation DNS or firewall evidence is incomplete")?;

    let staged_config = config_staging::stage_config(&runtime, spec.generated_config.as_bytes())
        .context("cannot stage generated core configuration in the root-owned runtime")?;
    staged_config.sync()?;

    let store = ManifestStore::open(runtime.clone())?;
    let coordinator = LifecycleCoordinator::new(store.clone())?;
    let sessions = SessionStore::open_root_owned(runtime.clone(), invoking_uid)?;
    ensure!(
        coordinator.load_current()?.is_none(),
        "an existing TUN activation must be recovered before starting another"
    );
    ensure!(
        store.load_transaction_journal()?.is_none(),
        "an unresolved TUN transaction journal must be recovered before starting another"
    );
    ensure!(
        sessions.load()?.is_none(),
        "an existing privileged TUN session must be recovered before starting another"
    );

    signal_guard.check_startup()?;

    let (token, applied) = match supervisor_activation::apply_native_kernel_plan(
        spec.core,
        store.clone(),
        &coordinator,
        &spec.activation_id,
        spec.generation,
        invoking_uid,
        invoking_gid,
    ) {
        Ok(value) => value,
        Err(error) => {
            let recovery = recover_after_apply_failure(
                &store,
                &coordinator,
                &sessions,
                &spec.activation_id,
                spec.generation,
            );
            return match recovery {
                Ok(()) => Err(error).context(
                    "native TUN kernel setup failed; any recoverable partial transaction was cleaned",
                ),
                Err(recovery_error) => Err(error).context(format!(
                    "native TUN kernel setup failed; automatic recovery also failed ({recovery_error:#}); durable evidence was retained"
                )),
            };
        }
    };

    if let Err(error) = signal_guard.check_startup() {
        let recovery = recover_committed_start(&store, &coordinator, &sessions, &token);
        return match recovery {
            Ok(()) => Err(error).context("startup signal received after kernel activation; journaled resources were recovered"),
            Err(recovery_error) => Err(error).context(format!("startup signal received after kernel activation; recovery also failed ({recovery_error:#}); durable evidence was retained")),
        };
    }

    let (core_mark, core_mark_mask, plan) = match (|| -> Result<_> {
        let (core_mark, core_mark_mask) =
            super::route_policy::mark_for_activation_id(&spec.activation_id)?;
        let bypass_priority = applied
            .manifest
            .rule_priority
            .checked_sub(1)
            .context("journaled TUN proxy priority has no preceding core-bypass priority")?;
        let plan = RoutingPolicyPlan::new(
            applied.manifest.table_id,
            bypass_priority,
            applied.manifest.rule_priority,
            core_mark,
            core_mark_mask,
            applied.manifest.interface_name.clone(),
            applied.manifest.interface_index,
        );
        plan.validate()?;
        Ok((core_mark, core_mark_mask, plan))
    })() {
        Ok(value) => value,
        Err(error) => {
            let recovery = recover_committed_start(&store, &coordinator, &sessions, &token);
            return match recovery {
                Ok(()) => Err(error).context(
                    "native TUN activation plan validation failed; journaled resources were recovered",
                ),
                Err(recovery_error) => Err(error).context(format!(
                    "native TUN activation plan validation failed; recovery also failed ({recovery_error:#}); durable evidence was retained"
                )),
            };
        }
    };

    let listener = SocketAddr::from(([127, 0, 0, 1], spec.listen_port));
    let readiness =
        |process: &super::process::ProcessIdentity, token: &ActivationToken| -> Result<()> {
            let current_host = crate::tun::inspect()
                .context("cannot capture post-activation DNS and firewall state")?;
            super::readiness::verify_native_core_dual_stack_end_to_end_readiness(
                &runtime,
                process,
                &applied.manifest.interface_name,
                applied.manifest.interface_index,
                core_mark,
                core_mark_mask,
                listener,
                Duration::from_secs(5),
                &plan,
                &spec.expected_peers,
                spec.peer_transport,
                &spec.traffic_targets,
                token.activation_id(),
                token.generation(),
                Duration::from_secs(10),
                64 * 1024,
                &baseline_host,
                &current_host,
            )
            .map(|_| ())
        };

    let (core, record) = match native_session::launch_and_commit_native_session(
        spec,
        staged_config.path(),
        invoking_uid,
        native_session::NativeSessionContext {
            coordinator: &coordinator,
            token: &token,
            sessions: &sessions,
            signal_guard: &mut signal_guard,
        },
        readiness,
    ) {
        Ok(value) => value,
        Err(error) => {
            let recovery = recover_committed_start(&store, &coordinator, &sessions, &token);
            return match recovery {
                Ok(()) => Err(error).context(
                    "native TUN startup failed; the core was terminated and the journaled activation was recovered",
                ),
                Err(recovery_error) => Err(error).context(format!(
                    "native TUN startup failed; automatic recovery also failed ({recovery_error:#}); durable evidence was retained"
                )),
            };
        }
    };

    Ok(RunningNativeSession {
        core,
        _staged_config: staged_config,
        store,
        coordinator,
        sessions,
        token,
        _signal_guard: signal_guard,
        record,
    })
}

fn recover_after_apply_failure(
    store: &ManifestStore,
    coordinator: &LifecycleCoordinator,
    sessions: &SessionStore,
    activation_id: &str,
    generation: u64,
) -> Result<()> {
    if let Some(current) = coordinator.load_current()? {
        ensure!(
            current.token.activation_id() == activation_id
                && current.token.generation() == generation,
            "a different TUN generation exists; preserving it without recovery"
        );
        return recover_committed_start(store, coordinator, sessions, &current.token);
    }
    let Some(journal) = store.load_transaction_journal()? else {
        return Ok(());
    };
    ensure!(
        journal.activation_id == activation_id && journal.generation == generation,
        "a different TUN transaction journal exists; preserving it without recovery"
    );
    let mut backend =
        LinuxJournalBackend::open_for_recovery(store.clone(), activation_id, generation)?;
    super::journal_recovery_executor::recover(store, &mut backend)
        .context("cannot recover the partial pre-manifest TUN transaction")?;
    Ok(())
}

fn recover_committed_start(
    store: &ManifestStore,
    coordinator: &LifecycleCoordinator,
    sessions: &SessionStore,
    token: &ActivationToken,
) -> Result<()> {
    let mut backend = LinuxJournalBackend::open_for_recovery(
        store.clone(),
        token.activation_id(),
        token.generation(),
    )?;
    coordinator
        .recover_session(token, sessions, &mut backend)
        .context("cannot recover the failed native TUN startup generation")?;
    Ok(())
}

#[cfg(test)]
mod signal_tests {
    use super::*;
    use std::{
        process::{Command, Stdio},
        sync::Mutex,
        time::Instant,
    };

    static SIGNAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct TestChild(std::process::Child);

    impl Drop for TestChild {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    // TestChild's Drop implementation always kills (when needed) and waits for the child.
    // Clippy cannot see that ownership transfer into the RAII wrapper guarantees reaping.
    #[allow(clippy::zombie_processes)]
    fn live_child() -> (TestChild, super::super::process::ProcessIdentity) {
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep must be available for signal-forwarding tests");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(identity) = super::super::process::ProcessIdentity::capture(child.id())
                && identity.verify().unwrap_or(false)
            {
                return (TestChild(child), identity);
            }
            if Instant::now() >= deadline {
                let mut child = child;
                let _ = child.kill();
                let _ = child.wait();
                panic!("test child did not remain available long enough to capture its identity");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn foreground_terminal_signal_is_not_forwarded_twice() {
        let _serial = SIGNAL_TEST_LOCK.lock().unwrap();
        let (child, identity) = live_child();
        let process = super::super::process::ProcessHandle::open(identity.clone()).unwrap();
        let mut guard = SignalForwardingGuard::install(true).unwrap();
        guard.attach_core(identity).unwrap();
        forward_supervisor_signal(libc::SIGINT);
        assert!(!process.is_exited().unwrap());
        drop(guard);
        drop(child);
    }

    #[test]
    fn startup_termination_is_observed_before_kernel_mutation() {
        let _serial = SIGNAL_TEST_LOCK.lock().unwrap();
        let guard = SignalForwardingGuard::install(false).unwrap();
        forward_supervisor_signal(libc::SIGTERM);
        assert!(guard.check_startup().is_err());
        drop(guard);
    }

    #[test]
    fn startup_termination_is_latched_and_cancels_core_attachment() {
        let _serial = SIGNAL_TEST_LOCK.lock().unwrap();
        let (child, identity) = live_child();
        let process = super::super::process::ProcessHandle::open(identity.clone()).unwrap();
        let mut guard = SignalForwardingGuard::install(false).unwrap();

        forward_supervisor_signal(libc::SIGTERM);

        assert!(
            guard.attach_core(identity).is_err(),
            "a startup signal must prevent the core from entering readiness"
        );
        assert!(process.wait_exit(Duration::from_secs(2)).unwrap());
        drop(guard);
        drop(child);
    }

    #[test]
    fn supervisor_only_termination_is_forwarded_to_the_pinned_child() {
        let _serial = SIGNAL_TEST_LOCK.lock().unwrap();
        let (child, identity) = live_child();
        let process = super::super::process::ProcessHandle::open(identity.clone()).unwrap();
        let mut guard = SignalForwardingGuard::install(false).unwrap();
        guard.attach_core(identity).unwrap();
        forward_supervisor_signal(libc::SIGTERM);
        assert!(process.wait_exit(Duration::from_secs(2)).unwrap());
        drop(guard);
        drop(child);
    }
}
