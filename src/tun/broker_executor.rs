//! End-to-end read-only socket-mark broker transaction.
//!
//! This module is the narrow execution path intended for a separately packaged helper.
//! It authenticates the caller and pins the requested process before opening the privileged
//! NETLINK_SOCK_DIAG transport. It never mutates links, routes, rules, DNS, or firewall state.
//! The module is not wired into the CLI and does not grant capabilities or launch a helper.

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};

#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use super::{
    broker_transport::write_socket_mark_response,
    privilege_broker::{
        BrokerPeerCredentials, SocketMarkBrokerRequest, SocketMarkBrokerResponse,
        accept_socket_mark_request, authorize_socket_mark_request_for_process,
        build_socket_mark_broker_response,
    },
    process::{ProcessHandle, ProcessIdentity},
    socket_diag_collector::{MAX_DUMP_TIMEOUT, collect_all},
    socket_diag_linux::LinuxSocketDiagnosticIo,
    socket_ownership::inspect_process_sockets,
};

/// Execute one authenticated, pidfd-bound diagnostic transaction.
///
/// The ordering is security-significant:
/// 1. validate the narrow request;
/// 2. pin its exact process instance;
/// 3. authenticate the Unix peer and enforce same-UID ownership;
/// 4. snapshot process socket inodes;
/// 5. only then open the netlink diagnostic socket and collect all four dumps;
/// 6. snapshot again and recheck pidfd identity/liveness;
/// 7. return only exact peer/mark candidates.
///
/// No response is produced from partial dumps or unstable process snapshots.
#[cfg(target_os = "linux")]
pub fn collect_authorized_socket_mark_response(
    request: &SocketMarkBrokerRequest,
    peer: BrokerPeerCredentials,
    timeout_per_dump: Duration,
) -> Result<SocketMarkBrokerResponse> {
    request.validate()?;
    ensure!(
        !timeout_per_dump.is_zero() && timeout_per_dump <= MAX_DUMP_TIMEOUT,
        "broker diagnostic timeout must be between zero and five seconds"
    );

    let target = ProcessHandle::open(request.process.clone())
        .context("cannot pin requested broker target process")?;
    authorize_socket_mark_request_for_process(request, peer, &target)
        .context("broker request authorization failed")?;

    // Procfs ownership inspection is unprivileged. Keep it immediately adjacent to
    // the diagnostic window so unrelated socket churn is less likely to cause ambiguity.
    let before = inspect_process_sockets(&target)
        .context("cannot snapshot broker target sockets before diagnostics")?;

    // This is the first operation that opens NETLINK_SOCK_DIAG. It occurs only after
    // peer authentication, pidfd pinning, and same-user authorization have succeeded.
    let mut diagnostic_io = LinuxSocketDiagnosticIo::open()
        .context("cannot open read-only socket diagnostic transport")?;
    let dumps = collect_all(&mut diagnostic_io, 1, timeout_per_dump)
        .context("cannot collect complete dual-stack socket diagnostics")?;
    drop(diagnostic_io);

    let after = inspect_process_sockets(&target)
        .context("cannot snapshot broker target sockets after diagnostics")?;
    ensure!(
        target.identity() == &request.process
            && target.identity().verify()?
            && !target.is_exited()?,
        "broker target process changed or exited during diagnostics"
    );

    let records = dumps
        .into_iter()
        .flat_map(|(_, _, dump)| dump.records)
        .collect::<Vec<_>>();
    build_socket_mark_broker_response(request, &before, &after, &records)
        .context("cannot assemble stable exact-peer socket-mark response")
}

/// Accept, authenticate, execute, and answer exactly one broker request.
///
/// This is the complete one-connection server boundary for a separately launched helper.
/// It intentionally does not spawn the helper, change capabilities, or install a service.
/// On any error the connection is dropped without sending partial or success-shaped output.
#[cfg(target_os = "linux")]
pub fn serve_one_socket_mark_request(
    listener: &std::os::unix::net::UnixListener,
    accept_timeout: Duration,
    diagnostic_timeout_per_dump: Duration,
    response_timeout: Duration,
) -> Result<()> {
    use std::net::Shutdown;

    ensure!(
        !accept_timeout.is_zero()
            && accept_timeout <= super::privilege_broker::MAX_BROKER_REQUEST_READ_TIMEOUT,
        "broker accept timeout is outside the permitted bound"
    );
    ensure!(
        !diagnostic_timeout_per_dump.is_zero() && diagnostic_timeout_per_dump <= MAX_DUMP_TIMEOUT,
        "broker diagnostic timeout is outside the permitted bound"
    );
    ensure!(
        !response_timeout.is_zero()
            && response_timeout <= super::broker_transport::MAX_BROKER_RESPONSE_IO_TIMEOUT,
        "broker response timeout is outside the permitted bound"
    );

    let (mut stream, peer, request) = accept_socket_mark_request(listener, accept_timeout)?;
    let response =
        collect_authorized_socket_mark_response(&request, peer, diagnostic_timeout_per_dump)?;
    write_socket_mark_response(&mut stream, &response, response_timeout)?;
    stream
        .shutdown(Shutdown::Write)
        .context("cannot close broker response write side")?;
    Ok(())
}

/// A testable identity check for callers that already own a pidfd handle.
///
/// This deliberately does not return readiness: a matching socket is only kernel
/// diagnostic evidence, not proof that an application request succeeded.
#[cfg(target_os = "linux")]
pub fn verify_broker_target(handle: &ProcessHandle, expected: &ProcessIdentity) -> Result<()> {
    ensure!(
        handle.identity() == expected,
        "broker target handle does not match expected process identity"
    );
    ensure!(
        handle.identity().verify()? && !handle.is_exited()?,
        "broker target process is no longer live"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn collect_authorized_socket_mark_response(
    _request: &(),
    _peer: (),
    _timeout_per_dump: std::time::Duration,
) -> anyhow::Result<()> {
    anyhow::bail!("socket-mark broker execution is supported only on Linux");
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        os::unix::net::UnixStream,
        process::{Command, Stdio},
    };

    fn live_child() -> (std::process::Child, ProcessIdentity, ProcessHandle) {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let identity = match ProcessIdentity::capture(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("fake child identity could not be captured: {error:#}");
            }
        };
        let handle = match ProcessHandle::open(identity.clone()) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("fake child process handle could not be opened: {error:#}");
            }
        };
        (child, identity, handle)
    }

    #[test]
    fn target_verification_requires_the_exact_pinned_identity() {
        let (mut child, identity, handle) = live_child();
        verify_broker_target(&handle, &identity).unwrap();
        let mut changed = identity.clone();
        changed.start_ticks += 1;
        assert!(verify_broker_target(&handle, &changed).is_err());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn broker_execution_rejects_wrong_peer_before_opening_diagnostic_transport() {
        let (mut child, identity, _handle) = live_child();
        let request = SocketMarkBrokerRequest {
            version: super::super::privilege_broker::BROKER_REQUEST_VERSION,
            process: identity,
            expected_peer: "198.51.100.10:443".parse().unwrap(),
            transport: super::super::privilege_broker::BrokerSocketTransport::Tcp,
            expected_mark: 0x42,
            mark_mask: 0xff,
        };
        let peer = BrokerPeerCredentials {
            pid: std::process::id(),
            uid: unsafe { libc::getuid() }.saturating_add(1),
            gid: unsafe { libc::getgid() },
        };
        assert!(
            collect_authorized_socket_mark_response(&request, peer, Duration::from_secs(1))
                .is_err()
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn unix_stream_pair_is_available_for_future_bounded_response_transport_tests() {
        let (left, right) = UnixStream::pair().unwrap();
        drop(left);
        drop(right);
    }
}
