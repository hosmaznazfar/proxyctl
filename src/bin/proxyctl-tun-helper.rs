//! Dedicated, single-request Linux socket-mark diagnostic helper.
//!
//! Install this binary separately with only CAP_NET_ADMIN (never setuid/root).
//! It accepts no shell commands, paths to executables, or kernel mutation requests.
//! The caller owns the private runtime directory and the helper exits after one request.

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::{
        env,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
        time::Duration,
    };

    const MAX_RUNTIME_PATH: usize = 4096;
    const ACCEPT_TIMEOUT: Duration = Duration::from_secs(2);
    const DIAGNOSTIC_TIMEOUT_PER_DUMP: Duration = Duration::from_secs(2);
    const RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

    let mut arguments = env::args_os().skip(1);
    let flag = arguments.next().context("expected --socket PATH")?;
    ensure!(flag == "--socket", "only --socket PATH is accepted");
    let socket_path = PathBuf::from(arguments.next().context("missing broker socket path")?);
    ensure!(arguments.next().is_none(), "unexpected helper arguments");
    ensure!(
        socket_path.as_os_str().as_encoded_bytes().len() <= MAX_RUNTIME_PATH,
        "broker socket path exceeds the safety limit"
    );
    ensure!(socket_path.is_absolute(), "broker socket path must be absolute");

    // Do not permit a file-capability helper to be used as a general-purpose
    // privilege trampoline. No child process is ever spawned by this executable.
    let no_new_privileges = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    ensure!(
        no_new_privileges == 0,
        "cannot enable no_new_privs: {}",
        std::io::Error::last_os_error()
    );
    let dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    ensure!(
        dumpable == 0,
        "cannot disable helper process dumps: {}",
        std::io::Error::last_os_error()
    );

    let parent = socket_path.parent().context("socket path has no parent")?;
    let metadata = std::fs::symlink_metadata(parent)
        .context("cannot inspect caller runtime directory")?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0,
        "runtime directory must be a real caller-owned 0700-or-stricter directory"
    );

    let listener = proxyctl::tun::privilege_broker::bind_private_broker_listener(&socket_path)?;
    proxyctl::tun::broker_executor::serve_one_socket_mark_request(
        &listener,
        ACCEPT_TIMEOUT,
        DIAGNOSTIC_TIMEOUT_PER_DUMP,
        RESPONSE_TIMEOUT,
    )?;
    drop(listener);
    std::fs::remove_file(&socket_path).context("cannot remove helper-owned broker socket")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("proxyctl-tun-helper is supported only on Linux");
    std::process::exit(2);
}
