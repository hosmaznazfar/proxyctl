//! Dedicated, single-request Linux socket-mark diagnostic helper.
//!
//! Install this binary separately with only CAP_NET_ADMIN (never setuid/root).
//! It accepts no shell commands, paths to executables, or kernel mutation requests.
//! The caller owns the private runtime directory and the helper exits after one request.

#[cfg(target_os = "linux")]
struct OwnedBrokerSocket {
    listener: std::os::unix::net::UnixListener,
    path: std::path::PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}

#[cfg(target_os = "linux")]
impl OwnedBrokerSocket {
    fn bind(path: std::path::PathBuf) -> anyhow::Result<Self> {
        use anyhow::Context;
        use std::os::unix::fs::MetadataExt;

        let listener = proxyctl::tun::privilege_broker::bind_private_broker_listener(&path)?;
        let metadata = std::fs::symlink_metadata(&path)
            .context("cannot capture private broker socket identity")?;
        Ok(Self {
            listener,
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
        })
    }
}

#[cfg(target_os = "linux")]
impl Drop for OwnedBrokerSocket {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        // Remove only the exact socket inode this helper created. If another actor
        // replaced the path, leave that object untouched.
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && metadata.uid() == self.uid
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

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
    let flag = arguments.next().context("expected --socket PATH or --mutation-socket PATH")?;
    ensure!(flag == "--socket" || flag == "--mutation-socket",
        "only --socket PATH or --mutation-socket PATH is accepted");
    let mutation_mode = flag == "--mutation-socket";
    let socket_path = PathBuf::from(arguments.next().context("missing broker socket path")?);
    ensure!(arguments.next().is_none(), "unexpected helper arguments");
    ensure!(
        socket_path.as_os_str().as_encoded_bytes().len() <= MAX_RUNTIME_PATH,
        "broker socket path exceeds the safety limit"
    );
    ensure!(
        socket_path.is_absolute(),
        "broker socket path must be absolute"
    );

    // Do not permit a file-capability helper to be used as a general-purpose
    // privilege trampoline. No child process is ever spawned by this executable.
    let status = std::fs::read_to_string("/proc/self/status")
        .context("cannot inspect helper capability state")?;
    let capability = 1u64 << 12; // CAP_NET_ADMIN
    let mut effective = None;
    let mut permitted = None;
    let mut inheritable = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("CapEff:") {
            effective = Some(u64::from_str_radix(value.trim(), 16)?);
        } else if let Some(value) = line.strip_prefix("CapPrm:") {
            permitted = Some(u64::from_str_radix(value.trim(), 16)?);
        } else if let Some(value) = line.strip_prefix("CapInh:") {
            inheritable = Some(u64::from_str_radix(value.trim(), 16)?);
        }
    }
    ensure!(
        effective == Some(capability) && permitted == Some(capability) && inheritable == Some(0),
        "helper must have exactly CAP_NET_ADMIN effective/permitted and no inheritable capabilities"
    );
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
    let metadata =
        std::fs::symlink_metadata(parent).context("cannot inspect caller runtime directory")?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0,
        "runtime directory must be a real caller-owned 0700-or-stricter directory"
    );

    let socket = OwnedBrokerSocket::bind(socket_path)?;
    if mutation_mode {
        proxyctl::tun::mutation_broker::serve(&socket.listener, parent)?;
    } else {
        proxyctl::tun::broker_executor::serve_one_socket_mark_request(
            &socket.listener,
            ACCEPT_TIMEOUT,
            DIAGNOSTIC_TIMEOUT_PER_DUMP,
            RESPONSE_TIMEOUT,
        )?;
    }
    drop(socket);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("proxyctl-tun-helper is supported only on Linux");
    std::process::exit(2);
}
