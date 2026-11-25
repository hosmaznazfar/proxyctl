//! Direct, shell-free privilege handoff for the internal TUN supervisor.
//!
//! This transports a bounded generated request only. The supervisor still fails closed
//! after validation until the root-owned lifecycle and recovery backend is implemented.
use anyhow::{Context, Result, ensure};
use std::{
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

use crate::tun::launch_spec::LaunchSpec;

fn find_sudo() -> Result<PathBuf> {
    let path = std::env::var_os("PATH").context("PATH is unavailable; cannot locate sudo")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("sudo");
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let metadata = candidate.metadata()?;
                ensure!(
                    metadata.permissions().mode() & 0o111 != 0,
                    "sudo candidate is not executable"
                );
            }
            return std::fs::canonicalize(candidate).context("cannot resolve sudo executable");
        }
    }
    anyhow::bail!("sudo is required for TUN mode but was not found on PATH")
}

/// Request root validation through sudo, with config delivered exclusively on stdin.
///
/// No shell is involved; sudo's password prompt is handled via its terminal, not stdin.
pub fn validate_supervisor_handoff(spec: &LaunchSpec) -> Result<()> {
    let encoded = spec
        .encode_bounded()
        .context("cannot encode bounded TUN request")?;
    let sudo = find_sudo()?;
    let executable =
        std::env::current_exe().context("cannot resolve current Proxyctl executable")?;
    let mut child = Command::new(sudo)
        .arg("--")
        .arg(executable)
        .arg("__tun-supervisor")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("cannot launch privileged Proxyctl supervisor via sudo")?;
    let stdin = child
        .stdin
        .take()
        .context("sudo request stdin unavailable")?;
    let mut stdin = stdin;
    stdin
        .write_all(&encoded)
        .context("cannot write TUN launch request to supervisor")?;
    drop(stdin);
    let status = child
        .wait()
        .context("cannot wait for supervisor validation")?;
    ensure!(
        status.success(),
        "privileged TUN supervisor validation exited with {status}"
    );
    Ok(())
}
