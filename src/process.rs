//! Bounded subprocess execution shared by validators and installers.
use std::{
    io::{Read, Seek, SeekFrom},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;

const MAX_CAPTURED_OUTPUT: u64 = 64 * 1024;

/// Run a child with file-backed output capture, a hard deadline, and bounded returned output.
pub(crate) fn run_bounded_command(
    mut command: Command,
    description: &str,
    timeout: Duration,
) -> anyhow::Result<Output> {
    anyhow::ensure!(!timeout.is_zero(), "process timeout must be non-zero");
    let mut stdout = tempfile::tempfile().context("could not create stdout spool")?;
    let mut stderr = tempfile::tempfile().context("could not create stderr spool")?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.try_clone()?))
        .stderr(Stdio::from(stderr.try_clone()?));
    let mut child = command
        .spawn()
        .with_context(|| format!("{description}: could not start process"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("{description}: process exceeded its {}-second deadline and was terminated", timeout.as_secs());
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).with_context(|| format!("{description}: could not inspect process"));
            }
        }
    };
    let stdout = read_bounded(&mut stdout)?;
    let stderr = read_bounded(&mut stderr)?;
    Ok(Output { status, stdout, stderr })
}

fn read_bounded(file: &mut std::fs::File) -> anyhow::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut output = Vec::new();
    file.take(MAX_CAPTURED_OUTPUT).read_to_end(&mut output)?;
    Ok(output)
}
