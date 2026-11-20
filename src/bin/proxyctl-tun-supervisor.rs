//! CLI-independent TUN recovery supervisor process.
//!
//! Intended to be launched by a supported service manager with the private Proxyctl runtime
//! directory as its sole argument. It resumes a persisted Prepared/Running/CleanupPending
//! generation and remains attached to the exact core pidfd until exit-triggered cleanup.
#[cfg(target_os = "linux")]
use anyhow::{Context, Result, ensure};
#[cfg(target_os = "linux")]
use std::{env, path::PathBuf, process};

#[cfg(target_os = "linux")]
use proxyctl::tun::{
    activation_orchestrator::ActivationOrchestrator,
    lifecycle_coordinator::LifecycleCoordinator,
    manifest_store::ManifestStore,
    mutation_helper_launcher::MutationHelper,
};

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("proxyctl-tun-supervisor: {error:#}");
        process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<()> {
    let mut args = env::args_os();
    let _program = args.next();
    let runtime = args.next().map(PathBuf::from)
        .context("usage: proxyctl-tun-supervisor ABSOLUTE_PRIVATE_RUNTIME_DIRECTORY ACTIVATION_UUID GENERATION")?;
    let activation_id = args.next().context("missing activation UUID")?
        .into_string().map_err(|_| anyhow::anyhow!("activation UUID must be UTF-8"))?;
    let generation = args.next().context("missing activation generation")?
        .into_string().map_err(|_| anyhow::anyhow!("activation generation must be UTF-8"))?
        .parse::<u64>().context("activation generation must be a positive integer")?;
    ensure!(args.next().is_none(), "unexpected extra supervisor arguments");
    let expected = proxyctl::tun::recovery::SupervisorIdentity::for_activation(
        &activation_id,
        runtime.join("tun-manifest.json").to_string_lossy().into_owned(),
        generation,
    )?;
    ensure!(runtime.is_absolute(), "supervisor runtime directory must be an absolute path");

    // ManifestStore validates ownership, directory permissions, and symlink boundaries.
    let store = ManifestStore::open(&runtime)
        .context("cannot open the private TUN lifecycle runtime directory")?;
    let coordinator = LifecycleCoordinator::new(store)
        .context("cannot initialize TUN lifecycle coordination")?;
    let helper = MutationHelper::ensure_started(&runtime)
        .context("cannot start or connect to the persistent TUN mutation broker")?;
    let current = coordinator.load_current()?.context("no TUN activation manifest exists")?;
    ensure!(
        current.token.activation_id() == expected.activation_id
            && current.token.generation() == expected.generation,
        "supervisor service identity does not match the persisted activation generation"
    );
    let supervisor = ActivationOrchestrator::new(&helper, &coordinator);
    supervisor.resume_generation(&expected.activation_id, expected.generation)
        .context("TUN recovery supervisor could not resume the requested activation generation")?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("proxyctl-tun-supervisor is supported only on Linux");
    std::process::exit(1);
}
