//! CLI-independent TUN recovery supervisor process.
//!
//! Intended to be launched by a supported service manager with the private Proxyctl runtime
//! directory as its sole argument. It resumes a persisted Prepared/Running/CleanupPending
//! generation and remains attached to the exact core pidfd until exit-triggered cleanup.
use anyhow::{Context, Result, ensure};
use std::{env, path::PathBuf, process};

use proxyctl::tun::{
    activation_orchestrator::ActivationOrchestrator,
    lifecycle_coordinator::LifecycleCoordinator,
    manifest_store::ManifestStore,
    mutation_helper_launcher::MutationHelper,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("proxyctl-tun-supervisor: {error:#}");
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = env::args_os();
    let _program = args.next();
    let runtime = args.next().map(PathBuf::from)
        .context("usage: proxyctl-tun-supervisor ABSOLUTE_PRIVATE_RUNTIME_DIRECTORY")?;
    ensure!(args.next().is_none(), "unexpected extra supervisor arguments");
    ensure!(runtime.is_absolute(), "supervisor runtime directory must be an absolute path");

    // ManifestStore validates ownership, directory permissions, and symlink boundaries.
    let store = ManifestStore::open(&runtime)
        .context("cannot open the private TUN lifecycle runtime directory")?;
    let coordinator = LifecycleCoordinator::new(store)
        .context("cannot initialize TUN lifecycle coordination")?;
    let helper = MutationHelper::ensure_started(&runtime)
        .context("cannot start or connect to the persistent TUN mutation broker")?;
    let supervisor = ActivationOrchestrator::new(&helper, &coordinator);
    supervisor.resume()
        .context("TUN recovery supervisor could not resume the persisted activation")?;
    Ok(())
}
