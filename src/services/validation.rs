//! Application use case for checking generated configurations with installed cores.
use std::path::Path;

use anyhow::Context;

use crate::{
    cores::{CoreId, adapters, core_binary_path},
    database::NodeDatabase,
};

/// Validate one stored node against a selected core, or every installed core when omitted.
/// Unsupported combinations are reported but are not treated as validation failures.
pub fn check_node(
    database_path: &Path,
    node_id: u64,
    selected_core: Option<CoreId>,
) -> anyhow::Result<()> {
    check_nodes(database_path, &[node_id], selected_core)
}

/// Validate every selected node. Continue after per-node validation failures and summarize them.
pub fn check_nodes(
    database_path: &Path,
    node_ids: &[u64],
    selected_core: Option<CoreId>,
) -> anyhow::Result<()> {
    anyhow::ensure!(!node_ids.is_empty(), "select at least one node to check");
    let mut failures = Vec::new();
    for node_id in node_ids {
        if let Err(error) = check_one_node(database_path, *node_id, selected_core) {
            eprintln!("Node #{node_id}: {error:#}");
            failures.push(*node_id);
        }
    }
    if !failures.is_empty() {
        anyhow::bail!(
            "configuration checks failed for node(s): {}",
            failures
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

fn check_one_node(
    database_path: &Path,
    node_id: u64,
    selected_core: Option<CoreId>,
) -> anyhow::Result<()> {
    let database = NodeDatabase::open(database_path)?;
    let record = database
        .get_node(node_id)?
        .with_context(|| format!("node #{node_id} was not found"))?;
    anyhow::ensure!(
        !record.is_deleted(),
        "node #{node_id} is deleted; restore it before checking"
    );
    let node = record.node;
    drop(database);
    println!("Node #{node_id}:");

    let cores = selected_core.map_or_else(|| CoreId::ALL.to_vec(), |core| vec![core]);
    let mut attempted = 0usize;
    let mut failures = Vec::new();

    for core in cores {
        let adapter = adapters::adapter(core);
        let compatibility = adapter.compatibility(&node);
        if !compatibility.is_supported() {
            println!(
                "{core}: unsupported ({})",
                compatibility
                    .reason
                    .as_deref()
                    .unwrap_or("configuration is incompatible")
            );
            continue;
        }

        let executable = core_binary_path(core)?;
        if !executable.is_file() {
            println!("{core}: compatible, but not installed by proxyctl.");
            continue;
        }

        attempted += 1;
        match adapters::validation::validate_node_config(core, &node, &executable) {
            Ok(()) => println!("{core}: configuration valid."),
            Err(error) => {
                eprintln!("{core}: validation failed: {error:#}");
                failures.push(core);
            }
        }
    }

    if attempted == 0 {
        anyhow::bail!("no installed compatible core was available to validate node #{node_id}");
    }
    if !failures.is_empty() {
        anyhow::bail!(
            "configuration validation failed for: {}",
            failures
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}
