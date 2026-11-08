//! Command-line interface definitions and command dispatch.
//!
//! Keep argument parsing and presentation here. Business behavior belongs in services.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::{
    database::{AddNodeOutcome, NodeRecord, default_database_path},
    services::nodes,
};

/// Top-level proxyctl command line.
#[derive(Debug, Parser)]
#[command(
    name = "proxyctl",
    version,
    about = "A lightweight CLI for managing and benchmarking proxy nodes",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Add one proxy URL.
    Add {
        /// A VLESS, VMess, Trojan, Shadowsocks, or Hysteria2 URL.
        url: String,
    },
    /// Import proxy URLs from a text file.
    Import {
        /// Source file. It is read without being modified.
        file: PathBuf,
    },
    /// List stored proxy nodes.
    List {
        /// Include soft-deleted nodes.
        #[arg(long)]
        include_deleted: bool,
    },
    /// Show details for one node.
    Show {
        /// Node ID.
        id: u64,
    },
    /// Soft-delete one node.
    Remove {
        /// Node ID.
        id: u64,
    },
    /// Restore a soft-deleted node.
    Restore {
        /// Node ID.
        id: u64,
    },
}

/// Execute the selected command.
pub fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let Some(command) = cli.command else {
        println!("Proxyctl is ready. Use --help to see available commands.");
        return Ok(());
    };

    let database_path = default_database_path()?;
    match command {
        Command::Add { url } => match nodes::add_url(&database_path, &url)? {
            AddNodeOutcome::Added(id) => println!("Added node #{id}."),
            AddNodeOutcome::Duplicate(id) => println!("This URL is already stored as node #{id}."),
        },
        Command::Import { file } => {
            let summary = nodes::import_file(&database_path, &file)?;
            println!(
                "Import complete: {} added, {} duplicates, {} invalid.",
                summary.added, summary.duplicates, summary.invalid
            );
            for failure in summary.failures {
                eprintln!("Line {}: {}", failure.line_number, failure.reason);
            }
        }
        Command::List { include_deleted } => {
            let records = nodes::list_nodes(&database_path, include_deleted)?;
            print_node_list(&records);
        }
        Command::Show { id } => {
            let record = nodes::get_node(&database_path, id)?
                .ok_or_else(|| anyhow::anyhow!("node #{id} was not found"))?;
            print_node_details(&record);
        }
        Command::Remove { id } => {
            if nodes::remove_node(&database_path, id)? {
                println!("Node #{id} was soft-deleted. Use 'proxyctl restore {id}' to restore it.");
            } else {
                println!("Node #{id} was not found or is already deleted.");
            }
        }
        Command::Restore { id } => {
            if nodes::restore_node(&database_path, id)? {
                println!("Restored node #{id}.");
            } else {
                println!("Node #{id} was not found or is not deleted.");
            }
        }
    }

    Ok(())
}

fn print_node_list(records: &[NodeRecord]) {
    if records.is_empty() {
        println!("No proxy nodes found.");
        return;
    }

    println!(
        "{:>5}  {:<12}  {:<32}  {:>5}  {}",
        "ID", "PROTOCOL", "SERVER", "PORT", "NAME"
    );
    for record in records {
        println!(
            "{:>5}  {:<12}  {:<32}  {:>5}  {}",
            record.id,
            record.node.protocol,
            safe_field(&record.node.server, 32),
            record.node.port,
            record
                .node
                .name
                .as_deref()
                .map(|name| safe_field(name, 32))
                .unwrap_or_else(|| "-".to_owned())
        );
    }
}

fn print_node_details(record: &NodeRecord) {
    let node = &record.node;
    println!("ID: {}", record.id);
    println!("Protocol: {}", node.protocol);
    println!("Server: {}", safe_field(&node.server, 200));
    println!("Port: {}", node.port);
    println!(
        "Name: {}",
        node.name
            .as_deref()
            .map(|name| safe_field(name, 200))
            .unwrap_or_else(|| "-".to_owned())
    );
    println!(
        "Status: {}",
        if record.is_deleted() {
            "deleted"
        } else {
            "active"
        }
    );
    println!(
        "Identity: {}",
        if node.identity.is_some() {
            "[masked]"
        } else {
            "-"
        }
    );
    println!(
        "Secret: {}",
        if node.secret.is_some() {
            "[masked]"
        } else {
            "-"
        }
    );
    println!("Fingerprint: {}", node.fingerprint());

    if !node.options.is_empty() {
        let keys = node
            .options
            .keys()
            .map(|key| safe_field(key, 48))
            .collect::<Vec<_>>()
            .join(", ");
        println!("Options: {keys} (values hidden)");
    }
}

fn safe_field(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(max_chars)
        .collect()
}
