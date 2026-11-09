//! CLI definitions and dispatch. Application behavior belongs in services.
use crate::{
    cores::CoreId,
    database::{AddNodeOutcome, NodeRecord, default_database_path},
    services::nodes,
    updates::release::ReleaseChannel,
};
use clap::{ArgGroup, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "proxyctl",
    version,
    about = "A lightweight CLI for managing and benchmarking proxy nodes"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Add {
        url: String,
    },
    Import {
        file: PathBuf,
    },
    List {
        #[arg(long)]
        include_deleted: bool,
    },
    Show {
        id: u64,
    },
    Remove {
        id: u64,
    },
    Restore {
        id: u64,
    },
    /// Validate a stored node's generated config without starting a proxy core.
    Check {
        id: u64,
        #[arg(long, value_name = "CORE")]
        core: Option<String>,
    },
    /// Show managed core status and versions.
    Cores,
    /// Install all supported cores, or one selected core.
    Setup {
        #[arg(long, value_name = "CORE")]
        core: Option<String>,
    },
    /// Run direct TCP ping and real-ping/download/upload tests through managed proxy cores.
    #[command(group(ArgGroup::new("test_scope").args(["all_cores", "node"]).required(true).multiple(false)))]
    Test {
        /// Test every active node against all installed compatible managed cores.
        #[arg(long)]
        all_cores: bool,
        /// Test one stored node; requires --core.
        #[arg(long, requires = "core")]
        node: Option<u64>,
        /// Managed core to use with --node.
        #[arg(long, value_name = "CORE", requires = "node")]
        core: Option<String>,
        /// HTTPS URL used for real HTTP ping through the selected core.
        #[arg(long, default_value = "https://www.google.com/generate_204")]
        latency_url: String,
        /// HTTPS URL of a bounded download test object (default: CacheFly 10 MB).
        #[arg(long, default_value = "https://cachefly.cachefly.net/10mb.test")]
        download_url: String,
        /// HTTPS endpoint accepting a POST body for uploads.
        #[arg(long, default_value = "https://speed.cloudflare.com/__up")]
        upload_url: String,
        /// Maximum accepted download size per sample (safety limit; default 16 MiB).
        #[arg(
            long = "download-max-bytes",
            alias = "download-bytes",
            default_value_t = 16_777_216
        )]
        download_bytes: u64,
        /// Upload payload size for each sample.
        #[arg(long, default_value_t = 1_048_576)]
        upload_bytes: u64,
        /// Maximum duration of each HTTP measurement request, in seconds.
        #[arg(long, default_value_t = 15)]
        request_timeout_secs: u64,
        /// Maximum startup/readiness wait for a managed core, in seconds.
        #[arg(long, default_value_t = 10)]
        startup_timeout_secs: u64,
    },
    /// Check for and install proxyctl and managed-core updates.
    #[command(group(ArgGroup::new("update_target").args(["app", "cores", "core"]).multiple(false)))]
    Update {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        app: bool,
        #[arg(long)]
        cores: bool,
        #[arg(long, value_name = "CORE")]
        core: Option<String>,
        /// Include prereleases instead of selecting stable releases only.
        #[arg(long)]
        prerelease: bool,
    },
}

pub fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let Some(command) = cli.command else {
        println!("Proxyctl is ready. Use --help to see available commands.");
        return Ok(());
    };
    let command = match command {
        Command::Cores => {
            for status in crate::services::cores::inventory()? {
                match status.version {
                    Some(version) => println!("{}: installed ({version})", status.core),
                    None => println!("{}: not installed", status.core),
                }
            }
            return Ok(());
        }
        Command::Setup { core } => {
            crate::services::cores::setup(parse_core(core.as_deref())?)?;
            return Ok(());
        }
        Command::Update {
            check,
            app,
            cores,
            core,
            prerelease,
        } => {
            let selected = parse_core(core.as_deref())?;
            let channel = if prerelease {
                ReleaseChannel::Prerelease
            } else {
                ReleaseChannel::Stable
            };
            if app {
                crate::services::updates::update_application(check, channel)?;
            } else if cores {
                crate::services::cores::update_installed(check, None, channel)?;
            } else if let Some(core) = selected {
                crate::services::cores::update_installed(check, Some(core), channel)?;
            } else {
                let app_result = crate::services::updates::update_application(check, channel);
                let core_result = crate::services::cores::update_installed(check, None, channel);
                if let Err(error) = &app_result {
                    eprintln!("proxyctl: {error:#}");
                }
                if let Err(error) = &core_result {
                    eprintln!("managed cores: {error:#}");
                }
                if app_result.is_err() || core_result.is_err() {
                    anyhow::bail!("one or more update targets failed; see errors above");
                }
            }
            return Ok(());
        }
        other => other,
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
            print_node_list(&nodes::list_nodes(&database_path, include_deleted)?)
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
                println!("Restored node #{id}.")
            } else {
                println!("Node #{id} was not found or is not deleted.");
            }
        }
        Command::Check { id, core } => {
            crate::services::validation::check_node(
                &database_path,
                id,
                parse_core(core.as_deref())?,
            )?;
        }
        Command::Test {
            all_cores,
            node,
            core,
            latency_url,
            download_url,
            upload_url,
            download_bytes,
            upload_bytes,
            request_timeout_secs,
            startup_timeout_secs,
        } => {
            let request_timeout_ms = request_timeout_secs
                .checked_mul(1_000)
                .ok_or_else(|| anyhow::anyhow!("request timeout is too large"))?;
            let startup_timeout_ms = startup_timeout_secs
                .checked_mul(1_000)
                .ok_or_else(|| anyhow::anyhow!("startup timeout is too large"))?;
            let mut settings = crate::services::benchmark::default_settings();
            settings.latency_url = latency_url;
            settings.download_url = download_url;
            settings.upload_url = upload_url;
            settings.download_bytes = download_bytes;
            settings.upload_bytes = upload_bytes;
            settings.request_timeout_ms = request_timeout_ms;
            settings.startup_timeout_ms = startup_timeout_ms;
            crate::services::benchmark::run_benchmark(
                &database_path,
                crate::services::benchmark::BenchmarkOptions {
                    all_cores,
                    node_id: node,
                    core: parse_core(core.as_deref())?,
                    settings,
                },
            )?;
        }
        Command::Cores | Command::Setup { .. } | Command::Update { .. } => {
            unreachable!("management commands are dispatched before database access")
        }
    }
    Ok(())
}

fn parse_core(value: Option<&str>) -> anyhow::Result<Option<CoreId>> {
    value.map(str::parse).transpose()
}

fn print_node_list(records: &[NodeRecord]) {
    if records.is_empty() {
        println!("No proxy nodes found.");
        return;
    }
    println!(
        "{:>5}  {:<12}  {:<32}  {:>5}  NAME",
        "ID", "PROTOCOL", "SERVER", "PORT"
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn test_command_accepts_all_cores_scope() {
        let cli = Cli::try_parse_from(["proxyctl", "test", "--all-cores"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Test {
                all_cores: true,
                node: None,
                core: None,
                ..
            })
        ));
    }

    #[test]
    fn test_command_requires_node_and_core_together() {
        assert!(Cli::try_parse_from(["proxyctl", "test", "--node", "7"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "test", "--core", "xray"]).is_err());
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "test",
                "--all-cores",
                "--node",
                "7",
                "--core",
                "xray"
            ])
            .is_err()
        );
    }

    #[test]
    fn test_command_accepts_one_node_and_core_with_custom_payloads() {
        let cli = Cli::try_parse_from([
            "proxyctl",
            "test",
            "--node",
            "7",
            "--core",
            "sing-box",
            "--download-bytes",
            "2097152",
            "--upload-bytes",
            "1048576",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Test {
                all_cores: false,
                node: Some(7),
                core: Some(ref core),
                download_bytes: 2_097_152,
                upload_bytes: 1_048_576,
                ..
            }) if core == "sing-box"
        ));
    }
}
