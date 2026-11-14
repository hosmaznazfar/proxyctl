//! CLI definitions and dispatch. Application behavior belongs in services.
use crate::{
    cores::CoreId,
    database::{AddNodeOutcome, NodeRecord, default_database_path},
    services::node_selection::{self, NodeSelection},
    services::{
        nodes,
        pruning::{self, PruneDecision, PruneOptions, PruneScope},
        reporting::{self, ReportMode, ReportOptions},
        sorting::{self, SortMetric},
    },
    updates::release::ReleaseChannel,
};
use clap::{ArgGroup, Parser, Subcommand};
use std::{collections::HashMap, path::PathBuf};
use tabled::{builder::Builder, settings::Style};

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
enum TunCommand {
    /// Show interfaces, default routes, DNS, and firewall state (read-only).
    Status,
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Set the persistent shared HTTP/SOCKS5 listener port.
    Set { key: String, value: u16 },
    /// Restore a setting to its built-in default.
    Reset { key: String },
    /// Configure table profiles used by show and report.
    Display {
        #[command(subcommand)]
        action: Option<DisplayAction>,
    },
}

#[derive(Debug, Subcommand)]
enum DisplayAction {
    Profile { name: String },
    AddField { profile: String, field: String },
    RemoveField { profile: String, field: String },
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
        /// Filter by protocol: vless, vmess, trojan, shadowsocks, or hysteria2.
        #[arg(
            long,
            value_name = "PROTOCOL",
            value_parser = ["vless", "vmess", "trojan", "shadowsocks", "ss", "hysteria2", "hy2"]
        )]
        protocol: Option<String>,
        /// Case-insensitive substring filter over server address and display name.
        #[arg(long, value_name = "TEXT")]
        search: Option<String>,
        /// Sort by real ping, direct TCP ping, download, or upload.
        #[arg(long, value_name = "METRIC", value_parser = ["ping", "tcp-ping", "download", "upload"])]
        sort: Option<String>,
        /// Restrict benchmark sorting to one managed core; requires --sort.
        #[arg(long, value_name = "CORE", requires = "sort")]
        core: Option<String>,
    },
    Show {
        #[arg(required = true, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        nodes: Vec<String>,
        /// Show connection/configuration details instead of benchmark results.
        #[arg(long)]
        details: bool,
    },
    Remove {
        #[arg(required = true, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        nodes: Vec<String>,
        #[arg(long, short = 'y')]
        yes: bool,
    },
    Restore {
        #[arg(required = true, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        nodes: Vec<String>,
    },
    /// Validate one or more stored nodes' generated configs without starting a proxy core.
    Check {
        #[arg(required = true, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        nodes: Vec<String>,
        #[arg(long, value_name = "CORE")]
        core: Option<String>,
    },
    /// Show managed core status and versions.
    Cores,
    /// Activate one node using one Proxyctl-managed core (loopback only by default).
    Use {
        #[arg(value_name = "NUMBER")]
        id: u64,
        #[arg(long, value_name = "CORE", required = true)]
        core: String,
        /// Override the persistent shared HTTP/SOCKS5 listener port for this activation only.
        #[arg(long, value_name = "PORT")]
        port: Option<u16>,
        /// TUN activation is temporarily disabled pending safe route ownership and crash recovery.
        #[arg(long)]
        tun: bool,
    },
    /// Show or change persistent listener settings.
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// Stop only the exact process tracked by Proxyctl.
    Stop,
    /// Install all supported cores, or one selected core.
    Setup {
        #[arg(long, value_name = "CORE")]
        core: Option<String>,
    },
    /// Run direct TCP ping and real-ping/download/upload tests through managed proxy cores.
    #[command(group(ArgGroup::new("test_scope").args(["all_cores", "core"]).required(true).multiple(false)))]
    #[command(group(ArgGroup::new("metric_selection").args(["latency_only", "download_only", "upload_only"]).multiple(false)))]
    Test {
        /// Test all active nodes, or only --node, against all installed compatible managed cores.
        #[arg(long)]
        all_cores: bool,
        /// Restrict testing to selected stored nodes; omit to test all active nodes.
        #[arg(long, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        node: Vec<String>,
        /// Test selected --node values with one managed core (mutually exclusive with --all-cores).
        #[arg(long, value_name = "CORE", requires = "node")]
        core: Option<String>,
        /// Run only HTTP latency through the selected core.
        #[arg(long, group = "metric_selection")]
        latency_only: bool,
        /// Run only download throughput measurements.
        #[arg(long, group = "metric_selection")]
        download_only: bool,
        /// Run only upload throughput measurements.
        #[arg(long, group = "metric_selection")]
        upload_only: bool,
        /// HTTPS URL used for real HTTP ping through the selected core.
        #[arg(long, default_value = "https://www.google.com/generate_204")]
        latency_url: String,
        /// HTTPS URL of a download test object (only the first 2 MiB are measured by default).
        #[arg(long, default_value = "https://cachefly.cachefly.net/10mb.test")]
        download_url: String,
        /// HTTPS endpoint accepting a POST body for uploads.
        #[arg(long, default_value = "https://speed.cloudflare.com/__up")]
        upload_url: String,
        /// Number of bytes to sample per download (default 2 MiB; larger responses are cut short).
        #[arg(
            long = "download-max-bytes",
            alias = "download-bytes",
            default_value_t = 2_097_152
        )]
        download_bytes: u64,
        /// Upload payload size for each sample (default 256 KiB).
        #[arg(long, default_value_t = 262_144)]
        upload_bytes: u64,
        /// Maximum duration of each HTTP measurement request, in seconds.
        #[arg(long, default_value_t = 15)]
        request_timeout_secs: u64,
        /// Maximum startup/readiness wait for a managed core, in seconds.
        #[arg(long, default_value_t = 10)]
        startup_timeout_secs: u64,
    },
    /// Show benchmark results, per-node history, or per-core comparisons.
    #[command(group(ArgGroup::new("report_view").args(["history", "compare"]).multiple(false)))]
    Report {
        /// Restrict the report to selected stored nodes.
        #[arg(long, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        node: Vec<String>,
        /// Show every benchmark run, newest first.
        #[arg(long)]
        history: bool,
        /// Compare the latest completed result for each core independently.
        #[arg(long)]
        compare: bool,
        /// Restrict --compare to one managed core.
        #[arg(long, value_name = "CORE", requires = "compare")]
        core: Option<String>,
        /// Show full core build/version metadata instead of concise versions.
        #[arg(long)]
        verbose: bool,
    },
    /// Soft-delete nodes proven unreachable through every compatible core.
    #[command(group(ArgGroup::new("prune_scope").args(["unavailable_all", "unavailable"]).required(true).multiple(false)))]
    Prune {
        /// Evaluate all installed cores that currently support each node.
        #[arg(long)]
        unavailable_all: bool,
        /// Evaluate one selected core; requires --core.
        #[arg(long, requires = "core")]
        unavailable: bool,
        /// Managed core used with --unavailable.
        #[arg(long, value_name = "CORE", requires = "unavailable")]
        core: Option<String>,
        /// Preview only (the default); never changes node state.
        #[arg(long, conflicts_with = "apply")]
        dry_run: bool,
        /// Apply eligible soft-deletions.
        #[arg(long, conflicts_with = "dry_run")]
        apply: bool,
    },
    /// Inspect Linux networking state without changing it.
    Tun {
        #[command(subcommand)]
        command: TunCommand,
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
        Command::Tun {
            command: TunCommand::Status,
        } => {
            crate::tun::inspect()?.print();
            return Ok(());
        }
        Command::Cores => {
            for status in crate::services::cores::inventory()? {
                match status.version {
                    Some(version) => println!("{}: installed ({version})", status.core),
                    None => println!("{}: not installed", status.core),
                }
            }
            return Ok(());
        }
        Command::Use {
            id,
            core,
            tun,
            port,
        } => {
            let core = parse_core(Some(&core))?
                .ok_or_else(|| anyhow::anyhow!("--core is required for activation"))?;
            let database_path = default_database_path()?;
            let selected = nodes::resolve_node_selection(
                &database_path,
                &NodeSelection::Ids(vec![id]),
                false,
            )?;
            let stable_id = *selected
                .first()
                .ok_or_else(|| anyhow::anyhow!("node number {id} was not found"))?;
            crate::services::activation::activate(stable_id, core, tun, port)?;
            return Ok(());
        }
        Command::Config { action } => {
            use crate::services::listener_config as settings;
            match action {
                None => println!(
                    "Shared HTTP/SOCKS5 listen port: 127.0.0.1:{}",
                    settings::listen_port()?
                ),
                Some(ConfigAction::Set { key, value }) => {
                    anyhow::ensure!(
                        key == "listen-port",
                        "unknown config key '{key}'; expected 'listen-port'"
                    );
                    settings::set_listen_port(value)?;
                    println!("Saved shared HTTP/SOCKS5 listen port: 127.0.0.1:{value}");
                }
                Some(ConfigAction::Reset { key }) => {
                    anyhow::ensure!(
                        key == "listen-port",
                        "unknown config key '{key}'; expected 'listen-port'"
                    );
                    settings::reset_listen_port()?;
                    println!(
                        "Restored default shared HTTP/SOCKS5 listen port: 127.0.0.1:{}",
                        settings::DEFAULT_LISTEN_PORT
                    );
                }
                Some(ConfigAction::Display { action }) => {
                    use crate::services::display_config as display;
                    match action {
                        None => print_display_config(&display::load()?),
                        Some(DisplayAction::Profile { name }) => {
                            let profile = name.parse::<display::DisplayProfile>()?;
                            let mut config = display::load()?;
                            config.active_profile = profile;
                            display::save(&config)?;
                            println!("Active display profile: {profile}");
                        }
                        Some(DisplayAction::AddField { profile, field }) => {
                            let profile = profile.parse::<display::DisplayProfile>()?;
                            let field = field.parse::<display::DisplayField>()?;
                            let mut config = display::load()?;
                            display::add_field(&mut config, profile, field)?;
                            display::save(&config)?;
                            println!("Added '{field}' to the {profile} profile.");
                        }
                        Some(DisplayAction::RemoveField { profile, field }) => {
                            let profile = profile.parse::<display::DisplayProfile>()?;
                            let field = field.parse::<display::DisplayField>()?;
                            let mut config = display::load()?;
                            display::remove_field(&mut config, profile, field)?;
                            display::save(&config)?;
                            println!("Removed '{field}' from the {profile} profile.");
                        }
                    }
                }
            }
            return Ok(());
        }
        Command::Stop => {
            crate::services::activation::stop()?;
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
            AddNodeOutcome::Added(id) => {
                let number = nodes::active_display_number(&database_path, id)?
                    .ok_or_else(|| anyhow::anyhow!("new node was not visible after insertion"))?;
                println!("Added node #{number}.");
            }
            AddNodeOutcome::Duplicate(id) => {
                if let Some(number) = nodes::active_display_number(&database_path, id)? {
                    println!("This URL is already stored as node #{number}.");
                } else {
                    let deleted_number = deleted_display_numbers(&database_path)?
                        .get(&id)
                        .copied()
                        .unwrap_or_default();
                    println!(
                        "This URL is already stored as deleted node D{deleted_number}; use 'restore {deleted_number}'."
                    );
                }
            }
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
        Command::List {
            include_deleted,
            protocol,
            search,
            sort,
            core,
        } => {
            let mut records = nodes::list_nodes(&database_path, include_deleted)?;
            let display_numbers = active_display_numbers(&database_path)?;
            let deleted_display_numbers = deleted_display_numbers(&database_path)?;
            if let Some(protocol) = protocol {
                let protocol = crate::domain::Protocol::from_scheme(&protocol)
                    .ok_or_else(|| anyhow::anyhow!("unsupported protocol filter '{protocol}'"))?;
                records.retain(|record| record.node.protocol == protocol);
            }
            if let Some(search) = search {
                let needle = search.to_lowercase();
                records.retain(|record| {
                    record.node.server.to_lowercase().contains(&needle)
                        || record
                            .node
                            .name
                            .as_deref()
                            .is_some_and(|name| name.to_lowercase().contains(&needle))
                });
            }
            if let Some(metric) = sort {
                let metric: SortMetric = metric.parse()?;
                let core = parse_core(core.as_deref())?;
                if metric == SortMetric::TcpPing && core.is_some() {
                    anyhow::bail!(
                        "--core cannot be used with --sort tcp-ping because TCP ping is measured directly"
                    );
                }
                let ranked = sorting::sort_nodes(&database_path, records, metric, core)?;
                print_sorted_node_list(&ranked, metric, &display_numbers, &deleted_display_numbers);
            } else {
                print_node_list(&records, &display_numbers, &deleted_display_numbers);
            }
        }
        Command::Show {
            nodes: selectors,
            details,
        } => {
            let selection = node_selection::parse_node_selection(&selectors)?;
            let ids = nodes::resolve_node_selection(&database_path, &selection, false)?;
            if ids.is_empty() {
                println!("No matching nodes.");
            } else if details {
                for id in ids {
                    match nodes::get_node(&database_path, id)? {
                        Some(record) => {
                            let number = nodes::active_display_number(&database_path, id)?
                                .unwrap_or(id as usize);
                            print_node_details(&record, number);
                        }
                        None => println!("Node #{id}: not found."),
                    }
                }
            } else {
                let config = crate::services::display_config::load()?;
                let display_numbers = active_display_numbers(&database_path)?;
                let mut reports = Vec::new();
                for id in ids {
                    reports.push(reporting::build_report(
                        &database_path,
                        ReportOptions {
                            mode: ReportMode::Latest,
                            node_id: Some(id),
                            core: None,
                        },
                    )?);
                }
                print_node_results(&reports, &config, &display_numbers);
            }
        }
        Command::Remove {
            nodes: selectors,
            yes,
        } => {
            let selection = node_selection::parse_node_selection(&selectors)?;
            let ids = nodes::resolve_node_selection(&database_path, &selection, false)?;
            if matches!(selection, NodeSelection::All) && !yes && !confirm_remove_all()? {
                println!("Removal cancelled; no nodes changed.");
                return Ok(());
            }
            let summary = nodes::remove_nodes(&database_path, &ids)?;
            print_batch_summary("Removed", &summary, "already deleted");
        }
        Command::Restore { nodes: selectors } => {
            let selection = node_selection::parse_node_selection(&selectors)?;
            let ids = nodes::resolve_node_selection(&database_path, &selection, true)?;
            let summary = nodes::restore_nodes(&database_path, &ids)?;
            print_batch_summary("Restored", &summary, "already active");
        }
        Command::Check {
            nodes: selectors,
            core,
        } => {
            let selection = node_selection::parse_node_selection(&selectors)?;
            let ids = nodes::resolve_node_selection(&database_path, &selection, false)?;
            crate::services::validation::check_nodes(
                &database_path,
                &ids,
                parse_core(core.as_deref())?,
            )?;
        }
        Command::Report {
            node,
            history,
            compare,
            core,
            verbose,
        } => {
            let mode = if compare {
                ReportMode::Compare
            } else if history {
                ReportMode::History
            } else {
                ReportMode::Latest
            };
            let core = parse_core(core.as_deref())?;
            let display_config = crate::services::display_config::load()?;
            let display_numbers = active_display_numbers(&database_path)?;
            if node.is_empty() {
                let report = reporting::build_report(
                    &database_path,
                    ReportOptions {
                        mode,
                        node_id: None,
                        core,
                    },
                )?;
                print_benchmark_report(&report, &display_config, verbose, &display_numbers);
            } else {
                let mut combined = reporting::BenchmarkReport {
                    mode,
                    nodes: Vec::new(),
                    comparisons: Vec::new(),
                };
                for id in selected_ids(&database_path, &node)? {
                    let report = reporting::build_report(
                        &database_path,
                        ReportOptions {
                            mode,
                            node_id: Some(id),
                            core,
                        },
                    )?;
                    combined.nodes.extend(report.nodes);
                    combined.comparisons.extend(report.comparisons);
                }
                print_benchmark_report(&combined, &display_config, verbose, &display_numbers);
            }
        }
        Command::Prune {
            unavailable_all,
            core,
            apply,
            ..
        } => {
            let scope = if unavailable_all {
                PruneScope::AllCompatible
            } else {
                PruneScope::Core(
                    parse_core(core.as_deref())?
                        .ok_or_else(|| anyhow::anyhow!("--unavailable requires --core"))?,
                )
            };
            let display_numbers = active_display_numbers(&database_path)?;
            let report = pruning::prune_nodes(&database_path, PruneOptions { scope, apply })?;
            if report.results.is_empty() {
                println!("No active nodes to evaluate.");
            }
            for result in &report.results {
                let label = match result.decision {
                    PruneDecision::Candidate if result.deleted => "deleted",
                    PruneDecision::Candidate => "would prune",
                    PruneDecision::Reachable => "keep (reachable)",
                    PruneDecision::InsufficientEvidence => "keep (insufficient evidence)",
                    PruneDecision::NoCompatibleCore => "keep (no compatible core)",
                };
                println!(
                    "Node #{}: {label} — {}",
                    display_numbers
                        .get(&result.node.id)
                        .copied()
                        .unwrap_or(result.node.id as usize),
                    safe_field(&result.detail, 200)
                );
            }
            let candidates = report
                .results
                .iter()
                .filter(|result| result.decision == PruneDecision::Candidate)
                .count();
            if apply {
                println!("Pruning complete: {candidates} node(s) soft-deleted.");
            } else {
                println!(
                    "Dry run: {candidates} node(s) eligible; no changes made. Use --apply to soft-delete."
                );
            }
        }
        Command::Test {
            all_cores,
            node,
            core,
            latency_url,
            download_url,
            upload_url,
            latency_only,
            download_only,
            upload_only,
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
            let metric_selection = if latency_only {
                crate::services::benchmark::BenchmarkMetricSelection::Latency
            } else if download_only {
                crate::services::benchmark::BenchmarkMetricSelection::Download
            } else if upload_only {
                crate::services::benchmark::BenchmarkMetricSelection::Upload
            } else {
                crate::services::benchmark::BenchmarkMetricSelection::All
            };
            let selected = if node.is_empty() {
                Vec::new()
            } else {
                selected_ids(&database_path, &node)?
            };
            if selected.is_empty() {
                crate::services::benchmark::run_benchmark(
                    &database_path,
                    crate::services::benchmark::BenchmarkOptions {
                        all_cores,
                        node_id: None,
                        core: parse_core(core.as_deref())?,
                        settings,
                        metric_selection,
                    },
                )?;
            } else {
                for id in selected {
                    crate::services::benchmark::run_benchmark(
                        &database_path,
                        crate::services::benchmark::BenchmarkOptions {
                            all_cores,
                            node_id: Some(id),
                            core: parse_core(core.as_deref())?,
                            settings: settings.clone(),
                            metric_selection,
                        },
                    )?;
                }
            }
        }
        Command::Cores
        | Command::Setup { .. }
        | Command::Update { .. }
        | Command::Use { .. }
        | Command::Config { .. }
        | Command::Stop
        | Command::Tun { .. } => {
            unreachable!("management commands are dispatched before database access")
        }
    }
    Ok(())
}

fn confirm_remove_all() -> anyhow::Result<bool> {
    use std::io::{self, IsTerminal, Write};

    if !io::stdin().is_terminal() {
        anyhow::bail!(
            "'remove all' requires an interactive terminal; use --yes to confirm explicitly"
        );
    }
    print!("Remove every active node? Reversible with 'proxyctl restore all'. [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn print_batch_summary(action: &str, summary: &nodes::BatchNodeSummary, unchanged: &str) {
    println!(
        "{action}: {} node(s); {} not found; {} {unchanged}.",
        summary.changed.len(),
        summary.missing.len(),
        summary.unchanged.len()
    );
    if !summary.missing.is_empty() {
        println!(
            "Not found: {}",
            summary
                .missing
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !summary.unchanged.is_empty() {
        println!(
            "Unchanged: {}",
            summary
                .unchanged
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

fn selected_ids(path: &std::path::Path, selectors: &[String]) -> anyhow::Result<Vec<u64>> {
    let selection = node_selection::parse_node_selection(selectors)?;
    let ids = nodes::resolve_node_selection(path, &selection, false)?;
    for id in &ids {
        let record = nodes::get_node(path, *id)?
            .ok_or_else(|| anyhow::anyhow!("node #{id} was not found"))?;
        anyhow::ensure!(
            !record.is_deleted(),
            "node #{id} is deleted; restore it before using this selection"
        );
    }
    Ok(ids)
}
fn print_display_config(config: &crate::services::display_config::DisplayConfig) {
    use crate::services::display_config::DisplayProfile;
    println!("Active profile: {}", config.active_profile);
    for profile in [
        DisplayProfile::Compact,
        DisplayProfile::Normal,
        DisplayProfile::Full,
    ] {
        let fields = config.profiles.get(&profile).cloned().unwrap_or_default();
        println!(
            "{profile}: {}",
            fields
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!(
        "Available fields: node, name, server, port, protocol, core, version, latency, tcp-ping, download, upload, status, samples, failures, run, tested"
    );
    println!("Add:    proxyctl config display add-field <compact|normal|full> <field>");
    println!("Remove: proxyctl config display remove-field <compact|normal|full> <field>");
}

fn print_node_results(
    reports: &[reporting::BenchmarkReport],
    config: &crate::services::display_config::DisplayConfig,
    display_numbers: &HashMap<u64, usize>,
) {
    use crate::services::display_config::DisplayField as F;
    let fields = config.fields();
    let mut builder = Builder::default();
    builder.push_record(fields.iter().map(ToString::to_string).collect::<Vec<_>>());
    let mut found = false;
    for report in reports {
        for node in &report.nodes {
            let number = display_numbers
                .get(&node.node.id)
                .copied()
                .unwrap_or(node.node.id as usize)
                .to_string();
            if node.runs.is_empty() {
                found = true;
                builder.push_record(
                    fields
                        .iter()
                        .map(|field| match field {
                            F::Node => number.clone(),
                            F::Name => node.node.node.name.clone().unwrap_or_else(|| "-".into()),
                            F::Server => safe_field(&node.node.node.server, 48),
                            F::Port => node.node.node.port.to_string(),
                            F::Protocol => node.node.node.protocol.to_string(),
                            F::Core | F::Version => "-".into(),
                            F::Latency | F::TcpPing | F::Download | F::Upload => "not-run".into(),
                            F::Status => "not-run".into(),
                            F::Samples | F::Failures | F::Run | F::Tested => "-".into(),
                        })
                        .collect::<Vec<_>>(),
                );
                continue;
            }
            for run in &node.runs {
                for target in &run.targets {
                    if target.target == "direct" && !fields.contains(&F::TcpPing) {
                        continue;
                    }
                    found = true;
                    let latency = target
                        .metrics
                        .iter()
                        .find(|m| m.metric == crate::domain::BenchmarkMetric::Latency);
                    let tcp_ping = target
                        .metrics
                        .iter()
                        .find(|m| m.metric == crate::domain::BenchmarkMetric::TcpPing);
                    let download = target
                        .metrics
                        .iter()
                        .find(|m| m.metric == crate::domain::BenchmarkMetric::Download);
                    let upload = target
                        .metrics
                        .iter()
                        .find(|m| m.metric == crate::domain::BenchmarkMetric::Upload);
                    let summaries = [latency, tcp_ping, download, upload]
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>();
                    let successes: usize = summaries.iter().map(|m| m.successful).sum();
                    let attempted: usize = summaries.iter().map(|m| m.attempted).sum();
                    let failures: usize = summaries
                        .iter()
                        .map(|m| m.failures.iter().map(|f| f.count).sum::<usize>())
                        .sum();
                    let metric_cell = |summary: Option<&reporting::MetricSummary>| {
                        summary
                            .map(metric_summary_cell)
                            .unwrap_or_else(|| "not-run".into())
                    };
                    builder.push_record(
                        fields
                            .iter()
                            .map(|field| match field {
                                F::Node => number.clone(),
                                F::Name => {
                                    node.node.node.name.clone().unwrap_or_else(|| "-".into())
                                }
                                F::Server => safe_field(&node.node.node.server, 48),
                                F::Port => node.node.node.port.to_string(),
                                F::Protocol => node.node.node.protocol.to_string(),
                                F::Core => target.target.clone(),
                                F::Version => target
                                    .core_version
                                    .as_deref()
                                    .map(|v| display_core_version(v, false))
                                    .unwrap_or_else(|| "-".into()),
                                F::Latency => {
                                    if target.target == "direct" {
                                        "-".into()
                                    } else {
                                        metric_cell(latency)
                                    }
                                }
                                F::TcpPing => {
                                    if target.target == "direct" {
                                        metric_cell(tcp_ping)
                                    } else {
                                        "-".into()
                                    }
                                }
                                F::Download => {
                                    if target.target == "direct" {
                                        "-".into()
                                    } else {
                                        metric_cell(download)
                                    }
                                }
                                F::Upload => {
                                    if target.target == "direct" {
                                        "-".into()
                                    } else {
                                        metric_cell(upload)
                                    }
                                }
                                F::Status => aggregate_target_status(&summaries, run.run.status),
                                F::Samples => format!("{successes}/{attempted}"),
                                F::Failures => failures.to_string(),
                                F::Run => run.run.id.to_string(),
                                F::Tested => run
                                    .run
                                    .completed_at
                                    .map(|v| v.to_string())
                                    .unwrap_or_else(|| "-".into()),
                            })
                            .collect::<Vec<_>>(),
                    );
                }
            }
        }
    }
    if !found {
        println!("No benchmark results.");
        return;
    }
    println!("{}", builder.build().with(Style::rounded()));
}

fn aggregate_target_status(
    summaries: &[&reporting::MetricSummary],
    run_status: crate::domain::BenchmarkRunStatus,
) -> String {
    use crate::domain::BenchmarkSampleStatus as S;
    for (status, label) in [
        (S::Unavailable, "unavailable"),
        (S::Unsupported, "unsupported"),
        (S::Invalid, "invalid"),
        (S::Timeout, "timeout"),
        (S::Unreachable, "unreachable"),
        (S::Cancelled, "cancelled"),
    ] {
        if summaries.iter().any(|summary| {
            summary.preflight == Some(status)
                || summary
                    .failures
                    .iter()
                    .any(|failure| failure.status == status)
        }) {
            return label.into();
        }
    }
    if summaries
        .iter()
        .all(|summary| summary.attempted == 0 && summary.preflight.is_none())
    {
        return "not-run".into();
    }
    run_status_label(run_status).into()
}

fn metric_summary_cell(summary: &reporting::MetricSummary) -> String {
    if let Some(value) = summary.median {
        let formatted = if summary.metric == crate::domain::BenchmarkMetric::Download
            || summary.metric == crate::domain::BenchmarkMetric::Upload
        {
            format!("{:.2} Mbps", value / 1_000_000.0)
        } else {
            format!("{value:.2} ms")
        };
        if summary.successful < 3 {
            format!("{formatted} ({}/3)", summary.successful)
        } else {
            formatted
        }
    } else if let Some(status) = summary.preflight {
        sample_status_label(status).to_owned()
    } else if summary.attempted == 0 {
        "not-run".into()
    } else {
        summary
            .failures
            .iter()
            .map(|f| format!("{}×{}", sample_status_label(f.status), f.count))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn print_benchmark_report(
    report: &reporting::BenchmarkReport,
    config: &crate::services::display_config::DisplayConfig,
    verbose: bool,
    display_numbers: &HashMap<u64, usize>,
) {
    use crate::services::display_config::DisplayField as F;
    use reporting::ReportMode;

    let fields = config.fields();
    let mut builder = Builder::default();
    builder.push_record(fields.iter().map(ToString::to_string).collect::<Vec<_>>());
    let mut found = false;

    if report.mode == ReportMode::Compare {
        for comparison in &report.comparisons {
            if comparison.target == "direct" && !fields.contains(&F::TcpPing) {
                continue;
            }
            found = true;
            builder.push_record(report_row(
                &fields,
                &comparison.node,
                display_numbers,
                ReportRowData {
                    target: &comparison.target,
                    core_version: comparison.core_version.as_deref(),
                    metrics: &comparison.metrics,
                    run_id: Some(comparison.run_id),
                    tested: None,
                    run_status: Some(crate::domain::BenchmarkRunStatus::Completed),
                    verbose,
                },
            ));
        }
    } else {
        for node in &report.nodes {
            if node.runs.is_empty() {
                found = true;
                builder.push_record(report_empty_node_row(&fields, &node.node, display_numbers));
                continue;
            }
            for run in &node.runs {
                for target in &run.targets {
                    if target.target == "direct" && !fields.contains(&F::TcpPing) {
                        continue;
                    }
                    found = true;
                    builder.push_record(report_row(
                        &fields,
                        &node.node,
                        display_numbers,
                        ReportRowData {
                            target: &target.target,
                            core_version: target.core_version.as_deref(),
                            metrics: &target.metrics,
                            run_id: Some(run.run.id),
                            tested: run.run.completed_at.or(Some(run.run.started_at)),
                            run_status: Some(run.run.status),
                            verbose,
                        },
                    ));
                }
            }
        }
    }

    if !found {
        println!(
            "{}",
            match report.mode {
                ReportMode::Latest => "No benchmark results.",
                ReportMode::History => "No benchmark history.",
                ReportMode::Compare => "No completed benchmark comparisons found.",
            }
        );
        return;
    }
    println!("{}", builder.build().with(Style::rounded()));
}

fn report_empty_node_row(
    fields: &[crate::services::display_config::DisplayField],
    node: &NodeRecord,
    display_numbers: &HashMap<u64, usize>,
) -> Vec<String> {
    use crate::services::display_config::DisplayField as F;
    fields.iter().map(|field| match field {
        F::Node => display_numbers.get(&node.id).copied().unwrap_or(node.id as usize).to_string(),
        F::Name => node.node.name.clone().unwrap_or_else(|| "-".into()),
        F::Server => safe_field(&node.node.server, 48),
        F::Port => node.node.port.to_string(),
        F::Protocol => node.node.protocol.to_string(),
        F::Core | F::Version | F::Samples | F::Failures | F::Run | F::Tested => "-".into(),
        F::Latency | F::TcpPing | F::Download | F::Upload | F::Status => "not-run".into(),
    }).collect()
}

struct ReportRowData<'a> {
    target: &'a str,
    core_version: Option<&'a str>,
    metrics: &'a [reporting::MetricSummary],
    run_id: Option<u64>,
    tested: Option<u64>,
    run_status: Option<crate::domain::BenchmarkRunStatus>,
    verbose: bool,
}

fn report_row(
    fields: &[crate::services::display_config::DisplayField],
    node: &NodeRecord,
    display_numbers: &HashMap<u64, usize>,
    data: ReportRowData<'_>,
) -> Vec<String> {
    use crate::services::display_config::DisplayField as F;

    let find = |metric| data.metrics.iter().find(|summary| summary.metric == metric);
    let latency = find(crate::domain::BenchmarkMetric::Latency);
    let tcp_ping = find(crate::domain::BenchmarkMetric::TcpPing);
    let download = find(crate::domain::BenchmarkMetric::Download);
    let upload = find(crate::domain::BenchmarkMetric::Upload);
    let summaries = [latency, tcp_ping, download, upload]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let successes: usize = summaries.iter().map(|summary| summary.successful).sum();
    let attempted: usize = summaries.iter().map(|summary| summary.attempted).sum();
    let failures: usize = summaries
        .iter()
        .map(|summary| {
            summary
                .failures
                .iter()
                .map(|failure| failure.count)
                .sum::<usize>()
        })
        .sum();
    let metric_cell = |summary: Option<&reporting::MetricSummary>| {
        summary
            .map(metric_summary_cell)
            .unwrap_or_else(|| "not-run".into())
    };

    fields
        .iter()
        .map(|field| match field {
            F::Node => display_numbers
                .get(&node.id)
                .copied()
                .unwrap_or(node.id as usize)
                .to_string(),
            F::Name => node.node.name.clone().unwrap_or_else(|| "-".into()),
            F::Server => safe_field(&node.node.server, 48),
            F::Port => node.node.port.to_string(),
            F::Protocol => node.node.protocol.to_string(),
            F::Core => data.target.to_owned(),
            F::Version => data
                .core_version
                .map(|version| display_core_version(version, data.verbose))
                .unwrap_or_else(|| "-".into()),
            F::Latency => {
                if data.target == "direct" {
                    "-".into()
                } else {
                    metric_cell(latency)
                }
            }
            F::TcpPing => {
                if data.target == "direct" {
                    metric_cell(tcp_ping)
                } else {
                    "-".into()
                }
            }
            F::Download => {
                if data.target == "direct" {
                    "-".into()
                } else {
                    metric_cell(download)
                }
            }
            F::Upload => {
                if data.target == "direct" {
                    "-".into()
                } else {
                    metric_cell(upload)
                }
            }
            F::Status => aggregate_target_status(
                &summaries,
                data
                    .run_status
                    .unwrap_or(crate::domain::BenchmarkRunStatus::Completed),
            ),
            F::Samples => format!("{successes}/{attempted}"),
            F::Failures => failures.to_string(),
            F::Run => data
                .run_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "-".into()),
            F::Tested => data
                .tested
                .map(|timestamp| timestamp.to_string())
                .unwrap_or_else(|| "-".into()),
        })
        .collect()
}

fn display_core_version(version: &str, verbose: bool) -> String {
    if verbose {
        return version.to_owned();
    }
    let short_version = version
        .chars()
        .skip_while(|character| !character.is_ascii_digit())
        .take_while(|character| character.is_ascii_digit() || *character == '.')
        .collect::<String>()
        .trim_end_matches('.')
        .to_owned();
    if short_version.is_empty() {
        version.to_owned()
    } else {
        short_version
    }
}

fn run_status_label(status: crate::domain::BenchmarkRunStatus) -> &'static str {
    match status {
        crate::domain::BenchmarkRunStatus::Running => "running",
        crate::domain::BenchmarkRunStatus::Completed => "completed",
        crate::domain::BenchmarkRunStatus::Interrupted => "interrupted",
        crate::domain::BenchmarkRunStatus::Cancelled => "cancelled",
    }
}

fn sample_status_label(status: crate::domain::BenchmarkSampleStatus) -> &'static str {
    match status {
        crate::domain::BenchmarkSampleStatus::Success => "success",
        crate::domain::BenchmarkSampleStatus::Unreachable => "unreachable",
        crate::domain::BenchmarkSampleStatus::Unsupported => "unsupported",
        crate::domain::BenchmarkSampleStatus::Invalid => "invalid",
        crate::domain::BenchmarkSampleStatus::Timeout => "timeout",
        crate::domain::BenchmarkSampleStatus::Unavailable => "unavailable",
        crate::domain::BenchmarkSampleStatus::Cancelled => "cancelled",
    }
}

fn active_display_numbers(path: &std::path::Path) -> anyhow::Result<HashMap<u64, usize>> {
    Ok(nodes::list_nodes(path, false)?
        .into_iter()
        .enumerate()
        .map(|(index, record)| (record.id, index + 1))
        .collect())
}

fn deleted_display_numbers(path: &std::path::Path) -> anyhow::Result<HashMap<u64, usize>> {
    Ok(nodes::list_nodes(path, true)?
        .into_iter()
        .filter(|record| record.is_deleted())
        .enumerate()
        .map(|(index, record)| (record.id, index + 1))
        .collect())
}

fn parse_core(value: Option<&str>) -> anyhow::Result<Option<CoreId>> {
    value.map(str::parse).transpose()
}

fn print_node_list(
    records: &[NodeRecord],
    display_numbers: &HashMap<u64, usize>,
    deleted_display_numbers: &HashMap<u64, usize>,
) {
    if records.is_empty() {
        println!("No proxy nodes found.");
        return;
    }
    println!(
        "{:>5}  {:<12}  {:<32}  {:>5}  NAME",
        "NO.", "PROTOCOL", "SERVER", "PORT"
    );
    for record in records {
        println!(
            "{:>5}  {:<12}  {:<32}  {:>5}  {}",
            if record.is_deleted() {
                format!(
                    "D{}",
                    deleted_display_numbers
                        .get(&record.id)
                        .copied()
                        .unwrap_or_default()
                )
            } else {
                display_numbers
                    .get(&record.id)
                    .copied()
                    .unwrap_or_default()
                    .to_string()
            },
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

fn print_sorted_node_list(
    records: &[sorting::RankedNode],
    metric: SortMetric,
    display_numbers: &HashMap<u64, usize>,
    deleted_display_numbers: &HashMap<u64, usize>,
) {
    if records.is_empty() {
        println!("No proxy nodes found.");
        return;
    }
    let core_width = records
        .iter()
        .map(|record| record.cores.chars().count())
        .max()
        .unwrap_or_default()
        .max("CORE(S)".len());
    println!(
        "{:>4}  {:>5}  {:<12}  {:<32}  {:>5}  {:>14}  {:<width$}  NAME",
        "RANK",
        "NO.",
        "PROTOCOL",
        "SERVER",
        "PORT",
        metric.label(),
        "CORE(S)",
        width = core_width
    );
    for (index, record) in records.iter().enumerate() {
        let value = match record.value {
            Some(value) if record.unit == "ms" => format!("{value:.2} ms"),
            Some(value) => format!("{:.2} Mbps", value / 1_000_000.0),
            None => "unmeasured".to_owned(),
        };
        println!(
            "{:>4}  {:>5}  {:<12}  {:<32}  {:>5}  {:>14}  {:<width$}  {}",
            if record.value.is_some() {
                (index + 1).to_string()
            } else {
                "-".into()
            },
            if record.node.is_deleted() {
                format!(
                    "D{}",
                    deleted_display_numbers
                        .get(&record.node.id)
                        .copied()
                        .unwrap_or_default()
                )
            } else {
                display_numbers
                    .get(&record.node.id)
                    .copied()
                    .unwrap_or_default()
                    .to_string()
            },
            record.node.node.protocol,
            safe_field(&record.node.node.server, 32),
            record.node.node.port,
            value,
            safe_field(&record.cores, core_width),
            record
                .node
                .node
                .name
                .as_deref()
                .map(|name| safe_field(name, 32))
                .unwrap_or_else(|| "-".to_owned()),
            width = core_width
        );
    }
}

fn print_node_details(record: &NodeRecord, display_number: usize) {
    let node = &record.node;
    println!("Node: #{display_number}");
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

    use super::{Cli, Command, TunCommand, display_core_version};

    #[test]
    fn list_command_accepts_metric_sorting_and_optional_core() {
        assert!(Cli::try_parse_from(["proxyctl", "list", "--sort", "ping"]).is_ok());
        assert!(
            Cli::try_parse_from(["proxyctl", "list", "--sort", "download", "--core", "xray"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["proxyctl", "list", "--core", "xray"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "list", "--sort", "unknown"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "use", "12", "--core", "xray"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "use", "12", "--core", "xray", "--tun"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "use", "12"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "stop"]).is_ok());
    }

    #[test]
    fn list_command_accepts_protocol_and_search_filters() {
        assert!(Cli::try_parse_from(["proxyctl", "list", "--protocol", "vless"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "list", "--search", "example.com"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "list", "--protocol", "invalid"]).is_err());
    }

    #[test]
    fn concise_report_versions_extract_core_version_and_verbose_keeps_metadata() {
        assert_eq!(
            display_core_version("sing-box version 1.14.4 (linux; go1.26.0)", false),
            "1.14.4"
        );
        assert_eq!(
            display_core_version("Mihomo Meta v1.19.33", false),
            "1.19.33"
        );
        assert_eq!(
            display_core_version("Xray 26.11.9 (go1.26.0)", true),
            "Xray 26.11.9 (go1.26.0)"
        );
    }

    #[test]
    fn show_uses_result_table_by_default_and_details_are_explicit() {
        assert!(Cli::try_parse_from(["proxyctl", "show", "1"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "show", "1", "--details"]).is_ok());
    }

    #[test]
    fn display_profiles_can_be_selected_and_customized() {
        assert!(Cli::try_parse_from(["proxyctl", "config", "display"]).is_ok());
        assert!(
            Cli::try_parse_from(["proxyctl", "config", "display", "profile", "compact"]).is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "config",
                "display",
                "add-field",
                "full",
                "tcp-ping"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "config",
                "display",
                "remove-field",
                "normal",
                "protocol"
            ])
            .is_ok()
        );
    }

    #[test]
    fn report_command_accepts_latest_history_and_core_comparison_views() {
        assert!(Cli::try_parse_from(["proxyctl", "report"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "report", "--node", "18", "--history"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "report", "--compare"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "report", "--compare", "--core", "xray"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "report", "--verbose"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "report", "--core", "xray"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "report", "--history", "--compare"]).is_err());
    }

    #[test]
    fn prune_command_requires_one_scope_and_supports_preview_or_apply() {
        assert!(Cli::try_parse_from(["proxyctl", "prune", "--unavailable-all"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "prune", "--unavailable-all", "--apply"]).is_ok());
        assert!(
            Cli::try_parse_from(["proxyctl", "prune", "--core", "xray", "--unavailable"]).is_ok()
        );
        assert!(Cli::try_parse_from(["proxyctl", "prune"]).is_err());
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "prune",
                "--unavailable-all",
                "--unavailable",
                "--core",
                "xray"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "prune",
                "--unavailable-all",
                "--apply",
                "--dry-run"
            ])
            .is_err()
        );
    }

    #[test]
    fn test_command_accepts_all_cores_scope() {
        let cli = Cli::try_parse_from(["proxyctl", "test", "--all-cores"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Test {
                all_cores: true,
                ref node,
                core: None,
                ..
            }) if node.is_empty()
        ));
    }

    #[test]
    fn test_command_accepts_each_metric_only_selector_and_rejects_combinations() {
        for selector in ["--latency-only", "--download-only", "--upload-only"] {
            assert!(Cli::try_parse_from(["proxyctl", "test", "--all-cores", selector]).is_ok());
        }
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "test",
                "--all-cores",
                "--latency-only",
                "--download-only"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "test",
                "--all-cores",
                "--download-only",
                "--upload-only"
            ])
            .is_err()
        );
    }

    #[test]
    fn test_command_requires_a_valid_scope_and_rejects_conflicting_core() {
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
    fn test_command_accepts_one_node_with_all_cores() {
        let cli = Cli::try_parse_from(["proxyctl", "test", "--node", "18", "--all-cores"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Test {
                all_cores: true,
                ref node,
                core: None,
                ..
            }) if node == &vec!["18".to_owned()]
        ));
    }

    #[test]
    fn node_commands_accept_lists_ranges_and_remove_all_confirmation_flag() {
        assert!(Cli::try_parse_from(["proxyctl", "show", "1", "2", "3"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "show", "1..5"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "remove", "all"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "remove", "all", "--yes"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "restore", "1..5"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "check", "1", "2", "--core", "xray"]).is_ok());
        let cli = Cli::try_parse_from(["proxyctl", "test", "--node", "1", "2", "3", "--all-cores"])
            .unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Test { node, .. })
                if node.iter().map(String::as_str).collect::<Vec<_>>() == vec!["1", "2", "3"]
        ));
    }

    #[test]
    fn tun_status_is_the_only_exposed_tun_operation() {
        let cli = Cli::try_parse_from(["proxyctl", "tun", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Tun {
                command: TunCommand::Status
            })
        ));
        assert!(Cli::try_parse_from(["proxyctl", "tun", "on"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "tun", "off"]).is_err());
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
                ref node,
                core: Some(ref core),
                download_bytes: 2_097_152,
                upload_bytes: 1_048_576,
                ..
            }) if node == &vec!["7".to_owned()] && core == "sing-box"
        ));
    }
}
