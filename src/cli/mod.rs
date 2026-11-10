//! CLI definitions and dispatch. Application behavior belongs in services.
use crate::{
    cores::CoreId,
    database::{AddNodeOutcome, NodeRecord, default_database_path},
    services::{
        nodes,
        pruning::{self, PruneDecision, PruneOptions, PruneScope},
        reporting::{self, ReportMode, ReportOptions},
        sorting::{self, SortMetric},
    },
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
        /// Sort by real ping, direct TCP ping, download, or upload.
        #[arg(long, value_name = "METRIC", value_parser = ["ping", "tcp-ping", "download", "upload"])]
        sort: Option<String>,
        /// Restrict benchmark sorting to one managed core; requires --sort.
        #[arg(long, value_name = "CORE", requires = "sort")]
        core: Option<String>,
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
    #[command(group(ArgGroup::new("test_scope").args(["all_cores", "core"]).required(true).multiple(false)))]
    Test {
        /// Test all active nodes, or only --node, against all installed compatible managed cores.
        #[arg(long)]
        all_cores: bool,
        /// Restrict --all-cores to one stored node; otherwise use with --core.
        #[arg(long)]
        node: Option<u64>,
        /// Test --node with one selected managed core (mutually exclusive with --all-cores).
        #[arg(long, value_name = "CORE", requires = "node")]
        core: Option<String>,
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
        /// Restrict the report to one stored node.
        #[arg(long)]
        node: Option<u64>,
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
        Command::List {
            include_deleted,
            sort,
            core,
        } => {
            let records = nodes::list_nodes(&database_path, include_deleted)?;
            if let Some(metric) = sort {
                let metric: SortMetric = metric.parse()?;
                let core = parse_core(core.as_deref())?;
                if metric == SortMetric::TcpPing && core.is_some() {
                    anyhow::bail!(
                        "--core cannot be used with --sort tcp-ping because TCP ping is measured directly"
                    );
                }
                let ranked = sorting::sort_nodes(&database_path, records, metric, core)?;
                print_sorted_node_list(&ranked, metric);
            } else {
                print_node_list(&records);
            }
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
            let report = reporting::build_report(
                &database_path,
                ReportOptions {
                    mode,
                    node_id: node,
                    core: parse_core(core.as_deref())?,
                    verbose,
                },
            )?;
            print_benchmark_report(&report, verbose);
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
            let report = pruning::prune_nodes(
                &database_path,
                PruneOptions {
                    scope,
                    apply,
                },
            )?;
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
                    result.node.id,
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
                println!("Dry run: {candidates} node(s) eligible; no changes made. Use --apply to soft-delete.");
            }
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

fn print_benchmark_report(report: &reporting::BenchmarkReport, verbose: bool) {
    use reporting::ReportMode;

    if report.mode == ReportMode::Compare {
        if report.comparisons.is_empty() {
            println!("No completed benchmark comparisons found.");
            return;
        }
        for comparison in &report.comparisons {
            println!(
                "Node #{} {}:{} — {} — run #{}{}",
                comparison.node.id,
                safe_field(&comparison.node.node.server, 48),
                comparison.node.node.port,
                comparison.target,
                comparison.run_id,
                comparison
                    .core_version
                    .as_deref()
                    .map(|version| format!(" ({})", display_core_version(version, verbose)))
                    .unwrap_or_default()
            );
            for metric in &comparison.metrics {
                print_metric_summary(metric);
            }
            println!();
        }
        return;
    }

    if report.nodes.is_empty() {
        println!("No proxy nodes found.");
        return;
    }
    for node in &report.nodes {
        println!(
            "Node #{} {}:{}{}",
            node.node.id,
            safe_field(&node.node.node.server, 48),
            node.node.node.port,
            node.node
                .node
                .name
                .as_deref()
                .map(|name| format!(" — {}", safe_field(name, 48)))
                .unwrap_or_default()
        );
        if node.runs.is_empty() {
            println!("  No benchmark history.");
            println!();
            continue;
        }
        for run in &node.runs {
            println!(
                "  Run #{} — {} — started {} — completed {}",
                run.run.id,
                run_status_label(run.run.status),
                run.run.started_at,
                run.run
                    .completed_at
                    .map(|timestamp| timestamp.to_string())
                    .unwrap_or_else(|| "-".into())
            );
            if let Some(summary) = run.run.summary.as_deref() {
                println!("    Summary: {}", safe_field(summary, 160));
            }
            for target in &run.targets {
                println!(
                    "    {}{}",
                    target.target,
                    target
                        .core_version
                        .as_deref()
                        .map(|version| format!(" ({})", display_core_version(version, verbose)))
                        .unwrap_or_default()
                );
                for metric in &target.metrics {
                    print_metric_summary(metric);
                }
            }
        }
        println!();
    }
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

fn print_metric_summary(summary: &reporting::MetricSummary) {
    let label = summary.metric.label();
    let missing = 3_usize.saturating_sub(summary.attempted);
    let failures = summary
        .failures
        .iter()
        .map(|failure| format!("{}={}", sample_status_label(failure.status), failure.count))
        .collect::<Vec<_>>()
        .join(", ");
    let suffix = if failures.is_empty() {
        String::new()
    } else {
        format!("; {failures}")
    };
    let missing_suffix = if missing > 0 {
        format!("; {missing} not run")
    } else {
        String::new()
    };

    match (summary.median, summary.successful, summary.preflight) {
        (Some(value), 3, _) => println!(
            "      {label}: {:.2} {} (3/3 successful)",
            value,
            summary.metric.unit()
        ),
        (Some(value), successful, _) => println!(
            "      {label}: {:.2} {} (partial: {successful}/3 successful{suffix}{missing_suffix})",
            value,
            summary.metric.unit()
        ),
        (None, _, Some(preflight)) => {
            println!(
                "      {label}: {} (preflight)",
                sample_status_label(preflight)
            )
        }
        (None, 0, None) if summary.attempted == 0 => {
            println!("      {label}: not run (0/3)")
        }
        (None, _, None) => {
            println!("      {label}: no successful samples (0/3{suffix}{missing_suffix})")
        }
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

fn print_sorted_node_list(records: &[sorting::RankedNode], metric: SortMetric) {
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
        "ID",
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
            record.node.id,
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
    fn list_command_accepts_metric_sorting_and_optional_core() {
        assert!(Cli::try_parse_from(["proxyctl", "list", "--sort", "ping"]).is_ok());
        assert!(
            Cli::try_parse_from(["proxyctl", "list", "--sort", "download", "--core", "xray"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["proxyctl", "list", "--core", "xray"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "list", "--sort", "unknown"]).is_err());
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
        assert!(Cli::try_parse_from(["proxyctl", "prune", "--core", "xray", "--unavailable"]).is_ok());
        assert!(Cli::try_parse_from(["proxyctl", "prune"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "prune", "--unavailable-all", "--unavailable", "--core", "xray"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "prune", "--unavailable-all", "--apply", "--dry-run"]).is_err());
    }

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
                node: Some(18),
                core: None,
                ..
            })
        ));
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
