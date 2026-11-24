//! CLI definitions and dispatch. Application behavior belongs in services.
use crate::{
    database::{AddNodeOutcome, default_database_path},
    services::node_selection::{self, NodeSelection},
    services::{
        nodes,
        pruning::{self, PruneDecision, PruneOptions, PruneScope},
        reporting::{self, ReportMode, ReportOptions},
        sorting::{self, SortMetric},
    },
    updates::release::ReleaseChannel,
};
use clap::{ArgGroup, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

mod handlers;
mod presentation;
mod table;
pub use handlers::dispatch;
use presentation::*;
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
enum CompletionAction {
    /// Install completion for the detected shell, or explicitly select a supported shell.
    Install {
        /// Shell to install completion for: fish, bash, or zsh.
        #[arg(long, value_parser = ["fish", "bash", "zsh"])]
        shell: Option<String>,
    },
    /// Print a completion script to standard output.
    Generate {
        /// Target shell for the generated completion script.
        shell: Shell,
    },
}

#[derive(Debug, Subcommand)]
enum TunCommand {
    /// Start TUN mode for the currently active session (not yet implemented).
    Start {
        /// Keep the TUN supervisor attached to this terminal.
        #[arg(long)]
        foreground: bool,
    },
    /// Return the current TUN session to loopback mode (not yet implemented).
    Stop,
    /// Show interfaces, default routes, DNS, and firewall state (read-only).
    Status,
}

#[derive(Debug, Subcommand)]
enum NodesCommand {
    /// Permanently purge soft-deleted nodes and their node-specific benchmark data.
    Purge {
        /// Select soft-deleted nodes only; active nodes are never eligible.
        #[arg(long, required = true)]
        deleted: bool,
        /// Minimum time since deletion (for example 30d, 12h, or 45m).
        #[arg(long, default_value = "0s")]
        older_than: String,
        /// Apply the purge. Without this flag the command is a dry run.
        #[arg(long, conflicts_with = "dry_run")]
        apply: bool,
        /// Explicitly request a preview without changing the database.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Set the persistent shared HTTP/SOCKS5 listener port.
    Set {
        #[arg(value_parser = ["listen-port"])]
        key: String,
        value: u16,
    },
    /// Restore a setting to its built-in default.
    Reset {
        #[arg(value_parser = ["listen-port"])]
        key: String,
    },
    /// Configure table profiles used by show and report.
    Display {
        #[command(subcommand)]
        action: Option<DisplayAction>,
    },
}

#[derive(Debug, Subcommand)]
enum DisplayAction {
    /// Select the active table profile: compact, normal, or full.
    Profile {
        #[arg(value_parser = ["compact", "normal", "full"])]
        name: String,
    },
    /// Add a supported column to a profile.
    AddField {
        #[arg(value_parser = ["compact", "normal", "full"])]
        profile: String,
        #[arg(value_parser = ["node", "name", "server", "port", "protocol", "core", "version", "latency", "tcp-ping", "download", "upload", "status", "samples", "failures", "run", "tested"])]
        field: String,
    },
    /// Remove a column from a profile (at least one must remain).
    RemoveField {
        #[arg(value_parser = ["compact", "normal", "full"])]
        profile: String,
        #[arg(value_parser = ["node", "name", "server", "port", "protocol", "core", "version", "latency", "tcp-ping", "download", "upload", "status", "samples", "failures", "run", "tested"])]
        field: String,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install shell completion or generate a script manually.
    Completions {
        #[command(subcommand)]
        action: CompletionAction,
    },
    /// Permanently manage stored node records.
    Nodes {
        #[command(subcommand)]
        command: NodesCommand,
    },
    /// Add one proxy URL to the local database.
    Add {
        /// Proxy URL to parse and store (credentials are masked in normal output).
        url: String,
    },
    /// Import proxy URLs from a newline-delimited text file.
    Import {
        /// Text file containing one proxy URL per line.
        file: PathBuf,
    },
    /// List stored nodes, with optional filters and benchmark sorting.
    List {
        /// Include soft-deleted nodes in the listing.
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
        #[arg(long, value_name = "CORE", value_parser = ["sing-box", "xray", "mihomo"], requires = "sort")]
        core: Option<String>,
    },
    /// Show benchmark results or connection details for selected nodes.
    Show {
        #[arg(required = true, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        nodes: Vec<String>,
        /// Show connection/configuration details instead of benchmark results.
        #[arg(long)]
        details: bool,
    },
    /// Soft-delete selected nodes without removing their benchmark history.
    Remove {
        /// Node numbers, ranges (for example 2..5), or all.
        #[arg(required = true, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        nodes: Vec<String>,
        /// Skip the confirmation prompt when removing all nodes.
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Restore previously soft-deleted nodes.
    Restore {
        /// Deleted node numbers, ranges, or all.
        #[arg(required = true, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        nodes: Vec<String>,
    },
    /// Validate one or more stored nodes' generated configs without starting a proxy core.
    Check {
        /// Node numbers, ranges, or all.
        #[arg(required = true, num_args = 1.., value_name = "NUMBER|RANGE|all")]
        nodes: Vec<String>,
        /// Validate only with this managed core; otherwise check all supported cores.
        #[arg(long, value_name = "CORE", value_parser = ["sing-box", "xray", "mihomo"])]
        core: Option<String>,
    },
    /// Show managed core status and versions.
    Cores,
    /// Activate one node using one Proxyctl-managed core (loopback only by default).
    Use {
        #[arg(value_name = "NUMBER")]
        id: u64,
        #[arg(long, value_name = "CORE", value_parser = ["sing-box", "xray", "mihomo"], required = true)]
        core: String,
        /// Override the persistent shared HTTP/SOCKS5 listener port for this activation only.
        #[arg(long, value_name = "PORT")]
        port: Option<u16>,
        /// Request TUN mode (temporarily disabled during the single-executable supervisor migration).
        #[arg(long)]
        tun: bool,
        /// Keep the selected core attached to this terminal instead of backgrounding it.
        #[arg(long, conflicts_with = "tun")]
        foreground: bool,
        /// Plain HTTP endpoint used for a bounded direct TUN probe; it must return the expected 2xx status and keep the HTTP connection alive.
        #[arg(
            long,
            default_value = "http://connectivitycheck.gstatic.com/generate_204"
        )]
        tun_probe_url: String,
        /// Expected final HTTP status from the TUN readiness endpoint.
        #[arg(long, default_value_t = 204, value_parser = clap::value_parser!(u16).range(200..=299))]
        tun_probe_status: u16,
    },
    /// Show or change persistent listener settings.
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
    /// Show the current Proxyctl-managed session and its mode.
    Status,
    /// Stop only the exact process tracked by Proxyctl.
    Stop,
    /// Install all supported cores, or one selected core.
    Setup {
        #[arg(long, value_name = "CORE", value_parser = ["sing-box", "xray", "mihomo"])]
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
        #[arg(long, value_name = "CORE", value_parser = ["sing-box", "xray", "mihomo"], requires = "node")]
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
        /// Throughput profile: quick (default) or accurate.
        #[arg(long, value_parser = ["quick", "accurate"], default_value = "quick")]
        profile: String,
        /// Local benchmark inbound protocol (default SOCKS5; HTTP remains available).
        #[arg(long, value_parser = ["socks5", "http"], default_value = "socks5")]
        proxy_type: String,
        /// HTTPS URL used for real HTTP ping through the selected core.
        #[arg(long, default_value = "https://www.google.com/generate_204")]
        latency_url: String,
        /// HTTPS URL of a download test object (profile default: 1 MiB quick, 8 MiB accurate).
        #[arg(long, default_value = "https://cachefly.cachefly.net/10mb.test")]
        download_url: String,
        /// HTTPS endpoint accepting a POST body for uploads.
        #[arg(long, default_value = "https://speed.cloudflare.com/__up")]
        upload_url: String,
        /// Override the profile's download byte budget (maximum 32 MiB).
        #[arg(long = "download-max-bytes", alias = "download-bytes")]
        download_bytes: Option<u64>,
        /// Override the profile's upload payload size (maximum 1 MiB).
        #[arg(long)]
        upload_bytes: Option<u64>,
        /// Maximum duration of each download/upload HTTP request, in seconds (default 60).
        #[arg(long, alias = "throughput-timeout-secs", default_value_t = 60)]
        request_timeout_secs: u64,
        /// Maximum duration of each real-latency HTTP request, in seconds.
        #[arg(long, default_value_t = 5)]
        latency_timeout_secs: u64,
        /// Maximum concurrent latency/TCP probes (1–3).
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=3))]
        concurrency: u8,
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
        #[arg(long, value_name = "CORE", value_parser = ["sing-box", "xray", "mihomo"], requires = "compare")]
        core: Option<String>,
        /// Show the full benchmark detail columns (full display profile).
        #[arg(long)]
        details: bool,
        /// Show full core build/version metadata instead of concise versions.
        #[arg(long)]
        verbose: bool,
    },
    /// Soft-delete nodes that have no successful real-ping path through any of the three cores.
    #[command(group(ArgGroup::new("prune_scope").args(["unavailable_all", "unavailable"]).required(true).multiple(false)))]
    Prune {
        /// Evaluate sing-box, Xray, and Mihomo; unsupported and invalid combinations count as unusable.
        #[arg(long)]
        unavailable_all: bool,
        /// Evaluate one selected core; requires --core.
        #[arg(long, requires = "core")]
        unavailable: bool,
        /// Managed core used with --unavailable.
        #[arg(long, value_name = "CORE", value_parser = ["sing-box", "xray", "mihomo"], requires = "unavailable")]
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
        /// Report available versions without downloading or installing files.
        #[arg(long)]
        check: bool,
        /// Update Proxyctl only.
        #[arg(long)]
        app: bool,
        /// Update all installed managed cores.
        #[arg(long)]
        cores: bool,
        /// Update one selected managed core.
        #[arg(long, value_name = "CORE", value_parser = ["sing-box", "xray", "mihomo"])]
        core: Option<String>,
        /// Include prereleases instead of selecting stable releases only.
        #[arg(long)]
        prerelease: bool,
    },
}

fn completion_script(shell: Shell) -> String {
    let mut command = Cli::command();
    let mut output = Vec::new();
    clap_complete::generate(shell, &mut command, "proxyctl", &mut output);
    let mut script = String::from_utf8(output).expect("clap completion scripts are valid UTF-8");

    if shell == Shell::Fish {
        // Fish otherwise falls back to filesystem entries for an empty argument.
        // Keep file suggestions only for the import command's path argument.
        let mut candidate_rules = Vec::new();
        append_fish_option_candidates(&Cli::command(), &mut Vec::new(), &mut candidate_rules);
        candidate_rules.extend([
            "complete -c proxyctl -a 'listen-port' -n '__fish_seen_subcommand_from config set'",
            "complete -c proxyctl -a 'listen-port' -n '__fish_seen_subcommand_from config reset'",
            "complete -c proxyctl -a 'compact normal full' -n '__fish_seen_subcommand_from config display profile'",
            "complete -c proxyctl -a 'compact normal full' -n '__fish_seen_subcommand_from config display add-field'",
            "complete -c proxyctl -a 'compact normal full' -n '__fish_seen_subcommand_from config display remove-field'",
            "complete -c proxyctl -a 'node name server port protocol core version latency tcp-ping download upload status samples failures run tested' -n '__fish_seen_subcommand_from config display add-field'",
            "complete -c proxyctl -a 'node name server port protocol core version latency tcp-ping download upload status samples failures run tested' -n '__fish_seen_subcommand_from config display remove-field'",
        ].into_iter().map(str::to_owned));
        script = format!(
            "complete -c proxyctl -f\ncomplete -c proxyctl -F -n '__fish_seen_subcommand_from import'\n{}\n{script}",
            candidate_rules.join("\n")
        );
    }

    script
}

fn append_fish_option_candidates(
    command: &clap::Command,
    ancestors: &mut Vec<String>,
    rules: &mut Vec<String>,
) {
    for subcommand in command.get_subcommands() {
        let Some(name) = subcommand.get_name().split_whitespace().next() else {
            continue;
        };
        ancestors.push(name.to_owned());

        let options = subcommand
            .get_arguments()
            .filter(|argument| !argument.is_hide_set())
            .filter_map(|argument| argument.get_long().map(|long| format!("--{long}")))
            .collect::<Vec<_>>();

        if !options.is_empty() {
            let condition = ancestors
                .iter()
                .map(|part| format!("__fish_seen_subcommand_from {part}"))
                .collect::<Vec<_>>()
                .join("; and ");
            rules.push(format!(
                "complete -c proxyctl -a '{}' -n '{}'",
                options.join(" "),
                condition
            ));
        }

        append_fish_option_candidates(subcommand, ancestors, rules);
        ancestors.pop();
    }
}

fn install_shell_completion(shell: crate::services::shell_completion::Shell) -> anyhow::Result<()> {
    let completion_shell = match shell {
        crate::services::shell_completion::Shell::Bash => Shell::Bash,
        crate::services::shell_completion::Shell::Fish => Shell::Fish,
        crate::services::shell_completion::Shell::Zsh => Shell::Zsh,
    };
    let path =
        crate::services::shell_completion::install(shell, &completion_script(completion_shell))?;
    println!("{} completion installed: {}", shell.name(), path.display());
    match shell {
        crate::services::shell_completion::Shell::Fish => {
            println!("Fish loads it automatically in new sessions.")
        }
        crate::services::shell_completion::Shell::Bash => {
            println!("Bash loads it automatically when bash-completion is installed and enabled.")
        }
        crate::services::shell_completion::Shell::Zsh => println!(
            "Zsh completion path was added to ~/.zshrc; restart Zsh or run 'source ~/.zshrc'."
        ),
    }
    Ok(())
}

fn offer_first_setup_completion() -> anyhow::Result<()> {
    use crate::services::shell_completion;
    use std::io::{self, IsTerminal, Write};

    let Some(shell) = shell_completion::detect_current() else {
        return Ok(());
    };
    if !io::stdin().is_terminal() || !shell_completion::should_offer_first_setup_prompt(shell)? {
        return Ok(());
    }

    print!(
        "Install {} tab completion for proxyctl now? [y/N] ",
        shell.name()
    );
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    shell_completion::mark_first_setup_prompted(shell)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        install_shell_completion(shell)?;
    } else {
        println!("Skipped. You can install it later with: proxyctl completions install");
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

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command, TunCommand, display_core_version};

    #[test]
    fn use_foreground_is_available_only_for_loopback_mode() {
        let parsed =
            Cli::try_parse_from(["proxyctl", "use", "7", "--core", "xray", "--foreground"])
                .expect("ordinary foreground activation arguments should parse");
        assert!(matches!(
            parsed.command,
            Some(Command::Use {
                foreground: true,
                tun: false,
                ..
            })
        ));
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "use",
                "7",
                "--core",
                "xray",
                "--foreground",
                "--tun",
            ])
            .is_err(),
            "foreground must not bypass the unfinished TUN supervisor lifecycle"
        );
    }

    #[test]
    fn every_supported_shell_completes_subcommand_options() {
        for shell in [
            clap_complete::Shell::Bash,
            clap_complete::Shell::Fish,
            clap_complete::Shell::Zsh,
        ] {
            let script = super::completion_script(shell);
            assert!(!script.is_empty(), "empty script for {shell:?}");
            for expected in ["proxyctl", "completions", "test"] {
                assert!(
                    script.contains(expected),
                    "{shell:?} completion script is missing {expected}"
                );
            }
            let command_options = [
                "protocol",
                "details",
                "yes",
                "core",
                "tun",
                "foreground",
                "all-cores",
                "latency-only",
                "download-only",
                "upload-only",
                "history",
                "unavailable-all",
                "prerelease",
            ];
            for option in command_options {
                let expected = match shell {
                    clap_complete::Shell::Fish => format!("-l {option}"),
                    _ => format!("--{option}"),
                };
                assert!(
                    script.contains(&expected),
                    "{shell:?} completion script is missing {expected}"
                );
            }
        }
    }

    #[test]
    fn fish_completion_offers_options_for_all_commands_without_hiding_import_paths() {
        let script = super::completion_script(clap_complete::Shell::Fish);
        assert!(script.starts_with("complete -c proxyctl -f\n"));
        assert!(
            script.contains("complete -c proxyctl -F -n '__fish_seen_subcommand_from import'"),
            "Fish completion must retain file suggestions for import"
        );

        for (command, option) in [
            ("list", "--protocol"),
            ("show", "--details"),
            ("remove", "--yes"),
            ("check", "--core"),
            ("use", "--tun"),
            ("use", "--foreground"),
            ("test", "--all-cores"),
            ("report", "--history"),
            ("prune", "--unavailable-all"),
            ("update", "--prerelease"),
        ] {
            let expected = "complete -c proxyctl -a ";
            assert!(
                script.lines().any(|line| {
                    line.starts_with(expected)
                        && line.contains(option)
                        && line.contains(&format!("__fish_seen_subcommand_from {command}"))
                }),
                "Fish completion is missing {option} for {command}"
            );
        }
    }

    #[test]
    fn positional_value_completions_are_generated_for_all_shells() {
        for shell in [
            clap_complete::Shell::Bash,
            clap_complete::Shell::Fish,
            clap_complete::Shell::Zsh,
        ] {
            let script = super::completion_script(shell);
            for expected in [
                "listen-port",
                "compact",
                "normal",
                "full",
                "tcp-ping",
                "tested",
                "sing-box",
                "xray",
                "mihomo",
            ] {
                assert!(
                    script.contains(expected),
                    "{shell:?} completion is missing positional or option value {expected}"
                );
            }
        }
    }

    #[test]
    fn completions_command_supports_generation_and_installation_for_all_shells() {
        for shell in ["bash", "fish", "zsh"] {
            assert!(Cli::try_parse_from(["proxyctl", "completions", "generate", shell]).is_ok());
        }
        assert!(Cli::try_parse_from(["proxyctl", "completions", "install"]).is_ok());
        for shell in ["bash", "fish", "zsh"] {
            assert!(
                Cli::try_parse_from(["proxyctl", "completions", "install", "--shell", shell])
                    .is_ok()
            );
        }
        assert!(Cli::try_parse_from(["proxyctl", "completions", "generate", "unknown"]).is_err());
        assert!(
            Cli::try_parse_from(["proxyctl", "completions", "install", "--shell", "nu"]).is_err()
        );
    }

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
        assert!(Cli::try_parse_from(["proxyctl", "show", "--details", "all"]).is_ok());
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
        assert!(Cli::try_parse_from(["proxyctl", "report", "--details"]).is_ok());
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
    fn test_command_defaults_to_quick_profile_and_accepts_accurate_override() {
        let default = Cli::try_parse_from(["proxyctl", "test", "--all-cores"]).unwrap();
        assert!(matches!(
            default.command,
            Some(Command::Test { ref profile, download_bytes: None, upload_bytes: None, .. })
                if profile == "quick"
        ));
        let accurate =
            Cli::try_parse_from(["proxyctl", "test", "--all-cores", "--profile", "accurate"])
                .unwrap();
        assert!(matches!(
            accurate.command,
            Some(Command::Test { ref profile, .. }) if profile == "accurate"
        ));
        assert!(
            Cli::try_parse_from(["proxyctl", "test", "--all-cores", "--profile", "invalid"])
                .is_err()
        );
    }

    #[test]
    fn test_command_defaults_to_socks5_and_accepts_http_override() {
        let default = Cli::try_parse_from(["proxyctl", "test", "--all-cores"]).unwrap();
        assert!(
            matches!(default.command, Some(Command::Test { ref proxy_type, .. }) if proxy_type == "socks5")
        );
        let http = Cli::try_parse_from(["proxyctl", "test", "--all-cores", "--proxy-type", "http"])
            .unwrap();
        assert!(
            matches!(http.command, Some(Command::Test { ref proxy_type, .. }) if proxy_type == "http")
        );
        assert!(
            Cli::try_parse_from(["proxyctl", "test", "--all-cores", "--proxy-type", "invalid"])
                .is_err()
        );
    }

    #[test]
    fn test_command_exposes_bounded_concurrency_and_separate_timeouts() {
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "test",
                "--all-cores",
                "--latency-timeout-secs",
                "4",
                "--request-timeout-secs",
                "25",
                "--concurrency",
                "2"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from(["proxyctl", "test", "--all-cores", "--concurrency", "4"]).is_err()
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
    fn node_purge_requires_explicit_deleted_scope_and_supports_preview_or_apply() {
        assert!(Cli::try_parse_from(["proxyctl", "nodes", "purge"]).is_err());
        assert!(Cli::try_parse_from(["proxyctl", "nodes", "purge", "--deleted"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "nodes",
                "purge",
                "--deleted",
                "--older-than",
                "30d",
                "--apply"
            ])
            .is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "proxyctl",
                "nodes",
                "purge",
                "--deleted",
                "--apply",
                "--dry-run"
            ])
            .is_err()
        );
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
    fn tun_cli_accepts_start_stop_and_status_without_legacy_aliases() {
        let cli = Cli::try_parse_from(["proxyctl", "tun", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Command::Tun {
                command: TunCommand::Status
            })
        ));
        let start = Cli::try_parse_from(["proxyctl", "tun", "start"]).unwrap();
        assert!(matches!(
            start.command,
            Some(Command::Tun {
                command: TunCommand::Start { foreground: false }
            })
        ));
        let foreground = Cli::try_parse_from(["proxyctl", "tun", "start", "--foreground"]).unwrap();
        assert!(matches!(
            foreground.command,
            Some(Command::Tun {
                command: TunCommand::Start { foreground: true }
            })
        ));
        let stop = Cli::try_parse_from(["proxyctl", "tun", "stop"]).unwrap();
        assert!(matches!(
            stop.command,
            Some(Command::Tun {
                command: TunCommand::Stop
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
            "1048576",
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
                download_bytes: Some(1_048_576),
                upload_bytes: Some(1_048_576),
                ..
            }) if node == &vec!["7".to_owned()] && core == "sing-box"
        ));
    }
}
