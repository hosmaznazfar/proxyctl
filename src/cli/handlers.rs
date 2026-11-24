//! CLI command handlers. Argument definitions remain in the parent CLI module.
use super::*;

pub fn dispatch(cli: Cli) -> anyhow::Result<()> {
    let Some(command) = cli.command else {
        println!("Proxyctl is ready. Use --help to see available commands.");
        return Ok(());
    };
    let command = match command {
        Command::Completions { action } => {
            match action {
                CompletionAction::Generate { shell } => {
                    let script = completion_script(shell);
                    print!("{script}");
                }
                CompletionAction::Install { shell } => {
                    let selected = match shell {
                        Some(value) => crate::services::shell_completion::Shell::parse(&value)?,
                        None => crate::services::shell_completion::detect_current()
                            .ok_or_else(|| anyhow::anyhow!("could not detect the current shell; specify --shell bash, --shell fish, or --shell zsh"))?,
                    };
                    install_shell_completion(selected)?;
                }
            }
            return Ok(());
        }
        Command::Tun {
            command: TunCommand::Status,
        } => {
            crate::tun::inspect()?.print();
            let manager = crate::tun::service_manager::ServiceManager::detect();
            let backend = crate::tun::recovery::RecoveryBackendKind::for_manager(manager);
            println!("Init/service manager: {}", manager.as_str());
            println!(
                "Crash-recovery supervisor: {}",
                if backend.is_implemented() {
                    format!("{} (implemented)", backend.as_str())
                } else {
                    format!("{} (not implemented)", backend.as_str())
                }
            );
            println!(
                "TUN activation: Xray is wired to the broker-owned descriptor, bounded HTTP dataplane probe, and generation-bound stop/recovery path; runtime validation has not been performed. sing-box/Mihomo remain unsupported pending native-device ownership backends."
            );
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
            foreground,
            port,
            tun_probe_url,
            tun_probe_status,
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
            if tun {
                crate::services::activation::activate_tun_core(
                    stable_id,
                    core,
                    port,
                    &tun_probe_url,
                    tun_probe_status,
                )?;
            } else {
                crate::services::activation::activate(stable_id, core, false, port, foreground)?;
            }
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
        Command::Status => {
            crate::services::activation::status()?;
            return Ok(());
        }
        Command::Stop => {
            crate::services::activation::stop()?;
            return Ok(());
        }
        Command::Setup { core } => {
            crate::services::cores::setup(parse_core(core.as_deref())?)?;
            offer_first_setup_completion()?;
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
        // Completion commands are handled before database initialization above.
        Command::Completions { .. } => {
            unreachable!("completion command returned before database access")
        }
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
                let display_numbers = active_display_numbers(&database_path)?;
                let records = ids
                    .into_iter()
                    .map(|id| nodes::get_node(&database_path, id))
                    .collect::<anyhow::Result<Vec<_>>>()?
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                print_node_details(&records, &display_numbers);
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
        Command::Nodes {
            command:
                NodesCommand::Purge {
                    deleted: _,
                    older_than,
                    apply,
                    ..
                },
        } => {
            let summary = nodes::purge_deleted_nodes(&database_path, &older_than, apply)?;
            if apply {
                println!(
                    "Permanent purge complete: {} node(s), {} benchmark sample(s), {} empty run(s) removed; {} node(s) skipped because a benchmark is running.",
                    summary.purged_nodes,
                    summary.removed_samples,
                    summary.removed_runs,
                    summary.skipped_running
                );
            } else {
                println!(
                    "Dry run: {} deleted node(s) eligible; {} protected by running benchmarks. No changes made. Use --apply to permanently remove eligible nodes and their associated benchmark samples.",
                    summary.eligible_nodes - summary.skipped_running,
                    summary.skipped_running
                );
            }
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
            details,
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
            let mut display_config = crate::services::display_config::load()?;
            if details {
                display_config.active_profile =
                    crate::services::display_config::DisplayProfile::Full;
            }
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
            proxy_type,
            latency_url,
            download_url,
            upload_url,
            latency_only,
            download_only,
            upload_only,
            profile,
            download_bytes,
            upload_bytes,
            request_timeout_secs,
            latency_timeout_secs,
            concurrency,
            startup_timeout_secs,
        } => {
            let request_timeout_ms = request_timeout_secs
                .checked_mul(1_000)
                .ok_or_else(|| anyhow::anyhow!("request timeout is too large"))?;
            let latency_timeout_ms = latency_timeout_secs
                .checked_mul(1_000)
                .ok_or_else(|| anyhow::anyhow!("latency timeout is too large"))?;
            let startup_timeout_ms = startup_timeout_secs
                .checked_mul(1_000)
                .ok_or_else(|| anyhow::anyhow!("startup timeout is too large"))?;
            let selected_profile = match profile.as_str() {
                "quick" => crate::domain::BenchmarkProfile::Quick,
                "accurate" => crate::domain::BenchmarkProfile::Accurate,
                _ => unreachable!("clap validates benchmark profile"),
            };
            let mut settings = crate::services::benchmark::default_settings_for(selected_profile);
            settings.proxy_type = match proxy_type.as_str() {
                "socks5" => crate::domain::BenchmarkProxyType::Socks5,
                "http" => crate::domain::BenchmarkProxyType::Http,
                _ => unreachable!("clap validates benchmark proxy type"),
            };
            settings.latency_url = latency_url;
            settings.download_url = download_url;
            settings.upload_url = upload_url;
            if let Some(bytes) = download_bytes {
                settings.download_bytes = bytes;
            }
            if let Some(bytes) = upload_bytes {
                settings.upload_bytes = bytes;
            }
            settings.request_timeout_ms = request_timeout_ms;
            settings.latency_timeout_ms = latency_timeout_ms;
            settings.probe_concurrency = concurrency;
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
            crate::services::benchmark::run_benchmark(
                &database_path,
                crate::services::benchmark::BenchmarkOptions {
                    all_cores,
                    node_id: None,
                    node_ids: selected,
                    core: parse_core(core.as_deref())?,
                    settings,
                    metric_selection,
                },
            )?;
        }
        Command::Cores
        | Command::Setup { .. }
        | Command::Update { .. }
        | Command::Use { .. }
        | Command::Config { .. }
        | Command::Status
        | Command::Stop
        | Command::Tun { .. } => {
            unreachable!("management commands are dispatched before database access")
        }
    }
    Ok(())
}
