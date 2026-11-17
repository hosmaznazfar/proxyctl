//! CLI output formatting and tabular presentation.
use std::collections::HashMap;

use tabled::builder::Builder;

use crate::{
    cores::CoreId,
    database::NodeRecord,
    services::{
        reporting,
        sorting::{self, SortMetric},
    },
};

use super::*;
use super::table::{self, Separator};

pub(super) fn print_display_config(config: &crate::services::display_config::DisplayConfig) {
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
        "Available fields: node, name, server, port, protocol, core, version, latency, tcp-ping, download, upload, status, attempts, failures, run, tested"
    );
    println!("Add:    proxyctl config display add-field <compact|normal|full> <field>");
    println!("Remove: proxyctl config display remove-field <compact|normal|full> <field>");
}

pub(super) fn print_node_results(
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
                            .map(|summary| metric_summary_cell(summary, false))
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
    let mut table_view = builder.build();
    let widths = fields.iter().map(|field| report_column_width(*field)).collect::<Vec<_>>();
    table::apply_formatting(&mut table_view, &widths, &[]);
    println!("{table_view}");
}

pub(super) fn aggregate_target_status(
    summaries: &[&reporting::MetricSummary],
    run_status: crate::domain::BenchmarkRunStatus,
) -> String {
    use crate::domain::BenchmarkSampleStatus as S;
    for (status, label) in [
        (S::Unavailable, "unavailable"),
        (S::Unsupported, "unsupported"),
        (S::Invalid, "invalid"),
        (S::Timeout, "timeout"),
        (S::Incomplete, "incomplete"),
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

pub(super) fn metric_summary_cell(summary: &reporting::MetricSummary, verbose: bool) -> String {
    let mut parts = Vec::new();

    if let Some(value) = summary.median {
        let formatted = if summary.metric == crate::domain::BenchmarkMetric::Download
            || summary.metric == crate::domain::BenchmarkMetric::Upload
        {
            format!("{:.2} Mbps", value / 1_000_000.0)
        } else {
            format!("{value:.0} ms")
        };
        parts.push(formatted);
        parts.push(format!("{}/3", summary.successful));
        if summary.partial_successful > 0 {
            parts.push(format!("{} partial", summary.partial_successful));
        }
    } else if let Some(status) = summary.preflight {
        parts.push(sample_status_label(status).to_owned());
    } else if summary.attempted == 0 {
        parts.push("not run".into());
    } else {
        parts.push(
            summary
                .failures
                .iter()
                .map(|failure| {
                    format!("{} ×{}", sample_status_label(failure.status), failure.count)
                })
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    if verbose {
        if summary.median.is_some() && !summary.failures.is_empty() {
            parts.push(format!(
                "failed: {}",
                summary
                    .failures
                    .iter()
                    .map(|failure| {
                        format!("{} ×{}", sample_status_label(failure.status), failure.count)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        for attempt in &summary.failed_transfers {
            let bytes = attempt
                .transferred_bytes
                .map(format_byte_count)
                .unwrap_or_else(|| "size unknown".into());
            let duration = attempt
                .duration_ms
                .map(|value| format!("{:.1}s", value as f64 / 1000.0))
                .unwrap_or_else(|| "time unknown".into());
            parts.push(format!("attempt {}: {bytes} in {duration}", attempt.sample_index));
        }
        if let Some(endpoint) = &summary.endpoint {
            parts.push(format!("via {}", endpoint_label(endpoint)));
        }
    }

    parts.join(" · ")
}

fn format_byte_count(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= 1024 {
        format!("{:.0} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn endpoint_label(endpoint: &str) -> String {
    let host = endpoint.split('/').next().unwrap_or(endpoint);
    match host {
        "www.google.com" | "google.com" => "Google".into(),
        "cachefly.cachefly.net" => "CacheFly".into(),
        "speed.cloudflare.com" => "Cloudflare".into(),
        _ => host.to_owned(),
    }
}

pub(super) fn print_benchmark_report(
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

    if report.mode == ReportMode::Compare {
        let mut comparisons = report.comparisons.iter().collect::<Vec<_>>();
        comparisons.sort_by(|left, right| {
            let left_number = display_numbers.get(&left.node.id).copied().unwrap_or(left.node.id as usize);
            let right_number = display_numbers.get(&right.node.id).copied().unwrap_or(right.node.id as usize);
            left_number.cmp(&right_number).then_with(|| report_target_order(&left.target).cmp(&report_target_order(&right.target)))
        });
        for comparison in comparisons {
            if comparison.target == "direct" && !fields.contains(&F::TcpPing) {
                continue;
            }
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
        if builder.count_records() == 1 {
            println!("No completed benchmark comparisons found.");
            return;
        }
    } else {
        let mut nodes = report.nodes.iter().collect::<Vec<_>>();
        nodes.sort_by_key(|node| display_numbers.get(&node.node.id).copied().unwrap_or(node.node.id as usize));
        let mut separators = Vec::new();

        for (node_index, node) in nodes.iter().enumerate() {
            let rows_before_node = builder.count_records();
            if node.runs.is_empty() {
                builder.push_record(report_empty_node_row(&fields, &node.node, display_numbers));
            } else {
                let mut targets = node
                    .runs
                    .iter()
                    .flat_map(|run| run.targets.iter().map(|target| target.target.clone()))
                    .collect::<Vec<_>>();
                targets.sort_by(|left, right| report_target_order(left).cmp(&report_target_order(right)));
                targets.dedup();
                if !fields.contains(&F::TcpPing) {
                    targets.retain(|target| target != "direct");
                }

                // Group by core first, then keep each core's runs newest-first.
                let target_count = targets.len();
                for (target_index, target_name) in targets.into_iter().enumerate() {
                    for run in &node.runs {
                        let Some(target) = run.targets.iter().find(|item| item.target == target_name)
                        else {
                            continue;
                        };
                        if target.target == "direct" && !fields.contains(&F::TcpPing) {
                            continue;
                        }
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
                    if target_index + 1 < target_count {
                        separators.push(Separator::Dotted(builder.count_records()));
                    }
                }
            }

            if builder.count_records() == rows_before_node {
                continue;
            }
            if node_index + 1 < nodes.len() {
                separators.push(Separator::Solid(builder.count_records()));
            }
        }

        if builder.count_records() == 1 {
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

        let mut table_view = builder.build();
        let widths = fields.iter().map(|field| report_column_width(*field)).collect::<Vec<_>>();
        table::apply_formatting(&mut table_view, &widths, &separators);
        println!("{table_view}");
        return;
    }

    let mut table_view = builder.build();
    let widths = fields.iter().map(|field| report_column_width(*field)).collect::<Vec<_>>();
    table::apply_formatting(&mut table_view, &widths, &[]);
    println!("{table_view}");
}

fn report_target_order(target: &str) -> (u8, &str) {
    let order = match target {
        "sing-box" => 0,
        "xray" => 1,
        "mihomo" => 2,
        "direct" => 3,
        _ => 4,
    };
    (order, target)
}

fn report_column_width(field: crate::services::display_config::DisplayField) -> usize {
    use crate::services::display_config::DisplayField as F;
    match field {
        F::Node => 4,
        F::Core => 8,
        F::Version => 10,
        F::Server | F::Name => 16,
        F::Protocol => 10,
        F::Port => 5,
        F::Status => 10,
        F::Samples | F::Failures => 7,
        F::Run => 6,
        F::Tested => 12,
        F::Latency | F::TcpPing | F::Download | F::Upload => 18,
    }
}


pub(super) fn report_empty_node_row(
    fields: &[crate::services::display_config::DisplayField],
    node: &NodeRecord,
    display_numbers: &HashMap<u64, usize>,
) -> Vec<String> {
    use crate::services::display_config::DisplayField as F;
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
            F::Core | F::Version | F::Samples | F::Failures | F::Run | F::Tested => "-".into(),
            F::Latency | F::TcpPing | F::Download | F::Upload | F::Status => "not-run".into(),
        })
        .collect()
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
            .map(|summary| metric_summary_cell(summary, data.verbose))
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
                data.run_status
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

pub(super) fn display_core_version(version: &str, verbose: bool) -> String {
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

pub(super) fn run_status_label(status: crate::domain::BenchmarkRunStatus) -> &'static str {
    match status {
        crate::domain::BenchmarkRunStatus::Running => "running",
        crate::domain::BenchmarkRunStatus::Completed => "completed",
        crate::domain::BenchmarkRunStatus::Interrupted => "interrupted",
        crate::domain::BenchmarkRunStatus::Cancelled => "cancelled",
    }
}

pub(super) fn sample_status_label(status: crate::domain::BenchmarkSampleStatus) -> &'static str {
    match status {
        crate::domain::BenchmarkSampleStatus::Success => "success",
        crate::domain::BenchmarkSampleStatus::Unreachable => "unreachable",
        crate::domain::BenchmarkSampleStatus::Unsupported => "unsupported",
        crate::domain::BenchmarkSampleStatus::Invalid => "invalid",
        crate::domain::BenchmarkSampleStatus::Timeout => "timeout",
        crate::domain::BenchmarkSampleStatus::Incomplete => "incomplete",
        crate::domain::BenchmarkSampleStatus::Unavailable => "unavailable",
        crate::domain::BenchmarkSampleStatus::Skipped => "skipped",
        crate::domain::BenchmarkSampleStatus::Cancelled => "cancelled",
    }
}

pub(super) fn active_display_numbers(
    path: &std::path::Path,
) -> anyhow::Result<HashMap<u64, usize>> {
    Ok(nodes::list_nodes(path, false)?
        .into_iter()
        .enumerate()
        .map(|(index, record)| (record.id, index + 1))
        .collect())
}

pub(super) fn deleted_display_numbers(
    path: &std::path::Path,
) -> anyhow::Result<HashMap<u64, usize>> {
    Ok(nodes::list_nodes(path, true)?
        .into_iter()
        .filter(|record| record.is_deleted())
        .enumerate()
        .map(|(index, record)| (record.id, index + 1))
        .collect())
}

pub(super) fn parse_core(value: Option<&str>) -> anyhow::Result<Option<CoreId>> {
    value.map(str::parse).transpose()
}

pub(super) fn print_node_list(
    records: &[NodeRecord],
    display_numbers: &HashMap<u64, usize>,
    deleted_display_numbers: &HashMap<u64, usize>,
) {
    if records.is_empty() {
        println!("No proxy nodes found.");
        return;
    }

    let mut builder = Builder::default();
    builder.push_record(["NO.", "PROTOCOL", "SERVER", "PORT", "NAME"]);
    for record in records {
        builder.push_record([
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
            record.node.protocol.to_string(),
            safe_field(&record.node.server, usize::MAX),
            record.node.port.to_string(),
            record.node.name.as_deref().map(|name| safe_field(name, usize::MAX)).unwrap_or_else(|| "-".to_owned()),
        ]);
    }

    let mut table_view = builder.build();
    table::apply_formatting(&mut table_view, &[5, 12, 32, 5, 32], &[]);
    println!("{table_view}");
}

pub(super) fn print_sorted_node_list(
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
    let mut builder = Builder::default();
    builder.push_record(["RANK", "NO.", "PROTOCOL", "SERVER", "PORT", metric.label(), "CORE(S)", "NAME"]);
    for (index, record) in records.iter().enumerate() {
        let value = match record.value {
            Some(value) if record.unit == "ms" => format!("{value:.2} ms"),
            Some(value) => format!("{:.2} Mbps", value / 1_000_000.0),
            None => "unmeasured".to_owned(),
        };
        builder.push_record([
            if record.value.is_some() { (index + 1).to_string() } else { "-".into() },
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
            record.node.node.protocol.to_string(),
            safe_field(&record.node.node.server, usize::MAX),
            record.node.node.port.to_string(),
            value,
            safe_field(&record.cores, usize::MAX),
            record.node.node.name.as_deref().map(|name| safe_field(name, usize::MAX)).unwrap_or_else(|| "-".to_owned()),
        ]);
    }

    let mut table_view = builder.build();
    table::apply_formatting(
        &mut table_view,
        &[4, 5, 12, 32, 5, 14, core_width.max(7), 32],
        &[],
    );
    println!("{table_view}");
}

pub(super) fn print_node_details(records: &[NodeRecord], display_numbers: &HashMap<u64, usize>) {
    if records.is_empty() {
        println!("No matching nodes.");
        return;
    }

    let mut builder = Builder::default();
    builder.push_record([
        "NODE", "PROTOCOL", "SERVER", "PORT", "NAME", "STATUS", "IDENTITY", "SECRET", "OPTIONS",
    ]);
    for record in records {
        let node = &record.node;
        let options = if node.options.is_empty() {
            "-".to_owned()
        } else {
            format!(
                "{} (values hidden)",
                node.options
                    .keys()
                    .map(|key| safe_field(key, 48))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        builder.push_record([
            display_numbers
                .get(&record.id)
                .copied()
                .unwrap_or(record.id as usize)
                .to_string(),
            node.protocol.to_string(),
            safe_field(&node.server, 200),
            node.port.to_string(),
            node.name
                .as_deref()
                .map(|name| safe_field(name, 200))
                .unwrap_or_else(|| "-".to_owned()),
            if record.is_deleted() {
                "deleted"
            } else {
                "active"
            }
            .to_owned(),
            if node.identity.is_some() {
                "[masked]"
            } else {
                "-"
            }
            .to_owned(),
            if node.secret.is_some() {
                "[masked]"
            } else {
                "-"
            }
            .to_owned(),
            options,
        ]);
    }

    let mut table_view = builder.build();
    table::apply_formatting(&mut table_view, &[6, 12, 24, 6, 20, 8, 10, 10, 24], &[]);
    println!("{table_view}");
}

pub(super) fn safe_field(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(max_chars)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        domain::{BenchmarkMetric, BenchmarkSampleStatus},
        services::reporting::{FailedTransferDetail, FailureCount, MetricSummary},
    };

    #[test]
    fn report_core_order_groups_each_nodes_history_consistently() {
        let mut targets = ["mihomo", "direct", "xray", "sing-box", "other"]
            .into_iter()
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| report_target_order(left).cmp(&report_target_order(right)));
        assert_eq!(targets, ["sing-box", "xray", "mihomo", "direct", "other"]);
    }

    #[test]
    fn verbose_metric_cell_keeps_failed_attempts_alongside_successes() {
        let summary = MetricSummary {
            metric: BenchmarkMetric::Download,
            endpoint: Some("example.test/download".into()),
            successful: 1,
            partial_successful: 1,
            attempted: 3,
            median: Some(250_000.0),
            failures: vec![FailureCount {
                status: BenchmarkSampleStatus::Timeout,
                count: 2,
            }],
            failed_transfers: vec![FailedTransferDetail {
                sample_index: 2,
                transferred_bytes: Some(1_572_864),
                duration_ms: Some(20_000),
            }],
            preflight: None,
        };

        let concise = metric_summary_cell(&summary, false);
        assert!(concise.contains("0.25 Mbps"));
        assert!(!concise.contains("example.test"));
        assert!(!concise.contains("1572864"));

        let verbose = metric_summary_cell(&summary, true);
        assert!(verbose.contains("timeout ×2"));
        assert!(verbose.contains("attempt 2: 1.5 MiB in 20.0s"));
        assert!(verbose.contains("via example.test"));
    }
}
