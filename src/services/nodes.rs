//! Node-management use cases.

use std::path::Path;

use anyhow::Context;

use crate::{
    database::{AddNodeOutcome, NodeDatabase, NodeRecord},
    parser::{ParseError, parse_proxy_url},
};

#[derive(Debug, Default)]
pub struct ImportSummary {
    pub added: usize,
    pub duplicates: usize,
    pub invalid: usize,
    pub failures: Vec<ImportFailure>,
    pub warnings: Vec<ImportLineWarning>,
}

#[derive(Debug)]
pub struct ImportLineWarning {
    pub line_number: usize,
    pub warning: super::import_warnings::ImportWarning,
}

#[derive(Debug)]
pub struct ImportFailure {
    pub line_number: usize,
    pub reason: String,
}

pub fn add_url(database_path: &Path, input: &str) -> anyhow::Result<AddNodeOutcome> {
    let node = parse_proxy_url(input)?;
    let database = NodeDatabase::open(database_path)?;
    database.add_node(&node)
}

/// Import URL lists or supported structured JSON profiles without modifying the source file.
pub fn import_file(database_path: &Path, source_path: &Path) -> anyhow::Result<ImportSummary> {
    let content = std::fs::read_to_string(source_path)
        .with_context(|| format!("could not read import file {}", source_path.display()))?;
    let content = decode_subscription_text(&content);
    let database = NodeDatabase::open(database_path)?;
    let mut summary = ImportSummary::default();

    if content.trim_start().starts_with('{') {
        match crate::parser::structured::parse_profile_detailed(&content) {
            Ok(profile) => {
                for skipped in profile.skipped {
                    summary.invalid += 1;
                    summary.failures.push(ImportFailure {
                        line_number: skipped.index,
                        reason: skipped.reason.into(),
                    });
                }
                for node in profile.nodes {
                    summary.warnings.extend(
                        super::import_warnings::analyze(&node)
                            .into_iter()
                            .map(|warning| ImportLineWarning {
                                line_number: 1,
                                warning,
                            }),
                    );
                    match database.add_node(&node)? {
                        AddNodeOutcome::Added(_) => summary.added += 1,
                        AddNodeOutcome::Duplicate(_) => summary.duplicates += 1,
                    }
                }
                if summary.added + summary.duplicates == 0 && summary.invalid == 0 {
                    summary.invalid = 1;
                    summary.failures.push(ImportFailure {
                        line_number: 1,
                        reason: "profile contains no outbound entries".into(),
                    });
                }
            }
            Err(_) => {
                summary.invalid = 1;
                summary.failures.push(ImportFailure {
                    line_number: 1,
                    reason: "structured profile could not be parsed".into(),
                });
            }
        }
        return Ok(summary);
    }

    if content.trim_start().starts_with("proxies:") {
        match crate::parser::mihomo::parse_profile_detailed(&content) {
            Ok(profile) => {
                for skipped in profile.skipped {
                    summary.invalid += 1;
                    summary.failures.push(ImportFailure {
                        line_number: skipped.index,
                        reason: skipped.reason.into(),
                    });
                }
                for node in profile.nodes {
                    summary.warnings.extend(
                        super::import_warnings::analyze(&node)
                            .into_iter()
                            .map(|warning| ImportLineWarning {
                                line_number: 1,
                                warning,
                            }),
                    );
                    match database.add_node(&node)? {
                        AddNodeOutcome::Added(_) => summary.added += 1,
                        AddNodeOutcome::Duplicate(_) => summary.duplicates += 1,
                    }
                }
                if summary.added + summary.duplicates == 0 && summary.invalid == 0 {
                    summary.invalid = 1;
                    summary.failures.push(ImportFailure {
                        line_number: 1,
                        reason: "YAML profile contains no proxy entries".into(),
                    });
                }
            }
            Err(_) => {
                summary.invalid = 1;
                summary.failures.push(ImportFailure {
                    line_number: 1,
                    reason: "Mihomo YAML profile could not be parsed".into(),
                });
            }
        }
        return Ok(summary);
    }
    for (index, line) in content.lines().enumerate() {
        let input = line.trim();
        if input.is_empty() || input.starts_with('#') {
            continue;
        }
        match parse_proxy_url(input) {
            Ok(node) => {
                summary
                    .warnings
                    .extend(
                        super::import_warnings::analyze(&node)
                            .into_iter()
                            .map(|warning| ImportLineWarning {
                                line_number: index + 1,
                                warning,
                            }),
                    );
                match database.add_node(&node)? {
                    AddNodeOutcome::Added(_) => summary.added += 1,
                    AddNodeOutcome::Duplicate(_) => summary.duplicates += 1,
                }
            }
            Err(error) => {
                summary.invalid += 1;
                summary.failures.push(ImportFailure {
                    line_number: index + 1,
                    reason: safe_parse_error(error),
                });
            }
        }
    }
    Ok(summary)
}

/// Decode common plain-text Base64 subscription payloads conservatively.
/// Only use the decoded value when it is valid UTF-8 and clearly looks like a
/// supported URL list or JSON profile; otherwise retain the original content.
fn decode_subscription_text(input: &str) -> String {
    use base64::Engine as _;
    let trimmed = input.trim();
    if trimmed.is_empty()
        || trimmed.contains("://")
        || trimmed.starts_with('{')
        || trimmed.starts_with('#')
    {
        return input.to_owned();
    }
    let compact = trimmed
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&compact) else {
        return input.to_owned();
    };
    let Ok(decoded) = String::from_utf8(bytes) else {
        return input.to_owned();
    };
    let text = decoded.trim();
    if text.starts_with('{')
        || text.starts_with("proxies:")
        || text.lines().any(|line| line.trim().contains("://"))
    {
        decoded
    } else {
        input.to_owned()
    }
}

pub fn list_nodes(database_path: &Path, include_deleted: bool) -> anyhow::Result<Vec<NodeRecord>> {
    NodeDatabase::open(database_path)?.list_nodes(include_deleted)
}

pub fn get_node(path: &Path, id: u64) -> anyhow::Result<Option<NodeRecord>> {
    NodeDatabase::open(path)?.get_node(id)
}

/// Return the current one-based display position for an active persistent node ID.
pub fn active_display_number(path: &Path, id: u64) -> anyhow::Result<Option<usize>> {
    Ok(NodeDatabase::open(path)?
        .list_nodes(false)?
        .iter()
        .position(|record| record.id == id)
        .map(|index| index + 1))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BatchNodeSummary {
    pub changed: Vec<u64>,
    pub missing: Vec<u64>,
    pub unchanged: Vec<u64>,
}

pub fn resolve_node_selection(
    path: &Path,
    selection: &super::node_selection::NodeSelection,
    include_deleted: bool,
) -> anyhow::Result<Vec<u64>> {
    let database = NodeDatabase::open(path)?;
    match selection {
        super::node_selection::NodeSelection::All => Ok(database
            .list_nodes(true)?
            .into_iter()
            .filter(|record| record.is_deleted() == include_deleted)
            .map(|record| record.id)
            .collect()),
        // Both active and deleted selectors are one-based positions in their
        // respective lists. Persistent IDs never escape this resolution boundary.
        super::node_selection::NodeSelection::Ids(positions) => {
            let records = database.list_nodes(include_deleted)?;
            let selected = if include_deleted {
                records
                    .into_iter()
                    .filter(NodeRecord::is_deleted)
                    .collect::<Vec<_>>()
            } else {
                records
            };
            positions
                .iter()
                .map(|position| {
                    let index = usize::try_from(*position - 1)
                        .map_err(|_| anyhow::anyhow!("node number {position} is out of range"))?;
                    selected.get(index).map(|record| record.id).ok_or_else(|| {
                        anyhow::anyhow!(
                            "node number {position} does not exist; there are {} {} node(s)",
                            selected.len(),
                            if include_deleted { "deleted" } else { "active" }
                        )
                    })
                })
                .collect()
        }
    }
}

pub fn remove_nodes(path: &Path, ids: &[u64]) -> anyhow::Result<BatchNodeSummary> {
    let database = NodeDatabase::open(path)?;
    let mut summary = BatchNodeSummary::default();
    for id in ids {
        match database.get_node(*id)? {
            None => summary.missing.push(*id),
            Some(record) if record.is_deleted() => summary.unchanged.push(*id),
            Some(_) if database.soft_delete(*id)? => summary.changed.push(*id),
            Some(_) => summary.unchanged.push(*id),
        }
    }
    Ok(summary)
}

/// Permanently purge soft-deleted nodes whose deletion age meets the requested duration.
pub fn purge_deleted_nodes(
    path: &Path,
    older_than: &str,
    apply: bool,
) -> anyhow::Result<crate::database::PurgeSummary> {
    let age_seconds = parse_age_seconds(older_than)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let cutoff = now.saturating_sub(age_seconds);
    NodeDatabase::open(path)?.purge_deleted_nodes(cutoff, apply)
}

fn parse_age_seconds(value: &str) -> anyhow::Result<u64> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (digits, unit) = value.split_at(split);
    anyhow::ensure!(
        !digits.is_empty(),
        "age must be a non-negative duration such as 30d or 0s"
    );
    let amount = digits.parse::<u64>()?;
    let multiplier = match unit {
        "d" => 86_400,
        "h" => 3_600,
        "m" => 60,
        "s" => 1,
        _ => {
            anyhow::bail!("unsupported age '{value}'; use a duration such as 30d, 12h, 45m, or 0s")
        }
    };
    amount
        .checked_mul(multiplier)
        .context("age duration is too large")
}

pub fn restore_nodes(path: &Path, ids: &[u64]) -> anyhow::Result<BatchNodeSummary> {
    let database = NodeDatabase::open(path)?;
    let mut summary = BatchNodeSummary::default();
    for id in ids {
        match database.get_node(*id)? {
            None => summary.missing.push(*id),
            Some(record) if !record.is_deleted() => summary.unchanged.push(*id),
            Some(_) if database.restore(*id)? => summary.changed.push(*id),
            Some(_) => summary.unchanged.push(*id),
        }
    }
    Ok(summary)
}

fn safe_parse_error(error: ParseError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn purge_age_parser_accepts_seconds_minutes_hours_and_days() {
        assert_eq!(parse_age_seconds("30d").unwrap(), 2_592_000);
        assert_eq!(parse_age_seconds("12h").unwrap(), 43_200);
        assert_eq!(parse_age_seconds("45m").unwrap(), 2_700);
        assert_eq!(parse_age_seconds("0s").unwrap(), 0);
        assert!(parse_age_seconds("yesterday").is_err());
        assert!(parse_age_seconds("2w").is_err());
    }

    #[test]
    fn decodes_base64_share_list_conservatively() {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD
            .encode("vless://synthetic@example.invalid:443\ntrojan://fake@example.invalid:443");
        assert_eq!(
            decode_subscription_text(&encoded),
            "vless://synthetic@example.invalid:443\ntrojan://fake@example.invalid:443"
        );
        assert_eq!(decode_subscription_text("ordinary text"), "ordinary text");
        assert_eq!(
            decode_subscription_text("vless://already-decoded"),
            "vless://already-decoded"
        );
    }

    #[test]
    fn decodes_base64_mihomo_yaml_conservatively() {
        use base64::Engine as _;
        let yaml = "proxies:\n  - type: vless\n    server: edge.invalid\n    port: 443\n    uuid: synthetic\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(yaml);
        assert_eq!(decode_subscription_text(&encoded), yaml);
        assert_eq!(decode_subscription_text("ordinary text"), "ordinary text");
    }

    #[test]
    fn imports_base64_mihomo_yaml_subscription() {
        use base64::Engine as _;
        let directory = tempdir().unwrap();
        let source = directory.path().join("subscription.txt");
        let database = directory.path().join("proxyctl.redb");
        let yaml = "proxies:\n  - type: vless\n    server: edge.invalid\n    port: 443\n    uuid: synthetic\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(yaml);
        fs::write(&source, encoded).unwrap();

        let summary = import_file(&database, &source).unwrap();

        assert_eq!(summary.added, 1);
        assert_eq!(summary.invalid, 0);
    }

    #[test]
    fn imports_valid_lines_and_preserves_source_file() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("nodes.txt");
        let database = directory.path().join("proxyctl.redb");
        let contents = concat!(
            "# proxy list\n",
            "\n",
            "vless://uuid@example.com:443?security=tls\n",
            "not-a-proxy-url\n",
            "vless://uuid@example.com:443?security=tls\n"
        );
        fs::write(&source, contents).unwrap();

        let summary = import_file(&database, &source).unwrap();

        assert_eq!(summary.added, 1);
        assert_eq!(summary.duplicates, 1);
        assert_eq!(summary.invalid, 1);
        assert_eq!(summary.failures[0].line_number, 4);
        assert_eq!(fs::read_to_string(source).unwrap(), contents);
    }

    #[test]
    fn imports_mihomo_yaml_and_reports_skipped_entries_without_echoing_credentials() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("profile.yaml");
        let database = directory.path().join("proxyctl.redb");
        let contents = concat!(
            "proxies:\n",
            "  - name: imported\n",
            "    type: vless\n",
            "    server: edge.invalid\n",
            "    port: 443\n",
            "    uuid: synthetic-uuid\n",
            "  - name: unsupported\n",
            "    type: direct\n",
            "    password: must-not-appear\n",
            "  - type: trojan\n",
            "    server: edge.invalid\n",
            "    port: 443\n"
        );
        fs::write(&source, contents).unwrap();

        let summary = import_file(&database, &source).unwrap();

        assert_eq!(summary.added, 1);
        assert_eq!(summary.duplicates, 0);
        assert_eq!(summary.invalid, 2);
        assert_eq!(summary.failures.len(), 2);
        assert_eq!(summary.failures[0].line_number, 2);
        assert_eq!(
            summary.failures[0].reason,
            "proxy protocol is not supported"
        );
        assert_eq!(summary.failures[1].line_number, 3);
        let diagnostics = format!(
            "{:?}",
            summary
                .failures
                .iter()
                .map(|f| &f.reason)
                .collect::<Vec<_>>()
        );
        assert!(!diagnostics.contains("must-not-appear"));
        assert_eq!(list_nodes(&database, false).unwrap().len(), 1);
    }

    #[test]
    fn imports_json_profile_and_reports_skipped_outbounds() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("profile.json");
        let database = directory.path().join("proxyctl.redb");
        let contents = r#"{"outbounds":[{"type":"vless","server":"edge.invalid","server_port":443,"uuid":"synthetic"},{"type":"direct"},{"type":"trojan","settings":{}}]}"#;
        fs::write(&source, contents).unwrap();

        let summary = import_file(&database, &source).unwrap();

        assert_eq!(summary.added, 1);
        assert_eq!(summary.invalid, 2);
        assert_eq!(summary.failures.len(), 2);
        assert_eq!(summary.failures[0].line_number, 2);
        assert_eq!(summary.failures[1].line_number, 3);
        assert_eq!(list_nodes(&database, false).unwrap().len(), 1);
    }

    #[test]
    fn batch_remove_and_restore_preserve_records_and_report_missing_ids() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("proxyctl.redb");
        let first = add_url(&database, "vless://uuid@one.example:443").unwrap();
        let second = add_url(&database, "vless://uuid@two.example:443").unwrap();
        assert_eq!(first, AddNodeOutcome::Added(1));
        assert_eq!(second, AddNodeOutcome::Added(2));

        let removed = remove_nodes(&database, &[1, 2, 99]).unwrap();
        assert_eq!(removed.changed, vec![1, 2]);
        assert_eq!(removed.missing, vec![99]);
        assert!(removed.unchanged.is_empty());

        let restored = restore_nodes(&database, &[1, 2, 99]).unwrap();
        assert_eq!(restored.changed, vec![1, 2]);
        assert_eq!(restored.missing, vec![99]);
        assert!(restored.unchanged.is_empty());

        let repeated = restore_nodes(&database, &[1, 2]).unwrap();
        assert!(repeated.changed.is_empty());
        assert_eq!(repeated.unchanged, vec![1, 2]);
    }

    #[test]
    fn display_numbers_compact_after_remove_and_new_nodes_keep_existing_records_stable() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("proxyctl.redb");
        for host in ["one", "two", "three"] {
            add_url(&database, &format!("vless://uuid@{host}.example:443")).unwrap();
        }

        let selection = super::super::node_selection::NodeSelection::Ids(vec![2]);
        let removed_id = resolve_node_selection(&database, &selection, false).unwrap();
        assert_eq!(removed_id, vec![2]);
        remove_nodes(&database, &removed_id).unwrap();

        assert_eq!(
            resolve_node_selection(&database, &selection, false).unwrap(),
            vec![3]
        );
        assert_eq!(
            add_url(&database, "vless://uuid@four.example:443").unwrap(),
            AddNodeOutcome::Added(4)
        );
        let third_position = super::super::node_selection::NodeSelection::Ids(vec![3]);
        assert_eq!(
            resolve_node_selection(&database, &third_position, false).unwrap(),
            vec![4]
        );

        // Deleted-list position 1 resolves to the old stable record ID 2 and appends it.
        let deleted_position = super::super::node_selection::NodeSelection::Ids(vec![1]);
        let restore_id = resolve_node_selection(&database, &deleted_position, true).unwrap();
        assert_eq!(restore_id, vec![2]);
        restore_nodes(&database, &restore_id).unwrap();
        let fourth_position = super::super::node_selection::NodeSelection::Ids(vec![4]);
        assert_eq!(
            resolve_node_selection(&database, &fourth_position, false).unwrap(),
            vec![2]
        );
        let active = list_nodes(&database, false).unwrap();
        assert_eq!(
            active.iter().map(|record| record.id).collect::<Vec<_>>(),
            vec![1, 3, 4, 2]
        );
    }

    #[test]
    fn add_url_reports_duplicate_records() {
        let directory = tempdir().unwrap();
        let database = directory.path().join("proxyctl.redb");
        let url = "vless://uuid@example.com:443";

        assert_eq!(add_url(&database, url).unwrap(), AddNodeOutcome::Added(1));
        assert_eq!(
            add_url(&database, url).unwrap(),
            AddNodeOutcome::Duplicate(1)
        );
    }
}
