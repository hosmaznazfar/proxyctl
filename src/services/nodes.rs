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

/// Import a text file without modifying it. Blank lines and lines beginning with # are ignored.
pub fn import_file(database_path: &Path, source_path: &Path) -> anyhow::Result<ImportSummary> {
    let content = std::fs::read_to_string(source_path)
        .with_context(|| format!("could not read import file {}", source_path.display()))?;
    let database = NodeDatabase::open(database_path)?;
    let mut summary = ImportSummary::default();

    for (index, line) in content.lines().enumerate() {
        let input = line.trim();
        if input.is_empty() || input.starts_with('#') {
            continue;
        }

        match parse_proxy_url(input) {
            Ok(node) => match database.add_node(&node)? {
                AddNodeOutcome::Added(_) => summary.added += 1,
                AddNodeOutcome::Duplicate(_) => summary.duplicates += 1,
            },
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

pub fn list_nodes(database_path: &Path, include_deleted: bool) -> anyhow::Result<Vec<NodeRecord>> {
    NodeDatabase::open(database_path)?.list_nodes(include_deleted)
}

pub fn get_node(path: &Path, id: u64) -> anyhow::Result<Option<NodeRecord>> {
    NodeDatabase::open(path)?.get_node(id)
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
        super::node_selection::NodeSelection::Ids(ids) => Ok(ids.clone()),
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
