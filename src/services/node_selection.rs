//! Shared parser for node ID lists and inclusive ranges.

use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NodeSelection {
    All,
    Ids(Vec<u64>),
}

pub fn parse_node_selection(tokens: &[String]) -> anyhow::Result<NodeSelection> {
    anyhow::ensure!(!tokens.is_empty(), "provide node IDs, ranges, or 'all'");
    if tokens.len() == 1 && tokens[0].eq_ignore_ascii_case("all") {
        return Ok(NodeSelection::All);
    }
    anyhow::ensure!(
        !tokens.iter().any(|value| value.eq_ignore_ascii_case("all")),
        "'all' cannot be combined with IDs or ranges"
    );

    let mut ids = BTreeSet::new();
    for token in tokens {
        if let Some((start, end)) = token.split_once("..") {
            anyhow::ensure!(!end.contains(".."), "invalid node range '{token}'");
            let start = parse_id(start)?;
            let end = parse_id(end)?;
            anyhow::ensure!(start <= end, "node range '{token}' is reversed");
            anyhow::ensure!(
                end - start <= 100_000,
                "node range '{token}' is too large (maximum 100001 IDs)"
            );
            ids.extend(start..=end);
        } else {
            ids.insert(parse_id(token)?);
        }
    }
    Ok(NodeSelection::Ids(ids.into_iter().collect()))
}

fn parse_id(value: &str) -> anyhow::Result<u64> {
    let id = value
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid node ID '{value}'"))?;
    anyhow::ensure!(id > 0, "node IDs must be greater than zero");
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_lists_ranges_and_deduplicates() {
        assert_eq!(
            parse_node_selection(&tokens(&["1", "2..4", "4"])).unwrap(),
            NodeSelection::Ids(vec![1, 2, 3, 4])
        );
    }

    #[test]
    fn all_must_be_standalone() {
        assert_eq!(
            parse_node_selection(&tokens(&["all"])).unwrap(),
            NodeSelection::All
        );
        assert!(parse_node_selection(&tokens(&["all", "2"])).is_err());
    }

    #[test]
    fn rejects_invalid_ids_and_ranges() {
        for values in [
            &["0"][..],
            &["4..2"][..],
            &["x"][..],
            &["1..2..3"][..],
            &["1..100002"][..],
        ] {
            assert!(parse_node_selection(&tokens(values)).is_err());
        }
    }
}
