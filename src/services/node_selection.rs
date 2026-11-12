//! Shared parser for node ID lists and inclusive ranges.
use std::collections::BTreeSet;
#[derive(Clone,Debug,Eq,PartialEq)] pub enum NodeSelection{All,Ids(Vec<u64>)}
pub fn parse_node_selection(tokens:&[String])->anyhow::Result<NodeSelection>{
 anyhow::ensure!(!tokens.is_empty(),"provide node IDs, ranges, or 'all'");
 if tokens.len()==1&&tokens[0].eq_ignore_ascii_case("all"){return Ok(NodeSelection::All)}
 anyhow::ensure!(!tokens.iter().any(|v|v.eq_ignore_ascii_case("all")),"'all' cannot be combined with IDs or ranges");
 let mut ids=BTreeSet::new();for t in tokens{if let Some((a,b))=t.split_once(".."){anyhow::ensure!(!b.contains(".."),"invalid node range '{t}'");let a=id(a)?;let b=id(b)?;anyhow::ensure!(a<=b,"node range '{t}' is reversed");anyhow::ensure!(b-a<=100_000,"node range '{t}' is too large (maximum 100001 IDs)");ids.extend(a..=b);}else{ids.insert(id(t)?);}}Ok(NodeSelection::Ids(ids.into_iter().collect()))
}
fn id(v:&str)->anyhow::Result<u64>{let n=v.parse::<u64>().map_err(|_|anyhow::anyhow!("invalid node ID '{v}'"))?;anyhow::ensure!(n>0,"node IDs must be greater than zero");Ok(n)}
#[cfg(test)] mod tests{use super::*;fn t(v:&[&str])->Vec<String>{v.iter().map(|x|x.to_string()).collect()}#[test]fn list_range_dedupe(){assert_eq!(parse_node_selection(&t(&["1","2..4","4"])).unwrap(),NodeSelection::Ids(vec![1,2,3,4]));}#[test]fn all_standalone(){assert_eq!(parse_node_selection(&t(&["all"])).unwrap(),NodeSelection::All);assert!(parse_node_selection(&t(&["all","2"])).is_err());}#[test]fn rejects_bad_ranges(){for v in [&["0"][..],&["4..2"][..],&["x"][..],&["1..2..3"][..],&["1..100002"][..]]{assert!(parse_node_selection(&t(v)).is_err());}}}
