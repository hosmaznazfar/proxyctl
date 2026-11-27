//! Structured JSON profile parsing for sing-box and Xray outbound collections.
use std::collections::BTreeMap;
use serde_json::{Value};
use crate::domain::{OptionEntry, Protocol, ProxyNode, SecretString};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProfileError { InvalidJson, MissingOutbounds, UnsupportedOutbound(String), InvalidNode }

pub fn parse_profile(input: &str) -> Result<Vec<ProxyNode>, ProfileError> {
 let root: Value=serde_json::from_str(input).map_err(|_|ProfileError::InvalidJson)?;
 let outbounds=root.get("outbounds").and_then(Value::as_array).ok_or(ProfileError::MissingOutbounds)?;
 let mut nodes=Vec::new();
 for outbound in outbounds {
  if outbound.get("type").and_then(Value::as_str).is_some() { // sing-box shape
    if let Some(node)=parse_singbox(outbound) { nodes.push(node); }
  } else if outbound.get("protocol").and_then(Value::as_str).is_some() { // Xray shape
    if let Some(node)=parse_xray(outbound) { nodes.push(node); }
  }
 }
 Ok(nodes)
}
fn parse_singbox(v:&Value)->Option<ProxyNode>{
 let kind=v.get("type")?.as_str()?;
 let protocol=match kind { "vless"=>Protocol::Vless,"vmess"=>Protocol::Vmess,"trojan"=>Protocol::Trojan,"shadowsocks"=>Protocol::Shadowsocks,"hysteria2"=>Protocol::Hysteria2,_=>return None};
 let server=v.get("server")?.as_str()?.to_owned(); let port=v.get("server_port")?.as_u64()?.try_into().ok()?;
 let name=v.get("tag").and_then(Value::as_str).map(str::to_owned);
 let credentials=match protocol {Protocol::Vless|Protocol::Vmess=>v.get("uuid"),Protocol::Shadowsocks=>v.get("method"),_=>v.get("password")}.and_then(Value::as_str).map(SecretString::new);
 let mut entries=Vec::new();
 for (key,val) in v.as_object()? { if !matches!(key.as_str(),"type"|"tag"|"server"|"server_port"|"uuid"|"password"|"method") {entries.push(OptionEntry{key:key.clone(),value:val.clone()});}}
 let opts=entries.iter().filter_map(|e|e.value.as_str().map(|s|(e.key.clone(),s.to_owned()))).collect::<BTreeMap<_,_>>();
 Some(ProxyNode::new(protocol,server,port,name,credentials.clone(),credentials,opts,SecretString::new("[structured profile]")).with_option_entries(entries))
}
fn parse_xray(v:&Value)->Option<ProxyNode>{
 let kind=v.get("protocol")?.as_str()?;
 let protocol=match kind {"vless"=>Protocol::Vless,"vmess"=>Protocol::Vmess,"trojan"=>Protocol::Trojan,"shadowsocks"=>Protocol::Shadowsocks,"socks"=>return None,_=>return None};
 let settings=v.get("settings")?.get("servers").and_then(Value::as_array).and_then(|a|a.first()).cloned().unwrap_or_else(||v.get("settings").cloned().unwrap_or(Value::Null));
 let server=settings.get("address")?.as_str()?.to_owned(); let port=settings.get("port")?.as_u64()?.try_into().ok()?;
 let credential=match protocol {Protocol::Vless|Protocol::Vmess=>settings.get("users").and_then(Value::as_array).and_then(|a|a.first()).and_then(|u|u.get("id")).and_then(Value::as_str),_=>settings.get("password").and_then(Value::as_str)}.map(SecretString::new);
 let name=v.get("tag").and_then(Value::as_str).map(str::to_owned);
 let mut entries=Vec::new(); if let Some(ss)=v.get("streamSettings"){entries.push(OptionEntry{key:"streamSettings".into(),value:ss.clone()});}
 if let Some(settings)=v.get("settings"){entries.push(OptionEntry{key:"settings".into(),value:settings.clone()});}
 let opts=BTreeMap::new();
 Some(ProxyNode::new(protocol,server,port,name,credential.clone(),credential,opts,SecretString::new("[structured profile]")).with_option_entries(entries))
}
#[cfg(test)]
mod tests{
 use super::*;
 #[test] fn extracts_singbox_vless_synthetic(){let s=r#"{"outbounds":[{"type":"vless","tag":"fixture","server":"edge.invalid","server_port":443,"uuid":"00000000-0000-4000-8000-000000000000","tls":{"enabled":true,"server_name":"tls.invalid"}}]}"#;let n=parse_profile(s).unwrap();assert_eq!(n.len(),1);assert_eq!(n[0].protocol,Protocol::Vless);assert_eq!(n[0].server,"edge.invalid");assert_eq!(n[0].option("tls").unwrap()["server_name"],"tls.invalid");}
 #[test] fn skips_non_proxy_outbound(){let s=r#"{"outbounds":[{"type":"direct"},{"type":"vless","server":"edge.invalid","server_port":443,"uuid":"fixture"}]}"#;assert_eq!(parse_profile(s).unwrap().len(),1);}
 #[test] fn rejects_non_json(){assert_eq!(parse_profile("nope"),Err(ProfileError::InvalidJson));}
}
