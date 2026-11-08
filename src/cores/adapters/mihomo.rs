use std::{path::Path, process::Command};

use anyhow::{Context, ensure};
use serde_json::json;

use crate::{
    cores::CoreId,
    domain::{Protocol, ProxyNode},
};

use super::{
    CoreAdapter, json_config,
    shared::{Compatibility, GeneratedConfig, tls_options, validate_common},
};

pub struct MihomoAdapter;

impl CoreAdapter for MihomoAdapter {
    fn core(&self) -> CoreId {
        CoreId::Mihomo
    }

    fn compatibility(&self, node: &ProxyNode) -> Compatibility {
        match validate_common(node) {
            Err(reason) => Compatibility::unsupported(reason),
            Ok(()) => match tls_options(node) {
                Ok(_) => Compatibility::supported(),
                Err(reason) => Compatibility::unsupported(reason),
            },
        }
    }
    fn generate_config(&self, node: &ProxyNode) -> anyhow::Result<GeneratedConfig> {
        let compatibility = self.compatibility(node);
        ensure!(
            compatibility.is_supported(),
            "{}",
            compatibility
                .reason
                .unwrap_or_else(|| "node is incompatible".into())
        );
        let name = node
            .name
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or("proxy");
        let mut proxy = match node.protocol {
            Protocol::Vless => {
                json!({"name":name,"type":"vless","server":node.server,"port":node.port,"uuid":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"network":"tcp"})
            }
            Protocol::Vmess => {
                json!({"name":name,"type":"vmess","server":node.server,"port":node.port,"uuid":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"alterId":node.options.get("aid").and_then(|v|v.parse::<u32>().ok()).unwrap_or(0),"cipher":node.options.get("scy").map(String::as_str).unwrap_or("auto"),"network":"tcp"})
            }
            Protocol::Trojan => {
                json!({"name":name,"type":"trojan","server":node.server,"port":node.port,"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default(),"network":"tcp"})
            }
            Protocol::Shadowsocks => {
                json!({"name":name,"type":"ss","server":node.server,"port":node.port,"cipher":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default()})
            }
            Protocol::Hysteria2 => {
                json!({"name":name,"type":"hysteria2","server":node.server,"port":node.port,"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default()})
            }
        };
        if let Some(tls) = tls_options(node).map_err(anyhow::Error::msg)? {
            proxy["tls"] = json!(true);
            if let Some(sni) = tls.get("server_name") {
                proxy["servername"] = sni.clone();
            }
            if let Some(alpn) = tls.get("alpn") {
                proxy["alpn"] = alpn.clone();
            }
        }
        json_config(json!({
            "allow-lan": false,
            "mode": "rule",
            "proxies": [proxy],
            "proxy-groups": [{"name":"PROXY","type":"select","proxies":[name]}],
            "rules": ["MATCH,PROXY"]
        }))
    }

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()> {
        let output = Command::new(executable)
            .arg("-t")
            .arg("-f")
            .arg(config)
            .output()
            .context("could not run Mihomo config validation")?;
        ensure!(
            output.status.success(),
            "Mihomo rejected the generated configuration (exit status {:?})",
            output.status.code()
        );
        Ok(())
    }
}
