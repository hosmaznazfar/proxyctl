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

pub struct XrayAdapter;

impl CoreAdapter for XrayAdapter {
    fn core(&self) -> CoreId {
        CoreId::Xray
    }

    fn compatibility(&self, node: &ProxyNode) -> Compatibility {
        if node.protocol == Protocol::Hysteria2 {
            return Compatibility::unsupported("Xray does not implement Hysteria2");
        }
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
        let (protocol, settings) = match node.protocol {
            Protocol::Vless => (
                "vless",
                json!({"vnext":[{"address":node.server,"port":node.port,"users":[{"id":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"encryption":"none","flow":node.options.get("flow").cloned().unwrap_or_default()}]}]}),
            ),
            Protocol::Vmess => (
                "vmess",
                json!({"vnext":[{"address":node.server,"port":node.port,"users":[{"id":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"alterId":node.options.get("aid").and_then(|v|v.parse::<u32>().ok()).unwrap_or(0),"security":node.options.get("scy").map(String::as_str).unwrap_or("auto")}]}]}),
            ),
            Protocol::Trojan => (
                "trojan",
                json!({"servers":[{"address":node.server,"port":node.port,"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default()}]}),
            ),
            Protocol::Shadowsocks => (
                "shadowsocks",
                json!({"servers":[{"address":node.server,"port":node.port,"method":node.identity.as_ref().map(|v|v.expose()).unwrap_or_default(),"password":node.secret.as_ref().map(|v|v.expose()).unwrap_or_default()}]}),
            ),
            Protocol::Hysteria2 => unreachable!("Hysteria2 rejected by compatibility"),
        };
        let mut outbound = json!({"protocol":protocol,"tag":"proxy","settings":settings,"streamSettings":{"network":"tcp"}});
        if let Some(tls) = tls_options(node).map_err(anyhow::Error::msg)? {
            let mut tls_settings = serde_json::Map::new();
            tls_settings.insert("allowInsecure".into(), serde_json::Value::Bool(false));
            if let Some(sni) = tls.get("server_name") {
                tls_settings.insert("serverName".into(), sni.clone());
            }
            if let Some(alpn) = tls.get("alpn") {
                tls_settings.insert("alpn".into(), alpn.clone());
            }
            outbound["streamSettings"]["security"] = json!("tls");
            outbound["streamSettings"]["tlsSettings"] = serde_json::Value::Object(tls_settings);
        }
        json_config(json!({"outbounds":[outbound]}))
    }

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()> {
        let output = Command::new(executable)
            .arg("run")
            .arg("-test")
            .arg("-c")
            .arg(config)
            .output()
            .context("could not run Xray config validation")?;
        ensure!(
            output.status.success(),
            "Xray rejected the generated configuration (exit status {:?})",
            output.status.code()
        );
        Ok(())
    }
}
