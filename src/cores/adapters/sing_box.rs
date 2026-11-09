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

pub struct SingBoxAdapter;

impl CoreAdapter for SingBoxAdapter {
    fn core(&self) -> CoreId {
        CoreId::SingBox
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
        let mut outbound = match node.protocol {
            Protocol::Vless => json!({
                "type": "vless", "tag": "proxy", "server": node.server, "server_port": node.port,
                "uuid": node.identity.as_ref().map(|v| v.expose()).unwrap_or_default()
            }),
            Protocol::Vmess => json!({
                "type": "vmess", "tag": "proxy", "server": node.server, "server_port": node.port,
                "uuid": node.identity.as_ref().map(|v| v.expose()).unwrap_or_default(),
                "alter_id": node.options.get("aid").and_then(|v| v.parse::<u32>().ok()).unwrap_or(0),
                "security": node.options.get("scy").map(String::as_str).unwrap_or("auto")
            }),
            Protocol::Trojan => json!({
                "type": "trojan", "tag": "proxy", "server": node.server, "server_port": node.port,
                "password": node.secret.as_ref().map(|v| v.expose()).unwrap_or_default()
            }),
            Protocol::Shadowsocks => json!({
                "type": "shadowsocks", "tag": "proxy", "server": node.server, "server_port": node.port,
                "method": node.identity.as_ref().map(|v| v.expose()).unwrap_or_default(),
                "password": node.secret.as_ref().map(|v| v.expose()).unwrap_or_default()
            }),
            Protocol::Hysteria2 => json!({
                "type": "hysteria2", "tag": "proxy", "server": node.server, "server_port": node.port,
                "password": node.secret.as_ref().map(|v| v.expose()).unwrap_or_default()
            }),
        };
        if let Some(mut tls) = tls_options(node).map_err(anyhow::Error::msg)? {
            if let Some(fingerprint) = tls
                .as_object_mut()
                .and_then(|options| options.remove("fingerprint"))
            {
                tls["utls"] = json!({"enabled": true, "fingerprint": fingerprint});
            }
            outbound
                .as_object_mut()
                .expect("outbound object")
                .insert("tls".into(), tls);
        }
        json_config(json!({ "outbounds": [outbound] }))
    }

    fn validate_config(&self, executable: &Path, config: &Path) -> anyhow::Result<()> {
        let output = Command::new(executable)
            .arg("check")
            .arg("-c")
            .arg(config)
            .output()
            .context("could not run sing-box config validation")?;
        ensure!(
            output.status.success(),
            "sing-box rejected the generated configuration (exit status {:?})",
            output.status.code()
        );
        Ok(())
    }
}
