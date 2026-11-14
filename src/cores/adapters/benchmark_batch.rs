//! Multi-node benchmark configuration generation.
//!
//! Each target receives a dedicated loopback listener and a uniquely tagged outbound.
//! The caller must pre-filter unsupported/invalid nodes before invoking this function.

use std::collections::HashSet;

use anyhow::{Context, ensure};
use serde_json::{Value, json};

use crate::{cores::CoreId, domain::ProxyNode};

use super::{CoreAdapter, GeneratedConfig, json_config};

/// One independently routed node in a temporary benchmark batch.
#[derive(Clone, Copy)]
pub struct BenchmarkTarget<'a> {
    pub node_id: u64,
    pub node: &'a ProxyNode,
    pub listen_port: u16,
}

pub(super) fn generate<A: CoreAdapter + ?Sized>(
    adapter: &A,
    targets: &[BenchmarkTarget<'_>],
) -> anyhow::Result<GeneratedConfig> {
    ensure!(
        !targets.is_empty(),
        "benchmark batch must contain at least one node"
    );

    let mut node_ids = HashSet::with_capacity(targets.len());
    let mut ports = HashSet::with_capacity(targets.len());
    for target in targets {
        ensure!(target.node_id > 0, "benchmark node ID must be non-zero");
        ensure!(
            target.listen_port > 0,
            "benchmark listener port must be non-zero"
        );
        ensure!(
            node_ids.insert(target.node_id),
            "benchmark batch contains a duplicate node ID"
        );
        ensure!(
            ports.insert(target.listen_port),
            "benchmark batch contains a duplicate listener port"
        );
        ensure!(
            adapter.compatibility(target.node).is_supported(),
            "benchmark batch contains a node unsupported by {}",
            adapter.core()
        );
    }

    match adapter.core() {
        CoreId::SingBox => generate_sing_box(adapter, targets),
        CoreId::Xray => generate_xray(adapter, targets),
        CoreId::Mihomo => generate_mihomo(adapter, targets),
    }
}

fn node_config<A: CoreAdapter + ?Sized>(adapter: &A, node: &ProxyNode) -> anyhow::Result<Value> {
    let generated = adapter
        .generate_config(node)
        .context("could not generate a node's native outbound configuration")?;
    serde_json::from_slice(&generated.content)
        .context("adapter generated an invalid JSON configuration")
}

fn generate_sing_box<A: CoreAdapter + ?Sized>(
    adapter: &A,
    targets: &[BenchmarkTarget<'_>],
) -> anyhow::Result<GeneratedConfig> {
    let mut outbounds = Vec::with_capacity(targets.len());
    let mut inbounds = Vec::with_capacity(targets.len());
    let mut rules = Vec::with_capacity(targets.len());

    for target in targets {
        let mut document = node_config(adapter, target.node)?;
        let node_outbounds = document
            .get_mut("outbounds")
            .and_then(Value::as_array_mut)
            .context("sing-box node config must contain an outbound array")?;
        ensure!(
            node_outbounds.len() == 1,
            "sing-box node config must contain exactly one proxy outbound"
        );
        let mut outbound = node_outbounds.remove(0);
        let outbound_tag = format!("proxyctl-benchmark-out-{}", target.node_id);
        let inbound_tag = format!("proxyctl-benchmark-in-{}", target.node_id);
        outbound["tag"] = json!(outbound_tag);
        outbounds.push(outbound);
        inbounds.push(json!({
            "type": "http",
            "tag": inbound_tag,
            "listen": "127.0.0.1",
            "listen_port": target.listen_port
        }));
        rules.push(json!({
            "inbound": [inbound_tag],
            "outbound": outbound_tag
        }));
    }

    let final_outbound = format!("proxyctl-benchmark-out-{}", targets[0].node_id);
    json_config(json!({
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": final_outbound
        }
    }))
}

fn generate_xray<A: CoreAdapter + ?Sized>(
    adapter: &A,
    targets: &[BenchmarkTarget<'_>],
) -> anyhow::Result<GeneratedConfig> {
    let mut outbounds = Vec::with_capacity(targets.len());
    let mut inbounds = Vec::with_capacity(targets.len());
    let mut rules = Vec::with_capacity(targets.len());

    for target in targets {
        let mut document = node_config(adapter, target.node)?;
        let node_outbounds = document
            .get_mut("outbounds")
            .and_then(Value::as_array_mut)
            .context("Xray node config must contain an outbound array")?;
        ensure!(
            node_outbounds.len() == 1,
            "Xray node config must contain exactly one proxy outbound"
        );
        let mut outbound = node_outbounds.remove(0);
        let outbound_tag = format!("proxyctl-benchmark-out-{}", target.node_id);
        let inbound_tag = format!("proxyctl-benchmark-in-{}", target.node_id);
        outbound["tag"] = json!(outbound_tag);
        outbounds.push(outbound);
        inbounds.push(json!({
            "listen": "127.0.0.1",
            "port": target.listen_port,
            "protocol": "http",
            "settings": {},
            "tag": inbound_tag
        }));
        rules.push(json!({
            "type": "field",
            "inboundTag": [inbound_tag],
            "outboundTag": outbound_tag
        }));
    }

    json_config(json!({
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "AsIs",
            "rules": rules
        }
    }))
}

fn generate_mihomo<A: CoreAdapter + ?Sized>(
    adapter: &A,
    targets: &[BenchmarkTarget<'_>],
) -> anyhow::Result<GeneratedConfig> {
    let mut proxies = Vec::with_capacity(targets.len());
    let mut listeners = Vec::with_capacity(targets.len());

    for target in targets {
        let document = node_config(adapter, target.node)?;
        let proxy = document
            .get("proxies")
            .and_then(Value::as_array)
            .and_then(|entries| entries.first())
            .context("Mihomo node config must contain a proxy entry")?;
        let mut proxy = proxy.clone();
        let proxy_name = format!("proxyctl-benchmark-out-{}", target.node_id);
        let listener_name = format!("proxyctl-benchmark-in-{}", target.node_id);
        proxy["name"] = json!(proxy_name);
        proxies.push(proxy);
        listeners.push(json!({
            "name": listener_name,
            "type": "mixed",
            "port": target.listen_port,
            "listen": "127.0.0.1",
            "proxy": proxy_name
        }));
    }

    json_config(json!({
        "allow-lan": false,
        "mode": "rule",
        "proxies": proxies,
        "listeners": listeners
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cores::adapters::adapter, parser::parse_proxy_url};

    fn targets<'a>(first: &'a ProxyNode, second: &'a ProxyNode) -> [BenchmarkTarget<'a>; 2] {
        [
            BenchmarkTarget {
                node_id: 11,
                node: first,
                listen_port: 43131,
            },
            BenchmarkTarget {
                node_id: 22,
                node: second,
                listen_port: 43132,
            },
        ]
    }

    #[test]
    fn every_adapter_routes_each_loopback_listener_to_its_own_outbound() {
        let first =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@first.example:443")
                .unwrap();
        let second = parse_proxy_url("trojan://second-secret@second.example:8443").unwrap();

        for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
            let generated = generate(adapter(core), &targets(&first, &second)).unwrap();
            let document: Value = serde_json::from_slice(&generated.content).unwrap();
            match core {
                CoreId::SingBox => {
                    assert_eq!(document["outbounds"].as_array().unwrap().len(), 2);
                    assert_eq!(document["inbounds"].as_array().unwrap().len(), 2);
                    assert_eq!(document["inbounds"][0]["listen"], "127.0.0.1");
                    assert_eq!(document["inbounds"][0]["listen_port"], 43131);
                    assert_eq!(document["inbounds"][1]["listen_port"], 43132);
                    assert_eq!(
                        document["route"]["rules"][0]["outbound"],
                        "proxyctl-benchmark-out-11"
                    );
                    assert_eq!(
                        document["route"]["rules"][1]["outbound"],
                        "proxyctl-benchmark-out-22"
                    );
                }
                CoreId::Xray => {
                    assert_eq!(document["outbounds"].as_array().unwrap().len(), 2);
                    assert_eq!(document["inbounds"].as_array().unwrap().len(), 2);
                    assert_eq!(document["inbounds"][0]["listen"], "127.0.0.1");
                    assert_eq!(document["inbounds"][0]["port"], 43131);
                    assert_eq!(document["inbounds"][1]["port"], 43132);
                    assert_eq!(
                        document["routing"]["rules"][0]["outboundTag"],
                        "proxyctl-benchmark-out-11"
                    );
                    assert_eq!(
                        document["routing"]["rules"][1]["outboundTag"],
                        "proxyctl-benchmark-out-22"
                    );
                }
                CoreId::Mihomo => {
                    assert_eq!(document["proxies"].as_array().unwrap().len(), 2);
                    assert_eq!(document["listeners"].as_array().unwrap().len(), 2);
                    assert_eq!(document["listeners"][0]["listen"], "127.0.0.1");
                    assert_eq!(document["listeners"][0]["port"], 43131);
                    assert_eq!(
                        document["listeners"][0]["proxy"],
                        "proxyctl-benchmark-out-11"
                    );
                    assert_eq!(document["listeners"][1]["port"], 43132);
                    assert_eq!(
                        document["listeners"][1]["proxy"],
                        "proxyctl-benchmark-out-22"
                    );
                    assert_eq!(document["allow-lan"], false);
                }
            }
            let serialized = String::from_utf8(generated.content).unwrap();
            assert!(!serialized.contains("first-secret"));
            assert!(serialized.contains("second-secret"));
        }
    }

    #[test]
    fn batch_generation_rejects_duplicate_ids_and_ports() {
        let first =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@first.example:443")
                .unwrap();
        let second = parse_proxy_url("trojan://second-secret@second.example:8443").unwrap();

        let duplicate_id = [
            BenchmarkTarget {
                node_id: 11,
                node: &first,
                listen_port: 43131,
            },
            BenchmarkTarget {
                node_id: 11,
                node: &second,
                listen_port: 43132,
            },
        ];
        assert!(generate(adapter(CoreId::SingBox), &duplicate_id).is_err());

        let duplicate_port = [
            BenchmarkTarget {
                node_id: 11,
                node: &first,
                listen_port: 43131,
            },
            BenchmarkTarget {
                node_id: 22,
                node: &second,
                listen_port: 43131,
            },
        ];
        assert!(generate(adapter(CoreId::Xray), &duplicate_port).is_err());
    }

    #[test]
    fn unsupported_node_is_rejected_before_batch_document_is_emitted() {
        let first =
            parse_proxy_url("vless://11111111-1111-4111-8111-111111111111@first.example:443")
                .unwrap();
        let unsupported = parse_proxy_url("hysteria2://secret@second.example:443").unwrap();
        let targets = [
            BenchmarkTarget {
                node_id: 11,
                node: &first,
                listen_port: 43131,
            },
            BenchmarkTarget {
                node_id: 22,
                node: &unsupported,
                listen_port: 43132,
            },
        ];
        assert!(generate(adapter(CoreId::Xray), &targets).is_err());
    }
    #[test]
    fn synthetic_batch_scaling_keeps_one_listener_and_route_per_node() {
        let node = parse_proxy_url(
            "vless://11111111-1111-4111-8111-111111111111@batch.example:443",
        )
        .unwrap();

        for count in [1_usize, 10, 50] {
            let targets = (0..count)
                .map(|index| BenchmarkTarget {
                    node_id: index as u64 + 1,
                    node: &node,
                    listen_port: 20_000 + index as u16,
                })
                .collect::<Vec<_>>();

            for core in [CoreId::SingBox, CoreId::Xray, CoreId::Mihomo] {
                let generated = generate(adapter(core), &targets).unwrap();
                let document: Value = serde_json::from_slice(&generated.content).unwrap();
                let (inbounds, outbounds) = match core {
                    CoreId::SingBox => (
                        document["inbounds"].as_array().unwrap().len(),
                        document["outbounds"].as_array().unwrap().len(),
                    ),
                    CoreId::Xray => (
                        document["inbounds"].as_array().unwrap().len(),
                        document["outbounds"].as_array().unwrap().len(),
                    ),
                    CoreId::Mihomo => (
                        document["listeners"].as_array().unwrap().len(),
                        document["proxies"].as_array().unwrap().len(),
                    ),
                };
                assert_eq!(inbounds, count, "{core} listener count at batch size {count}");
                assert_eq!(outbounds, count, "{core} outbound count at batch size {count}");
                match core {
                    CoreId::SingBox => {
                        assert_eq!(document["route"]["rules"].as_array().unwrap().len(), count);
                    }
                    CoreId::Xray => {
                        assert_eq!(document["routing"]["rules"].as_array().unwrap().len(), count);
                    }
                    CoreId::Mihomo => {}
                }
            }
        }
    }

}
