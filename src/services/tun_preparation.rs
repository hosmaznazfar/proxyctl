//! Side-effect-limited preparation of a native TUN supervisor launch request.
//!
//! Resolves user-owned node state and validates/generates the config in the unprivileged
//! process. It deliberately does not acquire privileged runtime state or mutate networking.
use anyhow::{Context, ensure};

use crate::{
    cores::{CoreId, adapters, core_binary_path, managed_cores_path},
    database::{NodeDatabase, default_database_path},
    tun::launch_spec::{CoreKind, LaunchSpec, from_generated_config},
};

/// Resolve a stored node and construct a bounded supervisor request, without launching it.
pub fn prepare_launch_spec(node_id: u64, core: CoreId, port: u16) -> anyhow::Result<LaunchSpec> {
    ensure!(node_id != 0, "node ID must be non-zero");
    ensure!(port >= 1024, "listener port must be between 1024 and 65535");

    let db = NodeDatabase::open(default_database_path()?)?;
    let record = db
        .get_node(node_id)?
        .with_context(|| format!("node #{node_id} not found"))?;
    ensure!(
        !record.is_deleted(),
        "node #{node_id} is deleted; restore it first"
    );
    let node = record.node;
    drop(db);

    let adapter = adapters::adapter(core);
    let compatibility = adapter.compatibility(&node);
    ensure!(
        compatibility.is_supported(),
        "selected core does not support this node: {}",
        compatibility
            .reason
            .as_deref()
            .unwrap_or("unsupported configuration")
    );

    let executable = core_binary_path(core)?;
    ensure!(
        executable.is_file(),
        "selected core is not installed by Proxyctl; run setup for the selected core"
    );
    let executable = std::fs::canonicalize(executable)?;
    let managed_root = std::fs::canonicalize(managed_cores_path()?)?;
    ensure!(
        executable.starts_with(managed_root),
        "refusing to validate a core outside Proxyctl's managed-core directory"
    );

    let activation_id = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .context("cannot obtain a kernel-generated activation UUID")?
        .trim()
        .to_ascii_lowercase();
    let (mark, mask) = crate::tun::route_policy::mark_for_activation_id(&activation_id)?;
    let outbound_mark = adapters::TunOutboundMark::new(mark, mask)?;
    ensure!(
        adapter.tun_attachment_mode() != adapters::TunAttachmentMode::Unsupported,
        "selected core does not expose a supported TUN attachment contract"
    );
    let generated = adapter
        .generate_tun_activation_config(&node, port, outbound_mark)
        .with_context(|| format!("could not generate {core} TUN configuration"))?;
    adapters::validation::validate_generated_config(core, &generated, &executable)
        .with_context(|| format!("{core} rejected the prepared TUN configuration"))?;

    let kind = match core {
        CoreId::SingBox => CoreKind::SingBox,
        CoreId::Xray => CoreKind::Xray,
        CoreId::Mihomo => CoreKind::Mihomo,
    };
    from_generated_config(node_id, kind, port, &generated.content)
}
