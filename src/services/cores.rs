//! Managed-core inventory use cases.

use crate::cores::CoreId;

/// Return each supported core and whether its proxyctl-managed executable is installed.
pub fn inventory() -> anyhow::Result<Vec<(CoreId, bool)>> {
    CoreId::ALL
        .into_iter()
        .map(|core| Ok((core, core.is_installed()?)))
        .collect()
}
