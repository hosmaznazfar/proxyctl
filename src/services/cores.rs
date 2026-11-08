//! Managed-core setup, update, and inventory use cases.
use crate::cores::{CoreId, installer, paths::core_binary_path};
#[derive(Debug)]
pub struct CoreStatus { pub core: CoreId, pub version: Option<String> }
pub fn inventory() -> anyhow::Result<Vec<CoreStatus>> {
    CoreId::ALL.into_iter().map(|core| {
        let path = core_binary_path(core)?;
        let version = if path.is_file() {
            Some(installer::current_version(core, &path).unwrap_or_else(|_| "version unavailable".to_owned()))
        } else { None };
        Ok(CoreStatus { core, version })
    }).collect()
}
pub fn setup(selected: Option<CoreId>) -> anyhow::Result<()> {
    let cores = selected.map_or_else(|| CoreId::ALL.to_vec(), |core| vec![core]);
    let mut failures = Vec::new();
    for core in cores {
        if let Err(error) = installer::install_or_update(core, false) {
            eprintln!("{core}: {error:#}");
            failures.push(core);
        }
    }
    if failures.is_empty() { Ok(()) } else {
        anyhow::bail!("installation failed for: {}", failures.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
    }
}
pub fn update_installed(check_only: bool, selected: Option<CoreId>) -> anyhow::Result<()> {
    let candidates = match selected {
        Some(core) => {
            if !core_binary_path(core)?.is_file() {
                anyhow::bail!("{core} is not installed by proxyctl; run setup --core {core} first");
            }
            vec![core]
        }
        None => inventory()?.into_iter().filter(|status| status.version.is_some()).map(|status| status.core).collect(),
    };
    if candidates.is_empty() { println!("No managed cores are installed."); return Ok(()); }
    let mut failures = Vec::new();
    for core in candidates {
        if let Err(error) = installer::install_or_update(core, check_only) {
            eprintln!("{core}: {error:#}");
            failures.push(core);
        }
    }
    if failures.is_empty() { Ok(()) } else {
        anyhow::bail!("update failed for: {}", failures.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "))
    }
}
