//! Read-only init/service-manager detection for Linux TUN recovery backends.
//!
//! Detection is based on PID 1 and runtime markers, never distribution names.
//! This module intentionally does not start, stop, or modify any service.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceManager {
    Systemd,
    OpenRc,
    Runit,
    S6,
    Dinit,
    SysVinit,
    Unknown,
}

impl ServiceManager {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::OpenRc => "OpenRC",
            Self::Runit => "runit",
            Self::S6 => "s6",
            Self::Dinit => "dinit",
            Self::SysVinit => "SysVinit",
            Self::Unknown => "unknown",
        }
    }

    /// Detect the init/service manager without consulting distribution metadata.
    #[cfg(target_os = "linux")]
    pub fn detect() -> Self {
        detect_with_paths(Path::new("/proc/1/comm"), Path::new("/run"))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn detect() -> Self {
        Self::Unknown
    }
}

#[cfg(target_os = "linux")]
fn detect_with_paths(pid1_comm: &Path, run_dir: &Path) -> ServiceManager {
    let comm = std::fs::read_to_string(pid1_comm)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    // PID 1 is authoritative. Runtime markers disambiguate init implementations
    // whose process name is the generic "init".
    // A specific PID 1 executable outranks stale or bind-mounted runtime markers.
    // Runtime markers are consulted only when PID 1 uses the generic "init" name.
    match comm.as_str() {
        "systemd" => return ServiceManager::Systemd,
        "openrc-init" => return ServiceManager::OpenRc,
        "runit" => return ServiceManager::Runit,
        "s6-svscan" => return ServiceManager::S6,
        "dinit" => return ServiceManager::Dinit,
        "init" => {
            if run_dir.join("systemd/system").is_dir() {
                return ServiceManager::Systemd;
            }
            if run_dir.join("openrc/softlevel").exists() {
                return ServiceManager::OpenRc;
            }
            if run_dir.join("runit").is_dir() {
                return ServiceManager::Runit;
            }
            if run_dir.join("s6").is_dir() {
                return ServiceManager::S6;
            }
            if run_dir.join("dinit").is_dir() {
                return ServiceManager::Dinit;
            }
            return ServiceManager::SysVinit;
        }
        _ => {}
    }

    ServiceManager::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn probe(comm: &str, markers: &[&str]) -> ServiceManager {
        let root = tempdir().unwrap();
        let proc = root.path().join("proc/1");
        let run = root.path().join("run");
        std::fs::create_dir_all(&proc).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(proc.join("comm"), comm).unwrap();
        for marker in markers {
            let path = run.join(marker);
            if marker.ends_with("softlevel") {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, "default").unwrap();
            } else {
                std::fs::create_dir_all(path).unwrap();
            }
        }
        detect_with_paths(&proc.join("comm"), &run)
    }

    #[test]
    fn detects_service_managers_by_runtime_identity() {
        for (comm, markers, expected) in [
            ("systemd", &[][..], ServiceManager::Systemd),
            ("openrc-init", &[][..], ServiceManager::OpenRc),
            ("runit", &[][..], ServiceManager::Runit),
            ("s6-svscan", &[][..], ServiceManager::S6),
            ("dinit", &[][..], ServiceManager::Dinit),
            ("init", &["openrc/softlevel"][..], ServiceManager::OpenRc),
            ("init", &["runit"][..], ServiceManager::Runit),
            ("init", &["s6"][..], ServiceManager::S6),
            ("init", &["dinit"][..], ServiceManager::Dinit),
            ("init", &[][..], ServiceManager::SysVinit),
            ("busybox", &[][..], ServiceManager::Unknown),
        ] {
            assert_eq!(probe(comm, markers), expected, "PID 1: {comm}");
        }
    }

    #[test]
    fn specific_pid1_identity_overrides_stale_runtime_markers() {
        let root = tempdir().unwrap();
        let proc = root.path().join("proc/1");
        let run = root.path().join("run");
        std::fs::create_dir_all(&proc).unwrap();
        std::fs::create_dir_all(run.join("systemd/system")).unwrap();
        std::fs::create_dir_all(run.join("openrc")).unwrap();
        std::fs::write(proc.join("comm"), "openrc-init").unwrap();
        std::fs::write(run.join("openrc/softlevel"), "default").unwrap();
        assert_eq!(
            detect_with_paths(&proc.join("comm"), &run),
            ServiceManager::OpenRc
        );
    }

    #[test]
    fn systemd_marker_takes_precedence_over_generic_init_name() {
        assert_eq!(probe("init", &["systemd/system"]), ServiceManager::Systemd);
    }

    #[test]
    fn missing_pid1_identity_fails_closed() {
        let root = tempdir().unwrap();
        assert_eq!(
            detect_with_paths(&root.path().join("missing"), &root.path().join("run")),
            ServiceManager::Unknown
        );
    }
}
