//! Secure, short-lived staging for generated TUN core configuration.
//!
//! The staged file is root-owned and private. Its guard removes the file on every
//! normal return path; durable session ownership is added with the supervisor lifecycle.
use anyhow::{Context, ensure};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

const CONFIG_MODE: u32 = 0o600;

#[derive(Debug)]
pub struct StagedConfig {
    path: PathBuf,
    file: Option<File>,
}

impl StagedConfig {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub fn sync(&self) -> anyhow::Result<()> {
        self.file
            .as_ref()
            .context("staged config file is already closed")?
            .sync_all()
            .context("cannot sync staged TUN configuration")
    }

    pub fn close(mut self) -> anyhow::Result<()> {
        if let Some(file) = self.file.take() {
            file.sync_all().context("cannot sync staged TUN configuration")?;
            drop(file);
        }
        fs::remove_file(&self.path).context("cannot remove staged TUN configuration")
    }
}

impl Drop for StagedConfig {
    fn drop(&mut self) {
        self.file.take();
        let _ = fs::remove_file(&self.path);
    }
}

/// Write generated JSON to a new root-owned 0600 file under the verified runtime directory.
pub fn stage_config(runtime: &std::path::Path, config: &[u8]) -> anyhow::Result<StagedConfig> {
    ensure!(!config.is_empty(), "generated TUN configuration is empty");
    ensure!(
        config.len() <= crate::tun::launch_spec::MAX_CONFIG_BYTES,
        "generated TUN configuration exceeds the size limit"
    );
    let document: serde_json::Value = serde_json::from_slice(config)
        .context("generated TUN configuration is not valid JSON")?;
    ensure!(document.is_object(), "generated TUN configuration must be a JSON object");

    let runtime_metadata = fs::symlink_metadata(runtime)
        .context("cannot inspect TUN runtime directory")?;
    ensure!(runtime_metadata.file_type().is_dir(), "TUN runtime path is not a real directory");
    ensure!(runtime_metadata.uid() == 0, "TUN runtime directory is not root-owned");
    ensure!(
        runtime_metadata.permissions().mode() & 0o7777 == 0o700,
        "TUN runtime directory does not have mode 0700"
    );

    let nonce = fs::read_to_string("/proc/sys/kernel/random/uuid")
        .context("cannot obtain a kernel-generated config identifier")?;
    let nonce = nonce.trim();
    ensure!(
        nonce.len() == 36
            && nonce.bytes().all(|byte| byte.is_ascii_hexdigit() || byte == b'-'),
        "kernel returned an invalid config identifier"
    );
    let path = runtime.join(format!("config-{nonce}.json"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(CONFIG_MODE)
        .open(&path)
        .with_context(|| format!("cannot create staged config {}", path.display()))?;

    let result = (|| -> anyhow::Result<()> {
        file.write_all(config).context("cannot write staged TUN configuration")?;
        file.sync_all().context("cannot sync staged TUN configuration")?;
        let metadata = file.metadata().context("cannot inspect staged config file")?;
        ensure!(metadata.is_file(), "staged config is not a regular file");
        ensure!(metadata.uid() == 0, "staged config is not root-owned");
        ensure!(
            metadata.permissions().mode() & 0o7777 == CONFIG_MODE,
            "staged config does not have mode 0600"
        );
        Ok(())
    })();
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(error);
    }

    Ok(StagedConfig {
        path,
        file: Some(file),
    })
}
