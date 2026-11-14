//! Extract only the expected regular executable; archive paths are never written to disk.
use std::io::{Cursor, Read};

use anyhow::{Context, ensure};

const MAX_BINARY_SIZE: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum ArchiveFormat {
    TarGz,
    Zip,
    Gzip,
}

pub fn extract_binary(
    bytes: &[u8],
    format: ArchiveFormat,
    executable: &str,
) -> anyhow::Result<Vec<u8>> {
    match format {
        ArchiveFormat::TarGz => extract_tar_gz(bytes, executable),
        ArchiveFormat::Zip => extract_zip(bytes, executable),
        ArchiveFormat::Gzip => extract_gzip(bytes),
    }
}

fn extract_tar_gz(bytes: &[u8], executable: &str) -> anyhow::Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries().context("invalid upstream tar archive")? {
        let entry = entry.context("could not read tar archive entry")?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path().context("invalid tar archive path")?;
        if path.file_name().and_then(|name| name.to_str()) != Some(executable) {
            continue;
        }
        let size = entry
            .header()
            .size()
            .context("invalid executable size in tar archive")?;
        ensure!(
            size <= MAX_BINARY_SIZE,
            "core executable exceeds the 128 MiB safety limit"
        );
        let mut binary = Vec::with_capacity(size as usize);
        entry
            .take(MAX_BINARY_SIZE + 1)
            .read_to_end(&mut binary)
            .context("could not extract core executable")?;
        ensure!(
            binary.len() as u64 <= MAX_BINARY_SIZE,
            "core executable exceeds the 128 MiB safety limit"
        );
        return Ok(binary);
    }
    anyhow::bail!("tar archive does not contain the expected regular executable")
}

fn extract_zip(bytes: &[u8], executable: &str) -> anyhow::Result<Vec<u8>> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("invalid upstream ZIP archive")?;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .context("could not read ZIP archive entry")?;
        if entry.is_dir()
            || entry
                .name()
                .context("ZIP archive entry has an invalid name")?
                .rsplit('/')
                .next()
                != Some(executable)
        {
            continue;
        }
        if let Some(mode) = entry.unix_mode() {
            ensure!(
                mode & 0o170000 == 0o100000,
                "ZIP executable entry is not a regular file"
            );
        }
        ensure!(
            entry.size() <= MAX_BINARY_SIZE,
            "core executable exceeds the 128 MiB safety limit"
        );
        let mut binary = Vec::with_capacity(entry.size() as usize);
        entry
            .take(MAX_BINARY_SIZE + 1)
            .read_to_end(&mut binary)
            .context("could not extract core executable")?;
        ensure!(
            binary.len() as u64 <= MAX_BINARY_SIZE,
            "core executable exceeds the 128 MiB safety limit"
        );
        return Ok(binary);
    }
    anyhow::bail!("ZIP archive does not contain the expected regular executable")
}

fn extract_gzip(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(Cursor::new(bytes));
    let mut binary = Vec::new();
    decoder
        .take(MAX_BINARY_SIZE + 1)
        .read_to_end(&mut binary)
        .context("could not decompress core executable")?;
    ensure!(
        binary.len() as u64 <= MAX_BINARY_SIZE,
        "core executable exceeds the 128 MiB safety limit"
    );
    Ok(binary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_archive_bytes() {
        assert!(extract_binary(b"not an archive", ArchiveFormat::Zip, "xray").is_err());
        assert!(extract_binary(b"not gzip", ArchiveFormat::Gzip, "mihomo").is_err());
        assert!(extract_binary(b"not gzip", ArchiveFormat::TarGz, "sing-box").is_err());
    }
}
