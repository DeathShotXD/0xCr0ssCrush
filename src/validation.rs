//! Sample validation against published driver metadata.
//!
//! Every claim about a driver in this repository is hash-specific.
//! Before a driver file is loaded, its SHA-256 digest is compared with
//! the digests published in `metadata/drivers.json`. Loading is refused
//! when the file does not match any known sample.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Compute the lowercase hex SHA-256 of a file.
pub fn sha256_file(path: &str) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| format!("open {}: {e}", path))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| format!("read {}: {e}", path))?;
    let mut hasher = Sha256::new();
    hasher.update(&buf);
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(""))
}

/// Known-good digests for the two driver samples carried by this repo.
/// Digest of any sample taken externally must agree with the entry in
/// `metadata/drivers.json` before we treat it as one of our samples.
pub struct DriverMeta {
    pub file: &'static str,
    pub sha256: &'static str,
}

pub const KNOWN_SAMPLES: &[DriverMeta] = &[
    DriverMeta {
        file: "DCRCVDrv.sys",
        sha256: "87e8d39db624f37d3e77aedf487a2dfd197f71a4730ea74f4e7a4341deaec2ff",
    },
    DriverMeta {
        file: "Alinubx.sys",
        sha256: "611b3ba687b7f46319a19609605ddfe5225e6d85277d8e923eea3fdb6f7b5b61",
    },
];

/// Return the metadata entry whose filename matches `path`, if any.
pub fn known_sample_for(path: &str) -> Option<&'static DriverMeta> {
    let name = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    KNOWN_SAMPLES
        .iter()
        .find(|m| m.file.eq_ignore_ascii_case(&name))
}

/// Validate `path` against the stored digest for that filename.
/// Returns Ok(digest) when the file matches, Err otherwise.
pub fn validate_driver(path: &str) -> Result<String, String> {
    let meta = known_sample_for(path)
        .ok_or_else(|| format!("{} is not one of the samples tracked by this repo", path))?;
    let digest = sha256_file(path)?;
    if digest.eq_ignore_ascii_case(meta.sha256) {
        Ok(digest)
    } else {
        Err(format!(
            "digest mismatch for {}: got {digest}, expected {}",
            meta.file, meta.sha256
        ))
    }
}
