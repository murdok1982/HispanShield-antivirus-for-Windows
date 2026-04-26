pub mod hash_detector;
pub mod heuristic_detector;
pub mod network_detector;
pub mod yara_detector;

pub use hash_detector::{HashDetector, IocMatch};
pub use heuristic_detector::{HeuristicResult, analyse_file, is_lolbin, is_suspicious_extension};
pub use network_detector::{NetworkDetector, NetworkThreatResult, NetworkThreatType};
pub use yara_detector::{YaraDetector, YaraMatch};

use anyhow::Result;
use sha2::{Digest, Sha256};
use sha1::Sha1;
use md5::Md5;
use std::path::Path;

/// Compute SHA-256, SHA-1 and MD5 hashes for a file on disk.
/// Returns (sha256_hex, sha1_hex, md5_hex).
pub fn hash_file(path: &Path) -> Result<(String, String, String)> {
    let data = std::fs::read(path)?;
    Ok(hash_bytes(&data))
}

/// Compute SHA-256, SHA-1 and MD5 for in-memory bytes.
/// Returns (sha256_hex, sha1_hex, md5_hex).
pub fn hash_bytes(data: &[u8]) -> (String, String, String) {
    let sha256 = format!("{:x}", Sha256::digest(data));
    let sha1 = format!("{:x}", Sha1::digest(data));
    let md5 = format!("{:x}", Md5::digest(data));
    (sha256, sha1, md5)
}
