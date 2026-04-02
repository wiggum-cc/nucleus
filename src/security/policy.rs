//! Shared policy file loading infrastructure.
//!
//! Provides generic TOML and JSON policy loaders with optional SHA-256
//! integrity verification. Used by caps_policy, landlock_policy, and
//! seccomp profile loading.

use crate::error::{NucleusError, Result};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::info;

/// Compute the SHA-256 hex digest of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Read a file and optionally verify its SHA-256 hash.
///
/// Returns the raw file contents on success. If `expected_sha256` is provided
/// and the hash doesn't match, returns an error.
pub fn read_and_verify(path: &Path, expected_sha256: Option<&str>) -> Result<Vec<u8>> {
    let content = std::fs::read(path).map_err(|e| {
        NucleusError::ConfigError(format!("Failed to read policy file {:?}: {}", path, e))
    })?;

    if let Some(expected) = expected_sha256 {
        let actual = sha256_hex(&content);
        if actual != expected {
            return Err(NucleusError::ConfigError(format!(
                "Policy file {:?} hash mismatch: expected {}, got {}",
                path, expected, actual
            )));
        }
        info!("Policy file {:?} hash verified: {}", path, actual);
    }

    Ok(content)
}

/// Load and parse a TOML policy file with optional SHA-256 verification.
pub fn load_toml_policy<T: DeserializeOwned>(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<T> {
    let content = read_and_verify(path, expected_sha256)?;
    let text = std::str::from_utf8(&content).map_err(|e| {
        NucleusError::ConfigError(format!("Policy file {:?} is not valid UTF-8: {}", path, e))
    })?;
    toml::from_str(text).map_err(|e| {
        NucleusError::ConfigError(format!("Failed to parse TOML policy {:?}: {}", path, e))
    })
}

/// Load and parse a JSON policy file with optional SHA-256 verification.
pub fn load_json_policy<T: DeserializeOwned>(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<T> {
    let content = read_and_verify(path, expected_sha256)?;
    serde_json::from_slice(&content).map_err(|e| {
        NucleusError::ConfigError(format!("Failed to parse JSON policy {:?}: {}", path, e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello world");
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
