use crate::error::{NucleusError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Context populator - copies files from source to destination
pub struct ContextPopulator {
    source: PathBuf,
    dest: PathBuf,
}

impl ContextPopulator {
    pub fn new<P: AsRef<Path>, Q: AsRef<Path>>(source: P, dest: Q) -> Self {
        Self {
            source: source.as_ref().to_path_buf(),
            dest: dest.as_ref().to_path_buf(),
        }
    }

    /// Populate the destination with files from source
    ///
    /// This implements the transition: mounted -> populated
    pub fn populate(&self) -> Result<()> {
        info!(
            "Populating context from {:?} to {:?}",
            self.source, self.dest
        );

        if !self.source.exists() {
            return Err(NucleusError::ContextError(format!(
                "Source directory does not exist: {:?}",
                self.source
            )));
        }

        if !self.source.is_dir() {
            return Err(NucleusError::ContextError(format!(
                "Source is not a directory: {:?}",
                self.source
            )));
        }

        // Create destination if it doesn't exist
        if !self.dest.exists() {
            fs::create_dir_all(&self.dest).map_err(|e| {
                NucleusError::ContextError(format!(
                    "Failed to create destination {:?}: {}",
                    self.dest, e
                ))
            })?;
        }

        // Walk source tree and copy (depth-limited to prevent stack overflow)
        self.copy_recursive(&self.source, &self.dest, 0)?;

        info!("Successfully populated context");

        Ok(())
    }

    /// Maximum directory recursion depth to prevent stack overflow
    const MAX_RECURSION_DEPTH: u32 = 128;

    /// Recursively copy directory contents
    fn copy_recursive(&self, src: &Path, dst: &Path, depth: u32) -> Result<()> {
        if depth > Self::MAX_RECURSION_DEPTH {
            return Err(NucleusError::ContextError(format!(
                "Maximum directory depth ({}) exceeded at {:?}",
                Self::MAX_RECURSION_DEPTH,
                src
            )));
        }
        let entries = fs::read_dir(src).map_err(|e| {
            NucleusError::ContextError(format!("Failed to read directory {:?}: {}", src, e))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                NucleusError::ContextError(format!("Failed to read entry in {:?}: {}", src, e))
            })?;

            let src_path = entry.path();
            let file_name = entry.file_name();
            let dst_path = dst.join(&file_name);

            // Skip excluded patterns
            if self.should_exclude(&file_name) {
                debug!("Skipping excluded file: {:?}", file_name);
                continue;
            }

            let metadata = fs::symlink_metadata(&src_path).map_err(|e| {
                NucleusError::ContextError(format!(
                    "Failed to get metadata for {:?}: {}",
                    src_path, e
                ))
            })?;

            if metadata.is_dir() {
                // Create directory and recurse
                fs::create_dir_all(&dst_path).map_err(|e| {
                    NucleusError::ContextError(format!(
                        "Failed to create directory {:?}: {}",
                        dst_path, e
                    ))
                })?;
                self.copy_recursive(&src_path, &dst_path, depth + 1)?;
            } else if metadata.is_file() {
                // Copy file
                fs::copy(&src_path, &dst_path).map_err(|e| {
                    NucleusError::ContextError(format!(
                        "Failed to copy {:?} to {:?}: {}",
                        src_path, dst_path, e
                    ))
                })?;
            } else if metadata.is_symlink() {
                // Skip symlinks entirely to prevent link-based escapes or host path leakage.
                warn!("Skipping symlink in context: {:?}", src_path);
            }
        }

        Ok(())
    }

    /// Check if a file should be excluded from copying
    fn should_exclude(&self, name: &std::ffi::OsStr) -> bool {
        let name_str = name.to_string_lossy();
        let lower = name_str.to_lowercase();

        // Exact matches: build artifacts, caches, sensitive directories
        if matches!(
            name_str.as_ref(),
            ".git"
                | "target"
                | "node_modules"
                | ".DS_Store"
                | "__pycache__"
                | ".svn"
                | ".env"
                | ".ssh"
                | ".gnupg"
                | ".aws"
                | ".docker"
        ) {
            return true;
        }

        // Prefix patterns: .env.* files (e.g., .env.local, .env.production)
        if name_str.starts_with(".env.") {
            return true;
        }

        // Suffix patterns: editor swap files
        if name_str.ends_with(".swp") || name_str.ends_with(".swo") {
            return true;
        }

        // Suffix patterns: crypto material
        if name_str.ends_with(".pem")
            || name_str.ends_with(".key")
            || name_str.ends_with(".p12")
            || name_str.ends_with(".crt")
            || name_str.ends_with(".pfx")
            || name_str.ends_with(".jks")
        {
            return true;
        }

        // Contains patterns (case-insensitive): secrets and credentials
        if lower.contains("credential") || lower.contains("secret") || lower.contains("private_key")
        {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_exclude_exact_matches() {
        let p = ContextPopulator::new("/tmp/src", "/tmp/dst");

        // Original exact matches
        assert!(p.should_exclude(std::ffi::OsStr::new(".git")));
        assert!(p.should_exclude(std::ffi::OsStr::new("target")));
        assert!(p.should_exclude(std::ffi::OsStr::new("node_modules")));
        assert!(p.should_exclude(std::ffi::OsStr::new(".DS_Store")));
        assert!(p.should_exclude(std::ffi::OsStr::new("__pycache__")));

        // New exact matches
        assert!(p.should_exclude(std::ffi::OsStr::new(".svn")));
        assert!(p.should_exclude(std::ffi::OsStr::new(".env")));
        assert!(p.should_exclude(std::ffi::OsStr::new(".ssh")));
        assert!(p.should_exclude(std::ffi::OsStr::new(".gnupg")));
        assert!(p.should_exclude(std::ffi::OsStr::new(".aws")));
        assert!(p.should_exclude(std::ffi::OsStr::new(".docker")));
    }

    #[test]
    fn test_should_exclude_env_variants() {
        let p = ContextPopulator::new("/tmp/src", "/tmp/dst");

        assert!(p.should_exclude(std::ffi::OsStr::new(".env.local")));
        assert!(p.should_exclude(std::ffi::OsStr::new(".env.production")));
        assert!(p.should_exclude(std::ffi::OsStr::new(".env.development")));
    }

    #[test]
    fn test_should_exclude_editor_swap() {
        let p = ContextPopulator::new("/tmp/src", "/tmp/dst");

        assert!(p.should_exclude(std::ffi::OsStr::new("file.swp")));
        assert!(p.should_exclude(std::ffi::OsStr::new("file.swo")));
    }

    #[test]
    fn test_should_exclude_crypto_material() {
        let p = ContextPopulator::new("/tmp/src", "/tmp/dst");

        assert!(p.should_exclude(std::ffi::OsStr::new("server.pem")));
        assert!(p.should_exclude(std::ffi::OsStr::new("private.key")));
        assert!(p.should_exclude(std::ffi::OsStr::new("cert.p12")));
        assert!(p.should_exclude(std::ffi::OsStr::new("ca.crt")));
        assert!(p.should_exclude(std::ffi::OsStr::new("keystore.pfx")));
        assert!(p.should_exclude(std::ffi::OsStr::new("app.jks")));
    }

    #[test]
    fn test_should_exclude_secrets_patterns() {
        let p = ContextPopulator::new("/tmp/src", "/tmp/dst");

        assert!(p.should_exclude(std::ffi::OsStr::new("credentials.json")));
        assert!(p.should_exclude(std::ffi::OsStr::new("my_secret.txt")));
        assert!(p.should_exclude(std::ffi::OsStr::new("private_key.pem")));
        assert!(p.should_exclude(std::ffi::OsStr::new("AWS_CREDENTIALS")));
        assert!(p.should_exclude(std::ffi::OsStr::new("app-secret-config.yaml")));
    }

    #[test]
    fn test_should_not_exclude_legitimate_files() {
        let p = ContextPopulator::new("/tmp/src", "/tmp/dst");

        assert!(!p.should_exclude(std::ffi::OsStr::new("src")));
        assert!(!p.should_exclude(std::ffi::OsStr::new("README.md")));
        assert!(!p.should_exclude(std::ffi::OsStr::new("main.rs")));
        assert!(!p.should_exclude(std::ffi::OsStr::new("Cargo.toml")));
        assert!(!p.should_exclude(std::ffi::OsStr::new("my_file.rs")));
        assert!(!p.should_exclude(std::ffi::OsStr::new("config.yaml")));
    }
}
