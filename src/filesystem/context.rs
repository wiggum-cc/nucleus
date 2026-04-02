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

    /// Validate a source tree without copying it.
    ///
    /// Used by bind-mount mode so the host tree gets the same preflight checks
    /// as copy mode.
    pub fn validate_source_tree(&self) -> Result<()> {
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

        self.validate_recursive(&self.source, 0)
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
            if Self::should_exclude_name(&file_name) {
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

    fn validate_recursive(&self, src: &Path, depth: u32) -> Result<()> {
        if depth > Self::MAX_RECURSION_DEPTH {
            return Err(NucleusError::ContextError(format!(
                "Maximum directory depth ({}) exceeded at {:?}",
                Self::MAX_RECURSION_DEPTH,
                src
            )));
        }

        for entry in fs::read_dir(src).map_err(|e| {
            NucleusError::ContextError(format!("Failed to read directory {:?}: {}", src, e))
        })? {
            let entry = entry.map_err(|e| {
                NucleusError::ContextError(format!("Failed to read entry in {:?}: {}", src, e))
            })?;

            let src_path = entry.path();
            let file_name = entry.file_name();

            if Self::should_exclude_name(&file_name) {
                continue;
            }

            let metadata = fs::symlink_metadata(&src_path).map_err(|e| {
                NucleusError::ContextError(format!(
                    "Failed to get metadata for {:?}: {}",
                    src_path, e
                ))
            })?;

            if metadata.is_symlink() {
                return Err(NucleusError::ContextError(format!(
                    "Bind-mounted contexts may not contain symlinks: {:?}",
                    src_path
                )));
            }

            if metadata.is_dir() {
                self.validate_recursive(&src_path, depth + 1)?;
            }
        }

        Ok(())
    }

    /// Check if a file should be excluded from copying
    pub(crate) fn should_exclude_name(name: &std::ffi::OsStr) -> bool {
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
                | ".azure"
                | ".gcloud"
                | ".config/gcloud"
                | ".docker"
                | ".netrc"
                | ".kube"
                | ".helm"
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
        if lower.contains("credential")
            || lower.contains("secret")
            || lower.contains("private_key")
            || lower.contains("kubeconfig")
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
        // Original exact matches
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".git"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "target"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "node_modules"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".DS_Store"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "__pycache__"
        )));

        // New exact matches
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".svn"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".env"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".ssh"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".gnupg"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".aws"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".docker"
        )));

        // L-2: expanded exclusion list
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".azure"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".gcloud"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".netrc"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".kube"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".helm"
        )));
    }

    #[test]
    fn test_should_exclude_env_variants() {
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".env.local"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".env.production"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            ".env.development"
        )));
    }

    #[test]
    fn test_should_exclude_editor_swap() {
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "file.swp"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "file.swo"
        )));
    }

    #[test]
    fn test_should_exclude_crypto_material() {
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "server.pem"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "private.key"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "cert.p12"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "ca.crt"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "keystore.pfx"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "app.jks"
        )));
    }

    #[test]
    fn test_should_exclude_secrets_patterns() {
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "credentials.json"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "my_secret.txt"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "private_key.pem"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "AWS_CREDENTIALS"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "app-secret-config.yaml"
        )));

        // L-2: kubeconfig pattern
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "kubeconfig"
        )));
        assert!(ContextPopulator::should_exclude_name(std::ffi::OsStr::new(
            "my-kubeconfig.yaml"
        )));
    }

    #[test]
    fn test_should_not_exclude_legitimate_files() {
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("src")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("README.md")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("main.rs")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("Cargo.toml")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("my_file.rs")
        ));
        assert!(!ContextPopulator::should_exclude_name(
            std::ffi::OsStr::new("config.yaml")
        ));
    }
}
