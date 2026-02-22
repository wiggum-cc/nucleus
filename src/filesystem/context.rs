use crate::error::{NucleusError, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

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
        info!("Populating context from {:?} to {:?}", self.source, self.dest);

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

        // Walk source tree and copy
        self.copy_recursive(&self.source, &self.dest)?;

        info!("Successfully populated context");

        Ok(())
    }

    /// Recursively copy directory contents
    fn copy_recursive(&self, src: &Path, dst: &Path) -> Result<()> {
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

            let metadata = entry.metadata().map_err(|e| {
                NucleusError::ContextError(format!(
                    "Failed to get metadata for {:?}: {}",
                    src_path, e
                ))
            })?;

            if metadata.is_dir() {
                // Create directory and recurse
                fs::create_dir(&dst_path).map_err(|e| {
                    NucleusError::ContextError(format!(
                        "Failed to create directory {:?}: {}",
                        dst_path, e
                    ))
                })?;
                self.copy_recursive(&src_path, &dst_path)?;
            } else if metadata.is_file() {
                // Copy file
                fs::copy(&src_path, &dst_path).map_err(|e| {
                    NucleusError::ContextError(format!(
                        "Failed to copy {:?} to {:?}: {}",
                        src_path, dst_path, e
                    ))
                })?;
            } else if metadata.is_symlink() {
                // Copy symlink
                let target = fs::read_link(&src_path).map_err(|e| {
                    NucleusError::ContextError(format!(
                        "Failed to read symlink {:?}: {}",
                        src_path, e
                    ))
                })?;
                std::os::unix::fs::symlink(&target, &dst_path).map_err(|e| {
                    NucleusError::ContextError(format!(
                        "Failed to create symlink {:?}: {}",
                        dst_path, e
                    ))
                })?;
            }
        }

        Ok(())
    }

    /// Check if a file should be excluded from copying
    fn should_exclude(&self, name: &std::ffi::OsStr) -> bool {
        let name_str = name.to_string_lossy();

        // Exclude common build/cache directories
        matches!(
            name_str.as_ref(),
            ".git" | "target" | "node_modules" | ".DS_Store" | "__pycache__"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_exclude() {
        let populator = ContextPopulator::new("/tmp/src", "/tmp/dst");

        assert!(populator.should_exclude(std::ffi::OsStr::new(".git")));
        assert!(populator.should_exclude(std::ffi::OsStr::new("target")));
        assert!(populator.should_exclude(std::ffi::OsStr::new("node_modules")));
        assert!(!populator.should_exclude(std::ffi::OsStr::new("src")));
        assert!(!populator.should_exclude(std::ffi::OsStr::new("README.md")));
    }
}
