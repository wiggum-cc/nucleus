use crate::error::{NucleusError, Result};
use crate::filesystem::ContextPopulator;
use std::path::Path;
use tracing::info;

/// Context population mode
#[derive(Debug, Clone)]
pub enum ContextMode {
    /// Traditional copy (default, backward compatible)
    Copy,
    /// Bind mount for zero-copy, instant access
    BindMount,
}

/// Lazy context populator that supports both copy and bind mount modes
pub struct LazyContextPopulator;

impl LazyContextPopulator {
    /// Populate context using the specified mode
    ///
    /// For BindMount mode, the bind mount must happen before pivot_root
    /// since the source is on the host filesystem.
    pub fn populate(mode: &ContextMode, source: &Path, dest: &Path) -> Result<()> {
        match mode {
            ContextMode::Copy => {
                let populator = ContextPopulator::new(source, dest);
                populator.populate()
            }
            ContextMode::BindMount => Self::bind_mount_context(source, dest),
        }
    }

    /// Bind mount source directory to destination (read-only)
    fn bind_mount_context(source: &Path, dest: &Path) -> Result<()> {
        ContextPopulator::new(source, dest).validate_source_tree()?;

        // Ensure destination exists
        std::fs::create_dir_all(dest).map_err(|e| {
            NucleusError::ContextError(format!("Failed to create destination {:?}: {}", dest, e))
        })?;

        info!(
            "Bind mounting context: {:?} -> {:?} (read-only)",
            source, dest
        );

        // Initial bind mount
        nix::mount::mount(
            Some(source),
            dest,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::ContextError(format!(
                "Failed to bind mount {:?} -> {:?}: {}",
                source, dest, e
            ))
        })?;

        // Remount read-only
        nix::mount::mount(
            None::<&str>,
            dest,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND
                | nix::mount::MsFlags::MS_REC
                | nix::mount::MsFlags::MS_RDONLY
                | nix::mount::MsFlags::MS_REMOUNT,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::ContextError(format!("Failed to remount {:?} read-only: {}", dest, e))
        })?;

        info!("Context bind mounted successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_mode_default() {
        let mode = ContextMode::Copy;
        assert!(matches!(mode, ContextMode::Copy));
    }

    #[test]
    fn test_bind_mount_nonexistent_source() {
        let result = LazyContextPopulator::bind_mount_context(
            Path::new("/nonexistent/path"),
            Path::new("/tmp/dest"),
        );
        assert!(result.is_err());
    }
}
