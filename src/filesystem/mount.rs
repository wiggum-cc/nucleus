use crate::error::{NucleusError, Result};
use nix::mount::{mount, MsFlags};
use nix::unistd::chroot;
use std::path::Path;
use tracing::{info, warn};

/// Create minimal filesystem structure in the new root
pub fn create_minimal_fs(root: &Path) -> Result<()> {
    info!("Creating minimal filesystem structure at {:?}", root);

    // Create essential directories
    let dirs = vec!["dev", "proc", "sys", "tmp", "bin", "etc", "context"];

    for dir in dirs {
        let path = root.join(dir);
        std::fs::create_dir_all(&path).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create directory {:?}: {}",
                path, e
            ))
        })?;
    }

    info!("Created minimal filesystem structure");

    Ok(())
}

/// Mount procfs at the given path
pub fn mount_procfs(proc_path: &Path) -> Result<()> {
    info!("Mounting procfs at {:?}", proc_path);

    mount(
        Some("proc"),
        proc_path,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to mount procfs at {:?}: {}", proc_path, e))
    })?;

    info!("Successfully mounted procfs");

    Ok(())
}

/// Switch to new root filesystem using pivot_root or chroot
///
/// This implements the transition: populated -> pivoted
pub fn switch_root(new_root: &Path) -> Result<()> {
    info!("Switching root to {:?}", new_root);

    // Try pivot_root first (preferred method)
    // If it fails, fall back to chroot

    match pivot_root_impl(new_root) {
        Ok(()) => {
            info!("Successfully switched root using pivot_root");
            Ok(())
        }
        Err(e) => {
            warn!("pivot_root failed ({}), falling back to chroot", e);
            chroot_impl(new_root)
        }
    }
}

/// Implement root switch using pivot_root(2)
///
/// pivot_root is preferred over chroot because:
/// - More secure (old root can be unmounted)
/// - Works better with mount namespaces
fn pivot_root_impl(new_root: &Path) -> Result<()> {
    use nix::unistd::pivot_root;

    // pivot_root requires new_root to be a mount point
    // and old_root to be under new_root

    let old_root = new_root.join(".old_root");
    std::fs::create_dir_all(&old_root).map_err(|e| {
        NucleusError::PivotRootError(format!("Failed to create old_root directory: {}", e))
    })?;

    // Perform pivot_root
    pivot_root(new_root, &old_root).map_err(|e| {
        NucleusError::PivotRootError(format!("pivot_root syscall failed: {}", e))
    })?;

    // Change to new root
    std::env::set_current_dir("/").map_err(|e| {
        NucleusError::PivotRootError(format!("Failed to chdir to /: {}", e))
    })?;

    // Unmount old root
    nix::mount::umount2("/.old_root", nix::mount::MntFlags::MNT_DETACH).map_err(|e| {
        NucleusError::PivotRootError(format!("Failed to unmount old root: {}", e))
    })?;

    // Remove old root directory
    let _ = std::fs::remove_dir("/.old_root");

    Ok(())
}

/// Implement root switch using chroot(2)
///
/// chroot is less secure than pivot_root but works in more situations
fn chroot_impl(new_root: &Path) -> Result<()> {
    chroot(new_root).map_err(|e| {
        NucleusError::PivotRootError(format!("chroot syscall failed: {}", e))
    })?;

    // Change to new root
    std::env::set_current_dir("/").map_err(|e| {
        NucleusError::PivotRootError(format!("Failed to chdir to /: {}", e))
    })?;

    info!("Successfully switched root using chroot");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Testing pivot_root and chroot requires root privileges
    // These are tested in integration tests
}
