use crate::error::{NucleusError, Result};
use nix::mount::{mount, MsFlags};
use nix::sys::stat::{makedev, mknod, Mode, SFlag};
use nix::unistd::chroot;
use std::path::Path;
use tracing::{debug, info, warn};

/// Create minimal filesystem structure in the new root
pub fn create_minimal_fs(root: &Path) -> Result<()> {
    info!("Creating minimal filesystem structure at {:?}", root);

    // Create essential directories
    let dirs = vec!["dev", "proc", "sys", "tmp", "bin", "etc", "context"];

    for dir in dirs {
        let path = root.join(dir);
        std::fs::create_dir_all(&path).map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to create directory {:?}: {}", path, e))
        })?;
    }

    info!("Created minimal filesystem structure");

    Ok(())
}

/// Create essential device nodes in /dev
///
/// In rootless mode, device node creation will fail gracefully
pub fn create_dev_nodes(dev_path: &Path) -> Result<()> {
    info!("Creating device nodes at {:?}", dev_path);

    // Device nodes: (name, type, major, minor)
    let devices = vec![
        ("null", SFlag::S_IFCHR, 1, 3),
        ("zero", SFlag::S_IFCHR, 1, 5),
        ("full", SFlag::S_IFCHR, 1, 7),
        ("random", SFlag::S_IFCHR, 1, 8),
        ("urandom", SFlag::S_IFCHR, 1, 9),
        ("tty", SFlag::S_IFCHR, 5, 0),
        ("console", SFlag::S_IFCHR, 5, 1),
    ];

    let mut created_count = 0;
    let mut failed_count = 0;

    for (name, dev_type, major, minor) in devices {
        let path = dev_path.join(name);
        let mode = Mode::from_bits(0o666).unwrap();
        let dev = makedev(major, minor);

        match mknod(&path, dev_type, mode, dev) {
            Ok(_) => {
                info!("Created device node: {:?}", path);
                created_count += 1;
            }
            Err(e) => {
                // In rootless mode, mknod fails - this is expected
                warn!(
                    "Failed to create device node {:?}: {} (this is normal in rootless mode)",
                    path, e
                );
                failed_count += 1;
            }
        }
    }

    if created_count > 0 {
        info!("Successfully created {} device nodes", created_count);
    }
    if failed_count > 0 {
        info!("Skipped {} device nodes (rootless mode)", failed_count);
    }

    Ok(())
}

/// Bind mount essential host directories into container
///
/// This allows host binaries to be accessible inside the container
pub fn bind_mount_host_paths(root: &Path, best_effort: bool) -> Result<()> {
    info!("Bind mounting host paths into container");

    // Essential paths to bind mount (read-only)
    let host_paths = vec![
        "/bin", "/usr", "/lib", "/lib64", "/nix", // For NixOS
    ];

    for host_path in host_paths {
        let host = Path::new(host_path);

        // Only mount if the path exists on the host
        if !host.exists() {
            debug!("Skipping {} (not present on host)", host_path);
            continue;
        }

        let container_path = root.join(host_path.trim_start_matches('/'));

        // Create mount point
        if let Err(e) = std::fs::create_dir_all(&container_path) {
            if best_effort {
                warn!("Failed to create mount point {:?}: {}", container_path, e);
                continue;
            }
            return Err(NucleusError::FilesystemError(format!(
                "Failed to create mount point {:?}: {}",
                container_path, e
            )));
        }

        // Attempt bind mount
        // Note: Linux ignores MS_RDONLY on the initial bind mount call.
        // A second remount is required to actually enforce read-only.
        match mount(
            Some(host),
            &container_path,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        ) {
            Ok(_) => {
                // Remount as read-only – required because MS_RDONLY is ignored on initial bind
                mount(
                    None::<&str>,
                    &container_path,
                    None::<&str>,
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_REC,
                    None::<&str>,
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to remount {} as read-only: {}",
                        host_path, e
                    ))
                })?;
                info!(
                    "Bind mounted {} to {:?} (read-only)",
                    host_path, container_path
                );
            }
            Err(e) => {
                if best_effort {
                    warn!(
                        "Failed to bind mount {}: {} (continuing anyway)",
                        host_path, e
                    );
                } else {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to bind mount {}: {}",
                        host_path, e
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Mount procfs at the given path
///
/// In rootless mode, procfs mounting should work due to user namespace capabilities
pub fn mount_procfs(proc_path: &Path, best_effort: bool) -> Result<()> {
    info!("Mounting procfs at {:?}", proc_path);

    match mount(
        Some("proc"),
        proc_path,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ) {
        Ok(_) => {
            info!("Successfully mounted procfs");
            Ok(())
        }
        Err(e) => {
            if best_effort {
                warn!("Failed to mount procfs: {} (continuing anyway)", e);
                Ok(())
            } else {
                Err(NucleusError::FilesystemError(format!(
                    "Failed to mount procfs: {}",
                    e
                )))
            }
        }
    }
}

/// Switch to new root filesystem using pivot_root or chroot
///
/// This implements the transition: populated -> pivoted
/// In rootless mode, this may fail - we'll just chdir instead
pub fn switch_root(new_root: &Path, allow_chdir_fallback: bool) -> Result<()> {
    info!("Switching root to {:?}", new_root);

    // Try pivot_root first (preferred method)
    // If it fails, fall back to chroot
    // If chroot fails, just chdir (rootless mode)

    match pivot_root_impl(new_root) {
        Ok(()) => {
            info!("Successfully switched root using pivot_root");
            Ok(())
        }
        Err(e) => {
            warn!("pivot_root failed ({}), falling back to chroot", e);
            match chroot_impl(new_root) {
                Ok(()) => Ok(()),
                Err(e2) => {
                    if allow_chdir_fallback {
                        warn!(
                            "SECURITY WARNING: pivot_root and chroot both failed. \
                             chdir fallback provides NO filesystem isolation. \
                             Landlock is the only remaining filesystem defense."
                        );
                        warn!("chroot failure reason: {}", e2);
                        // Just change directory - works in rootless
                        std::env::set_current_dir(new_root).map_err(|e| {
                            NucleusError::PivotRootError(format!("Failed to chdir: {}", e))
                        })?;
                        info!("Changed directory to {:?} (rootless mode)", new_root);
                        Ok(())
                    } else {
                        Err(e2)
                    }
                }
            }
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
    pivot_root(new_root, &old_root)
        .map_err(|e| NucleusError::PivotRootError(format!("pivot_root syscall failed: {}", e)))?;

    // Change to new root
    std::env::set_current_dir("/")
        .map_err(|e| NucleusError::PivotRootError(format!("Failed to chdir to /: {}", e)))?;

    // Unmount old root
    nix::mount::umount2("/.old_root", nix::mount::MntFlags::MNT_DETACH)
        .map_err(|e| NucleusError::PivotRootError(format!("Failed to unmount old root: {}", e)))?;

    // Remove old root directory
    let _ = std::fs::remove_dir("/.old_root");

    Ok(())
}

/// Implement root switch using chroot(2)
///
/// chroot is less secure than pivot_root but works in more situations
fn chroot_impl(new_root: &Path) -> Result<()> {
    chroot(new_root)
        .map_err(|e| NucleusError::PivotRootError(format!("chroot syscall failed: {}", e)))?;

    // Change to new root
    std::env::set_current_dir("/")
        .map_err(|e| NucleusError::PivotRootError(format!("Failed to chdir to /: {}", e)))?;

    info!("Successfully switched root using chroot");

    Ok(())
}

#[cfg(test)]
mod tests {
    // Note: Testing pivot_root and chroot requires root privileges
    // These are tested in integration tests
}
