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
pub fn create_dev_nodes(dev_path: &Path, include_tty: bool) -> Result<()> {
    info!("Creating device nodes at {:?}", dev_path);

    // Device nodes: (name, type, major, minor)
    let mut devices = vec![
        ("null", SFlag::S_IFCHR, 1, 3),
        ("zero", SFlag::S_IFCHR, 1, 5),
        ("full", SFlag::S_IFCHR, 1, 7),
        ("random", SFlag::S_IFCHR, 1, 8),
        ("urandom", SFlag::S_IFCHR, 1, 9),
    ];
    if include_tty {
        devices.push(("tty", SFlag::S_IFCHR, 5, 0));
    }

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

/// Bind mount a pre-built rootfs (e.g. a Nix store closure) into the container.
///
/// Instead of exposing the full host /bin, /usr, /lib, /lib64, /nix, this mounts
/// a minimal, purpose-built root filesystem. Suitable for production services.
pub fn bind_mount_rootfs(root: &Path, rootfs_path: &Path) -> Result<()> {
    info!(
        "Bind mounting production rootfs {:?} into container {:?}",
        rootfs_path, root
    );

    if !rootfs_path.exists() {
        return Err(NucleusError::FilesystemError(format!(
            "Rootfs path does not exist: {:?}",
            rootfs_path
        )));
    }

    // Bind mount the rootfs contents into the container root.
    // The rootfs is expected to contain a standard FHS layout (/bin, /lib, /etc, etc.)
    // produced by a Nix buildEnv or similar.
    let subdirs = ["bin", "sbin", "lib", "lib64", "usr", "etc", "nix"];

    for subdir in &subdirs {
        let source = rootfs_path.join(subdir);
        if !source.exists() {
            debug!("Rootfs subdir {} not present, skipping", subdir);
            continue;
        }

        let target = root.join(subdir);
        std::fs::create_dir_all(&target).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to create mount point {:?}: {}",
                target, e
            ))
        })?;

        mount(
            Some(&source),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to bind mount rootfs {:?} -> {:?}: {}",
                source, target, e
            ))
        })?;

        // Remount read-only
        mount(
            None::<&str>,
            &target,
            None::<&str>,
            MsFlags::MS_REMOUNT
                | MsFlags::MS_BIND
                | MsFlags::MS_RDONLY
                | MsFlags::MS_REC
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remount rootfs {:?} read-only: {}",
                target, e
            ))
        })?;

        info!("Mounted rootfs/{} read-only", subdir);
    }

    Ok(())
}

/// Bind mount essential host directories into container
///
/// This allows host binaries to be accessible inside the container.
/// Used in agent mode. Production mode should use bind_mount_rootfs() instead.
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
                    MsFlags::MS_REMOUNT
                        | MsFlags::MS_BIND
                        | MsFlags::MS_RDONLY
                        | MsFlags::MS_REC
                        | MsFlags::MS_NOSUID
                        | MsFlags::MS_NODEV,
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
pub fn mount_procfs(proc_path: &Path, best_effort: bool, read_only: bool) -> Result<()> {
    info!("Mounting procfs at {:?}", proc_path);

    match mount(
        Some("proc"),
        proc_path,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    ) {
        Ok(_) => {
            if read_only {
                mount(
                    None::<&str>,
                    proc_path,
                    None::<&str>,
                    MsFlags::MS_REMOUNT
                        | MsFlags::MS_RDONLY
                        | MsFlags::MS_NOSUID
                        | MsFlags::MS_NODEV
                        | MsFlags::MS_NOEXEC,
                    None::<&str>,
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to remount procfs read-only: {}",
                        e
                    ))
                })?;
                info!("Successfully mounted procfs (read-only)");
            } else {
                info!("Successfully mounted procfs");
            }
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

/// Mask sensitive /proc paths by bind-mounting /dev/null or tmpfs over them
///
/// This reduces kernel information leakage from the container. Follows OCI runtime
/// conventions for masked paths.
pub fn mask_proc_paths(proc_path: &Path) -> Result<()> {
    info!("Masking sensitive /proc paths");

    // Paths to mask with /dev/null (files)
    let null_masked = ["kallsyms", "kcore", "sched_debug", "timer_list"];

    // Paths to mask with empty tmpfs (directories)
    let tmpfs_masked = ["acpi", "bus", "irq", "scsi", "sys"];

    let dev_null = Path::new("/dev/null");

    for name in &null_masked {
        let target = proc_path.join(name);
        if !target.exists() {
            continue;
        }
        match mount(
            Some(dev_null),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        ) {
            Ok(_) => debug!("Masked /proc/{}", name),
            Err(e) => warn!("Failed to mask /proc/{}: {} (continuing)", name, e),
        }
    }

    for name in &tmpfs_masked {
        let target = proc_path.join(name);
        if !target.exists() {
            continue;
        }
        match mount(
            Some("tmpfs"),
            &target,
            Some("tmpfs"),
            MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            Some("size=0"),
        ) {
            Ok(_) => debug!("Masked /proc/{}", name),
            Err(e) => warn!("Failed to mask /proc/{}: {} (continuing)", name, e),
        }
    }

    info!("Finished masking sensitive /proc paths");
    Ok(())
}

/// Switch to new root filesystem using pivot_root or chroot
///
/// This implements the transition: populated -> pivoted
/// Fails closed if root switching cannot be established.
pub fn switch_root(new_root: &Path, allow_chroot_fallback: bool) -> Result<()> {
    info!("Switching root to {:?}", new_root);

    match pivot_root_impl(new_root) {
        Ok(()) => {
            info!("Successfully switched root using pivot_root");
            Ok(())
        }
        Err(e) => {
            if allow_chroot_fallback {
                warn!(
                    "pivot_root failed ({}), falling back to chroot due to explicit \
                     configuration",
                    e
                );
                chroot_impl(new_root)
            } else {
                Err(NucleusError::PivotRootError(format!(
                    "pivot_root failed: {}. chroot fallback is disabled by default; use \
                     --allow-chroot-fallback to allow weaker isolation",
                    e
                )))
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

/// Mount secret files into the container root.
///
/// Each secret is bind-mounted read-only from its source to the destination
/// path inside the container. Intermediate directories are created as needed.
pub fn mount_secrets(
    root: &Path,
    secrets: &[crate::container::SecretMount],
) -> Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }

    info!("Mounting {} secret(s) into container", secrets.len());

    for secret in secrets {
        if !secret.source.exists() {
            return Err(NucleusError::FilesystemError(format!(
                "Secret source does not exist: {:?}",
                secret.source
            )));
        }

        // Destination inside container root
        let dest = root.join(secret.dest.strip_prefix("/").unwrap_or(&secret.dest));

        // Create parent directories
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret mount parent {:?}: {}",
                    parent, e
                ))
            })?;
        }

        // Create mount point file
        if secret.source.is_file() {
            std::fs::write(&dest, "").map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret mount point {:?}: {}",
                    dest, e
                ))
            })?;
        } else {
            std::fs::create_dir_all(&dest).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret mount dir {:?}: {}",
                    dest, e
                ))
            })?;
        }

        // Bind mount read-only
        mount(
            Some(secret.source.as_path()),
            &dest,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to bind mount secret {:?}: {}",
                secret.source, e
            ))
        })?;

        mount(
            None::<&str>,
            &dest,
            None::<&str>,
            MsFlags::MS_REMOUNT
                | MsFlags::MS_BIND
                | MsFlags::MS_RDONLY
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV
                | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to remount secret {:?} read-only: {}",
                dest, e
            ))
        })?;

        // Apply configured file permissions on the mount point
        if secret.source.is_file() {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(secret.mode);
            if let Err(e) = std::fs::set_permissions(&dest, perms) {
                warn!(
                    "Failed to set mode {:04o} on secret {:?}: {} (bind mount may override)",
                    secret.mode, dest, e
                );
            }
        }

        debug!("Mounted secret {:?} -> {:?} (mode {:04o})", secret.source, secret.dest, secret.mode);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Note: Testing pivot_root and chroot requires root privileges
    // These are tested in integration tests
}
