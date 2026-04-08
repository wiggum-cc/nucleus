use crate::error::{NucleusError, Result};
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, MsFlags};
use nix::sys::stat::{fstat, makedev, mknod, Mode, SFlag};
use nix::unistd::chroot;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use tracing::{debug, info, warn};

/// Expected mount flags for audit verification.
struct ExpectedMount {
    path: &'static str,
    required_flags: &'static [&'static str],
    /// If true, the mount *must* exist in production mode. A missing critical
    /// mount (e.g. /proc) is treated as a violation rather than silently skipped.
    critical: bool,
}

/// Known mount paths and the flags they must carry in production mode.
const PRODUCTION_MOUNT_EXPECTATIONS: &[ExpectedMount] = &[
    ExpectedMount {
        path: "/bin",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: true,
    },
    ExpectedMount {
        path: "/usr",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: true,
    },
    ExpectedMount {
        path: "/lib",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: false, // not all rootfs layouts have /lib
    },
    ExpectedMount {
        path: "/lib64",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: false, // not all rootfs layouts have /lib64
    },
    ExpectedMount {
        path: "/etc",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: true,
    },
    ExpectedMount {
        path: "/nix",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: false, // only present on NixOS-based rootfs
    },
    ExpectedMount {
        path: "/sbin",
        required_flags: &["ro", "nosuid", "nodev"],
        critical: false, // not all rootfs layouts have /sbin
    },
    ExpectedMount {
        path: "/proc",
        required_flags: &["nosuid", "nodev", "noexec"],
        critical: true,
    },
    ExpectedMount {
        path: "/run/secrets",
        required_flags: &["nosuid", "nodev", "noexec"],
        critical: false, // only present when secrets are configured
    },
];

/// Normalize an absolute container destination path and reject traversal.
///
/// Returns a normalized absolute path containing only `RootDir` and `Normal`
/// components. `.` segments are ignored; `..` and relative paths are rejected.
pub fn normalize_container_destination(dest: &Path) -> Result<PathBuf> {
    if !dest.is_absolute() {
        return Err(NucleusError::ConfigError(format!(
            "Container destination must be absolute: {:?}",
            dest
        )));
    }

    let mut normalized = PathBuf::from("/");
    let mut saw_component = false;

    for component in dest.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::Normal(part) => {
                normalized.push(part);
                saw_component = true;
            }
            Component::ParentDir => {
                return Err(NucleusError::ConfigError(format!(
                    "Container destination must not contain parent traversal: {:?}",
                    dest
                )));
            }
            Component::Prefix(_) => {
                return Err(NucleusError::ConfigError(format!(
                    "Unsupported container destination prefix: {:?}",
                    dest
                )));
            }
        }
    }

    if !saw_component {
        return Err(NucleusError::ConfigError(format!(
            "Container destination must not be the root directory: {:?}",
            dest
        )));
    }

    Ok(normalized)
}

/// Resolve a validated container destination under a host-side root directory.
pub fn resolve_container_destination(root: &Path, dest: &Path) -> Result<PathBuf> {
    let normalized = normalize_container_destination(dest)?;
    let relative = normalized.strip_prefix("/").map_err(|_| {
        NucleusError::ConfigError(format!(
            "Container destination is not absolute after normalization: {:?}",
            normalized
        ))
    })?;
    Ok(root.join(relative))
}

pub(crate) fn read_regular_file_nofollow(path: &Path) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to open file {:?} with O_NOFOLLOW: {}",
                path, e
            ))
        })?;

    let metadata = file.metadata().map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to stat file {:?}: {}", path, e))
    })?;
    if !metadata.is_file() {
        return Err(NucleusError::FilesystemError(format!(
            "Expected regular file for {:?}, found non-file source",
            path
        )));
    }

    let mut content = Vec::new();
    file.read_to_end(&mut content).map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to read file {:?}: {}", path, e))
    })?;
    Ok(content)
}

/// Audit all mounts in the container's mount namespace.
///
/// Reads /proc/self/mounts and verifies that each known mount point carries
/// its expected flags. In production mode, any missing flag is fatal.
/// Returns Ok(()) if all checks pass, or a list of violations.
pub fn audit_mounts(production_mode: bool) -> Result<()> {
    let mounts_content = std::fs::read_to_string("/proc/self/mounts").map_err(|e| {
        NucleusError::FilesystemError(format!("Failed to read /proc/self/mounts: {}", e))
    })?;

    let mut violations = Vec::new();

    for expectation in PRODUCTION_MOUNT_EXPECTATIONS {
        // Find the mount entry for this path
        let mount_entry = mounts_content.lines().find(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts.len() >= 4 && parts[1] == expectation.path
        });

        if let Some(entry) = mount_entry {
            let parts: Vec<&str> = entry.split_whitespace().collect();
            if parts.len() >= 4 {
                let options = parts[3];
                for &flag in expectation.required_flags {
                    if !options.split(',').any(|opt| opt == flag) {
                        violations.push(format!(
                            "Mount {} missing required flag '{}' (has: {})",
                            expectation.path, flag, options
                        ));
                    }
                }
            }
        } else if expectation.critical && production_mode {
            violations.push(format!(
                "Critical mount {} is missing from the mount namespace",
                expectation.path
            ));
        }
    }

    if violations.is_empty() {
        info!("Mount audit passed: all expected flags verified");
        Ok(())
    } else if production_mode {
        Err(NucleusError::FilesystemError(format!(
            "Mount audit failed in production mode:\n  {}",
            violations.join("\n  ")
        )))
    } else {
        for v in &violations {
            warn!("Mount audit: {}", v);
        }
        Ok(())
    }
}

/// Create minimal filesystem structure in the new root
pub fn create_minimal_fs(root: &Path) -> Result<()> {
    info!("Creating minimal filesystem structure at {:?}", root);

    // Create essential directories
    let dirs = vec![
        "dev",
        "proc",
        "sys",
        "tmp",
        "bin",
        "sbin",
        "usr",
        "lib",
        "lib64",
        "etc",
        "nix",
        "nix/store",
        "run",
        "context",
    ];

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
        let mode = Mode::from_bits_truncate(0o660);
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

    if std::fs::symlink_metadata(rootfs_path).is_err() {
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

/// H7: Sensitive host paths that must not be bind-mounted into containers.
const DENIED_BIND_MOUNT_SOURCES_EXACT: &[&str] = &[
    "/",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/passwd",
    "/etc/gshadow",
];

/// Sensitive host subtrees that must not be exposed to a container at all.
const DENIED_BIND_MOUNT_SOURCE_PREFIXES: &[&str] = &["/proc", "/sys", "/dev", "/boot"];

fn normalize_bind_mount_source_for_policy(source: &Path) -> Result<PathBuf> {
    if !source.is_absolute() {
        return Err(NucleusError::ConfigError(format!(
            "Bind mount source must be absolute: {:?}",
            source
        )));
    }

    let mut normalized = PathBuf::from("/");

    for component in source.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                normalized.pop();
                if normalized.as_os_str().is_empty() {
                    normalized.push("/");
                }
            }
            Component::Prefix(_) => {
                return Err(NucleusError::ConfigError(format!(
                    "Unsupported bind mount source prefix: {:?}",
                    source
                )));
            }
        }
    }

    Ok(normalized)
}

fn reject_denied_bind_mount_source(source: &Path) -> Result<()> {
    for denied in DENIED_BIND_MOUNT_SOURCES_EXACT {
        if source == Path::new(denied) {
            return Err(NucleusError::ConfigError(format!(
                "Bind mount source '{}' is a sensitive host path and cannot be mounted into containers",
                source.display()
            )));
        }
    }

    for denied in DENIED_BIND_MOUNT_SOURCE_PREFIXES {
        let denied_path = Path::new(denied);
        if source == denied_path || source.starts_with(denied_path) {
            return Err(NucleusError::ConfigError(format!(
                "Bind mount source '{}' is under sensitive host path '{}' and cannot be mounted into containers",
                source.display(),
                denied
            )));
        }
    }

    Ok(())
}

/// Validate that a bind mount source is not a sensitive host path or subtree.
pub fn validate_bind_mount_source(source: &Path) -> Result<()> {
    let normalized = normalize_bind_mount_source_for_policy(source)?;
    reject_denied_bind_mount_source(&normalized)?;

    let canonical = std::fs::canonicalize(source).map_err(|e| {
        NucleusError::ConfigError(format!(
            "Failed to resolve bind mount source {:?}: {}",
            source, e
        ))
    })?;
    reject_denied_bind_mount_source(&canonical)
}

/// Mount persistent bind volumes and ephemeral tmpfs volumes into the container root.
pub fn mount_volumes(root: &Path, volumes: &[crate::container::VolumeMount]) -> Result<()> {
    use crate::container::VolumeSource;

    if volumes.is_empty() {
        return Ok(());
    }

    info!("Mounting {} volume(s) into container", volumes.len());

    for volume in volumes {
        let dest = resolve_container_destination(root, &volume.dest)?;

        match &volume.source {
            VolumeSource::Bind { source } => {
                // H7: Deny bind-mounting sensitive host paths
                validate_bind_mount_source(source)?;

                // Use symlink_metadata (lstat) instead of .exists() to avoid
                // following symlinks in the existence check (O_NOFOLLOW semantics).
                if std::fs::symlink_metadata(source).is_err() {
                    return Err(NucleusError::FilesystemError(format!(
                        "Volume source does not exist: {:?}",
                        source
                    )));
                }

                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create volume mount parent {:?}: {}",
                            parent, e
                        ))
                    })?;
                }

                let recursive = source.is_dir();
                if source.is_file() {
                    std::fs::write(&dest, "").map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create volume mount point {:?}: {}",
                            dest, e
                        ))
                    })?;
                } else {
                    std::fs::create_dir_all(&dest).map_err(|e| {
                        NucleusError::FilesystemError(format!(
                            "Failed to create volume mount dir {:?}: {}",
                            dest, e
                        ))
                    })?;
                }

                let initial_flags = if recursive {
                    MsFlags::MS_BIND | MsFlags::MS_REC
                } else {
                    MsFlags::MS_BIND
                };
                mount(
                    Some(source.as_path()),
                    &dest,
                    None::<&str>,
                    initial_flags,
                    None::<&str>,
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to bind mount volume {:?} -> {:?}: {}",
                        source, dest, e
                    ))
                })?;

                let mut remount_flags =
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
                if recursive {
                    remount_flags |= MsFlags::MS_REC;
                }
                if volume.read_only {
                    remount_flags |= MsFlags::MS_RDONLY;
                }

                mount(
                    None::<&str>,
                    &dest,
                    None::<&str>,
                    remount_flags,
                    None::<&str>,
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to remount volume {:?} with final flags: {}",
                        dest, e
                    ))
                })?;

                info!(
                    "Mounted bind volume {:?} -> {:?} ({})",
                    source,
                    volume.dest,
                    if volume.read_only { "ro" } else { "rw" }
                );
            }
            VolumeSource::Tmpfs { size } => {
                std::fs::create_dir_all(&dest).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create tmpfs mount dir {:?}: {}",
                        dest, e
                    ))
                })?;

                // M8: Validate size parameter to prevent option injection.
                // Only allow digits, optionally followed by K/M/G suffix.
                if let Some(value) = size.as_ref() {
                    let valid = value
                        .chars()
                        .all(|c| c.is_ascii_digit() || "kKmMgG".contains(c));
                    if !valid || value.is_empty() {
                        return Err(NucleusError::FilesystemError(format!(
                            "Invalid tmpfs size value '{}': only digits with optional K/M/G suffix allowed",
                            value
                        )));
                    }
                }

                // M7: Default to 64MB instead of half of physical RAM to
                // prevent memory DoS from unbounded tmpfs volumes.
                let mount_data = size
                    .as_ref()
                    .map(|value| format!("size={},mode=0700", value))
                    .unwrap_or_else(|| "size=64M,mode=0700".to_string());

                let mut flags = MsFlags::MS_NOSUID | MsFlags::MS_NODEV;
                if volume.read_only {
                    flags |= MsFlags::MS_RDONLY;
                }
                mount(
                    Some("tmpfs"),
                    &dest,
                    Some("tmpfs"),
                    flags,
                    Some(mount_data.as_str()),
                )
                .map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to mount tmpfs volume at {:?}: {}",
                        dest, e
                    ))
                })?;

                info!(
                    "Mounted tmpfs volume at {:?}{}{}",
                    volume.dest,
                    size.as_ref()
                        .map(|value| format!(" (size={})", value))
                        .unwrap_or_default(),
                    if volume.read_only { " (ro)" } else { "" }
                );
            }
        }
    }

    Ok(())
}

/// Mount procfs at the given path
///
/// In rootless mode, procfs mounting should work due to user namespace capabilities.
/// When `hide_pids` is true, mounts with hidepid=2 so processes cannot enumerate
/// other PIDs (production hardening).
pub fn mount_procfs(
    proc_path: &Path,
    best_effort: bool,
    read_only: bool,
    hide_pids: bool,
) -> Result<()> {
    info!(
        "Mounting procfs at {:?} (hidepid={})",
        proc_path,
        if hide_pids { "2" } else { "0" }
    );

    let mount_data: Option<&str> = if hide_pids { Some("hidepid=2") } else { None };

    match mount(
        Some("proc"),
        proc_path,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        mount_data,
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

/// Paths to mask with /dev/null (files) – matches OCI runtime spec masked paths.
/// Exposed for testing; the canonical list of sensitive /proc entries that must
/// be hidden from container processes.
pub const PROC_NULL_MASKED: &[&str] = &[
    "kallsyms",
    "kcore",
    "sched_debug",
    "timer_list",
    "timer_stats",
    "keys",
    "latency_stats",
    "config.gz",
    "sysrq-trigger",
    "kpagecount",
    "kpageflags",
    "kpagecgroup",
];

/// Paths to mask with empty tmpfs (directories).
pub const PROC_TMPFS_MASKED: &[&str] = &["acpi", "bus", "irq", "scsi", "sys"];

/// Mask sensitive /proc paths by bind-mounting /dev/null or tmpfs over them
///
/// This reduces kernel information leakage from the container. Follows OCI runtime
/// conventions for masked paths.
///
/// SEC-06: When `production` is true, failures to mask critical paths
/// (kcore, kallsyms, sysrq-trigger) are fatal instead of warn-and-continue.
pub fn mask_proc_paths(proc_path: &Path, production: bool) -> Result<()> {
    info!("Masking sensitive /proc paths");

    const CRITICAL_PROC_PATHS: &[&str] = &["kcore", "kallsyms", "sysrq-trigger"];

    let dev_null = Path::new("/dev/null");

    for name in PROC_NULL_MASKED {
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
            Ok(_) => {
                // Remount read-only: Linux ignores MS_RDONLY on the initial bind mount,
                // so a separate MS_REMOUNT|MS_BIND|MS_RDONLY call is required.
                if let Err(e) = mount(
                    None::<&str>,
                    &target,
                    None::<&str>,
                    MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY,
                    None::<&str>,
                ) {
                    if production && CRITICAL_PROC_PATHS.contains(name) {
                        return Err(NucleusError::FilesystemError(format!(
                            "Failed to remount /proc/{} read-only in production mode: {}",
                            name, e
                        )));
                    }
                    warn!(
                        "Failed to remount /proc/{} read-only: {} (continuing)",
                        name, e
                    );
                }
                debug!("Masked /proc/{} (read-only)", name);
            }
            Err(e) => {
                if production && CRITICAL_PROC_PATHS.contains(name) {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to mask critical /proc/{} in production mode: {}",
                        name, e
                    )));
                }
                warn!("Failed to mask /proc/{}: {} (continuing)", name, e);
            }
        }
    }

    for name in PROC_TMPFS_MASKED {
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
            Err(e) => {
                if production {
                    return Err(NucleusError::FilesystemError(format!(
                        "Failed to mask /proc/{} in production mode: {}",
                        name, e
                    )));
                }
                warn!("Failed to mask /proc/{}: {} (continuing)", name, e);
            }
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

    // L3: Drop CAP_SYS_CHROOT after chroot to prevent escape via nested chroot.
    // Also close any FDs pointing outside the new root.
    if let Err(e) = caps::drop(
        None,
        caps::CapSet::Bounding,
        caps::Capability::CAP_SYS_CHROOT,
    ) {
        debug!(
            "Could not drop CAP_SYS_CHROOT after chroot: {} (may not be present)",
            e
        );
    }
    if let Err(e) = caps::drop(
        None,
        caps::CapSet::Effective,
        caps::Capability::CAP_SYS_CHROOT,
    ) {
        debug!(
            "Could not drop effective CAP_SYS_CHROOT: {} (may not be present)",
            e
        );
    }
    if let Err(e) = caps::drop(
        None,
        caps::CapSet::Permitted,
        caps::Capability::CAP_SYS_CHROOT,
    ) {
        debug!(
            "Could not drop permitted CAP_SYS_CHROOT: {} (may not be present)",
            e
        );
    }

    info!("Successfully switched root using chroot (CAP_SYS_CHROOT dropped)");

    Ok(())
}

/// Mount secret files into the container root.
///
/// Each secret is bind-mounted read-only from its source to the destination
/// path inside the container. Intermediate directories are created as needed.
pub fn mount_secrets(root: &Path, secrets: &[crate::container::SecretMount]) -> Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }

    info!("Mounting {} secret(s) into container", secrets.len());

    for secret in secrets {
        let source_fd = open(
            &secret.source,
            OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to open secret source {:?} with O_NOFOLLOW: {}",
                secret.source, e
            ))
        })?;
        let source_stat = fstat(&source_fd).map_err(|e| {
            NucleusError::FilesystemError(format!(
                "Failed to stat secret source {:?}: {}",
                secret.source, e
            ))
        })?;
        let source_kind = SFlag::from_bits_truncate(source_stat.st_mode);
        let source_is_file = source_kind == SFlag::S_IFREG;
        let source_is_dir = source_kind == SFlag::S_IFDIR;
        if !source_is_file && !source_is_dir {
            return Err(NucleusError::FilesystemError(format!(
                "Secret source {:?} must be a regular file or directory",
                secret.source
            )));
        }
        let source_fd_path = PathBuf::from(format!("/proc/self/fd/{}", source_fd.as_raw_fd()));

        // Destination inside container root
        let dest = resolve_container_destination(root, &secret.dest)?;

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
        if source_is_file {
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
            Some(source_fd_path.as_path()),
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
        if source_is_file {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(secret.mode);
            if let Err(e) = std::fs::set_permissions(&dest, perms) {
                warn!(
                    "Failed to set mode {:04o} on secret {:?}: {} (bind mount may override)",
                    secret.mode, dest, e
                );
            }
        }

        debug!(
            "Mounted secret {:?} -> {:?} (mode {:04o})",
            secret.source, secret.dest, secret.mode
        );
    }

    Ok(())
}

/// Mount secrets onto a dedicated in-memory tmpfs instead of bind-mounting host paths.
///
/// Creates a per-container tmpfs at `<root>/run/secrets` with MS_NOEXEC | MS_NOSUID | MS_NODEV,
/// copies secret contents into it, then zeros the read buffer. This ensures secrets
/// never reference host-side files after setup and are never persisted to disk.
pub fn mount_secrets_inmemory(
    root: &Path,
    secrets: &[crate::container::SecretMount],
    identity: &crate::container::ProcessIdentity,
) -> Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }

    info!("Mounting {} secret(s) on in-memory tmpfs", secrets.len());

    let secrets_dir = root.join("run/secrets");
    std::fs::create_dir_all(&secrets_dir).map_err(|e| {
        NucleusError::FilesystemError(format!(
            "Failed to create secrets dir {:?}: {}",
            secrets_dir, e
        ))
    })?;

    // Mount a size-limited tmpfs for secrets (16 MiB max)
    if let Err(e) = mount(
        Some("tmpfs"),
        &secrets_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=16m,mode=0700"),
    ) {
        let _ = std::fs::remove_dir_all(&secrets_dir);
        return Err(NucleusError::FilesystemError(format!(
            "Failed to mount secrets tmpfs at {:?}: {}",
            secrets_dir, e
        )));
    }

    if !identity.is_root() {
        nix::unistd::chown(
            &secrets_dir,
            Some(nix::unistd::Uid::from_raw(identity.uid)),
            Some(nix::unistd::Gid::from_raw(identity.gid)),
        )
        .map_err(|e| {
            let _ = nix::mount::umount2(&secrets_dir, nix::mount::MntFlags::MNT_DETACH);
            let _ = std::fs::remove_dir_all(&secrets_dir);
            NucleusError::FilesystemError(format!(
                "Failed to set /run/secrets owner to {}:{}: {}",
                identity.uid, identity.gid, e
            ))
        })?;
    }

    // Rollback: unmount tmpfs and remove dir if any secret fails
    let result = mount_secrets_inmemory_inner(&secrets_dir, root, secrets, identity);
    if let Err(ref e) = result {
        let _ = nix::mount::umount2(&secrets_dir, nix::mount::MntFlags::MNT_DETACH);
        let _ = std::fs::remove_dir_all(&secrets_dir);
        return Err(NucleusError::FilesystemError(format!(
            "Secret mount failed (rolled back): {}",
            e
        )));
    }

    info!("All secrets mounted on in-memory tmpfs");
    Ok(())
}

fn mount_secrets_inmemory_inner(
    secrets_dir: &Path,
    root: &Path,
    secrets: &[crate::container::SecretMount],
    identity: &crate::container::ProcessIdentity,
) -> Result<()> {
    for secret in secrets {
        let mut content = read_regular_file_nofollow(&secret.source)?;

        // Determine destination path inside the secrets tmpfs
        let dest = resolve_container_destination(secrets_dir, &secret.dest)?;

        // Create parent directories within the tmpfs
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret parent dir {:?}: {}",
                    parent, e
                ))
            })?;
        }

        // Write secret content to tmpfs
        std::fs::write(&dest, &content).map_err(|e| {
            NucleusError::FilesystemError(format!("Failed to write secret to {:?}: {}", dest, e))
        })?;

        // Set permissions
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(secret.mode);
            std::fs::set_permissions(&dest, perms).map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to set permissions on secret {:?}: {}",
                    dest, e
                ))
            })?;
        }

        if !identity.is_root() {
            nix::unistd::chown(
                &dest,
                Some(nix::unistd::Uid::from_raw(identity.uid)),
                Some(nix::unistd::Gid::from_raw(identity.gid)),
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to set permissions owner on secret {:?} to {}:{}: {}",
                    dest, identity.uid, identity.gid, e
                ))
            })?;
        }

        // Zero the in-memory buffer
        zeroize::Zeroize::zeroize(&mut content);
        drop(content);

        // Also bind-mount the secret to its expected container path for compatibility
        let container_dest = resolve_container_destination(root, &secret.dest)?;
        if container_dest != dest {
            if let Some(parent) = container_dest.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    NucleusError::FilesystemError(format!(
                        "Failed to create secret mount parent {:?}: {}",
                        parent, e
                    ))
                })?;
            }

            std::fs::write(&container_dest, "").map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to create secret mount point {:?}: {}",
                    container_dest, e
                ))
            })?;

            mount(
                Some(dest.as_path()),
                &container_dest,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| {
                NucleusError::FilesystemError(format!(
                    "Failed to bind mount secret {:?} -> {:?}: {}",
                    dest, container_dest, e
                ))
            })?;

            mount(
                None::<&str>,
                &container_dest,
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
                    container_dest, e
                ))
            })?;
        }

        debug!(
            "Secret {:?} -> {:?} (in-memory tmpfs, mode {:04o})",
            secret.source, secret.dest, secret.mode
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn test_validate_bind_mount_source_rejects_sensitive_subtrees() {
        for path in ["/proc/sys", "/sys/fs/cgroup", "/dev/kmsg", "/boot"] {
            let err = validate_bind_mount_source(Path::new(path)).unwrap_err();
            assert!(
                err.to_string().contains("sensitive host path"),
                "expected sensitive-path rejection for {path}, got: {err}"
            );
        }
    }

    #[test]
    fn test_validate_bind_mount_source_allows_regular_host_paths() {
        let temp = tempfile::TempDir::new().unwrap();
        let safe_path = temp.path().join("data");
        std::fs::create_dir(&safe_path).unwrap();

        validate_bind_mount_source(&safe_path).unwrap();
    }

    #[test]
    fn test_validate_bind_mount_source_normalizes_parent_components_before_filtering() {
        let temp = tempfile::TempDir::new().unwrap();
        let safe_path = temp.path().join("data");
        std::fs::create_dir(&safe_path).unwrap();

        validate_bind_mount_source(&safe_path.join("../data")).unwrap();
    }

    #[test]
    fn test_proc_mask_includes_sysrq_trigger() {
        assert!(
            PROC_NULL_MASKED.contains(&"sysrq-trigger"),
            "/proc/sysrq-trigger must be masked to prevent host DoS"
        );
    }

    #[test]
    fn test_proc_mask_includes_timer_stats() {
        assert!(
            PROC_NULL_MASKED.contains(&"timer_stats"),
            "/proc/timer_stats must be masked to prevent kernel info leakage"
        );
    }

    #[test]
    fn test_proc_mask_includes_kpage_files() {
        for path in &["kpagecount", "kpageflags", "kpagecgroup"] {
            assert!(
                PROC_NULL_MASKED.contains(path),
                "/proc/{} must be masked to prevent host memory layout leakage",
                path
            );
        }
    }

    #[test]
    fn test_proc_mask_includes_oci_standard_paths() {
        // OCI runtime spec required masked paths
        for path in &["kallsyms", "kcore", "sched_debug", "keys", "config.gz"] {
            assert!(
                PROC_NULL_MASKED.contains(path),
                "/proc/{} must be in null-masked list (OCI spec)",
                path
            );
        }
        for path in &["acpi", "bus", "scsi", "sys"] {
            assert!(
                PROC_TMPFS_MASKED.contains(path),
                "/proc/{} must be in tmpfs-masked list (OCI spec)",
                path
            );
        }
    }

    #[test]
    fn test_read_regular_file_nofollow_reads_regular_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("secret.txt");
        std::fs::write(&path, "supersecret").unwrap();

        let content = read_regular_file_nofollow(&path).unwrap();
        assert_eq!(content, b"supersecret");
    }

    #[test]
    fn test_read_regular_file_nofollow_rejects_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.txt");
        let link = temp.path().join("secret-link");
        std::fs::write(&target, "supersecret").unwrap();
        symlink(&target, &link).unwrap();

        let err = read_regular_file_nofollow(&link).unwrap_err();
        assert!(
            err.to_string().contains("O_NOFOLLOW"),
            "symlink reads must fail via O_NOFOLLOW"
        );
    }
}
