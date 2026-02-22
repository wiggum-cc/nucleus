# Filesystem Design

## Overview

Nucleus uses memory-backed filesystems (tmpfs/ramfs) for container root to achieve:
- **Zero I/O latency** - All data in RAM
- **Fast startup** - No image extraction
- **Ephemeral by default** - Data disappears on exit
- **Context pre-population** - Copy agent context before exec

## Filesystem Types

### tmpfs (Recommended)

**Characteristics:**
- Backed by RAM + swap
- Size-limited (`size=512M` option)
- Pages can be swapped to disk under memory pressure
- Supports full POSIX semantics

**Use when:**
- Resource limits are needed
- Swap is acceptable
- POSIX features required (extended attributes, ACLs)

### ramfs

**Characteristics:**
- Backed by RAM only (no swap)
- No size limit (grows until OOM)
- Cannot be swapped out
- Simpler implementation

**Use when:**
- Guaranteed in-memory performance
- cgroup memory.max enforces limit anyway
- Maximum performance needed

## Filesystem Layout

```
/                       # tmpfs root (ephemeral)
├── context/            # Pre-populated from --context
│   ├── README.md
│   ├── src/
│   │   ├── main.rs
│   │   └── lib.rs
│   └── docs/
│       └── api.md
│
├── bin/                # Minimal binaries
│   ├── sh            # Statically linked shell (busybox)
│   ├── ls
│   ├── cat
│   ├── grep
│   └── agent         # User's agent binary (copied or bind-mounted)
│
├── dev/                # Minimal device nodes
│   ├── null
│   ├── zero
│   ├── full
│   ├── random
│   ├── urandom
│   ├── tty
│   └── console
│
├── proc/               # procfs (mounted)
├── sys/                # sysfs (optional, usually not needed)
├── tmp/                # Writable temporary space
└── etc/                # Minimal config
    ├── passwd
    ├── group
    └── hostname
```

## Context Population

### Design Goals

1. **Fast copying** - Parallel file copies, minimal syscalls
2. **Preserve metadata** - Timestamps, permissions
3. **Filtering** - Exclude `.git`, `target/`, etc.
4. **Large context support** - Handle multi-GB contexts efficiently

### Algorithm

```rust
fn populate_context(host_path: &Path, container_path: &Path) -> Result<()> {
    // 1. Create directory structure
    create_dir_all(container_path)?;

    // 2. Walk host directory tree
    for entry in WalkDir::new(host_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| should_include(e))
    {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(host_path)?;
        let dest = container_path.join(rel_path);

        if entry.file_type().is_dir() {
            create_dir_all(&dest)?;
        } else if entry.file_type().is_file() {
            // Fast file copy (copy_file_range on Linux)
            copy_file(entry.path(), &dest)?;
            // Preserve metadata
            copy_metadata(entry.path(), &dest)?;
        }
        // Symlinks: optionally copy or dereference
    }

    Ok(())
}

fn should_include(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_str().unwrap_or("");

    // Exclude VCS
    if name == ".git" || name == ".svn" { return false; }

    // Exclude build artifacts
    if name == "target" || name == "node_modules" { return false; }

    // Exclude editor files
    if name.starts_with(".") && name.ends_with(".swp") { return false; }

    true
}
```

### Optimization: Parallel Copying

```rust
use rayon::prelude::*;

fn populate_context_parallel(host: &Path, container: &Path) -> Result<()> {
    // 1. Collect all file paths
    let files: Vec<_> = WalkDir::new(host)
        .into_iter()
        .filter_map(|e| e.ok())
        .collect();

    // 2. Create all directories first (sequential)
    for entry in &files {
        if entry.file_type().is_dir() {
            let dest = map_path(entry.path(), host, container);
            create_dir_all(dest)?;
        }
    }

    // 3. Copy files in parallel
    files.par_iter()
        .filter(|e| e.file_type().is_file())
        .try_for_each(|entry| {
            let dest = map_path(entry.path(), host, container);
            copy_file(entry.path(), &dest)?;
            copy_metadata(entry.path(), &dest)
        })?;

    Ok(())
}
```

## Mount Operations

### Initial Mount

```rust
use nix::mount::{mount, MsFlags};

fn setup_root_filesystem() -> Result<()> {
    let root = Path::new("/tmp/nucleus-XXXXXX");

    // Mount tmpfs with size limit
    mount(
        Some("tmpfs"),
        root,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=512M,mode=0755")
    )?;

    // Create directory structure
    create_dir_all(root.join("context"))?;
    create_dir_all(root.join("bin"))?;
    create_dir_all(root.join("dev"))?;
    create_dir_all(root.join("tmp"))?;

    Ok(())
}
```

### Device Nodes

```rust
use nix::sys::stat::{mknod, Mode, SFlag};
use nix::unistd::{Uid, Gid};

fn create_device_nodes(dev_path: &Path) -> Result<()> {
    let devices = [
        ("null",    makedev(1, 3)),
        ("zero",    makedev(1, 5)),
        ("full",    makedev(1, 7)),
        ("random",  makedev(1, 8)),
        ("urandom", makedev(1, 9)),
    ];

    for (name, dev) in devices {
        let path = dev_path.join(name);
        mknod(
            &path,
            SFlag::S_IFCHR,
            Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IWGRP | Mode::S_IROTH | Mode::S_IWOTH,
            dev
        )?;
    }

    Ok(())
}
```

### procfs and sysfs

```rust
fn mount_pseudo_filesystems(root: &Path) -> Result<()> {
    // Mount /proc
    let proc = root.join("proc");
    create_dir_all(&proc)?;
    mount(
        Some("proc"),
        &proc,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>
    )?;

    // Optional: Mount /sys (usually not needed for agents)
    // let sys = root.join("sys");
    // create_dir_all(&sys)?;
    // mount(Some("sysfs"), &sys, Some("sysfs"), MsFlags::empty(), None)?;

    Ok(())
}
```

### pivot_root vs chroot

**pivot_root (preferred):**
- Changes root of mount namespace
- Old root can be unmounted
- Cleaner isolation

```rust
use nix::unistd::pivot_root;

fn switch_root(new_root: &Path) -> Result<()> {
    let old_root = new_root.join("old-root");
    create_dir_all(&old_root)?;

    // Move current root to old_root
    pivot_root(new_root, &old_root)?;

    // Change to new root
    chdir("/")?;

    // Unmount old root
    umount2("/old-root", MntFlags::MNT_DETACH)?;
    remove_dir("/old-root")?;

    Ok(())
}
```

**chroot (fallback):**
- Simpler but less secure
- Old root still accessible via file descriptors
- Use when pivot_root unavailable

## Bind Mounts (Optional)

For persistent storage or read-only data:

```rust
fn bind_mount_host_path(src: &Path, dest: &Path, readonly: bool) -> Result<()> {
    create_dir_all(dest)?;

    let mut flags = MsFlags::MS_BIND;
    mount(Some(src), dest, None::<&str>, flags, None::<&str>)?;

    if readonly {
        flags |= MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT;
        mount(Some(src), dest, None::<&str>, flags, None::<&str>)?;
    }

    Ok(())
}
```

## Performance Characteristics

| Operation | Latency | Notes |
|-----------|---------|-------|
| tmpfs mount | ~1ms | One-time setup |
| Context copy (10MB) | ~5ms | Parallel copying |
| Context copy (1GB) | ~500ms | Memory bandwidth limited |
| File read/write | <1μs | RAM latency |
| pivot_root | ~1ms | One-time switch |

## Future Optimizations

1. **Copy-on-write** - Share readonly context across containers
2. **mmap-based copying** - Use splice(2) or copy_file_range(2)
3. **Lazy population** - FUSE overlay to load on demand
4. **Compression** - Compress context in memory (zstd)
5. **Content-addressable storage** - Deduplicate common files
