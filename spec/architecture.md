# Nucleus Architecture

## Overview

Nucleus is a minimalist container runtime designed for AI agent workloads. Unlike Docker/containerd, it prioritizes minimal overhead, fast startup, and pre-populated context delivery over features like image layers or orchestration.

Supported platform: Linux `x86_64` only. 32-bit Linux userlands (`i386`/`x86`) are not supported.

## Design Principles

1. **Zero abstraction cost** - Direct syscalls to kernel primitives, no daemon
2. **Agent-optimized** - Pre-seed filesystems with context files agents can grep/read
3. **Ephemeral by default** - Memory-backed root filesystem, no persistence
4. **Linux-native** - Leverage kernel features without portability layer
5. **Security through isolation** - Defense in depth: namespaces + cgroups + seccomp + capabilities + Landlock

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    nucleus CLI                          │
│  (single binary, no daemon, direct kernel interaction) │
└────────────────────┬────────────────────────────────────┘
                     │
                     ├─> Container Launcher
                     │   ├─> Namespace Setup (unshare)
                     │   ├─> cgroup Configuration
                     │   ├─> Filesystem Mount (tmpfs)
                     │   ├─> Context Population (copy or bind)
                     │   ├─> Network Setup (none/host/bridge)
                     │   └─> Process Execution
                     │
                     ├─> Container Management
                     │   ├─> Unique ID generation
                     │   ├─> Name resolution (ID, name, prefix)
                     │   ├─> Stop / Kill / Remove
                     │   ├─> Attach (enter namespaces)
                     │   └─> Checkpoint / Restore (CRIU)
                     │
                     ├─> Isolation Layer
                     │   ├─> PID namespace
                     │   ├─> Mount namespace
                     │   ├─> Network namespace
                     │   ├─> UTS namespace
                     │   ├─> IPC namespace
                     │   └─> User namespace
                     │
                     ├─> Resource Control
                     │   ├─> cgroup v2 (memory, cpu, io)
                     │   └─> Resource limits enforcement
                     │
                     ├─> Security Enforcement
                     │   ├─> Capability dropping (cap_set)
                     │   ├─> seccomp filters
                     │   ├─> Landlock filesystem policy
                     │   └─> Optional gVisor integration
                     │
                     ├─> Networking Layer
                     │   ├─> None mode (fully isolated)
                     │   ├─> Host mode (shared netns)
                     │   └─> Bridge mode (veth + NAT)
                     │
                     └─> Filesystem Layer
                         ├─> tmpfs/ramfs root
                         ├─> Context pre-population (copy)
                         ├─> Context streaming (bind mount)
                         └─> Bind mounts (optional)
```

## Components

### 1. Container Launcher

Entry point that orchestrates all isolation mechanisms.

**Responsibilities:**
- Parse CLI arguments
- Validate configuration
- Generate unique container ID
- Set up namespaces via `unshare(2)`
- Configure cgroups
- Mount filesystems
- Execute target process

### 2. Container Management

Multi-container lifecycle operations.

**Operations:**
- **Stop** – SIGTERM → wait(timeout) → SIGKILL
- **Kill** – Send arbitrary signal
- **Remove** – Delete state file (verify stopped first)
- **Attach** – Enter container namespaces via `setns(2)`, fork/exec
- **Checkpoint** – CRIU dump to directory
- **Restore** – CRIU restore from directory

**Container Resolution:**
- Exact ID match → exact name match → ID prefix match
- Ambiguous prefix returns error

### 3. Namespace Manager

Handles Linux namespace isolation.

**Namespaces used:**
- **PID** - Process isolation (container sees PID 1)
- **Mount** - Filesystem isolation
- **Network** - Network stack isolation (configurable: none/host/bridge)
- **UTS** - Hostname/domain isolation
- **IPC** - Inter-process communication isolation
- **User** - UID/GID mapping (optional, for rootless)

**Implementation:**
- `unshare(2)` syscall for namespace creation
- `/proc/self/ns/*` for namespace inspection
- `setns(2)` for namespace joining (attach command)

### 4. cgroup Controller

Resource limit enforcement using cgroup v2.

**Resources controlled:**
- **memory.max** - Hard memory limit
- **memory.high** - Soft memory limit (throttling)
- **cpu.max** - CPU bandwidth limiting
- **io.max** - I/O throttling

**Implementation:**
- Write to `/sys/fs/cgroup/` hierarchy
- Create dedicated cgroup for each container
- Move process to cgroup via `cgroup.procs`

### 5. Filesystem Layer

Memory-backed root filesystem for zero-latency I/O.

**Design:**
- Mount `tmpfs` or `ramfs` as root
- Pre-populate with context directory contents
- Two modes: **Copy** (traditional) and **Bind mount** (zero-copy, instant)
- Optionally bind-mount host paths
- Use `pivot_root(2)` or `chroot(2)` for isolation

**Context population:**
```
/context/           # Pre-populated from --context flag
  ├─ README.md
  ├─ src/
  └─ docs/

/bin/               # Minimal busybox or static binaries
/tmp/               # Writable temp space
/proc/              # procfs mount
/sys/               # sysfs mount (optional)
/dev/               # Minimal /dev (null, zero, urandom)
```

### 6. Security Enforcer

Defense-in-depth security model.

**Capabilities:**
- Drop all capabilities by default
- Allow-list specific capabilities if needed

**Seccomp:**
- Whitelist syscalls (read, write, open, etc.)
- Block dangerous syscalls (ptrace, module loading, kexec)

**Landlock:**
- Path-based filesystem access control via Linux LSM (kernel 5.13+)
- Restricts what operations are allowed on which paths inside the container
- `/context` read-only, `/tmp` read+write, binaries read+execute
- Irreversible once applied, stackable with seccomp and capabilities

**gVisor (optional):**
- Run with runsc for application kernel
- Syscall interception and emulation
- Reduced kernel attack surface

### 7. Networking Layer

Optional networking with three modes.

**None mode (default):**
- Full network namespace isolation
- No network access whatsoever

**Host mode:**
- Skip network namespace creation
- Container shares host network stack

**Bridge mode:**
- Create `nucleus0` bridge interface
- Create veth pair, move one end to container
- Assign IP from `10.0.42.0/24` subnet
- NAT via iptables masquerade
- Port forwarding via iptables DNAT
- Requires root (degrades to None in rootless)

### 8. Checkpoint/Restore

CRIU-based container snapshotting.

**Checkpoint:**
- `criu dump --tree <pid> --images-dir <dir> --shell-job`
- Metadata (container ID, command, timestamp) stored as JSON
- Output directory secured with mode 0o700

**Restore:**
- `criu restore --images-dir <dir> --shell-job`
- Requires root (`CAP_SYS_PTRACE`)

## Execution Flow

```
1. nucleus run --name my-agent --context ./ctx/ --memory 512M -- /bin/agent

2. Generate unique container ID (12 hex chars)

3. Parse arguments, validate paths

4. Create cgroup hierarchy
   └─> /sys/fs/cgroup/nucleus-<id>/
       ├─ memory.max = 536870912
       └─ cpu.max = 2000000 100000

5. Unshare namespaces
   └─> unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | ...)

6. Fork child process
   └─> Child becomes PID 1 in new namespace

7. Parent: Save container state, set up bridge networking (if bridge mode)

8. Child: Mount tmpfs as root
   └─> mount("tmpfs", "/tmp/nucleus-root", "tmpfs", ...)

9. Child: Populate filesystem
   └─> Copy or bind mount ./ctx/ → /tmp/nucleus-root/context/
   └─> Create minimal /bin, /dev, /proc

10. Child: pivot_root or chroot
    └─> pivot_root("/tmp/nucleus-root", "/tmp/nucleus-root/old-root")

11. Child: Drop capabilities
    └─> cap_set_proc({})

12. Child: Apply seccomp filter
    └─> prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)

13. Child: Apply Landlock filesystem policy
    └─> landlock_restrict_self (read-only context, r+w /tmp, r+x binaries)

14. Child: exec target process
    └─> execve("/bin/agent", ...)

15. Parent: Wait for child, cleanup cgroups, delete state, cleanup networking
```

## Performance Characteristics

- **Startup time:** < 10ms (no image pulls, no layers)
- **Memory overhead:** ~1MB (no daemon, minimal state)
- **I/O latency:** 0ns (tmpfs, already in memory)
- **Context loading:** O(n) file copies (copy mode), O(1) bind mount (bind mode)

## Comparison to Docker

| Feature | Docker | Nucleus |
|---------|--------|---------|
| Daemon | Yes (dockerd) | No (direct exec) |
| Image layers | Yes (overlay fs) | No (tmpfs) |
| Networking | Full CNI | None/Host/Bridge |
| Storage | Persistent | Ephemeral (RAM) |
| Startup | ~100-500ms | <10ms |
| Multi-container | Yes | Yes |
| Attach | Yes | Yes |
| Checkpoint | Optional | Yes (CRIU) |
| Use case | General containers | Agent workloads |
