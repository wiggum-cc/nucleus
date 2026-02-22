# Nucleus Architecture

## Overview

Nucleus is a minimalist container runtime designed for AI agent workloads. Unlike Docker/containerd, it prioritizes minimal overhead, fast startup, and pre-populated context delivery over features like image layers, networking, or orchestration.

## Design Principles

1. **Zero abstraction cost** - Direct syscalls to kernel primitives, no daemon
2. **Agent-optimized** - Pre-seed filesystems with context files agents can grep/read
3. **Ephemeral by default** - Memory-backed root filesystem, no persistence
4. **Linux-native** - Leverage kernel features without portability layer
5. **Security through isolation** - Defense in depth: namespaces + cgroups + seccomp + capabilities

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
                     │   ├─> Context Population
                     │   └─> Process Execution
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
                     │   └─> Optional gVisor integration
                     │
                     └─> Filesystem Layer
                         ├─> tmpfs/ramfs root
                         ├─> Context pre-population
                         └─> Bind mounts (optional)
```

## Components

### 1. Container Launcher

Entry point that orchestrates all isolation mechanisms.

**Responsibilities:**
- Parse CLI arguments
- Validate configuration
- Set up namespaces via `unshare(2)`
- Configure cgroups
- Mount filesystems
- Execute target process

### 2. Namespace Manager

Handles Linux namespace isolation.

**Namespaces used:**
- **PID** - Process isolation (container sees PID 1)
- **Mount** - Filesystem isolation
- **Network** - Network stack isolation (initially no network)
- **UTS** - Hostname/domain isolation
- **IPC** - Inter-process communication isolation
- **User** - UID/GID mapping (optional, for rootless)

**Implementation:**
- `unshare(2)` syscall for namespace creation
- `/proc/self/ns/*` for namespace inspection
- `setns(2)` for namespace joining (future: attach command)

### 3. cgroup Controller

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

### 4. Filesystem Layer

Memory-backed root filesystem for zero-latency I/O.

**Design:**
- Mount `tmpfs` or `ramfs` as root
- Pre-populate with context directory contents
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

### 5. Security Enforcer

Defense-in-depth security model.

**Capabilities:**
- Drop all capabilities by default
- Allow-list specific capabilities if needed
- Use `cap_set_proc(3)` / `capset(2)`

**Seccomp:**
- Whitelist syscalls (read, write, open, etc.)
- Block dangerous syscalls (ptrace, module loading, kexec)
- Use `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`

**gVisor (optional):**
- Run with runsc for application kernel
- Syscall interception and emulation
- Reduced kernel attack surface

## Execution Flow

```
1. nucleus run --context ./ctx/ --memory 512M -- /bin/agent

2. Parse arguments, validate paths

3. Create cgroup hierarchy
   └─> /sys/fs/cgroup/nucleus-<id>/
       ├─ memory.max = 536870912
       └─ cpu.max = 2000000 100000

4. Unshare namespaces
   └─> unshare(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | ...)

5. Fork child process
   └─> Child becomes PID 1 in new namespace

6. Child: Mount tmpfs as root
   └─> mount("tmpfs", "/tmp/nucleus-root", "tmpfs", ...)

7. Child: Populate filesystem
   └─> Copy ./ctx/ → /tmp/nucleus-root/context/
   └─> Create minimal /bin, /dev, /proc

8. Child: pivot_root or chroot
   └─> pivot_root("/tmp/nucleus-root", "/tmp/nucleus-root/old-root")

9. Child: Drop capabilities
   └─> cap_set_proc({ CAP_NET_BIND_SERVICE })

10. Child: Apply seccomp filter
    └─> prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)

11. Child: exec target process
    └─> execve("/bin/agent", ...)

12. Parent: Wait for child, cleanup cgroups
```

## Performance Characteristics

- **Startup time:** < 10ms (no image pulls, no layers)
- **Memory overhead:** ~1MB (no daemon, minimal state)
- **I/O latency:** 0ns (tmpfs, already in memory)
- **Context loading:** O(n) file copies, parallelizable

## Comparison to Docker

| Feature | Docker | Nucleus |
|---------|--------|---------|
| Daemon | Yes (dockerd) | No (direct exec) |
| Image layers | Yes (overlay fs) | No (tmpfs) |
| Networking | Full CNI | None (isolated) |
| Storage | Persistent | Ephemeral (RAM) |
| Startup | ~100-500ms | <10ms |
| Use case | General containers | Agent workloads |

## Future Extensions

- **Attach command** - `nucleus attach <id>` to enter running container
- **Resource monitoring** - Real-time cgroup stats
- **gVisor by default** - Enhanced security boundary
- **Context streaming** - Lazy-load large contexts
- **Snapshot/restore** - CRIU integration for checkpointing
