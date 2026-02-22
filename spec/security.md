# Security Model

## Threat Model

Nucleus assumes:
- **Untrusted workloads** - Agent code may be malicious or compromised
- **Host kernel is trusted** - We rely on Linux kernel isolation primitives
- **No lateral movement** - Containers should not escape or affect each other
- **Resource exhaustion prevention** - Malicious agents should not DoS the host

## Defense in Depth

Nucleus employs multiple layers of security:

### 1. Namespaces (Isolation)

**PID Namespace:**
- Container sees only its own processes
- Cannot signal or inspect host processes
- Init process (PID 1) inside container

**Mount Namespace:**
- Isolated filesystem view
- Host mounts are invisible
- tmpfs root prevents persistence

**Network Namespace:**
- No network access by default
- Cannot bind to host ports
- Cannot sniff host traffic

**UTS Namespace:**
- Isolated hostname/domainname
- Prevents information leakage

**IPC Namespace:**
- Isolated System V IPC, POSIX message queues
- No shared memory with host

**User Namespace (optional):**
- UID/GID remapping
- Root inside container = unprivileged outside
- Enables rootless containers

### 2. Capabilities (Privilege Reduction)

Default: **Drop all capabilities**

Minimal set if needed:
- `CAP_NET_BIND_SERVICE` - Bind to ports < 1024 (if networking enabled)
- `CAP_SETUID/CAP_SETGID` - Only if agent needs user switching

**Blocked capabilities:**
- `CAP_SYS_ADMIN` - Mount, pivot_root, etc.
- `CAP_SYS_MODULE` - Load kernel modules
- `CAP_SYS_RAWIO` - Direct disk access
- `CAP_SYS_BOOT` - Reboot system
- `CAP_SYS_PTRACE` - Trace arbitrary processes

### 3. Seccomp (Syscall Filtering)

**Whitelist approach:**

Allowed syscalls:
```
read, write, open, openat, close, stat, fstat, lstat
mmap, munmap, mprotect, brk
clone, fork, vfork, execve, wait4, exit, exit_group
getpid, gettid, getuid, getgid
socket, connect, send, recv (if networking)
...
```

Blocked syscalls:
```
ptrace          # Process tracing
kexec_load      # Load new kernel
add_key         # Kernel keyring
request_key
keyctl
bpf             # eBPF program loading
perf_event_open # Performance monitoring
userfaultfd     # User fault handling
io_uring        # Async I/O (potential escape vector)
```

### 4. cgroups (Resource Limits)

**Memory limits:**
- `memory.max` - Hard limit, OOM kill if exceeded
- `memory.high` - Soft limit, throttling threshold
- `memory.swap.max` - Swap limit (usually disabled)

**CPU limits:**
- `cpu.max` - CPU bandwidth (e.g., 200000/100000 = 2 cores)
- `cpu.weight` - Relative share

**I/O limits:**
- `io.max` - IOPS and bandwidth limits per device

**PID limits:**
- `pids.max` - Maximum number of processes (prevent fork bombs)

### 5. gVisor Integration (Optional)

When `--runtime gvisor`:
- Use runsc (gVisor runtime)
- Intercept syscalls via ptrace or KVM
- Implement syscalls in userspace
- Reduced kernel attack surface (~70 syscalls → ~200 gVisor syscalls)

**Trade-offs:**
- ✓ Stronger isolation
- ✓ Smaller kernel attack surface
- ✗ Performance overhead (~10-30%)
- ✗ Some syscalls unsupported

## Attack Scenarios

### 1. Container Escape

**Attack:** Exploit kernel vulnerability to break out of namespace

**Mitigations:**
- Seccomp blocks dangerous syscalls
- Capabilities prevent privileged operations
- gVisor reduces kernel attack surface
- User namespaces (rootless mode)

**Residual risk:** Zero-day kernel exploit

### 2. Resource Exhaustion

**Attack:** Consume all host memory/CPU

**Mitigations:**
- cgroup memory.max enforces hard limits
- cgroup cpu.max throttles CPU usage
- pids.max prevents fork bombs

**Residual risk:** None (enforced by kernel)

### 3. Information Disclosure

**Attack:** Read host files or other containers' data

**Mitigations:**
- Mount namespace isolation
- tmpfs root (no host filesystem access)
- No bind mounts by default

**Residual risk:** Minimal (requires explicit bind mount)

### 4. Privilege Escalation

**Attack:** Gain root on host via setuid binary

**Mitigations:**
- All capabilities dropped
- No setuid binaries in tmpfs
- User namespace remapping (rootless)

**Residual risk:** Minimal

### 5. Side Channel Attacks

**Attack:** Spectre/Meltdown, cache timing

**Mitigations:**
- cgroup CPU isolation (partial)
- gVisor reduces some attack surface

**Residual risk:** High (kernel mitigations depend on CPU/kernel version)

## Security Best Practices

### For Nucleus Users

1. **Never mount sensitive host paths** - Avoid `--bind /etc` or similar
2. **Use minimal resource limits** - Don't over-provision
3. **Enable gVisor for untrusted code** - `--runtime gvisor`
4. **Run rootless when possible** - Use user namespaces
5. **Keep kernel updated** - Security patches are critical

### For Nucleus Developers

1. **Fail closed** - Deny by default, allow on opt-in
2. **Validate all inputs** - Paths, resource limits, etc.
3. **Use safe Rust** - Avoid `unsafe` except for FFI
4. **Audit syscall whitelist** - Review seccomp filter regularly
5. **Test against exploits** - Run security benchmarks

## Comparison to Docker/runc

| Security Feature | Docker/runc | Nucleus |
|------------------|-------------|---------|
| Namespaces | All 6 | All 6 |
| Capabilities | Drop most | Drop all (default) |
| Seccomp | Whitelist (~300) | Whitelist (~100) |
| cgroups | v1/v2 | v2 only |
| Rootless | Yes | Yes (planned) |
| gVisor | Optional | Optional |
| AppArmor/SELinux | Yes | Planned |

Nucleus aims for a **smaller attack surface** by:
- No daemon (smaller code)
- Stricter seccomp defaults
- Ephemeral-only (no persistence concerns)
- Simpler design (fewer features = fewer bugs)
