# Implementation Plan

## Phase 1: Core Infrastructure (Week 1)

### 1.1 Project Setup
- [x] Initialize Cargo project
- [x] Set up Nix flake with Rust toolchain
- [x] Configure CI/CD (GitHub Actions)
- [x] Add dependencies: clap, nix, anyhow, thiserror

### 1.2 CLI Interface
```rust
// src/cli.rs
pub struct RunCommand {
    pub context: Option<PathBuf>,
    pub memory: Option<String>,
    pub cpus: Option<f64>,
    pub pids: Option<u64>,
    pub runtime: Runtime,
    pub command: Vec<String>,
}
```

**Tasks:**
- [ ] Implement argument parsing with clap
- [ ] Validate input parameters
- [ ] Parse resource limits (512M, 1G, etc.)
- [ ] Add --help and --version

**Tests:**
- [ ] Argument parsing edge cases
- [ ] Invalid resource limits
- [ ] Missing required arguments

### 1.3 Error Handling
```rust
// src/error.rs
#[derive(Debug, thiserror::Error)]
pub enum NucleusError {
    #[error("Failed to create namespace: {0}")]
    NamespaceError(String),

    #[error("Failed to configure cgroup: {0}")]
    CgroupError(String),

    #[error("Failed to mount filesystem: {0}")]
    FilesystemError(String),

    // ...
}
```

**Tasks:**
- [ ] Define error types
- [ ] Implement From<T> for common errors
- [ ] Add context with anyhow

## Phase 2: Filesystem Layer (Week 2)

### 2.1 tmpfs Management
```rust
// src/filesystem/tmpfs.rs
pub struct TmpfsMount {
    path: PathBuf,
    size_bytes: u64,
}

impl TmpfsMount {
    pub fn new(size_bytes: u64) -> Result<Self>;
    pub fn mount(&self) -> Result<()>;
    pub fn unmount(&self) -> Result<()>;
}
```

**Tasks:**
- [ ] Implement tmpfs mounting with nix::mount
- [ ] Add size limits
- [ ] Handle mount flags (nosuid, nodev, noexec)
- [ ] Cleanup on drop

**Tests:**
- [ ] Mount and unmount tmpfs
- [ ] Verify size limits
- [ ] Test permissions

### 2.2 Context Population
```rust
// src/filesystem/context.rs
pub struct ContextPopulator {
    source: PathBuf,
    dest: PathBuf,
}

impl ContextPopulator {
    pub fn populate(&self) -> Result<()>;
    pub fn populate_parallel(&self) -> Result<()>;
}
```

**Tasks:**
- [ ] Walk source directory tree
- [ ] Copy files with metadata
- [ ] Filter excluded patterns (.git, target/, etc.)
- [ ] Parallel file copying with rayon
- [ ] Symlink handling

**Tests:**
- [ ] Copy directory tree
- [ ] Preserve permissions and timestamps
- [ ] Filter .git directories
- [ ] Handle symlinks safely

### 2.3 Minimal Filesystem
```rust
// src/filesystem/minimal.rs
pub fn create_minimal_fs(root: &Path) -> Result<()>;
pub fn create_dev_nodes(dev_path: &Path) -> Result<()>;
pub fn mount_procfs(proc_path: &Path) -> Result<()>;
```

**Tasks:**
- [ ] Create /bin, /dev, /tmp, /proc directories
- [ ] Create device nodes (null, zero, random, urandom)
- [ ] Mount procfs
- [ ] Create minimal /etc (passwd, group, hostname)

**Tests:**
- [ ] Verify directory structure
- [ ] Test device nodes are accessible
- [ ] Verify procfs is mounted

## Phase 3: Isolation Layer (Week 3)

### 3.1 Namespace Management
```rust
// src/isolation/namespaces.rs
pub struct NamespaceConfig {
    pub pid: bool,
    pub mnt: bool,
    pub net: bool,
    pub uts: bool,
    pub ipc: bool,
    pub user: bool,
}

pub fn unshare_namespaces(config: &NamespaceConfig) -> Result<()>;
```

**Tasks:**
- [ ] Implement unshare(2) wrapper
- [ ] Configure all 6 namespace types
- [ ] Set hostname in UTS namespace
- [ ] User namespace UID/GID mapping (for rootless)

**Tests:**
- [ ] Verify PID namespace (container sees PID 1)
- [ ] Verify mount namespace isolation
- [ ] Verify network namespace (no network)
- [ ] Test UID remapping

### 3.2 Root Filesystem Switch
```rust
// src/isolation/pivot.rs
pub fn pivot_root(new_root: &Path) -> Result<()>;
pub fn chroot_fallback(new_root: &Path) -> Result<()>;
```

**Tasks:**
- [ ] Implement pivot_root(2) wrapper
- [ ] Fallback to chroot(2) if pivot_root fails
- [ ] Unmount old root after pivot
- [ ] Change working directory to /

**Tests:**
- [ ] Verify filesystem view after pivot
- [ ] Ensure old root is inaccessible

## Phase 4: Resource Control (Week 4)

### 4.1 cgroup v2 Interface
```rust
// src/resources/cgroup.rs
pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    pub fn create(name: &str) -> Result<Self>;
    pub fn set_memory_limit(&self, bytes: u64) -> Result<()>;
    pub fn set_cpu_limit(&self, cores: f64) -> Result<()>;
    pub fn set_pids_limit(&self, max_pids: u64) -> Result<()>;
    pub fn attach_process(&self, pid: u32) -> Result<()>;
    pub fn cleanup(&self) -> Result<()>;
}
```

**Tasks:**
- [ ] Create cgroup hierarchy
- [ ] Write to memory.max, cpu.max, pids.max
- [ ] Attach process via cgroup.procs
- [ ] Cleanup cgroup on exit

**Tests:**
- [ ] Create and delete cgroups
- [ ] Set resource limits
- [ ] Verify limits are enforced
- [ ] Test OOM behavior

### 4.2 Resource Monitoring
```rust
// src/resources/stats.rs
pub struct ResourceStats {
    pub memory_current: u64,
    pub memory_max: u64,
    pub cpu_usage_usec: u64,
    pub pids_current: u64,
}

pub fn collect_stats(cgroup: &Cgroup) -> Result<ResourceStats>;
```

**Tasks:**
- [ ] Read memory.current, memory.stat
- [ ] Parse cpu.stat
- [ ] Read pids.current
- [ ] Format stats for output

**Tests:**
- [ ] Verify stats accuracy
- [ ] Test parsing edge cases

## Phase 5: Security Layer (Week 5)

### 5.1 Capability Dropping
```rust
// src/security/capabilities.rs
pub struct CapabilitySet {
    caps: Vec<Capability>,
}

impl CapabilitySet {
    pub fn empty() -> Self;
    pub fn minimal() -> Self;
    pub fn drop_all() -> Result<()>;
    pub fn drop_except(&self, keep: &[Capability]) -> Result<()>;
}
```

**Tasks:**
- [ ] Wrapper around cap_set_proc(3)
- [ ] Drop all capabilities by default
- [ ] Allow-list specific capabilities
- [ ] Verify capabilities are dropped

**Tests:**
- [ ] Test capability dropping
- [ ] Verify cannot regain capabilities

### 5.2 Seccomp Filters
```rust
// src/security/seccomp.rs
pub struct SeccompFilter {
    allowed_syscalls: Vec<&'static str>,
}

impl SeccompFilter {
    pub fn minimal() -> Self;
    pub fn apply(&self) -> Result<()>;
}
```

**Tasks:**
- [ ] Define syscall whitelist
- [ ] Build BPF filter program
- [ ] Apply filter via prctl(PR_SET_SECCOMP)
- [ ] Test blocked syscalls fail

**Tests:**
- [ ] Verify allowed syscalls work
- [ ] Verify blocked syscalls return EPERM
- [ ] Test filter cannot be removed

### 5.3 gVisor Integration (Optional)
```rust
// src/security/gvisor.rs
pub fn exec_with_gvisor(command: &[String]) -> Result<()>;
```

**Tasks:**
- [ ] Detect runsc binary
- [ ] Exec via runsc instead of direct exec
- [ ] Pass configuration to runsc
- [ ] Handle runsc exit codes

## Phase 6: Process Execution (Week 6)

### 6.1 Container Init
```rust
// src/container/init.rs
pub fn container_init(config: &ContainerConfig) -> Result<()> {
    // 1. Unshare namespaces
    // 2. Mount tmpfs
    // 3. Populate context
    // 4. Create minimal filesystem
    // 5. pivot_root
    // 6. Drop capabilities
    // 7. Apply seccomp
    // 8. exec target process
}
```

**Tasks:**
- [ ] Orchestrate all setup steps
- [ ] Fork child process for namespace isolation
- [ ] Parent waits for child, monitors
- [ ] Handle errors and cleanup

**Tests:**
- [ ] End-to-end container execution
- [ ] Verify all isolation mechanisms
- [ ] Test cleanup on success and failure

### 6.2 Process Management
```rust
// src/container/process.rs
pub fn exec_in_container(command: &[String]) -> Result<()>;
pub fn wait_for_exit(pid: Pid) -> Result<i32>;
```

**Tasks:**
- [ ] execve(2) wrapper
- [ ] Set up stdio (stdin, stdout, stderr)
- [ ] Handle signals (SIGTERM, SIGKILL)
- [ ] Reap zombie processes

**Tests:**
- [ ] Execute simple commands
- [ ] Verify exit codes
- [ ] Test signal handling

## Phase 7: Testing & Documentation (Week 7)

### 7.1 Integration Tests
- [ ] End-to-end container lifecycle
- [ ] Resource limit enforcement
- [ ] Security isolation verification
- [ ] Context population correctness
- [ ] Error handling and cleanup

### 7.2 Documentation
- [ ] User guide
- [ ] API documentation
- [ ] Security model documentation
- [ ] Examples and tutorials

### 7.3 Benchmarks
- [ ] Startup latency
- [ ] Memory overhead
- [ ] Context population speed
- [ ] Comparison with Docker

## Implementation Dependencies

```
Phase 1 (CLI)
    │
    ├─> Phase 2 (Filesystem)
    │       │
    │       └─> Phase 3 (Isolation)
    │
    ├─> Phase 4 (Resources)
    │
    └─> Phase 5 (Security)
            │
            └─> Phase 6 (Execution)
                    │
                    └─> Phase 7 (Testing)
```

## Success Criteria

- [ ] Can run simple container with isolation
- [ ] Resource limits enforced (memory, CPU, PIDs)
- [ ] All security layers active (namespaces, caps, seccomp)
- [ ] Context pre-populated before execution
- [ ] Startup time < 50ms (target: < 10ms)
- [ ] All tests passing
- [ ] Documentation complete
- [ ] Zero memory leaks (valgrind clean)

## Future Enhancements (Post-MVP)

- [ ] `nucleus attach <id>` - Attach to running container
- [ ] `nucleus ps` - List running containers
- [ ] `nucleus stats <id>` - Real-time resource stats
- [ ] Rootless mode (user namespaces)
- [ ] gVisor by default
- [ ] CRIU snapshot/restore
- [ ] Context streaming (lazy load)
- [ ] Multi-container support
- [ ] Container networking (optional)
