# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Detached mode (`-d`/`--detach`) for running containers in the background as systemd transient services
  - `nucleus create -d` prints the container ID and exits immediately
  - Container process supervised by systemd (`systemd-run --collect`)
  - Graceful shutdown via `KillMode=mixed` with 30s `TimeoutStopSec`
  - Compatible with all existing management commands (`stop`, `kill`, `attach`, `state`, `stats`)
- `nucleus logs` command for viewing detached container output from the systemd journal
  - `-f`/`--follow` for live log tailing
  - `-n`/`--lines` to limit output to recent lines

- Initial implementation of Nucleus container runtime
- Security enforcement with state machine (Privileged → CapabilitiesDropped → SeccompApplied → LandlockApplied → Locked)
- gVisor integration with state machine (NativeKernel → GVisorKernel)
  - Automatic runsc detection in common paths
  - `--runtime gvisor` CLI flag support
  - Ptrace-based platform (works without KVM)
- Namespace isolation (PID, Mount, Network, UTS, IPC, User)
- Resource control via cgroup v2 (memory, CPU, PID limits)
- Filesystem management with tmpfs and context population
- Container orchestration coordinating all components
- CLI interface with resource limit flags and runtime selection
- Comprehensive test suite (83 tests total):
  - 42 unit tests
  - 32 model-based property tests
  - 10 tla-connect driver tests (6 passing, 4 require Apalache)
  - 8 integration tests
- Formal TLA+ specifications for all state machines
- tla-connect integration for model-based testing
- Intent specifications for high-level system design
- Complete documentation:
  - README.md with usage examples
  - SPEC_DRIVEN_DEVELOPMENT.md explaining methodology
  - IMPLEMENTATION_SUMMARY.md with statistics
  - TLA_CONNECT_INTEGRATION.md for testing guide
  - CONTRIBUTING.md for contributors
- Three example programs demonstrating usage
- Apalache-verified temporal properties

- Landlock filesystem access control (Linux 5.13+)
  - Path-based access rules enforced by kernel LSM
  - Read-only context, read+execute binaries, read+write /tmp
  - Graceful degradation on older kernels (best-effort mode)
  - Irreversible once applied (matches security lockdown invariant)

- Multi-container support
  - Unique container IDs (12 hex chars from timestamp+PID hash)
  - Container naming via `--name` flag
  - Container resolution by exact ID, name, or ID prefix
  - `nucleus stop` with graceful SIGTERM → timeout → SIGKILL
  - `nucleus kill` with arbitrary signal support
  - `nucleus rm` with optional `--force` flag
  - `creator_uid` tracking for ownership validation

- Container attach (`nucleus attach`)
  - Enter running container namespaces via `setns(2)`
  - Fork/exec pattern with configurable command (default: `/bin/sh`)
  - Ownership validation (root or same creator UID)

- Optional networking
  - `--network none` (default, fully isolated)
  - `--network host` (share host network namespace)
  - `--network bridge` (bridge network with veth pairs, NAT, iptables)
  - Port forwarding via `-p/--publish host:container[/protocol]`
  - Automatic DNS configuration (`/etc/resolv.conf`)
  - Rootless graceful degradation (bridge requires root)

- CRIU checkpoint/restore
  - `nucleus checkpoint` to snapshot running containers
  - `nucleus restore` to resume from checkpoint
  - Metadata storage alongside dump images
  - Secure output directory (mode 0o700)
  - Root-only (CRIU requires `CAP_SYS_PTRACE`)

- Context streaming (lazy load)
  - `--context-mode copy` (default, traditional copy)
  - `--context-mode bind` (zero-copy bind mount, instant access)
  - Read-only bind mount for security (Landlock already enforces)
  - Bind mount happens before pivot_root (source on host filesystem)

- Production hardening
  - PID 1 mini-init with zombie reaping and signal forwarding (production mode + PID namespace)
  - In-memory secrets on dedicated 16MB tmpfs at `/run/secrets` with `write_volatile` zeroing
  - Post-setup mount flag audit (fatal in production mode)
  - `hidepid=2` on `/proc` in production mode (hides other processes)
  - Landlock ABI V3 minimum assertion in production mode
  - `no_new_privs` enforcement before seccomp/Landlock
  - RLIMIT_NPROC and RLIMIT_NOFILE backstops before seccomp

- External security policy files
  - Per-service seccomp profiles (JSON, OCI format) with SHA-256 integrity verification
  - TOML capability policy files (`--caps-policy`) replacing default drop-all
  - TOML Landlock policy files (`--landlock-policy`) replacing default hardcoded rules
  - SHA-256 pinning for all policy files (supply-chain integrity)

- Seccomp profile generation workflow
  - `--seccomp-mode trace` installs allow-all filter with `SECCOMP_FILTER_FLAG_LOG`
  - `--seccomp-log <path>` writes NDJSON trace of observed syscalls
  - `nucleus seccomp generate <trace>` produces minimal OCI-format JSON profile
  - Inverse syscall number-to-name mapping (~150 syscalls)

- Structured audit logging
  - JSON audit events for all security-critical actions
  - Event types: ContainerStart, ContainerStop, CapabilitiesDropped, SeccompApplied, SeccompProfileLoaded, LandlockApplied, MountAuditPassed, NoNewPrivsSet, InitSupervisorStarted
  - Emitted via `tracing::info!(target: "nucleus::audit", ...)`

- Multi-container topology (Compose equivalent)
  - TOML topology configuration (services, networks, volumes, dependencies)
  - Dependency DAG resolution with Kahn's algorithm (topological sort)
  - Circular dependency detection
  - Reconciliation engine: diff running vs desired state, plan and execute changes
  - Per-topology /etc/hosts DNS injection
  - `nucleus compose` subcommand: `up`, `down`, `ps`, `plan`, `validate`
  - NixOS module `topologies` option with systemd oneshot services

- NixOS module updates
  - `seccompProfile` / `seccompProfileSha256` options
  - `capsPolicy` / `capsPolicySha256` options
  - `landlockPolicy` / `landlockPolicySha256` options
  - `topologies.<name>` with `configFile` for declarative multi-container stacks

### Dependencies
- Core: nix, libc, caps, seccompiler, landlock, clap, anyhow, thiserror, tracing, toml, sha2, hex
- Dev: tla-connect, itf, tempfile, proptest

## [0.1.0] - TBD

Initial release (not yet published)
