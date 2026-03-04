# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

### Dependencies
- Core: nix, libc, caps, seccompiler, landlock, clap, anyhow, thiserror, tracing
- Dev: tla-connect, itf, tempfile, proptest

## [0.1.0] - TBD

Initial release (not yet published)
