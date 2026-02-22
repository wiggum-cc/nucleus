# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of Nucleus container runtime
- Security enforcement with state machine (Privileged → CapabilitiesDropped → SeccompApplied → Locked)
- gVisor integration with state machine (NativeKernel → GVisorKernel)
  - Automatic runsc detection in common paths
  - `--runtime gvisor` CLI flag support
  - Ptrace-based platform (works without KVM)
- Namespace isolation (PID, Mount, Network, UTS, IPC, User)
- Resource control via cgroup v2 (memory, CPU, PID limits)
- Filesystem management with tmpfs and context population
- Container orchestration coordinating all components
- CLI interface with resource limit flags and runtime selection
- Comprehensive test suite (72 tests total):
  - 31 unit tests
  - 32 model-based property tests
  - 10 tla-connect driver tests (6 passing, 4 require Apalache)
  - 5 integration tests
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

### Dependencies
- Core: nix, libc, caps, seccompiler, clap, anyhow, thiserror, tracing
- Dev: tla-connect, itf, tempfile, proptest

## [0.1.0] - TBD

Initial release (not yet published)
