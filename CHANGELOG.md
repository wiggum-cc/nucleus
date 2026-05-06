# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- No unreleased changes.

## [0.3.6] - 2026-05-06

### Fixed
- Include the gVisor `runsc` executable-path patch in the Nix flake source.

## [0.3.3] - 2026-04-08

### Added
- Detached mode (`-d`/`--detach`) for running containers as systemd transient services.
- `nucleus logs` for detached-container journal access, including follow and tail support.
- Userspace NAT and `slirp4netns` bridge fallback support.
- PostgreSQL 18 benchmark harness and updated performance documentation.
- Opt-in seccomp syscall extensions via `--seccomp-allow`.
- Memlock resource control plumbing.

### Fixed
- gVisor runtime handling and network-mode integration.
- Capability dropping and seccomp filter correctness.
- Audit-path hardening and benchmark reporting polish.

## [0.3.2] - 2026-04-07

### Fixed
- Audit hardening and release polish.

## [0.3.1] - 2026-04-07

### Added
- Volume mounts for workloads.
- Environment-variable injection and benchmark updates.
- Workload identity controls via UID/GID privilege drop.

### Fixed
- gVisor Nix integration.
- A runtime memory leak.
- Audit hardening follow-ups.

## [0.3.0] - 2026-04-06

### Added
- Initial public Nucleus runtime release.
- Native and gVisor runtimes, rootless mode, stats/ps lifecycle commands, cgroup v2 controls, and namespace isolation.
- Landlock, seccomp, capability, and production-mode hardening.
- Multi-tenant container support, integration tests, audit logging, and benchmark tooling.

## [0.2.1] - 2026-04-05

### Fixed
- AArch64 compatibility for release artifacts.

## [0.2.0] - 2026-04-05

### Added
- First tagged crate release with the baseline container runtime functionality.
