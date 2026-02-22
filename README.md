# Nucleus

**Extremely lightweight Docker alternative for agents**

Nucleus is a minimalist container runtime designed specifically for AI agents running on Linux. It provides isolated execution environments using Linux kernel primitives without the overhead of traditional container runtimes.

## Why Nucleus?

AI agents need isolated, ephemeral execution environments with pre-populated context. Traditional containers are too heavyweight. Nucleus provides:

- **Zero-overhead isolation** — Direct use of cgroups, namespaces, chroot, capabilities, and seccomp
- **Memory-backed filesystems** — Container disk mapped to tmpfs/ramfs, pre-populated with agent context
- **gVisor integration** — Optional application kernel for enhanced security
- **Agent-optimized** — Fast startup, pre-seeded with files agents can read/grep
- **Linux-native** — Runs on standard Linux and NixOS

## Architecture

Nucleus leverages Linux kernel isolation primitives:

- **Namespaces** — PID, mount, network, UTS, IPC, user isolation
- **cgroups** — Resource limits (CPU, memory, I/O)
- **chroot** — Filesystem isolation
- **Capabilities** — Fine-grained privilege control
- **seccomp** — Syscall filtering
- **gVisor** — Optional application kernel (runsc)

Container filesystem is backed by tmpfs/ramfs and pre-populated with context files before agent execution, allowing agents to use standard tools (read, grep, find) on the provided context.

## Platform Support

- Linux (kernel 5.x+)
- NixOS
- **Not supported**: macOS, Windows, BSDs

This is a Linux-only tool by design — the isolation primitives are kernel-specific.

## Installation

```bash
cargo install nucleus
```

Or via Nix:

```bash
nix run github:0kenx/nucleus
```

## Usage

```bash
# Run agent in isolated container with pre-populated context
nucleus run --context ./agent-context/ -- /usr/bin/agent

# Specify resource limits
nucleus run --memory 512M --cpus 2 --context ./ctx/ -- ./agent

# Use gVisor for enhanced isolation
nucleus run --runtime gvisor --context ./ctx/ -- ./agent
```

## Development

This project uses Nix flakes for reproducible builds:

```bash
# Enter development shell
nix develop

# Build
cargo build

# Run tests
cargo nextest run

# Run checks (clippy, fmt, audit)
nix flake check
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
