# Nucleus

**Extremely lightweight Docker alternative for agents**

Nucleus is a minimalist container runtime designed specifically for AI agents running on Linux. It provides isolated execution environments using Linux kernel primitives without the overhead of traditional container runtimes.

## Why Nucleus?

AI agents need isolated, ephemeral execution environments with pre-populated context. Traditional containers are too heavyweight. Nucleus provides:

- **Zero-overhead isolation** – Direct use of cgroups, namespaces, chroot, capabilities, seccomp, and Landlock
- **Memory-backed filesystems** – Container disk mapped to tmpfs/ramfs, pre-populated with agent context
- **gVisor integration** – Optional application kernel for enhanced security
- **Agent-optimized** – Fast startup, pre-seeded with files agents can read/grep
- **Linux-native** – Runs on standard Linux and NixOS

## Architecture

Nucleus leverages Linux kernel isolation primitives:

- **Namespaces** – PID, mount, network, UTS, IPC, user isolation
- **cgroups** – Resource limits (CPU, memory, I/O)
- **chroot** – Filesystem isolation
- **Capabilities** – Fine-grained privilege control
- **seccomp** – Syscall filtering
- **Landlock** – Path-based filesystem access control (Linux 5.13+)
- **gVisor** – Optional application kernel (runsc)

Container filesystem is backed by tmpfs/ramfs and pre-populated with context files before agent execution, allowing agents to use standard tools (read, grep, find) on the provided context.

## Platform Support

- Linux (kernel 5.x+)
- NixOS
- **Not supported**: macOS, Windows, BSDs

This is a Linux-only tool by design – the isolation primitives are kernel-specific.

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

# Name your container
nucleus run --name my-agent --context ./ctx/ -- ./agent

# Use gVisor for enhanced isolation
nucleus run --runtime gvisor --context ./ctx/ -- ./agent

# Rootless mode
nucleus run --rootless -- /bin/sh

# List running containers
nucleus ps

# List all containers (including stopped)
nucleus ps --all

# Show resource usage statistics
nucleus stats

# Stop a container (SIGTERM, then SIGKILL after timeout)
nucleus stop <container>
nucleus stop --timeout 30 <container>

# Kill a container with a specific signal
nucleus kill <container>
nucleus kill --signal TERM <container>

# Remove a stopped container
nucleus rm <container>
nucleus rm --force <container>

# Attach to a running container
nucleus attach <container>
nucleus attach <container> -- /bin/bash

# Optional networking
nucleus run --network host -- curl https://example.com
nucleus run --network bridge -p 8080:80 -- ./server

# Context streaming (bind mount for instant access)
nucleus run --context ./large-dir/ --context-mode bind -- ./agent

# Checkpoint a running container
nucleus checkpoint <container> --output /path/to/checkpoint

# Restore from checkpoint
nucleus restore --input /path/to/checkpoint
```

## Development

This project uses Nix flakes for reproducible builds:

```bash
# Enter development shell
nix develop

# Build
cargo build

# Run tests (74 passing, 5 ignored - require root/Apalache)
cargo test

# Run with Apalache installed
cargo test -- --include-ignored

# Build release binary
cargo build --release

# Run examples (requires root)
sudo cargo run --example simple_container
```

### Project Structure

```
nucleus/
├── src/
│   ├── container/      # Container orchestration, lifecycle, state
│   ├── isolation/      # Namespace management, attach
│   ├── resources/      # cgroup resource control
│   ├── filesystem/     # tmpfs, context population, lazy loading
│   ├── security/       # Capabilities, seccomp, Landlock, gVisor
│   ├── network/        # Optional networking (none/host/bridge)
│   ├── checkpoint/     # CRIU checkpoint/restore
│   └── error.rs        # Error types
├── tests/
│   ├── model_based_*   # Property-based tests from TLA+ specs
│   └── tla_*           # tla-connect driver tests
├── formal/tla/         # TLA+ formal specifications
├── intent/             # Intent high-level specs
└── examples/           # Usage examples
```

### Testing

Nucleus uses spec-driven development with comprehensive testing:

- **Unit tests**: 42 tests for individual components
- **Model-based tests**: 25 tests verifying TLA+ properties
- **tla-connect tests**: 10 tests mapping TLA+ to Rust (6 passing, 4 require Apalache)
- **Integration tests**: 8 tests for complete lifecycle

All state machines are formally verified using TLA+ and Apalache model checker.

### System-Level TLA+ Model

In addition to subsystem specs, a composed system model is available:

- `formal/tla/Nucleus_System.tla`
- `formal/tla/Nucleus_System.cfg`

This model verifies cross-subsystem ordering, authorization (owner/root control), and end-to-end
progress properties over bounded container/user sets.

Example Apalache run:

```bash
apalache-mc check --config=formal/tla/Nucleus_System.cfg formal/tla/Nucleus_System.tla
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
