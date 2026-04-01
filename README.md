# Nucleus

**Extremely lightweight Docker alternative for agents and production services**

Nucleus is a minimalist container runtime for Linux. It provides isolated execution environments using Linux kernel primitives without the overhead of traditional container runtimes. Nucleus supports two operating modes:

- **Agent mode** (default) — ephemeral, fast-startup sandboxes for AI agent workloads
- **Production mode** — strict isolation for long-running, network-bound NixOS services with declarative configuration, egress policy enforcement, health checks, and systemd integration

## Why Nucleus?

- **Zero-overhead isolation** – Direct use of cgroups, namespaces, pivot_root, capabilities, seccomp, and Landlock
- **Memory-backed filesystems** – Container disk mapped to tmpfs, pre-populated with agent context
- **gVisor integration** – Optional application kernel for enhanced security, including networked service mode
- **Production service support** – Declarative NixOS module, egress policies, health checks, secrets mounting, sd_notify, and journald integration
- **Minimal rootfs** – Replace host bind mounts with a purpose-built Nix store closure for production services
- **Linux-native** – Runs on standard Linux and NixOS

## Architecture

Nucleus leverages Linux kernel isolation primitives:

- **Namespaces** – PID, mount, network, UTS, IPC, user isolation
- **cgroups v2** – Resource limits (CPU, memory, PIDs, I/O)
- **pivot_root** – Filesystem isolation (chroot fallback available in agent mode only)
- **Capabilities** – All capabilities dropped (irreversible)
- **seccomp** – Syscall whitelist filtering (irreversible)
- **Landlock** – Path-based filesystem access control (Linux 5.13+)
- **gVisor** – Optional application kernel (runsc) with None/Sandbox/Host network modes

Container filesystem is backed by tmpfs and either populated with context files (agent mode) or mounted from a pre-built Nix rootfs closure (production mode).

## Platform Support

- Linux (kernel 6.x+) on `x86_64`
- NixOS (first-class NixOS module support)
- **Not supported**: macOS, Windows, BSDs, 32-bit Linux

## Installation

```bash
cargo install nucleus
```

Or via Nix:

```bash
nix run github:0kenx/nucleus
```

## Usage

### Agent Mode (default)

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

# Optional networking
nucleus run --network host --allow-host-network -- curl https://example.com
nucleus run --network bridge -p 8080:80 -- ./server

# Context streaming (bind mount for instant access)
nucleus run --context ./large-dir/ --context-mode bind -- ./agent

# Environment variables
nucleus run -e API_KEY=secret -e DEBUG=1 -- ./agent
```

### Production Mode

Production mode enforces strict security invariants:
- Forbids `--allow-degraded-security`, `--allow-chroot-fallback`, and `--allow-host-network`
- Requires explicit `--memory` limit
- Requires successful cgroup creation (no fallback to running without limits)
- Egress policy failures are fatal (no silent degradation)
- Bridge DNS must be configured explicitly (no public resolver defaults)

```bash
# Run a long-running service with production hardening
nucleus run \
  --service-mode production \
  --trust-level trusted \
  --memory 1G --cpus 2 --pids 256 \
  --rootfs /nix/store/...-my-service-rootfs \
  --network bridge --dns 10.0.0.1 \
  --egress-allow 10.0.0.0/8 --egress-tcp-port 443 --egress-tcp-port 8443 \
  --health-cmd "curl -sf http://localhost:8080/health" \
  --health-interval 30 --health-retries 3 \
  --secret /run/secrets/tls-cert:/etc/tls/cert.pem \
  -e CONFIG_PATH=/etc/myservice/config.toml \
  --sd-notify \
  -p 8080:8080 \
  -- /bin/my-service --config /etc/myservice/config.toml

# gVisor with network access (sandbox network stack)
nucleus run \
  --service-mode production \
  --runtime gvisor \
  --memory 512M \
  --network bridge --dns 10.0.0.1 \
  --rootfs /nix/store/...-proxy-rootfs \
  -- /bin/proxy
```

### Container Management

```bash
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

# Checkpoint a running container (requires root, CRIU)
nucleus checkpoint <container> --output /path/to/checkpoint

# Restore from checkpoint
nucleus restore --input /path/to/checkpoint
```

## NixOS Module

Nucleus provides a declarative NixOS module for running containers as systemd services. Each container is managed as a `nucleus-<name>.service` unit with journald logging, sd_notify readiness, and automatic restart.

### Flake Setup

```nix
{
  inputs.nucleus.url = "github:0kenx/nucleus";

  outputs = { self, nixpkgs, nucleus, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nucleus.nixosModules.default
        ./configuration.nix
      ];
    };
  };
}
```

### Service Configuration

```nix
{ pkgs, nucleus, ... }:

let
  # Build a minimal rootfs containing only the packages your service needs.
  # This replaces host bind mounts with a locked-down Nix closure.
  proxyRootfs = nucleus.lib.mkRootfs {
    inherit pkgs;
    packages = [ my-proxy-pkg pkgs.cacert pkgs.curl ];
  };
in
{
  services.nucleus = {
    enable = true;
    package = nucleus.packages.x86_64-linux.default;

    containers.sigid-proxy = {
      enable = true;
      command = [ "/bin/sigid-proxy" "--config" "/etc/sigid/proxy.toml" ];
      rootfs = proxyRootfs;

      # Resource limits (required in production mode)
      memory = "1G";
      cpus = 2.0;
      pids = 256;

      # Networking
      network = "bridge";
      dns = [ "10.0.0.1" ];  # internal resolver — no public DNS default
      portForwards = [ "8080:8080" "8443:8443" ];

      # Egress policy — audited outbound access
      egressAllow = [ "10.0.0.0/8" ];
      egressTcpPorts = [ 443 8443 ];

      # Health checking
      healthCheck = "curl -sf http://localhost:8080/health";
      healthInterval = 30;
      healthRetries = 3;
      healthStartPeriod = 10;

      # Secrets (mounted read-only)
      secrets = [
        { source = config.age.secrets.proxy-tls.path; dest = "/etc/tls/cert.pem"; }
      ];

      # Environment
      environment = {
        RUST_LOG = "info";
        CONFIG_PATH = "/etc/sigid/proxy.toml";
      };

      # systemd integration
      sdNotify = true;  # Type=notify, passes NOTIFY_SOCKET into container
    };
  };
}
```

### What the Module Generates

For each enabled container, the module creates a systemd service:

- **Unit**: `nucleus-<name>.service`, ordered after `network-online.target`
- **Type**: `notify` (when `sdNotify = true`) or `simple`
- **Restart**: `on-failure` with 5s backoff
- **Logging**: stdout/stderr captured to journald with `SyslogIdentifier=nucleus-<name>`
- **Command**: `nucleus run --service-mode production ...` with all configured options
- **Hardening**: `ProtectSystem=strict`, `ProtectHome=true` at the systemd level (defense-in-depth)

### Building a Rootfs

Use `nucleus.lib.mkRootfs` to build a minimal, reproducible root filesystem:

```nix
nucleus.lib.mkRootfs {
  inherit pkgs;
  name = "my-service-rootfs";  # optional, defaults to "nucleus-rootfs"
  packages = [
    my-service-package
    pkgs.cacert       # TLS certificates
    pkgs.curl         # for health checks
    pkgs.busybox      # minimal coreutils
  ];
}
```

This produces a Nix store path containing `/bin`, `/lib`, `/etc`, etc. from the specified packages. It is mounted read-only inside the container, replacing the host bind mounts used in agent mode.

## Production Mode vs Agent Mode

| Feature | Agent Mode | Production Mode |
|---|---|---|
| Service mode | `--service-mode agent` (default) | `--service-mode production` |
| Degraded security | Allowed with flag | Forbidden |
| Chroot fallback | Allowed with flag | Forbidden |
| Host networking | Allowed with flag | Forbidden |
| Cgroup limits | Best-effort | Required (fatal on failure) |
| Bridge DNS | Defaults to 8.8.8.8/8.8.4.4 | Must be configured explicitly |
| Rootfs | Host bind mounts (/bin, /usr, /lib, /nix) | Pre-built Nix closure (`--rootfs`) |
| Egress policy | Optional | Optional (fatal on apply failure) |
| Memory limit | Optional | Required |
| Health checks | Optional | Optional |
| sd_notify | Optional | Optional |
| Secrets mounting | Optional | Optional |

## Egress Policy

When `--egress-allow` is specified, Nucleus applies iptables OUTPUT chain rules inside the container's network namespace:

1. Allow loopback traffic
2. Allow established/related connections
3. Allow DNS to configured resolvers
4. Allow traffic to permitted CIDRs (optionally restricted to specific ports)
5. Log denied packets (rate-limited, `nucleus-egress-denied:` prefix)
6. Drop everything else

```bash
# Allow outbound to internal network on HTTPS only
nucleus run --network bridge --dns 10.0.0.1 \
  --egress-allow 10.0.0.0/8 --egress-tcp-port 443 \
  -- ./my-service

# Deny-all egress (only DNS to configured resolvers is allowed)
nucleus run --network bridge --dns 10.0.0.1 \
  --egress-allow "" \
  -- ./isolated-service
```

## gVisor Network Modes

When using gVisor (`--runtime gvisor`), the network mode is automatically selected:

| Container `--network` | gVisor `--network` flag | Description |
|---|---|---|
| `none` | `none` | Fully isolated (default for agents) |
| `bridge` | `sandbox` | gVisor user-space network stack |
| `host` | `host` | Shared host network namespace |

The `sandbox` mode gives gVisor-isolated services full network access through gVisor's user-space TCP/IP stack, without exposing the host kernel's network code.

## Development

This project uses Nix flakes for reproducible builds:

```bash
# Enter development shell
nix develop

# Build
cargo build

# Run tests
cargo test

# Run with Apalache installed (for TLA+ trace replay)
cargo test -- --include-ignored

# Build release binary
cargo build --release

# Clippy
cargo clippy --all-targets -- --deny warnings
```

### Project Structure

```
nucleus/
├── src/
│   ├── container/      # Container orchestration, lifecycle, state, config
│   ├── isolation/      # Namespace management, user mapping, attach
│   ├── resources/      # cgroup v2 resource control, stats
│   ├── filesystem/     # tmpfs, rootfs mounting, context population, secrets
│   ├── security/       # Capabilities, seccomp, Landlock, gVisor, OCI
│   ├── network/        # Networking (none/host/bridge), egress policy
│   ├── checkpoint/     # CRIU checkpoint/restore
│   └── error.rs        # Error types
├── nix/
│   └── module.nix      # NixOS module for declarative service management
├── tests/
│   ├── model_based_*   # Property-based tests from TLA+ specs
│   └── tla_*           # tla-connect driver tests
├── formal/tla/         # TLA+ formal specifications
├── intent/             # Intent high-level specs
└── flake.nix           # Nix flake (packages, modules, lib.mkRootfs)
```

### Testing

Nucleus uses spec-driven development with comprehensive testing:

- **Unit tests**: Individual component functionality
- **Model-based tests**: Property-based tests verifying TLA+ specifications
- **tla-connect tests**: TLA+ to Rust state machine mapping
- **Integration tests**: Complete container lifecycle

All state machines are formally verified using TLA+ and the Apalache model checker.

### System-Level TLA+ Model

A composed system model verifies cross-subsystem ordering, authorization, and end-to-end progress:

```bash
apalache-mc check --config=formal/tla/Nucleus_System.cfg formal/tla/Nucleus_System.tla
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
