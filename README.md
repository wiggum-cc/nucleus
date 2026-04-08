# Nucleus

[![Crates.io](https://img.shields.io/crates/v/nucleus-container.svg)](https://crates.io/crates/nucleus-container)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Extremely lightweight, declarative container runtime for agents and production services**

Nucleus is a minimalist container runtime for Linux. It provides isolated execution environments using Linux kernel primitives without the overhead of traditional container runtimes. For production services, it is designed around a fully declarative model: Nix builds the root filesystem, the NixOS module declares the service, and Nucleus mounts a pinned, reproducible closure at runtime.

Nucleus supports two operating modes:

- **Agent mode** (default) – ephemeral, fast-startup sandboxes for AI agent workloads
- **Production mode** – strict isolation for long-running, network-bound NixOS services with declarative configuration, reproducible Nix-built root filesystems, egress policy enforcement, health checks, and systemd integration

Production deployments are built to be:

- **Fully declarative** – service topology, runtime settings, and mounted rootfs are defined up front instead of assembled imperatively at deploy time
- **Nix-native** – first-class NixOS module support plus `nucleus.lib.mkRootfs` for minimal service closures
- **Reproducible** – flake-based builds, pinned store paths, and rootfs attestation keep runtime inputs stable and auditable

## Benchmarks

### Cold Start

| Runtime | Startup Time |
|---|---|
| **Nucleus** | **12 ms** |
| Docker | ~500 ms |

### PostgreSQL 18 (pgbench, 8 clients, 60s, scale 50)

In the native runtime, PostgreSQL stays near bare-metal performance under Nucleus
isolation. In this harness, occasional wins over bare metal should be treated as
benchmark noise rather than a guaranteed speedup.

**SELECT-only (read-heavy)**

| Environment | I/O Method | Avg TPS | Avg Latency |
|---|---|---|---|
| Baremetal | worker | 100,222 | 0.080 ms |
| Baremetal | io_uring | 84,895 | 0.096 ms |
| **Nucleus** | **worker** | **105,965** | **0.075 ms** |
| **Nucleus** | **io_uring** | **107,039** | **0.074 ms** |

**TPC-B (mixed read/write)**

| Environment | I/O Method | Avg TPS | Avg Latency |
|---|---|---|---|
| Baremetal | worker | 1,490 | 5.38 ms |
| Baremetal | io_uring | 1,382 | 5.79 ms |
| **Nucleus** | **worker** | **1,757** | **4.55 ms** |
| **Nucleus** | **io_uring** | **1,585** | **5.05 ms** |

> Measured on Linux 6.18 x86_64. This benchmark uses the native runtime with a
> bind-mounted host `pgdata` directory and `--network host`, so it measures the
> steady-state cost of Nucleus isolation rather than VM or gVisor emulation
> overhead. Full results: [`benches/pg18_io/results/`](benches/pg18_io/results/)

## Why Nucleus?

- **Declarative by default for services** – Production deployments are defined in NixOS and TOML rather than stitched together with ad hoc runtime scripting
- **Deep Nix integration** – First-class NixOS module, `mkRootfs`, and Nix store closures for minimal, locked-down service roots
- **Reproducible service builds** – Flake-based packaging, pinned inputs, and rootfs attestation make runtime state auditable and repeatable
- **Zero-overhead isolation** – Direct use of cgroups, namespaces, pivot_root, capabilities, seccomp, and Landlock
- **Memory-backed filesystems** – Container disk mapped to tmpfs, pre-populated with agent context
- **gVisor integration** – Optional application kernel for enhanced security, including networked service mode
- **OCI runtime-spec subset for gVisor** – Generates OCI bundle/config data for `runsc`, including process identity, mounts, namespaces, seccomp, hooks, and cgroup path wiring
- **Detached mode** – Run containers in the background as systemd transient services with `--detach`, managed via `nucleus stop`/`logs`/`attach`
- **Production service support** – Declarative NixOS module, egress policies, health checks, secrets mounting, sd_notify, and journald integration
- **Explicit workload identity** – Native and gVisor runtimes can drop to a configured `uid`/`gid` plus supplementary groups after privileged setup
- **Minimal rootfs** – Replace host bind mounts with a purpose-built Nix store closure for production services
- **External security policies** – Per-service seccomp profiles (JSON), capability policies (TOML), and Landlock rules (TOML) with SHA-256 pinning
- **Seccomp profile generation** – Trace mode records syscalls, then `nucleus seccomp generate` creates a minimal allowlist profile
- **Multi-container topologies** – Compose-equivalent TOML format with dependency DAG, reconciliation, and NixOS systemd integration
- **Integrity & audit controls** – Structured audit log, context hashing, rootfs attestation, seccomp deny logging, mount flag verification, and kernel lockdown assertions
- **Structured telemetry** – Optional OpenTelemetry export for container lifecycle tracing
- **Linux-native** – Runs on standard Linux and NixOS

## Architecture

Nucleus leverages Linux kernel isolation primitives:

- **Namespaces** – PID, mount, network, UTS, IPC, user, cgroup, and optional time isolation
- **cgroups v2** – Resource limits (CPU, memory, PIDs, I/O)
- **pivot_root** – Filesystem isolation (chroot fallback available in agent mode only)
- **Capabilities** – All capabilities dropped by default, or configured via TOML policy file (irreversible)
- **seccomp** – Syscall whitelist filtering with per-service JSON profiles and trace-based generation (irreversible)
- **Landlock** – Path-based filesystem access control via hardcoded defaults or TOML policy file (Linux 5.13+)
- **gVisor** – Optional application kernel (runsc) with None/Sandbox/Host network modes
- **OCI bundle generation** – Emits OCI `config.json` plus bundle layout for gVisor, including `process.user`, lifecycle hooks, seccomp, resource limits, and namespace mappings
- **PID 1 init** – Mini-init supervisor in production mode for zombie reaping and signal forwarding
- **In-memory secrets** – Dedicated tmpfs at `/run/secrets` with volatile zeroing of source buffers
- **Mount audit** – Post-setup verification of mount flags in production mode

Container filesystem is backed by tmpfs and either populated with context files (agent mode) or mounted from a pre-built Nix rootfs closure (production mode). That lets production services run from a declaratively built, reproducible root filesystem instead of inheriting mutable host state.

## Platform Support

- Linux (kernel 6.x+) on `x86_64`
- NixOS (first-class NixOS module support)
- **Not supported**: macOS, Windows, BSDs, 32-bit Linux

## Installation

```bash
cargo install nucleus-container --version 0.3.0
```

Or via Nix (recommended for reproducible builds and NixOS integration):

```bash
nix run github:0kenx/nucleus/v0.3.0
```

The Cargo package name is `nucleus-container`; it installs the `nucleus` binary. The repository itself is packaged as a Nix flake, so `nix run`, `nix build`, and the NixOS module all share the same pinned inputs.

## Recent Features in 0.3.0

- **Privilege drop for services** – `--user`, `--group`, and `--additional-group` now apply a real post-setup workload identity in both the native runtime and gVisor.
- **Ownership-aware secrets and writable paths** – Production secret staging and NixOS `createHostPath = true` defaults now align file ownership with the configured workload user/group.
- **OCI bundle identity support** – Generated gVisor OCI configs now carry `process.user` including supplementary groups, alongside namespaces, mounts, resource limits, seccomp, hooks, and `cgroupsPath`.
- **Probe execution under workload identity** – Exec-based health and readiness probes now run as the configured service account instead of implicitly as root.
- **Systemd/NixOS service integration improvements** – The module exposes `user`, `group`, and `supplementaryGroups`, and packaged Nix usage includes `gvisor` in the flake/dev shell path.

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
nucleus run --network bridge -p 127.0.0.1:8080:80 -- ./server
nucleus run --rootless --network bridge -- ./client
nucleus run --network bridge --nat-backend userspace -- ./client

# Context streaming (bind mount for instant access)
nucleus run --context ./large-dir/ --context-mode bind -- ./agent

# Integrity and audit hardening
nucleus run --context ./ctx/ --verify-context-integrity --seccomp-log-denied -- ./agent

# Environment variables
nucleus run -e DEBUG=1 -- ./agent

# Pass sensitive values via --secret (mounted in-memory at /run/secrets)
nucleus run --secret /path/to/api-key:/run/secrets/api_key -- ./agent
```

### Detached Mode

Use `-d`/`--detach` to run a container in the background as a systemd transient service. The CLI prints the container ID and exits immediately; systemd supervises the container process.

```bash
# Run a container in the background
nucleus create -d --memory 512M -- /bin/sleep 3600
# prints: a1b2c3d4e5f6...

# All management commands work with detached containers
nucleus state                        # list running containers
nucleus logs <container>             # view stdout/stderr (from journald)
nucleus logs -f <container>          # follow logs
nucleus logs -n 50 <container>       # last 50 lines
nucleus attach <container>           # exec into it
nucleus stop <container>             # graceful SIGTERM → SIGKILL
nucleus kill <container>             # send signal

# Detach works with all create flags
nucleus create -d \
  --name my-service \
  --memory 1G --cpus 2 \
  --network bridge -p 8080:80 \
  -- ./my-server

# systemd unit is named nucleus-<id-prefix>
systemctl status nucleus-a1b2c3d4e5f6
journalctl -u nucleus-a1b2c3d4e5f6
```

The systemd transient service uses `KillMode=mixed` and `TimeoutStopSec=30`, so `systemctl stop` also works for graceful shutdown. The `--collect` flag ensures the unit is garbage-collected after the container exits.

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
  --verify-rootfs-attestation \
  --require-kernel-lockdown integrity \
  --network bridge --dns 10.0.0.1 \
  --egress-allow 10.0.0.0/8 --egress-tcp-port 443 --egress-tcp-port 8443 \
  --health-cmd "curl -sf http://localhost:8080/health" \
  --health-interval 30 --health-retries 3 \
  --secret /run/secrets/tls-cert:/etc/tls/cert.pem \
  --systemd-credential db-url:/run/secrets/db-url \
  --volume /var/lib/myservice:/var/lib/myservice:rw \
  -e CONFIG_PATH=/etc/myservice/config.toml \
  --sd-notify \
  -p 127.0.0.1:8080:8080 \
  -- /bin/my-service --config /etc/myservice/config.toml

# gVisor with network access (sandbox network stack)
nucleus run \
  --service-mode production \
  --runtime gvisor \
  --gvisor-platform kvm \
  --memory 512M \
  --network bridge --dns 10.0.0.1 \
  --rootfs /nix/store/...-proxy-rootfs \
  -- /bin/proxy
```

### Security Policy Files

Nix defines the service and the root filesystem; separate files define security policy (what the process is allowed to do at the kernel level). This separation keeps deployments declarative, security config auditable, and runtime inputs reproducible without coupling policy changes to application rebuilds.

```bash
# Run with external security policies
nucleus run \
  --service-mode production \
  --rootfs /nix/store/...-my-service-rootfs \
  --memory 512M --cpus 1 \
  --seccomp-profile ./config/my-service.seccomp.json \
  --seccomp-profile-sha256 abc123... \
  --caps-policy ./config/my-service.caps.toml \
  --landlock-policy ./config/my-service.landlock.toml \
  -- /bin/my-service
```

**Seccomp profile** (JSON – OCI-native format, tooling emits it directly):
```json
{
  "defaultAction": "SCMP_ACT_KILL_PROCESS",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "close", "openat", "fstat",
                "mmap", "munmap", "brk", "futex", "clock_gettime"],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

**Capability policy** (TOML):
```toml
# config/my-service.caps.toml
[bounding]
keep = []          # empty = drop all

[ambient]
keep = []
```

**Landlock policy** (TOML):
```toml
# config/my-service.landlock.toml
min_abi = 3

[[rules]]
path = "/bin"
access = ["read", "execute"]

[[rules]]
path = "/etc/myservice"
access = ["read"]

[[rules]]
path = "/run/secrets"
access = ["read"]

[[rules]]
path = "/tmp"
access = ["read", "write", "create", "remove"]
```

### Seccomp Profile Generation

Profiles shouldn't be hand-written from scratch. Use trace mode to record actual syscall usage, then generate a minimal profile:

```bash
# 1. Run in trace mode – all syscalls allowed but logged
nucleus run \
  --seccomp-mode trace \
  --seccomp-log ./trace.ndjson \
  --rootfs /nix/store/...-my-service-rootfs \
  --memory 512M \
  -- /bin/my-service

# 2. Generate minimal profile from trace
nucleus seccomp generate ./trace.ndjson -o config/my-service.seccomp.json

# 3. Review and tighten (remove anything surprising)
# 4. Commit – Nix pins the SHA-256 hash
# 5. Run in enforce mode
nucleus run \
  --seccomp-profile ./config/my-service.seccomp.json \
  --seccomp-profile-sha256 "$(sha256sum config/my-service.seccomp.json | cut -d' ' -f1)" \
  -- /bin/my-service
```

Trace mode requires root or `CAP_SYSLOG` (reads `/dev/kmsg`). It is rejected in production mode – it is a development tool only.

### Multi-Container Topologies

Nucleus includes a Compose-equivalent for managing multi-container stacks using TOML configuration with dependency ordering.

```toml
# topology.toml
name = "myapp"

[networks.internal]
subnet = "10.42.0.0/24"

[volumes.db-data]
volume_type = "persistent"
path = "/var/lib/nucleus/myapp/db"
owner = "70:70"

[volumes.cache]
volume_type = "ephemeral"
size = "128M"

[services.postgres]
rootfs = "/nix/store/...-postgres"
command = ["postgres", "-D", "/var/lib/postgresql/data"]
memory = "2G"
cpus = 2.0
networks = ["internal"]
volumes = [
  "db-data:/var/lib/postgresql/data",
  "cache:/var/cache/postgresql"
]
health_check = "pg_isready -U myapp"

[services.web]
rootfs = "/nix/store/...-web"
command = ["/bin/web-server"]
memory = "512M"
networks = ["internal"]
nat_backend = "userspace"
port_forwards = ["8443:8443"]
egress_allow = ["10.42.0.0/24"]

[[services.web.depends_on]]
service = "postgres"
condition = "healthy"
```

```bash
# Validate topology and show dependency order
nucleus compose validate -f topology.toml

# Bring up all services in dependency order
nucleus compose up -f topology.toml

# Show service status
nucleus compose ps -f topology.toml

# Tear down in reverse dependency order
nucleus compose down -f topology.toml
```

### Container Management

```bash
# List running containers
nucleus ps

# List all containers (including stopped)
nucleus ps --all

# Show resource usage statistics
nucleus stats

# View logs for a detached container (from systemd journal)
nucleus logs <container>
nucleus logs -f <container>          # follow output
nucleus logs -n 100 <container>      # last 100 lines

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
  inputs.nucleus.url = "github:0kenx/nucleus/v0.3.0";

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
      user = "sigid-proxy";
      group = "sigid-proxy";

      # Resource limits (required in production mode)
      memory = "1G";
      cpus = 2.0;
      pids = 256;

      # Security policy files (separate from Nix, auditable by security engineers)
      seccompProfile = {
        path = ./config/sigid-proxy.seccomp.json;
        sha256 = "abc123...";  # Nix verifies at build time
      };
      capsPolicy = ./config/sigid-proxy.caps.toml;
      landlockPolicy = ./config/sigid-proxy.landlock.toml;

      # Optional hardening toggles
      verifyRootfsAttestation = true;
      seccompLogDenied = true;
      requireKernelLockdown = "integrity";

      # Networking
      network = "bridge";
      natBackend = "auto";  # or "userspace" to force slirp4netns
      dns = [ "10.0.0.1" ];  # internal resolver – no public DNS default
      portForwards = [ "127.0.0.1:8080:8080" "127.0.0.1:8443:8443" ];

      # Egress policy – audited outbound access
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

      # systemd-creds integration
      credentials = [
        {
          name = "proxy-key";
          source = config.age.secrets.proxy-key.path;
          dest = "/run/secrets/proxy-key";
          encrypted = false;
        }
      ];

      # Volumes (bind-mounted host paths)
      volumes = [
        {
          source = "/var/lib/sigid-proxy";
          dest = "/var/lib/sigid-proxy";
          createHostPath = true;
        }
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

Writable bind volumes are automatically added to the generated systemd unit's `ReadWritePaths`. When `createHostPath = true`, the NixOS module creates the host directory with `systemd-tmpfiles` before the container starts. If the container declares a workload `user`/`group`, those become the default tmpfiles owner for new writable paths unless the volume overrides them.

Credentials declared via `credentials = [ ... ]` use systemd's credential pipeline (`LoadCredential` or `LoadCredentialEncrypted`) and are mounted into the container through Nucleus's secret path. The CLI flag `--systemd-credential NAME:DEST` resolves `NAME` from `CREDENTIALS_DIRECTORY` at runtime.

Set `user`, `group`, and optional `supplementaryGroups` on a NixOS container definition when the workload should run as a dedicated service account instead of root.

### Topology Services

Topologies can also be managed as systemd services:

```nix
{
  services.nucleus = {
    enable = true;
    package = nucleus.packages.x86_64-linux.default;

    topologies.myapp = {
      enable = true;
      configFile = ./topology.toml;
    };
  };
}
```

This creates a `nucleus-topology-myapp.service` (Type=oneshot, RemainAfterExit) that runs `nucleus compose up` on start and `nucleus compose down` on stop.

### What the Module Generates

For each enabled container, the module creates a systemd service:

- **Unit**: `nucleus-<name>.service`, ordered after `network-online.target`
- **Type**: `notify` (when `sdNotify = true`) or `simple`
- **Restart**: `on-failure` with 5s backoff
- **Logging**: stdout/stderr captured to journald with `SyslogIdentifier=nucleus-<name>`
- **Command**: `nucleus run --service-mode production ...` with all configured options
- **Workload identity**: Nucleus itself starts as root for setup, then drops the container workload to the configured `user` / `group` before exec
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

`mkRootfs` also emits a `.nucleus-rootfs-sha256` manifest at the root of the closure. Use `--verify-rootfs-attestation` or `verifyRootfsAttestation = true;` to require that manifest to match the mounted rootfs at startup.

## Security Notes

**Do not pass secrets via `-e` / `--env`.** Environment variables are visible in `/proc/<pid>/environ` to any process that can read it (mitigated by `hidepid=2` in production mode, but not in agent mode). Use `--secret` instead – secrets are mounted on an in-memory tmpfs at `/run/secrets` with volatile source buffer zeroing.

**Privilege dropping is explicit.** Nucleus must start with elevated privileges to create namespaces, mount filesystems, and configure cgroups/networking. Use `--user` / `--group` (or the NixOS module's `user` / `group` options) so the workload itself does not continue running as root after setup. In production mode, staged secrets under `/run/secrets` are re-owned to that workload identity.

**Agent mode is not hardened.** By design, agent mode applies several security mechanisms on a best-effort basis: seccomp and Landlock failures are warn-and-continue (with `--allow-degraded-security`), chroot fallback is available (with `--allow-chroot-fallback`), bridge DNS defaults to public resolvers (`8.8.8.8`), and cgroup creation failures are non-fatal. Operators requiring strict isolation should use production mode, which makes all of these fatal.

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
| Egress policy | Optional | Deny-all default (fatal on apply failure) |
| Memory limit | Optional | Required |
| PID 1 init | Direct exec | Mini-init with zombie reaping + signal forwarding |
| Workload uid/gid | Root by default | Configurable post-setup drop via `--user` / `--group` |
| Secrets | Bind mount | In-memory tmpfs with volatile zeroing |
| /proc | Mounted normally | `hidepid=2` (hides other processes) |
| Mount audit | Skipped | Post-setup flag verification (fatal) |
| Seccomp trace mode | Allowed | Forbidden |
| Landlock ABI | Best-effort | V3 minimum required |
| Health checks | Optional | Optional |
| sd_notify | Optional | Optional |
| Security policies | Optional | Optional (recommended) |

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

## Native Bridge Backends

For the native runtime, `--network bridge` now has two backends:

| `--nat-backend` | When used | Implementation |
|---|---|---|
| `auto` | Default | Kernel bridge/veth/iptables when privileged, `slirp4netns` userspace NAT when rootless |
| `kernel` | Explicit opt-in | Kernel bridge + veth + iptables MASQUERADE/DNAT |
| `userspace` | Explicit opt-in | `slirp4netns` userspace NAT + API-socket port forwarding |

This changes the native rootless behavior from "degrade to `none`" to a real userspace NAT path.

## gVisor Network Modes

When using gVisor (`--runtime gvisor`), the network mode is automatically selected:

| Container `--network` | gVisor `--network` flag | Description |
|---|---|---|
| `none` | `none` | Fully isolated (default for agents) |
| `bridge` | `sandbox` | gVisor user-space network stack |
| `host` | `host` | Shared host network namespace |

The `sandbox` mode gives gVisor-isolated services full network access through gVisor's user-space TCP/IP stack, without exposing the host kernel's network code.

## OCI Support

Nucleus is not a generic external OCI runtime. For gVisor execution it generates an OCI bundle layout and `config.json` that follow the OCI runtime-spec fields Nucleus uses in practice.

- `process`: args, env, cwd, `noNewPrivileges`, terminal settings, rlimits, and `process.user` (`uid`, `gid`, `additionalGids`)
- `root` and `mounts`: read-only rootfs plus bind, tmpfs, and secret mounts
- `linux`: namespaces, cgroup path, resource limits, uid/gid mappings, masked paths, readonly paths, devices, seccomp, and sysctls
- `hooks`: OCI lifecycle hooks with OCI state JSON on stdin
- `annotations`: runtime metadata passed through to the bundle

That OCI path is the contract used with `runsc`. The native runtime uses Nucleus's direct Linux setup path rather than exposing a separate OCI CLI surface.

## Additional Hardening Flags

- `--seccomp-profile <path>` loads a custom per-service seccomp profile (OCI JSON format).
- `--seccomp-profile-sha256 <hex>` verifies the profile's SHA-256 hash before loading.
- `--seccomp-mode trace|enforce` switches between trace (record all syscalls) and enforce (default).
- `--seccomp-log <path>` writes NDJSON syscall trace when in trace mode.
- `--caps-policy <path>` loads a TOML capability policy (replaces default drop-all).
- `--caps-policy-sha256 <hex>` verifies the capability policy hash.
- `--landlock-policy <path>` loads a TOML Landlock filesystem policy (replaces default rules).
- `--landlock-policy-sha256 <hex>` verifies the Landlock policy hash.
- `--verify-context-integrity` hashes the source context tree before launch and verifies the populated `/context` tree matches.
- `--verify-rootfs-attestation` requires a `.nucleus-rootfs-sha256` manifest and verifies the mounted rootfs against it.
- `--seccomp-log-denied` requests kernel logging for denied seccomp decisions when the host supports `SECCOMP_FILTER_FLAG_LOG`.
- `--require-kernel-lockdown integrity|confidentiality` refuses startup unless `/sys/kernel/security/lockdown` satisfies the requested mode.
- `--gvisor-platform systrap|kvm|ptrace` selects the runsc backend explicitly.
- `--time-namespace` enables Linux time namespaces for native containers.
- `--disable-cgroup-namespace` turns off cgroup namespace isolation when a workload needs the host cgroup view.

If `NUCLEUS_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` is set, Nucleus exports lifecycle spans over OTLP in addition to normal local logging.

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

# Host vs container runtime benchmarks (requires root)
sudo -E cargo bench --bench container_runtime
```

### Project Structure

```
nucleus/
├── src/
│   ├── container/      # Container orchestration, lifecycle, state, config
│   ├── isolation/      # Namespace management, user mapping, attach
│   ├── resources/      # cgroup v2 resource control, stats
│   ├── filesystem/     # tmpfs, rootfs mounting, context population, secrets, attestation
│   ├── security/       # Capabilities, seccomp, Landlock, gVisor, OCI, policy files
│   │   ├── caps_policy.rs       # TOML capability policy loader
│   │   ├── landlock_policy.rs   # TOML Landlock policy loader
│   │   ├── seccomp_trace.rs     # Seccomp trace mode (syscall recording)
│   │   ├── seccomp_generate.rs  # Profile generator from traces
│   │   └── policy.rs            # Shared policy infrastructure (SHA-256, TOML/JSON loaders)
│   ├── network/        # Networking (none/host/bridge), egress policy
│   ├── topology/       # Multi-container topology (Compose equivalent)
│   │   ├── config.rs   # TOML topology config (services, networks, volumes)
│   │   ├── dag.rs      # Dependency DAG with topological sort
│   │   ├── reconcile.rs # Diff running vs desired state, apply changes
│   │   └── dns.rs      # Per-topology /etc/hosts DNS
│   ├── checkpoint/     # CRIU checkpoint/restore
│   ├── audit.rs        # Structured audit log (JSON events)
│   └── error.rs        # Error types
├── nix/
│   └── module.nix      # NixOS module (containers + topologies)
├── config/             # Security policy files (per-service)
│   ├── *.seccomp.json  # Seccomp syscall allowlists (OCI format)
│   ├── *.caps.toml     # Capability bounding set policies
│   └── *.landlock.toml # Landlock filesystem access rules
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

### Performance Benchmarks

`benches/container_runtime.rs` compares the same workloads when run directly on the host vs inside a native Nucleus container. The matrix covers:

- cold startup (`/bin/sh -lc ':'`)
- a CPU-bound shell arithmetic loop
- context-heavy file scans with both bind-mounted and copied context
- a constrained profile that applies the same cgroup limits to the direct host process and the containerized process

Because the benchmark creates namespaces and cgroups, it must run as root:

```bash
sudo -E cargo bench --bench container_runtime
```

Criterion writes the comparison reports to `target/criterion/container_runtime/`.

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
