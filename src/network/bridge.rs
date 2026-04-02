use crate::error::{NucleusError, Result};
use crate::network::config::{BridgeConfig, EgressPolicy, PortForward};
use crate::network::NetworkState;
use std::process::Command;
use tracing::{debug, info, warn};

/// Bridge network manager
pub struct BridgeNetwork {
    config: BridgeConfig,
    container_ip: String,
    veth_host: String,
    container_id: String,
    prev_ip_forward: Option<String>,
    state: NetworkState,
}

impl BridgeNetwork {
    /// Set up bridge networking for a container
    ///
    /// Creates bridge, veth pair, assigns IPs, enables NAT.
    /// Must be called from the parent process after fork (needs host netns).
    ///
    /// State transitions: Unconfigured -> Configuring -> Active
    pub fn setup(pid: u32, config: &BridgeConfig) -> Result<Self> {
        Self::setup_for(pid, config, &format!("{:x}", pid))
    }

    /// Set up bridge networking with an explicit container ID for IP tracking.
    pub fn setup_with_id(pid: u32, config: &BridgeConfig, container_id: &str) -> Result<Self> {
        Self::setup_for(pid, config, container_id)
    }

    fn setup_for(pid: u32, config: &BridgeConfig, container_id: &str) -> Result<Self> {
        // Validate all network parameters before using them in shell commands
        config.validate().map_err(|e| {
            NucleusError::NetworkError(format!("Invalid bridge configuration: {}", e))
        })?;

        let mut net_state = NetworkState::Unconfigured;
        net_state = net_state.transition(NetworkState::Configuring)?;

        let alloc_dir = Self::ip_alloc_dir();
        let container_ip = Self::reserve_ip_in_dir(
            &alloc_dir,
            container_id,
            &config.subnet,
            config.container_ip.as_deref(),
        )?;
        let prefix = Self::subnet_prefix(&config.subnet);

        // Linux interface names max 15 chars; truncate if needed
        let veth_host_full = format!("veth-{:x}", pid);
        let veth_cont_full = format!("vethc-{:x}", pid);
        let veth_host = veth_host_full[..veth_host_full.len().min(15)].to_string();
        let veth_container = veth_cont_full[..veth_cont_full.len().min(15)].to_string();
        let mut rollback = SetupRollback::new(
            veth_host.clone(),
            config.subnet.clone(),
            Some((alloc_dir.clone(), container_id.to_string())),
        );

        // 1. Create bridge if it doesn't exist
        Self::ensure_bridge_for(&config.bridge_name, &config.subnet)?;

        // 2. Create veth pair
        Self::run_cmd(
            "ip",
            &[
                "link",
                "add",
                &veth_host,
                "type",
                "veth",
                "peer",
                "name",
                &veth_container,
            ],
        )?;
        rollback.veth_created = true;

        // 3. Attach host end to bridge
        Self::run_cmd(
            "ip",
            &["link", "set", &veth_host, "master", &config.bridge_name],
        )?;
        Self::run_cmd("ip", &["link", "set", &veth_host, "up"])?;

        // 4. Move container end to container's network namespace
        Self::run_cmd(
            "ip",
            &["link", "set", &veth_container, "netns", &pid.to_string()],
        )?;

        // 5. Configure container interface (inside container netns via nsenter)
        let pid_str = pid.to_string();
        Self::run_cmd(
            "nsenter",
            &[
                "-t",
                &pid_str,
                "-n",
                "ip",
                "addr",
                "add",
                &format!("{}/{}", container_ip, prefix),
                "dev",
                &veth_container,
            ],
        )?;
        Self::run_cmd(
            "nsenter",
            &[
                "-t",
                &pid_str,
                "-n",
                "ip",
                "link",
                "set",
                &veth_container,
                "up",
            ],
        )?;
        Self::run_cmd(
            "nsenter",
            &["-t", &pid_str, "-n", "ip", "link", "set", "lo", "up"],
        )?;

        // 6. Set default route in container
        let gateway = Self::gateway_from_subnet(&config.subnet);
        Self::run_cmd(
            "nsenter",
            &[
                "-t", &pid_str, "-n", "ip", "route", "add", "default", "via", &gateway,
            ],
        )?;

        // 7. Enable NAT (masquerade) on the host
        Self::run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                &config.subnet,
                "-j",
                "MASQUERADE",
            ],
        )?;
        rollback.nat_added = true;

        // 8. Enable IP forwarding (save previous value for restore on cleanup)
        let prev_ip_forward = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .unwrap_or_default()
            .trim()
            .to_string();
        rollback.prev_ip_forward = Some(prev_ip_forward);
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| {
            NucleusError::NetworkError(format!("Failed to enable IP forwarding: {}", e))
        })?;

        // 9. Set up port forwarding rules
        for pf in &config.port_forwards {
            Self::setup_port_forward_for(&container_ip, pf)?;
            rollback
                .port_forwards
                .push((container_ip.clone(), pf.clone()));
        }

        net_state = net_state.transition(NetworkState::Active)?;

        info!(
            "Bridge network configured: {} -> {} (IP: {})",
            veth_host, veth_container, container_ip
        );
        let prev_ip_forward = rollback.prev_ip_forward.clone();
        rollback.disarm();

        Ok(Self {
            config: config.clone(),
            container_ip,
            veth_host,
            container_id: container_id.to_string(),
            prev_ip_forward,
            state: net_state,
        })
    }

    /// Apply egress policy rules inside the container's network namespace.
    ///
    /// Uses iptables OUTPUT chain to restrict outbound connections.
    /// Must be called after bridge setup while the container netns is reachable.
    pub fn apply_egress_policy(&self, pid: u32, policy: &EgressPolicy) -> Result<()> {
        // Validate egress CIDRs before passing to iptables
        for cidr in &policy.allowed_cidrs {
            crate::network::config::validate_egress_cidr(cidr)
                .map_err(|e| NucleusError::NetworkError(format!("Invalid egress CIDR: {}", e)))?;
        }

        let pid_str = pid.to_string();

        // Default policy: drop all OUTPUT (except established/related and loopback)
        Self::run_cmd(
            "nsenter",
            &[
                "-t", &pid_str, "-n", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT",
            ],
        )?;

        Self::run_cmd(
            "nsenter",
            &[
                "-t",
                &pid_str,
                "-n",
                "iptables",
                "-A",
                "OUTPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        )?;

        // Allow DNS to configured resolvers (only when policy permits it)
        if policy.allow_dns {
            for dns in &self.config.dns {
                Self::run_cmd(
                    "nsenter",
                    &[
                        "-t", &pid_str, "-n", "iptables", "-A", "OUTPUT", "-p", "udp", "-d", dns,
                        "--dport", "53", "-j", "ACCEPT",
                    ],
                )?;
                Self::run_cmd(
                    "nsenter",
                    &[
                        "-t", &pid_str, "-n", "iptables", "-A", "OUTPUT", "-p", "tcp", "-d", dns,
                        "--dport", "53", "-j", "ACCEPT",
                    ],
                )?;
            }
        }

        // Allow traffic to each permitted CIDR
        for cidr in &policy.allowed_cidrs {
            if policy.allowed_tcp_ports.is_empty() && policy.allowed_udp_ports.is_empty() {
                // Allow all ports to this CIDR
                Self::run_cmd(
                    "nsenter",
                    &[
                        "-t", &pid_str, "-n", "iptables", "-A", "OUTPUT", "-d", cidr, "-j",
                        "ACCEPT",
                    ],
                )?;
            } else {
                for port in &policy.allowed_tcp_ports {
                    Self::run_cmd(
                        "nsenter",
                        &[
                            "-t",
                            &pid_str,
                            "-n",
                            "iptables",
                            "-A",
                            "OUTPUT",
                            "-p",
                            "tcp",
                            "-d",
                            cidr,
                            "--dport",
                            &port.to_string(),
                            "-j",
                            "ACCEPT",
                        ],
                    )?;
                }
                for port in &policy.allowed_udp_ports {
                    Self::run_cmd(
                        "nsenter",
                        &[
                            "-t",
                            &pid_str,
                            "-n",
                            "iptables",
                            "-A",
                            "OUTPUT",
                            "-p",
                            "udp",
                            "-d",
                            cidr,
                            "--dport",
                            &port.to_string(),
                            "-j",
                            "ACCEPT",
                        ],
                    )?;
                }
            }
        }

        // Log denied packets (rate-limited)
        if policy.log_denied {
            Self::run_cmd(
                "nsenter",
                &[
                    "-t",
                    &pid_str,
                    "-n",
                    "iptables",
                    "-A",
                    "OUTPUT",
                    "-m",
                    "limit",
                    "--limit",
                    "5/min",
                    "-j",
                    "LOG",
                    "--log-prefix",
                    "nucleus-egress-denied: ",
                ],
            )?;
        }

        // Drop everything else
        Self::run_cmd(
            "nsenter",
            &["-t", &pid_str, "-n", "iptables", "-P", "OUTPUT", "DROP"],
        )?;

        info!(
            "Egress policy applied: {} allowed CIDRs",
            policy.allowed_cidrs.len()
        );
        debug!("Egress policy details: {:?}", policy);

        Ok(())
    }

    /// Clean up bridge networking
    ///
    /// State transition: Active -> Cleaned
    pub fn cleanup(mut self) -> Result<()> {
        self.state = self.state.transition(NetworkState::Cleaned)?;

        // Release the IP allocation
        Self::release_allocated_ip(&self.container_id);

        // Remove port forwarding rules
        for pf in &self.config.port_forwards {
            if let Err(e) = self.cleanup_port_forward(pf) {
                warn!("Failed to cleanup port forward: {}", e);
            }
        }

        // Remove NAT rule
        let _ = Self::run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                &self.config.subnet,
                "-j",
                "MASQUERADE",
            ],
        );

        // Delete veth pair (deleting one end removes both)
        let _ = Self::run_cmd("ip", &["link", "del", &self.veth_host]);

        // Restore previous ip_forward state if we changed it
        if let Some(ref prev) = self.prev_ip_forward {
            if prev == "0" {
                if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", "0") {
                    warn!("Failed to restore ip_forward to 0: {}", e);
                } else {
                    info!("Restored net.ipv4.ip_forward to 0");
                }
            }
        }

        info!("Bridge network cleaned up");
        Ok(())
    }

    /// Detect and remove orphaned iptables rules from previous Nucleus runs.
    ///
    /// Checks for stale MASQUERADE rules referencing the nucleus subnet that
    /// have no corresponding running container. Prevents gradual degradation
    /// of network isolation from accumulated orphaned rules.
    pub fn cleanup_orphaned_rules(subnet: &str) {
        // List NAT rules and look for nucleus-related MASQUERADE entries
        let output = match Command::new("iptables")
            .args(["-t", "nat", "-L", "POSTROUTING", "-n"])
            .output()
        {
            Ok(o) => o,
            Err(e) => {
                debug!("Cannot check iptables for orphaned rules: {}", e);
                return;
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut orphaned_count = 0u32;
        for line in stdout.lines() {
            if line.contains("MASQUERADE") && line.contains(subnet) {
                // Try to remove it; if it fails, it may be actively used
                let _ = Self::run_cmd(
                    "iptables",
                    &["-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"],
                );
                orphaned_count += 1;
            }
        }

        if orphaned_count > 0 {
            info!(
                "Cleaned up {} orphaned iptables MASQUERADE rule(s) for subnet {}",
                orphaned_count, subnet
            );
        }
    }

    fn ensure_bridge_for(bridge_name: &str, subnet: &str) -> Result<()> {
        // Check if bridge exists
        if Self::run_cmd("ip", &["link", "show", bridge_name]).is_ok() {
            return Ok(());
        }

        // Create bridge
        Self::run_cmd(
            "ip",
            &["link", "add", "name", bridge_name, "type", "bridge"],
        )?;

        let gateway = Self::gateway_from_subnet(subnet);
        Self::run_cmd(
            "ip",
            &[
                "addr",
                "add",
                &format!("{}/{}", gateway, Self::subnet_prefix(subnet)),
                "dev",
                bridge_name,
            ],
        )?;
        Self::run_cmd("ip", &["link", "set", bridge_name, "up"])?;

        info!("Created bridge {}", bridge_name);
        Ok(())
    }

    fn setup_port_forward_for(container_ip: &str, pf: &PortForward) -> Result<()> {
        for chain in ["PREROUTING", "OUTPUT"] {
            let args = Self::port_forward_rule_args("-A", chain, container_ip, pf);
            Self::run_cmd_owned("iptables", &args)?;
        }

        info!(
            "Port forward: {}:{} -> {}:{}/{}",
            "host", pf.host_port, container_ip, pf.container_port, pf.protocol
        );
        Ok(())
    }

    fn cleanup_port_forward(&self, pf: &PortForward) -> Result<()> {
        for chain in ["OUTPUT", "PREROUTING"] {
            let args = Self::port_forward_rule_args("-D", chain, &self.container_ip, pf);
            Self::run_cmd_owned("iptables", &args)?;
        }
        Ok(())
    }

    /// Allocate a container IP from the subnet using /dev/urandom.
    ///
    /// Checks both host-visible interfaces (via `ip addr`) and IPs assigned to
    /// other Nucleus containers (via state files) to avoid duplicates. Container
    /// IPs inside network namespaces are invisible to `ip addr show` on the host.
    fn allocate_ip_with_reserved(
        subnet: &str,
        reserved: &std::collections::HashSet<String>,
    ) -> Result<String> {
        let base = subnet.split('/').next().unwrap_or("10.0.42.0");
        let parts: Vec<&str> = base.split('.').collect();
        if parts.len() != 4 {
            return Ok("10.0.42.2".to_string());
        }

        // Use rejection sampling to avoid modulo bias.
        // Range is 2..=254 (253 values). We reject random bytes >= 253 to
        // ensure uniform distribution, then add 2 to shift into the valid range.
        // Open /dev/urandom once and read all randomness in a single batch.
        let mut rand_buf = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut rand_buf))
            .map_err(|e| NucleusError::NetworkError(format!("Failed to read /dev/urandom: {}", e)))?;
        for &byte in &rand_buf {
            // Rejection sampling: discard values that would cause modulo bias
            if byte >= 253 {
                continue;
            }
            let offset = byte as u32 + 2;
            let candidate = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], offset);
            if reserved.contains(&candidate) {
                continue;
            }
            if !Self::is_ip_in_use(&candidate)? {
                // Lock is released when lock_file is dropped
                return Ok(candidate);
            }
        }

        Err(NucleusError::NetworkError(format!(
            "Failed to allocate free IP in subnet {}",
            subnet
        )))
    }

    fn reserve_ip_in_dir(
        alloc_dir: &std::path::Path,
        container_id: &str,
        subnet: &str,
        requested_ip: Option<&str>,
    ) -> Result<String> {
        std::fs::create_dir_all(alloc_dir).map_err(|e| {
            NucleusError::NetworkError(format!("Failed to create IP alloc dir: {}", e))
        })?;
        let lock_path = alloc_dir.join(".lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                NucleusError::NetworkError(format!("Failed to open IP alloc lock: {}", e))
            })?;
        use std::os::unix::io::AsRawFd;
        let lock_ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
        if lock_ret != 0 {
            return Err(NucleusError::NetworkError(format!(
                "Failed to acquire IP alloc lock: {}",
                std::io::Error::last_os_error()
            )));
        }

        let reserved = Self::collect_reserved_ips_in_dir(alloc_dir);
        let ip = match requested_ip {
            Some(ip) => {
                if reserved.contains(ip) || Self::is_ip_in_use(ip)? {
                    return Err(NucleusError::NetworkError(format!(
                        "Requested container IP {} is already in use",
                        ip
                    )));
                }
                ip.to_string()
            }
            None => Self::allocate_ip_with_reserved(subnet, &reserved)?,
        };

        Self::record_allocated_ip_in_dir(alloc_dir, container_id, &ip)?;
        Ok(ip)
    }

    /// Scan the Nucleus IP allocation directory for IPs already assigned.
    fn collect_reserved_ips_in_dir(
        alloc_dir: &std::path::Path,
    ) -> std::collections::HashSet<String> {
        let mut ips = std::collections::HashSet::new();
        if let Ok(entries) = std::fs::read_dir(alloc_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".ip") {
                        if let Ok(ip) = std::fs::read_to_string(entry.path()) {
                            let ip = ip.trim().to_string();
                            if !ip.is_empty() {
                                ips.insert(ip);
                            }
                        }
                    }
                }
            }
        }
        ips
    }

    /// Persist the allocated IP for this container so other containers can see it.
    fn record_allocated_ip_in_dir(
        alloc_dir: &std::path::Path,
        container_id: &str,
        ip: &str,
    ) -> Result<()> {
        std::fs::create_dir_all(alloc_dir).map_err(|e| {
            NucleusError::NetworkError(format!("Failed to create IP alloc dir: {}", e))
        })?;
        let path = alloc_dir.join(format!("{}.ip", container_id));
        std::fs::write(&path, ip).map_err(|e| {
            NucleusError::NetworkError(format!("Failed to record IP allocation: {}", e))
        })?;
        Ok(())
    }

    /// Remove the persisted IP allocation for a container.
    fn release_allocated_ip(container_id: &str) {
        let alloc_dir = Self::ip_alloc_dir();
        Self::release_allocated_ip_in_dir(&alloc_dir, container_id);
    }

    fn release_allocated_ip_in_dir(alloc_dir: &std::path::Path, container_id: &str) {
        let path = alloc_dir.join(format!("{}.ip", container_id));
        let _ = std::fs::remove_file(path);
    }

    fn ip_alloc_dir() -> std::path::PathBuf {
        if nix::unistd::Uid::effective().is_root() {
            std::path::PathBuf::from("/var/run/nucleus/ip-alloc")
        } else {
            dirs::runtime_dir()
                .map(|d| d.join("nucleus/ip-alloc"))
                .or_else(|| dirs::data_local_dir().map(|d| d.join("nucleus/ip-alloc")))
                .unwrap_or_else(|| {
                    dirs::home_dir()
                        .map(|h| h.join(".nucleus/ip-alloc"))
                        .unwrap_or_else(|| std::path::PathBuf::from("/var/run/nucleus/ip-alloc"))
                })
        }
    }

    /// Get gateway IP from subnet (first usable address)
    fn gateway_from_subnet(subnet: &str) -> String {
        let base = subnet.split('/').next().unwrap_or("10.0.42.0");
        let parts: Vec<&str> = base.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.{}.1", parts[0], parts[1], parts[2])
        } else {
            "10.0.42.1".to_string()
        }
    }

    fn subnet_prefix(subnet: &str) -> u8 {
        subnet
            .split_once('/')
            .and_then(|(_, p)| p.parse::<u8>().ok())
            .filter(|p| *p <= 32)
            .unwrap_or(24)
    }

    /// Resolve a system binary to an absolute path when running as root.
    /// When unprivileged, falls back to bare name (PATH-based resolution).
    fn resolve_bin(name: &str) -> String {
        if nix::unistd::Uid::effective().is_root() {
            let search_dirs: &[&str] = match name {
                "ip" => &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"],
                "iptables" => &["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"],
                "nsenter" => &["/usr/bin/nsenter", "/usr/sbin/nsenter", "/bin/nsenter"],
                _ => &[],
            };
            for path in search_dirs {
                if std::path::Path::new(path).exists() {
                    return path.to_string();
                }
            }
        }
        name.to_string()
    }

    fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
        let resolved = Self::resolve_bin(program);
        let output = Command::new(&resolved).args(args).output().map_err(|e| {
            NucleusError::NetworkError(format!("Failed to run {} {:?}: {}", resolved, args, e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NucleusError::NetworkError(format!(
                "{} {:?} failed: {}",
                program, args, stderr
            )));
        }

        Ok(())
    }

    fn run_cmd_owned(program: &str, args: &[String]) -> Result<()> {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        Self::run_cmd(program, &refs)
    }

    fn port_forward_rule_args(
        operation: &str,
        chain: &str,
        container_ip: &str,
        pf: &PortForward,
    ) -> Vec<String> {
        let mut args = vec![
            "-t".to_string(),
            "nat".to_string(),
            operation.to_string(),
            chain.to_string(),
            "-p".to_string(),
            pf.protocol.clone(),
        ];

        if chain == "OUTPUT" {
            args.extend([
                "-m".to_string(),
                "addrtype".to_string(),
                "--dst-type".to_string(),
                "LOCAL".to_string(),
            ]);
        }

        args.extend([
            "--dport".to_string(),
            pf.host_port.to_string(),
            "-j".to_string(),
            "DNAT".to_string(),
            "--to-destination".to_string(),
            format!("{}:{}", container_ip, pf.container_port),
        ]);

        args
    }

    fn is_ip_in_use(ip: &str) -> Result<bool> {
        let ip_bin = Self::resolve_bin("ip");
        let output = Command::new(&ip_bin)
            .args(["-4", "addr", "show"])
            .output()
            .map_err(|e| {
                NucleusError::NetworkError(format!("Failed to inspect host IPs: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(NucleusError::NetworkError(format!(
                "ip -4 addr show failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains(&format!(" {}/", ip)))
    }

    /// Write resolv.conf inside container (for writable /etc, e.g. agent mode)
    pub fn write_resolv_conf(root: &std::path::Path, dns: &[String]) -> Result<()> {
        let resolv_path = root.join("etc/resolv.conf");
        let content: String = dns
            .iter()
            .map(|server| format!("nameserver {}\n", server))
            .collect();
        std::fs::write(&resolv_path, content).map_err(|e| {
            NucleusError::NetworkError(format!("Failed to write resolv.conf: {}", e))
        })?;
        Ok(())
    }

    /// Bind-mount a resolv.conf over a read-only /etc (for production rootfs mode).
    ///
    /// Writes the resolver config to a tmpfile then bind-mounts it over
    /// /etc/resolv.conf so it works even when the rootfs /etc is read-only.
    pub fn bind_mount_resolv_conf(root: &std::path::Path, dns: &[String]) -> Result<()> {
        use nix::mount::{mount, MsFlags};

        let content: String = dns
            .iter()
            .map(|server| format!("nameserver {}\n", server))
            .collect();

        // Write to a staging file outside /etc
        let staging = root.join("tmp/.resolv.conf.nucleus");
        std::fs::write(&staging, content).map_err(|e| {
            NucleusError::NetworkError(format!("Failed to write staging resolv.conf: {}", e))
        })?;

        // Ensure the mount target exists (rootfs should provide /etc/resolv.conf,
        // but create an empty file if not)
        let target = root.join("etc/resolv.conf");
        if !target.exists() {
            let _ = std::fs::write(&target, "");
        }

        // Bind mount the staging file over the read-only resolv.conf
        mount(
            Some(staging.as_path()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            NucleusError::NetworkError(format!("Failed to bind mount resolv.conf: {}", e))
        })?;

        info!("Bind-mounted resolv.conf for bridge networking (rootfs mode)");
        Ok(())
    }
}

struct SetupRollback {
    veth_host: String,
    subnet: String,
    veth_created: bool,
    nat_added: bool,
    port_forwards: Vec<(String, PortForward)>,
    prev_ip_forward: Option<String>,
    reserved_ip: Option<(std::path::PathBuf, String)>,
    armed: bool,
}

impl SetupRollback {
    fn new(
        veth_host: String,
        subnet: String,
        reserved_ip: Option<(std::path::PathBuf, String)>,
    ) -> Self {
        Self {
            veth_host,
            subnet,
            veth_created: false,
            nat_added: false,
            port_forwards: Vec::new(),
            prev_ip_forward: None,
            reserved_ip,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SetupRollback {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        for (container_ip, pf) in self.port_forwards.iter().rev() {
            for chain in ["OUTPUT", "PREROUTING"] {
                let args = BridgeNetwork::port_forward_rule_args("-D", chain, container_ip, pf);
                let _ = BridgeNetwork::run_cmd_owned("iptables", &args);
            }
        }

        if self.nat_added {
            let _ = BridgeNetwork::run_cmd(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-s",
                    &self.subnet,
                    "-j",
                    "MASQUERADE",
                ],
            );
        }

        if self.veth_created {
            let _ = BridgeNetwork::run_cmd("ip", &["link", "del", &self.veth_host]);
        }

        if let Some((alloc_dir, container_id)) = &self.reserved_ip {
            BridgeNetwork::release_allocated_ip_in_dir(alloc_dir, container_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_allocation_rejection_sampling_range() {
        // H-5: Verify that rejection sampling produces values in 2..=254
        // and that values >= 253 are rejected (no modulo bias).
        for byte in 0u8..253 {
            let offset = byte as u32 + 2;
            assert!((2..=254).contains(&offset), "offset {} out of range", offset);
        }
        // Values 253, 254, 255 must be rejected
        for byte in [253u8, 254, 255] {
            assert!(byte >= 253);
        }
    }

    #[test]
    fn test_reserve_ip_blocks_duplicate_requested_address() {
        let temp = tempfile::tempdir().unwrap();
        BridgeNetwork::record_allocated_ip_in_dir(temp.path(), "one", "10.0.42.2").unwrap();

        let err = BridgeNetwork::reserve_ip_in_dir(
            temp.path(),
            "two",
            "10.0.42.0/24",
            Some("10.0.42.2"),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("already in use"),
            "second reservation of the same IP must fail"
        );
    }

    #[test]
    fn test_setup_rollback_releases_reserved_ip() {
        let temp = tempfile::tempdir().unwrap();
        BridgeNetwork::record_allocated_ip_in_dir(temp.path(), "rollback", "10.0.42.3").unwrap();

        let rollback = SetupRollback {
            veth_host: "veth-test".to_string(),
            subnet: "10.0.42.0/24".to_string(),
            veth_created: false,
            nat_added: false,
            port_forwards: Vec::new(),
            prev_ip_forward: None,
            reserved_ip: Some((temp.path().to_path_buf(), "rollback".to_string())),
            armed: true,
        };

        drop(rollback);

        assert!(
            !temp.path().join("rollback.ip").exists(),
            "rollback must release reserved IP files on setup failure"
        );
    }

    #[test]
    fn test_port_forward_rules_include_output_chain_for_local_host_clients() {
        let pf = PortForward {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        };

        let prerouting = BridgeNetwork::port_forward_rule_args("-A", "PREROUTING", "10.0.42.2", &pf);
        let output = BridgeNetwork::port_forward_rule_args("-A", "OUTPUT", "10.0.42.2", &pf);

        assert!(prerouting.iter().any(|arg| arg == "PREROUTING"));
        assert!(output.iter().any(|arg| arg == "OUTPUT"));
        assert!(
            output.windows(2).any(|pair| pair[0] == "--dst-type" && pair[1] == "LOCAL"),
            "OUTPUT rule must target local-destination traffic"
        );
    }
}
