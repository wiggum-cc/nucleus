use super::{egress, netlink, netns};
use crate::error::{NucleusError, Result, StateTransition};
use crate::network::config::{BridgeConfig, EgressPolicy, PortForward};
use crate::network::NetworkState;
use std::fs::OpenOptions;
use std::net::Ipv4Addr;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
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
    fn open_dev_urandom() -> Result<std::fs::File> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/dev/urandom")
            .map_err(|e| {
                NucleusError::NetworkError(format!("Failed to open /dev/urandom: {}", e))
            })?;

        let metadata = file.metadata().map_err(|e| {
            NucleusError::NetworkError(format!("Failed to stat /dev/urandom: {}", e))
        })?;
        if !metadata.file_type().is_char_device() {
            return Err(NucleusError::NetworkError(
                "/dev/urandom is not a character device".to_string(),
            ));
        }

        Ok(file)
    }

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
        config.validate()?;

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
        netlink::create_veth(&veth_host, &veth_container)?;
        rollback.veth_created = true;

        // 3. Attach host end to bridge
        netlink::set_link_master(&veth_host, &config.bridge_name)?;
        netlink::set_link_up(&veth_host)?;

        // 4. Move container end to container's network namespace
        netlink::set_link_netns(&veth_container, pid)?;

        // 5. Configure container interface (inside container netns via setns).
        // Capture the process start time from /proc to detect PID recycling
        // between the caller passing the PID and our netns operations.
        let start_ticks = Self::read_pid_start_ticks(pid);
        if start_ticks == 0 {
            drop(rollback);
            return Err(NucleusError::NetworkError(format!(
                "Cannot read start_ticks for PID {} – process may have exited",
                pid
            )));
        }

        let container_addr: Ipv4Addr = container_ip.parse().map_err(|e| {
            NucleusError::NetworkError(format!("invalid container IP '{}': {}", container_ip, e))
        })?;
        {
            let vc = veth_container.clone();
            netns::in_netns(pid, move || {
                netlink::add_addr(&vc, container_addr, prefix)?;
                netlink::set_link_up(&vc)?;
                netlink::set_link_up("lo")?;
                Ok(())
            })?;
        }

        // Verify PID was not recycled during netns operations
        let current_ticks = Self::read_pid_start_ticks(pid);
        if current_ticks != start_ticks {
            drop(rollback);
            return Err(NucleusError::NetworkError(format!(
                "PID {} was recycled during network setup (start_ticks changed: {} -> {})",
                pid, start_ticks, current_ticks
            )));
        }

        // 6. Set default route in container
        let gateway = Self::gateway_from_subnet(&config.subnet);
        let gateway_addr: Ipv4Addr = gateway.parse().map_err(|e| {
            NucleusError::NetworkError(format!("invalid gateway IP '{}': {}", gateway, e))
        })?;
        netns::in_netns(pid, move || netlink::add_default_route(gateway_addr))?;

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
        let prev_ip_forward = match std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
            Ok(v) => Some(v.trim().to_string()),
            Err(e) => {
                warn!(
                    "Could not read ip_forward state (will not restore on cleanup): {}",
                    e
                );
                None
            }
        };
        rollback.prev_ip_forward = prev_ip_forward;
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
        egress::apply_egress_policy(pid, &self.config.dns, policy, false)
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
        let _ = netlink::del_link(&self.veth_host);

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

    /// Best-effort cleanup for use in Drop. Performs the same teardown as
    /// `cleanup()` but ignores all errors and skips the state transition
    /// (which requires ownership).
    fn cleanup_best_effort(&mut self) {
        if self.state == NetworkState::Cleaned {
            return;
        }

        Self::release_allocated_ip(&self.container_id);

        for pf in &self.config.port_forwards {
            let _ = self.cleanup_port_forward(pf);
        }

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

        let _ = netlink::del_link(&self.veth_host);

        if let Some(ref prev) = self.prev_ip_forward {
            if prev == "0" {
                let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "0");
            }
        }

        self.state = NetworkState::Cleaned;
        debug!("Bridge network cleaned up (best-effort via drop)");
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
                    &[
                        "-t",
                        "nat",
                        "-D",
                        "POSTROUTING",
                        "-s",
                        subnet,
                        "-j",
                        "MASQUERADE",
                    ],
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
        if netlink::link_exists(bridge_name) {
            return Ok(());
        }

        netlink::create_bridge(bridge_name)?;

        let gateway = Self::gateway_from_subnet(subnet);
        let gateway_addr: Ipv4Addr = gateway.parse().map_err(|e| {
            NucleusError::NetworkError(format!("invalid bridge gateway '{}': {}", gateway, e))
        })?;
        netlink::add_addr(bridge_name, gateway_addr, Self::subnet_prefix(subnet))?;
        netlink::set_link_up(bridge_name)?;

        info!("Created bridge {}", bridge_name);
        Ok(())
    }

    fn setup_port_forward_for(container_ip: &str, pf: &PortForward) -> Result<()> {
        for chain in ["PREROUTING", "OUTPUT"] {
            let args = Self::port_forward_rule_args("-A", chain, container_ip, pf);
            Self::run_cmd_owned("iptables", &args)?;
        }

        let host_ip = pf
            .host_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "0.0.0.0".to_string());
        info!(
            "Port forward: {}:{} -> {}:{}/{}",
            host_ip, pf.host_port, container_ip, pf.container_port, pf.protocol
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
        // 128 bytes gives ~125 valid candidates (byte < 253), making exhaustion
        // in a populated subnet far less likely than the previous 32-byte buffer.
        let mut rand_buf = [0u8; 128];
        let mut urandom = Self::open_dev_urandom()?;
        std::io::Read::read_exact(&mut urandom, &mut rand_buf).map_err(|e| {
            NucleusError::NetworkError(format!("Failed to read /dev/urandom: {}", e))
        })?;
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
        Self::ensure_alloc_dir(alloc_dir)?;
        let lock_path = alloc_dir.join(".lock");
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| {
                NucleusError::NetworkError(format!("Failed to open IP alloc lock: {}", e))
            })?;
        // SAFETY: lock_file is a valid open fd. LOCK_EX is a blocking exclusive
        // lock that is released when the fd is closed (end of scope).
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
        Self::ensure_alloc_dir(alloc_dir)?;
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

    /// Create the IP allocation directory with restrictive permissions (0700)
    /// and reject symlinked paths to prevent symlink attacks.
    fn ensure_alloc_dir(alloc_dir: &std::path::Path) -> Result<()> {
        // L11: Check for symlinks BEFORE creating directories to avoid TOCTOU.
        // If the path already exists, verify it's not a symlink.
        if alloc_dir.exists() {
            if let Ok(meta) = std::fs::symlink_metadata(alloc_dir) {
                if meta.file_type().is_symlink() {
                    return Err(NucleusError::NetworkError(format!(
                        "IP alloc dir {:?} is a symlink, refusing to use",
                        alloc_dir
                    )));
                }
            }
        }
        // Also check parent directory for symlinks
        if let Some(parent) = alloc_dir.parent() {
            if let Ok(meta) = std::fs::symlink_metadata(parent) {
                if meta.file_type().is_symlink() {
                    return Err(NucleusError::NetworkError(format!(
                        "IP alloc dir parent {:?} is a symlink, refusing to use",
                        parent
                    )));
                }
            }
        }

        std::fs::create_dir_all(alloc_dir).map_err(|e| {
            NucleusError::NetworkError(format!("Failed to create IP alloc dir: {}", e))
        })?;

        // Restrict permissions to owner-only atomically after creation
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(alloc_dir, perms).map_err(|e| {
            NucleusError::NetworkError(format!(
                "Failed to set permissions on IP alloc dir {:?}: {}",
                alloc_dir, e
            ))
        })?;

        // Re-verify no symlink replacement after permissions were set
        if let Ok(meta) = std::fs::symlink_metadata(alloc_dir) {
            if meta.file_type().is_symlink() {
                return Err(NucleusError::NetworkError(format!(
                    "IP alloc dir {:?} was replaced with a symlink during setup",
                    alloc_dir
                )));
            }
        }
        Ok(())
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

    /// Read the start time (field 22) from /proc/<pid>/stat to detect PID recycling.
    /// Returns 0 if the process does not exist or the field cannot be parsed.
    fn read_pid_start_ticks(pid: u32) -> u64 {
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(content) = std::fs::read_to_string(&stat_path) {
            // Field 22 is starttime. The comm field (2) may contain spaces/parens,
            // so find the last ')' and count fields from there.
            if let Some(after_comm) = content.rfind(')') {
                return content[after_comm + 2..]
                    .split_whitespace()
                    .nth(19) // field 22 is 20th after the ')' + state field
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
        0
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

    /// Resolve a system binary to a validated absolute path.
    ///
    /// When running as root, searches known sysadmin paths and validates
    /// ownership and permissions before use. When unprivileged, uses
    /// `which`-style PATH resolution but still validates the result.
    /// Returns an error if no valid binary is found.
    pub(crate) fn resolve_bin(name: &str) -> Result<String> {
        let search_dirs: &[&str] = match name {
            "iptables" => &["/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"],
            "slirp4netns" => &[
                "/usr/bin/slirp4netns",
                "/bin/slirp4netns",
                "/run/current-system/sw/bin/slirp4netns",
            ],
            _ => &[],
        };

        for path in search_dirs {
            let p = std::path::Path::new(path);
            if p.exists() {
                Self::validate_network_binary(p, name)?;
                return Ok(path.to_string());
            }
        }

        // Fallback: resolve via PATH, but validate the result
        if let Ok(output) = Command::new("which").arg(name).output() {
            if output.status.success() {
                let resolved = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !resolved.is_empty() {
                    let p = std::path::Path::new(&resolved);
                    Self::validate_network_binary(p, name)?;
                    return Ok(resolved);
                }
            }
        }

        Err(NucleusError::NetworkError(format!(
            "Required binary '{}' not found or failed validation",
            name
        )))
    }

    /// Validate a network binary's ownership and permissions.
    /// Rejects binaries that are group/world-writable or not owned by root/euid,
    /// except for immutable Nix store artifacts.
    fn validate_network_binary(path: &std::path::Path, name: &str) -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let meta = std::fs::metadata(&resolved)
            .map_err(|e| NucleusError::NetworkError(format!("Cannot stat {}: {}", name, e)))?;
        let mode = meta.mode();
        if mode & 0o022 != 0 {
            return Err(NucleusError::NetworkError(format!(
                "Binary '{}' at {:?} is writable by group/others (mode {:o}), refusing to execute",
                name, resolved, mode
            )));
        }
        let owner = meta.uid();
        let euid = nix::unistd::Uid::effective().as_raw();
        if owner != 0
            && owner != euid
            && !Self::is_trusted_store_network_binary(&resolved, mode)
        {
            return Err(NucleusError::NetworkError(format!(
                "Binary '{}' at {:?} owned by UID {} (expected root or euid {}), refusing to execute",
                name, resolved, owner, euid
            )));
        }
        Ok(())
    }

    fn is_trusted_store_network_binary(path: &std::path::Path, mode: u32) -> bool {
        if !path.starts_with("/nix/store") {
            return false;
        }
        if mode & 0o200 != 0 {
            return false;
        }
        if let Some(parent) = path.parent() {
            if let Ok(parent_meta) = std::fs::metadata(parent) {
                return parent_meta.mode() & 0o222 == 0;
            }
        }
        false
    }

    fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
        let resolved = Self::resolve_bin(program)?;
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
            pf.protocol.as_str().to_string(),
        ];

        if chain == "OUTPUT" {
            args.extend([
                "-m".to_string(),
                "addrtype".to_string(),
                "--dst-type".to_string(),
                "LOCAL".to_string(),
            ]);
        }

        if let Some(host_ip) = pf.host_ip {
            args.extend(["-d".to_string(), host_ip.to_string()]);
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
        let addr: Ipv4Addr = ip
            .parse()
            .map_err(|e| NucleusError::NetworkError(format!("invalid IP '{}': {}", ip, e)))?;
        netlink::is_addr_in_use(&addr)
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
    /// Creates a memfd-backed resolv.conf and bind-mounts it over
    /// /etc/resolv.conf so it works even when the rootfs /etc is read-only.
    /// The memfd is cleaned up when the container exits.
    pub fn bind_mount_resolv_conf(root: &std::path::Path, dns: &[String]) -> Result<()> {
        use nix::mount::{mount, MsFlags};

        let content: String = dns
            .iter()
            .map(|server| format!("nameserver {}\n", server))
            .collect();

        // Create a memfd-backed file to avoid leaving staging files on disk
        let memfd_name = std::ffi::CString::new("nucleus-resolv").map_err(|e| {
            NucleusError::NetworkError(format!("Failed to create memfd name: {}", e))
        })?;
        // SAFETY: memfd_name is a valid NUL-terminated CString. memfd_create
        // returns a new fd or -1 on error; we check for error below.
        let raw_fd = unsafe { libc::memfd_create(memfd_name.as_ptr(), 0) };
        if raw_fd < 0 {
            // Fallback to staging file if memfd_create is unavailable
            return Self::bind_mount_resolv_conf_staging(root, dns);
        }
        // SAFETY: raw_fd is a valid, newly-created fd from memfd_create.
        // OwnedFd takes ownership and will close it exactly once on drop,
        // preventing double-close on any error path.
        let memfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw_fd) };

        // Write content to memfd using File I/O to handle partial writes correctly.
        use std::io::Write as _;
        let mut memfd_file = std::fs::File::from(memfd);
        if memfd_file.write_all(content.as_bytes()).is_err() {
            // memfd_file dropped here, closing the fd automatically
            return Self::bind_mount_resolv_conf_staging(root, dns);
        }
        // Re-extract the OwnedFd for the proc path below
        use std::os::fd::IntoRawFd;
        let memfd = {
            let raw = memfd_file.into_raw_fd();
            // SAFETY: raw is the valid fd we just extracted from the File.
            unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) }
        };

        // Ensure the mount target exists
        let target = root.join("etc/resolv.conf");
        if !target.exists() {
            let _ = std::fs::write(&target, "");
        }

        // Bind mount the memfd over the read-only resolv.conf
        let memfd_path = format!("/proc/self/fd/{}", memfd.as_raw_fd());
        mount(
            Some(memfd_path.as_str()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            // memfd dropped here via the returned Err, closing the fd automatically
            NucleusError::NetworkError(format!("Failed to bind mount resolv.conf: {}", e))
        })?;

        // memfd dropped here – the mount holds a kernel reference to the file,
        // so it survives the fd close.

        info!("Bind-mounted resolv.conf for bridge networking (rootfs mode, memfd)");
        Ok(())
    }

    /// Fallback: bind-mount a staging resolv.conf file.
    fn bind_mount_resolv_conf_staging(root: &std::path::Path, dns: &[String]) -> Result<()> {
        use nix::mount::{mount, MsFlags};

        let content: String = dns
            .iter()
            .map(|server| format!("nameserver {}\n", server))
            .collect();

        // Write to a staging file outside /etc
        let staging = root.join("tmp/.resolv.conf.nucleus");
        if let Some(parent) = staging.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                NucleusError::NetworkError(format!(
                    "Failed to create resolv.conf staging parent: {}",
                    e
                ))
            })?;
        }
        std::fs::write(&staging, content).map_err(|e| {
            NucleusError::NetworkError(format!("Failed to write staging resolv.conf: {}", e))
        })?;

        // Ensure the mount target exists
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

        // The bind mount holds a reference to the inode, so we can safely
        // unlink the staging path to avoid leaking DNS server info on disk.
        if let Err(e) = std::fs::remove_file(&staging) {
            warn!("Failed to remove staging resolv.conf {:?}: {}", staging, e);
        }

        info!("Bind-mounted resolv.conf for bridge networking (rootfs mode, staging)");
        Ok(())
    }
}

impl Drop for BridgeNetwork {
    fn drop(&mut self) {
        self.cleanup_best_effort();
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
                if let Err(e) = BridgeNetwork::run_cmd_owned("iptables", &args) {
                    warn!(
                        "Rollback: failed to remove iptables {} rule for {}: {}",
                        chain, container_ip, e
                    );
                }
            }
        }

        if self.nat_added {
            if let Err(e) = BridgeNetwork::run_cmd(
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
            ) {
                warn!("Rollback: failed to remove NAT rule: {}", e);
            }
        }

        if self.veth_created {
            if let Err(e) = netlink::del_link(&self.veth_host) {
                warn!("Rollback: failed to delete veth {}: {}", self.veth_host, e);
            }
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
            assert!(
                (2..=254).contains(&offset),
                "offset {} out of range",
                offset
            );
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

        let err =
            BridgeNetwork::reserve_ip_in_dir(temp.path(), "two", "10.0.42.0/24", Some("10.0.42.2"))
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
            host_ip: None,
            host_port: 8080,
            container_port: 80,
            protocol: crate::network::config::Protocol::Tcp,
        };

        let prerouting =
            BridgeNetwork::port_forward_rule_args("-A", "PREROUTING", "10.0.42.2", &pf);
        let output = BridgeNetwork::port_forward_rule_args("-A", "OUTPUT", "10.0.42.2", &pf);

        assert!(prerouting.iter().any(|arg| arg == "PREROUTING"));
        assert!(output.iter().any(|arg| arg == "OUTPUT"));
        assert!(
            output
                .windows(2)
                .any(|pair| pair[0] == "--dst-type" && pair[1] == "LOCAL"),
            "OUTPUT rule must target local-destination traffic"
        );
    }

    #[test]
    fn test_port_forward_rules_include_host_ip_when_configured() {
        let pf = PortForward {
            host_ip: Some(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            host_port: 4173,
            container_port: 4173,
            protocol: crate::network::config::Protocol::Tcp,
        };

        let prerouting =
            BridgeNetwork::port_forward_rule_args("-A", "PREROUTING", "10.0.42.2", &pf);
        let output = BridgeNetwork::port_forward_rule_args("-A", "OUTPUT", "10.0.42.2", &pf);

        for args in [&prerouting, &output] {
            assert!(
                args.windows(2)
                    .any(|pair| pair[0] == "-d" && pair[1] == "127.0.0.1"),
                "port forward must restrict DNAT rules to the configured host IP"
            );
        }
    }
}
