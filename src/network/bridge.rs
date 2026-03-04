use crate::error::{NucleusError, Result};
use crate::network::config::{BridgeConfig, PortForward};
use crate::network::NetworkState;
use std::process::Command;
use tracing::{info, warn};

/// Bridge network manager
pub struct BridgeNetwork {
    config: BridgeConfig,
    container_ip: String,
    veth_host: String,
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
        let mut net_state = NetworkState::Unconfigured;
        net_state = net_state.transition(NetworkState::Configuring)?;

        let container_ip = match &config.container_ip {
            Some(ip) => {
                if Self::is_ip_in_use(ip)? {
                    return Err(NucleusError::NetworkError(format!(
                        "Requested container IP {} is already in use",
                        ip
                    )));
                }
                ip.clone()
            }
            None => Self::allocate_ip(&config.subnet)?,
        };

        // Linux interface names max 15 chars; truncate if needed
        let veth_host_full = format!("veth-{:x}", pid);
        let veth_cont_full = format!("vethc-{:x}", pid);
        let veth_host = veth_host_full[..veth_host_full.len().min(15)].to_string();
        let veth_container = veth_cont_full[..veth_cont_full.len().min(15)].to_string();
        let mut rollback = SetupRollback::new(veth_host.clone(), config.subnet.clone());

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
                &format!("{}/24", container_ip),
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

        // 8. Enable IP forwarding
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
        rollback.disarm();

        Ok(Self {
            config: config.clone(),
            container_ip,
            veth_host,
            state: net_state,
        })
    }

    /// Clean up bridge networking
    ///
    /// State transition: Active -> Cleaned
    pub fn cleanup(mut self) -> Result<()> {
        self.state = self.state.transition(NetworkState::Cleaned)?;
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

        info!("Bridge network cleaned up");
        Ok(())
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
                &format!("{}/24", gateway),
                "dev",
                bridge_name,
            ],
        )?;
        Self::run_cmd("ip", &["link", "set", bridge_name, "up"])?;

        info!("Created bridge {}", bridge_name);
        Ok(())
    }

    fn setup_port_forward_for(container_ip: &str, pf: &PortForward) -> Result<()> {
        Self::run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                &pf.protocol,
                "--dport",
                &pf.host_port.to_string(),
                "-j",
                "DNAT",
                "--to-destination",
                &format!("{}:{}", container_ip, pf.container_port),
            ],
        )?;

        info!(
            "Port forward: {}:{} -> {}:{}/{}",
            "host", pf.host_port, container_ip, pf.container_port, pf.protocol
        );
        Ok(())
    }

    fn cleanup_port_forward(&self, pf: &PortForward) -> Result<()> {
        Self::run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "PREROUTING",
                "-p",
                &pf.protocol,
                "--dport",
                &pf.host_port.to_string(),
                "-j",
                "DNAT",
                "--to-destination",
                &format!("{}:{}", self.container_ip, pf.container_port),
            ],
        )?;
        Ok(())
    }

    /// Allocate a container IP from the subnet using /dev/urandom
    fn allocate_ip(subnet: &str) -> Result<String> {
        let base = subnet.split('/').next().unwrap_or("10.0.42.0");
        let parts: Vec<&str> = base.split('.').collect();
        if parts.len() != 4 {
            return Ok("10.0.42.2".to_string());
        }

        let mut buf = [0u8; 1];
        for _ in 0..32 {
            let _ = std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut buf));
            let offset = (buf[0] as u32 % 253) + 2;
            let candidate = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], offset);
            if !Self::is_ip_in_use(&candidate)? {
                return Ok(candidate);
            }
        }

        Err(NucleusError::NetworkError(format!(
            "Failed to allocate free IP in subnet {}",
            subnet
        )))
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

    fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
        let output = Command::new(program).args(args).output().map_err(|e| {
            NucleusError::NetworkError(format!("Failed to run {} {:?}: {}", program, args, e))
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

    fn is_ip_in_use(ip: &str) -> Result<bool> {
        let output = Command::new("ip")
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

    /// Write resolv.conf inside container
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
}

struct SetupRollback {
    veth_host: String,
    subnet: String,
    veth_created: bool,
    nat_added: bool,
    port_forwards: Vec<(String, PortForward)>,
    armed: bool,
}

impl SetupRollback {
    fn new(veth_host: String, subnet: String) -> Self {
        Self {
            veth_host,
            subnet,
            veth_created: false,
            nat_added: false,
            port_forwards: Vec::new(),
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
            let _ = BridgeNetwork::run_cmd(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-D",
                    "PREROUTING",
                    "-p",
                    &pf.protocol,
                    "--dport",
                    &pf.host_port.to_string(),
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &format!("{}:{}", container_ip, pf.container_port),
                ],
            );
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
    }
}
