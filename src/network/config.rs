/// Network mode for container
#[derive(Debug, Clone)]
pub enum NetworkMode {
    /// No networking (default, fully isolated)
    None,
    /// Share host network namespace
    Host,
    /// Bridge network with NAT
    Bridge(BridgeConfig),
}

/// Configuration for bridge networking
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Bridge interface name
    pub bridge_name: String,
    /// Subnet (e.g., "10.0.42.0/24")
    pub subnet: String,
    /// Container IP address (auto-assigned from subnet)
    pub container_ip: Option<String>,
    /// DNS servers
    pub dns: Vec<String>,
    /// Port forwarding rules
    pub port_forwards: Vec<PortForward>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            bridge_name: "nucleus0".to_string(),
            subnet: "10.0.42.0/24".to_string(),
            container_ip: None,
            // Empty by default — production services must configure DNS explicitly.
            // Agent mode callers can use BridgeConfig::with_public_dns() for convenience.
            dns: Vec::new(),
            port_forwards: Vec::new(),
        }
    }
}

impl BridgeConfig {
    /// Convenience: populate with public Google DNS resolvers.
    /// Suitable for agent/sandbox workloads, NOT for production services.
    pub fn with_public_dns(mut self) -> Self {
        self.dns = vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()];
        self
    }

    pub fn with_dns(mut self, servers: Vec<String>) -> Self {
        self.dns = servers;
        self
    }
}

/// Egress policy for audited outbound network access.
///
/// When set, iptables OUTPUT chain rules restrict which destinations the
/// container process can connect to. An empty allowed list means no
/// outbound connections are permitted (deny-all egress).
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// Allowed destination CIDRs (e.g., "10.0.0.0/8", "192.168.1.0/24").
    pub allowed_cidrs: Vec<String>,
    /// Allowed destination TCP ports. Empty means all ports on allowed CIDRs.
    pub allowed_tcp_ports: Vec<u16>,
    /// Allowed destination UDP ports.
    pub allowed_udp_ports: Vec<u16>,
    /// Whether to log denied egress attempts (rate-limited).
    pub log_denied: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allowed_cidrs: Vec::new(),
            allowed_tcp_ports: Vec::new(),
            allowed_udp_ports: Vec::new(),
            log_denied: true,
        }
    }
}

impl EgressPolicy {
    /// Create a deny-all egress policy.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Allow egress to the given CIDRs on any port.
    pub fn with_allowed_cidrs(mut self, cidrs: Vec<String>) -> Self {
        self.allowed_cidrs = cidrs;
        self
    }

    pub fn with_allowed_tcp_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_tcp_ports = ports;
        self
    }

    pub fn with_allowed_udp_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_udp_ports = ports;
        self
    }
}

/// Port forwarding rule
#[derive(Debug, Clone)]
pub struct PortForward {
    /// Host port
    pub host_port: u16,
    /// Container port
    pub container_port: u16,
    /// Protocol (tcp/udp)
    pub protocol: String,
}

impl PortForward {
    /// Parse a port forward spec like "8080:80" or "8080:80/udp"
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (ports, protocol) = if let Some((p, proto)) = spec.rsplit_once('/') {
            if proto != "tcp" && proto != "udp" {
                return Err(format!("Invalid protocol '{}', must be tcp or udp", proto));
            }
            (p, proto.to_string())
        } else {
            (spec, "tcp".to_string())
        };

        let parts: Vec<&str> = ports.split(':').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid port forward format '{}', expected HOST:CONTAINER",
                spec
            ));
        }

        let host_port: u16 = parts[0]
            .parse()
            .map_err(|_| format!("Invalid host port: {}", parts[0]))?;
        let container_port: u16 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid container port: {}", parts[1]))?;

        Ok(Self {
            host_port,
            container_port,
            protocol,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_forward_parse() {
        let pf = PortForward::parse("8080:80").unwrap();
        assert_eq!(pf.host_port, 8080);
        assert_eq!(pf.container_port, 80);
        assert_eq!(pf.protocol, "tcp");

        let pf = PortForward::parse("5353:53/udp").unwrap();
        assert_eq!(pf.host_port, 5353);
        assert_eq!(pf.container_port, 53);
        assert_eq!(pf.protocol, "udp");
    }

    #[test]
    fn test_port_forward_parse_invalid() {
        assert!(PortForward::parse("8080").is_err());
        assert!(PortForward::parse("abc:80").is_err());
        assert!(PortForward::parse("8080:abc").is_err());
    }
}
