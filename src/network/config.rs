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

    /// Validate all fields to prevent argument injection into ip/iptables commands.
    pub fn validate(&self) -> crate::error::Result<()> {
        // Bridge name: alphanumeric, dash, underscore; max 15 chars (Linux IFNAMSIZ)
        if self.bridge_name.is_empty() || self.bridge_name.len() > 15 {
            return Err(crate::error::NucleusError::NetworkError(format!(
                "Bridge name must be 1-15 characters, got '{}'",
                self.bridge_name
            )));
        }
        if !self
            .bridge_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(crate::error::NucleusError::NetworkError(format!(
                "Bridge name contains invalid characters (allowed: a-zA-Z0-9_-): '{}'",
                self.bridge_name
            )));
        }

        // Subnet: must be valid IPv4 CIDR
        validate_ipv4_cidr(&self.subnet).map_err(|e| {
            crate::error::NucleusError::NetworkError(e)
        })?;

        // Container IP (if specified)
        if let Some(ref ip) = self.container_ip {
            validate_ipv4_addr(ip).map_err(|e| {
                crate::error::NucleusError::NetworkError(e)
            })?;
        }

        // DNS servers
        for dns in &self.dns {
            validate_ipv4_addr(dns).map_err(|e| {
                crate::error::NucleusError::NetworkError(e)
            })?;
        }

        Ok(())
    }
}

/// Validate that a string is a valid IPv4 address (no leading dashes, proper octets).
fn validate_ipv4_addr(s: &str) -> Result<(), String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("Invalid IPv4 address: '{}'", s));
    }
    for part in &parts {
        if part.is_empty() {
            return Err(format!("Invalid IPv4 address: '{}'", s));
        }
        if part.len() > 1 && part.starts_with('0') {
            return Err(format!(
                "Invalid IPv4 address: '{}' — octet '{}' has leading zero",
                s, part
            ));
        }
        match part.parse::<u8>() {
            Ok(_) => {}
            Err(_) => return Err(format!("Invalid IPv4 address: '{}'", s)),
        }
    }
    Ok(())
}

/// Validate that a string is a valid IPv4 CIDR (e.g., "10.0.42.0/24").
fn validate_ipv4_cidr(s: &str) -> Result<(), String> {
    let (addr, prefix) = s
        .split_once('/')
        .ok_or_else(|| format!("Invalid CIDR (missing /prefix): '{}'", s))?;
    validate_ipv4_addr(addr)?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| format!("Invalid CIDR prefix: '{}'", s))?;
    if prefix > 32 {
        return Err(format!("CIDR prefix must be 0-32, got {}", prefix));
    }
    Ok(())
}

/// Validate that a string is a valid IPv4 CIDR for egress rules.
pub fn validate_egress_cidr(s: &str) -> Result<(), String> {
    validate_ipv4_cidr(s)
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
    /// Whether to allow DNS (port 53 UDP/TCP) to configured resolvers even in
    /// deny-all mode. Defaults to `true` for usability; set to `false` for
    /// strict deny-all egress (containers must use pre-resolved addresses).
    pub allow_dns: bool,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            allowed_cidrs: Vec::new(),
            allowed_tcp_ports: Vec::new(),
            allowed_udp_ports: Vec::new(),
            log_denied: true,
            allow_dns: true,
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

/// Network protocol for port forwarding rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
    pub protocol: Protocol,
}

impl PortForward {
    /// Parse a port forward spec like "8080:80" or "8080:80/udp"
    pub fn parse(spec: &str) -> crate::error::Result<Self> {
        let (ports, protocol) = if let Some((p, proto)) = spec.rsplit_once('/') {
            let protocol = match proto {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => {
                    return Err(crate::error::NucleusError::ConfigError(format!(
                        "Invalid protocol '{}', must be tcp or udp",
                        proto
                    )))
                }
            };
            (p, protocol)
        } else {
            (spec, Protocol::Tcp)
        };

        let parts: Vec<&str> = ports.split(':').collect();
        if parts.len() != 2 {
            return Err(crate::error::NucleusError::ConfigError(format!(
                "Invalid port forward format '{}', expected HOST:CONTAINER",
                spec
            )));
        }

        let host_port: u16 = parts[0].parse().map_err(|_| {
            crate::error::NucleusError::ConfigError(format!("Invalid host port: {}", parts[0]))
        })?;
        let container_port: u16 = parts[1].parse().map_err(|_| {
            crate::error::NucleusError::ConfigError(format!(
                "Invalid container port: {}",
                parts[1]
            ))
        })?;

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
        assert_eq!(pf.protocol, Protocol::Tcp);

        let pf = PortForward::parse("5353:53/udp").unwrap();
        assert_eq!(pf.host_port, 5353);
        assert_eq!(pf.container_port, 53);
        assert_eq!(pf.protocol, Protocol::Udp);
    }

    #[test]
    fn test_port_forward_parse_invalid() {
        assert!(PortForward::parse("8080").is_err());
        assert!(PortForward::parse("abc:80").is_err());
        assert!(PortForward::parse("8080:abc").is_err());
    }

    #[test]
    fn test_validate_ipv4_addr_rejects_leading_zeros() {
        assert!(validate_ipv4_addr("10.0.42.1").is_ok());
        assert!(validate_ipv4_addr("0.0.0.0").is_ok());
        assert!(
            validate_ipv4_addr("010.0.0.1").is_err(),
            "leading zero in first octet must be rejected"
        );
        assert!(
            validate_ipv4_addr("10.01.0.1").is_err(),
            "leading zero in second octet must be rejected"
        );
        assert!(
            validate_ipv4_addr("10.0.01.1").is_err(),
            "leading zero in third octet must be rejected"
        );
        assert!(
            validate_ipv4_addr("10.0.0.01").is_err(),
            "leading zero in fourth octet must be rejected"
        );
    }
}
