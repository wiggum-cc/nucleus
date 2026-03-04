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
            dns: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            port_forwards: Vec::new(),
        }
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
            (p, proto.to_string())
        } else {
            (spec, "tcp".to_string())
        };

        let parts: Vec<&str> = ports.split(':').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid port forward format '{}', expected HOST:CONTAINER", spec));
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
