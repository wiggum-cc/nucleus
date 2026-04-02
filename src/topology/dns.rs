//! Lightweight per-topology DNS for container name resolution.
//!
//! Provides DNS-based service discovery within a topology. Container names
//! resolve to their bridge IPs, enabling inter-service communication by name.
//!
//! This is a minimal implementation that writes static DNS entries rather than
//! running a full DNS server. For production deployments with dynamic scaling,
//! consider integrating Hickory DNS or dnsmasq.

use crate::error::{NucleusError, Result};
use std::collections::BTreeMap;
use std::path::Path;
use tracing::info;

/// DNS record for a container in the topology.
#[derive(Debug, Clone)]
pub struct DnsRecord {
    /// Container/service name
    pub name: String,
    /// IP address
    pub ip: String,
}

/// Generate /etc/hosts entries for all services in a topology.
///
/// Returns a hosts-format string that can be appended to each container's
/// /etc/hosts file for simple name resolution.
pub fn generate_hosts_entries(
    topology_name: &str,
    service_ips: &BTreeMap<String, String>,
) -> String {
    let mut entries = String::new();
    entries.push_str("# Nucleus topology DNS entries\n");

    for (service_name, ip) in service_ips {
        // Service is reachable by both short name and topology-qualified name
        entries.push_str(&format!(
            "{}\t{}\t{}-{}\n",
            ip, service_name, topology_name, service_name
        ));
    }

    entries
}

/// Write DNS entries into a container's /etc/hosts file.
///
/// Appends topology service entries to the existing hosts file.
pub fn inject_hosts(
    container_root: &Path,
    topology_name: &str,
    service_ips: &BTreeMap<String, String>,
) -> Result<()> {
    let hosts_path = container_root.join("etc/hosts");
    let entries = generate_hosts_entries(topology_name, service_ips);

    // Read existing content (may not exist yet)
    let existing = std::fs::read_to_string(&hosts_path).unwrap_or_default();

    // Append topology entries
    let new_content = format!(
        "{}\n127.0.0.1\tlocalhost\n::1\tlocalhost\n{}\n",
        existing.trim(),
        entries
    );

    std::fs::write(&hosts_path, new_content).map_err(|e| {
        NucleusError::NetworkError(format!(
            "Failed to write topology DNS entries to {:?}: {}",
            hosts_path, e
        ))
    })?;

    info!(
        "Injected {} DNS entries for topology '{}'",
        service_ips.len(),
        topology_name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_hosts_entries() {
        let mut ips = BTreeMap::new();
        ips.insert("postgres".to_string(), "10.42.0.2".to_string());
        ips.insert("web".to_string(), "10.42.0.3".to_string());

        let entries = generate_hosts_entries("myapp", &ips);
        assert!(entries.contains("10.42.0.2\tpostgres\tmyapp-postgres"));
        assert!(entries.contains("10.42.0.3\tweb\tmyapp-web"));
    }
}
