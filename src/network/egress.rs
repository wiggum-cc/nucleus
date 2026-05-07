use super::{netns, BridgeNetwork, EgressPolicy};
use crate::error::{NucleusError, Result};
use tracing::{debug, info};

pub(crate) fn apply_egress_policy(
    pid: u32,
    dns: &[String],
    policy: &EgressPolicy,
    join_userns: bool,
) -> Result<()> {
    for cidr in &policy.allowed_cidrs {
        crate::network::config::validate_egress_cidr(cidr)
            .map_err(|e| NucleusError::NetworkError(format!("Invalid egress CIDR: {}", e)))?;
    }

    let ipt = BridgeNetwork::resolve_bin("iptables")?;
    let exec = |args: &[&str]| {
        if join_userns {
            netns::exec_in_user_netns(pid, &ipt, "iptables", args)
        } else {
            netns::exec_in_netns(pid, &ipt, "iptables", args)
        }
    };

    exec(&["-P", "OUTPUT", "DROP"])?;
    exec(&["-F", "OUTPUT"])?;
    exec(&["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])?;
    exec(&[
        "-A",
        "OUTPUT",
        "-m",
        "conntrack",
        "--ctstate",
        "ESTABLISHED,RELATED",
        "-j",
        "ACCEPT",
    ])?;

    if policy.allow_dns {
        for dns in dns {
            exec(&[
                "-A", "OUTPUT", "-p", "udp", "-d", dns, "--dport", "53", "-j", "ACCEPT",
            ])?;
            exec(&[
                "-A", "OUTPUT", "-p", "tcp", "-d", dns, "--dport", "53", "-j", "ACCEPT",
            ])?;
        }
    }

    for cidr in &policy.allowed_cidrs {
        if policy.allowed_tcp_ports.is_empty() && policy.allowed_udp_ports.is_empty() {
            exec(&["-A", "OUTPUT", "-d", cidr, "-j", "ACCEPT"])?;
        } else {
            for port in &policy.allowed_tcp_ports {
                let port_s = port.to_string();
                exec(&[
                    "-A", "OUTPUT", "-p", "tcp", "-d", cidr, "--dport", &port_s, "-j", "ACCEPT",
                ])?;
            }
            for port in &policy.allowed_udp_ports {
                let port_s = port.to_string();
                exec(&[
                    "-A", "OUTPUT", "-p", "udp", "-d", cidr, "--dport", &port_s, "-j", "ACCEPT",
                ])?;
            }
        }
    }

    if policy.log_denied {
        exec(&[
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
        ])?;
    }

    exec(&["-P", "OUTPUT", "DROP"])?;

    info!(
        "Egress policy applied: {} allowed CIDRs",
        policy.allowed_cidrs.len()
    );
    debug!("Egress policy details: {:?}", policy);

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_egress_policy_preserves_iptables_applet_argv0() {
        let source = include_str!("egress.rs");

        assert!(
            source.contains("exec_in_user_netns(pid, &ipt, \"iptables\", args)"),
            "rootless egress policy must preserve iptables argv[0] inside the target namespaces"
        );
        assert!(
            source.contains("exec_in_netns(pid, &ipt, \"iptables\", args)"),
            "privileged egress policy must preserve iptables argv[0] inside the target netns"
        );
    }
}
