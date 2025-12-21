use clap::Parser;
use common::{ExitPolicy, NodeType};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Configuration for a relay node
#[derive(Debug, Clone, Parser)]
#[command(name = "relay-node")]
#[command(about = "Tor-like relay node", long_about = None)]
pub struct RelayConfig {
    /// Type of relay node (entry, middle, exit)
    #[arg(long, value_parser = parse_node_type)]
    pub node_type: NodeType,

    /// Port to bind to
    #[arg(long, default_value = "9001")]
    pub port: u16,

    /// Host address to bind to
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Directory service URL
    #[arg(long, default_value = "http://localhost:8080")]
    pub directory_url: String,

    /// Bandwidth capacity in bytes per second
    #[arg(long, default_value = "1048576")] // 1 MB/s default
    pub bandwidth: u64,

    /// Heartbeat interval in seconds
    #[arg(long, default_value = "60")]
    pub heartbeat_interval: u64,

    /// Allow exit to all ports (only for exit nodes)
    #[arg(long, default_value = "false")]
    pub exit_allow_all: bool,
}

impl RelayConfig {
    /// Get the socket address to bind to
    pub fn bind_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        let ip: IpAddr = self.host.parse()?;
        Ok(SocketAddr::new(ip, self.port))
    }

    /// Get the default exit policy for this node
    pub fn exit_policy(&self) -> Option<ExitPolicy> {
        if self.node_type == NodeType::Exit {
            Some(if self.exit_allow_all {
                ExitPolicy {
                    allowed_ports: vec![],
                    blocked_ports: vec![],
                    allowed_ips: vec![],
                    blocked_ips: vec![],
                }
            } else {
                ExitPolicy {
                    allowed_ports: vec![80, 443, 8080, 8443],
                    blocked_ports: vec![25, 465, 587],
                    allowed_ips: vec![],
                    blocked_ips: vec![
                        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
                        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
                    ],
                }
            })
        } else {
            None
        }
    }
}

/// Parse node type from string
fn parse_node_type(s: &str) -> Result<NodeType, String> {
    match s.to_lowercase().as_str() {
        "entry" => Ok(NodeType::Entry),
        "middle" => Ok(NodeType::Middle),
        "exit" => Ok(NodeType::Exit),
        _ => Err(format!(
            "Invalid node type: '{}'. Must be 'entry', 'middle', or 'exit'",
            s
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_node_type() {
        assert_eq!(parse_node_type("entry").ok(), Some(NodeType::Entry));
        assert_eq!(parse_node_type("middle").ok(), Some(NodeType::Middle));
        assert_eq!(parse_node_type("exit").ok(), Some(NodeType::Exit));
        assert_eq!(parse_node_type("ENTRY").ok(), Some(NodeType::Entry));
        assert!(parse_node_type("invalid").is_err());
    }

    #[test]
    fn test_bind_addr() {
        let config = RelayConfig {
            node_type: NodeType::Entry,
            port: 9001,
            host: "127.0.0.1".to_string(),
            directory_url: "http://localhost:8080".to_string(),
            bandwidth: 1048576,
            heartbeat_interval: 60,
            exit_allow_all: false,
        };

        let addr = config.bind_addr().ok();
        assert_eq!(
            addr,
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                9001
            ))
        );
    }

    #[test]
    fn test_exit_policy_for_exit_node() {
        let config = RelayConfig {
            node_type: NodeType::Exit,
            port: 9001,
            host: "127.0.0.1".to_string(),
            directory_url: "http://localhost:8080".to_string(),
            bandwidth: 1048576,
            heartbeat_interval: 60,
            exit_allow_all: false,
        };

        let policy = config.exit_policy();
        assert!(policy.is_some());
        let policy = policy.ok_or("no policy").ok();
        assert!(policy.is_some());
    }

    #[test]
    fn test_no_exit_policy_for_non_exit() {
        let config = RelayConfig {
            node_type: NodeType::Middle,
            port: 9001,
            host: "127.0.0.1".to_string(),
            directory_url: "http://localhost:8080".to_string(),
            bandwidth: 1048576,
            heartbeat_interval: 60,
            exit_allow_all: false,
        };

        assert!(config.exit_policy().is_none());
    }
}
