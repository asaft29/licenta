use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// Node type in the Tor network (from class diagram lines 284-288)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
pub enum NodeType {
    Entry,
    Middle,
    Exit,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::Entry => write!(f, "entry"),
            NodeType::Middle => write!(f, "middle"),
            NodeType::Exit => write!(f, "exit"),
        }
    }
}

impl std::str::FromStr for NodeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "entry" => Ok(NodeType::Entry),
            "middle" => Ok(NodeType::Middle),
            "exit" => Ok(NodeType::Exit),
            _ => Err(format!("Invalid node type: {}", s)),
        }
    }
}

/// Public key for a relay node (from class diagram lines 262-264)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
pub struct PublicKey {
    pub bytes: [u8; 32],
}

impl PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Create from hex string for testing/debugging
    ///
    /// # Errors
    /// Returns an error if hex string is not 64 characters or contains invalid hex digits
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        if hex.len() != 64 {
            return Err("Hex string must be 64 characters (32 bytes)".to_string());
        }

        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let hex_slice = hex
                .get(i * 2..i * 2 + 2)
                .ok_or_else(|| format!("Invalid hex slice at position {}", i))?;
            *byte = u8::from_str_radix(hex_slice, 16).map_err(|e| format!("Invalid hex: {}", e))?;
        }

        Ok(Self { bytes })
    }

    /// Convert to hex string for display/debugging
    pub fn to_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.to_hex()[..16]) // Show first 16 chars
    }
}

/// Exit policy for exit nodes
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ExitPolicy {
    pub allowed_ports: Vec<u16>,
    pub blocked_ports: Vec<u16>,
    #[schema(value_type = Vec<String>)]
    pub allowed_ips: Vec<IpAddr>,
    #[schema(value_type = Vec<String>)]
    pub blocked_ips: Vec<IpAddr>,
}

impl ExitPolicy {
    /// Default policy: Allow common web ports
    pub fn default_policy() -> Self {
        Self {
            allowed_ports: vec![80, 443, 8080, 8443],
            blocked_ports: vec![25, 587, 465], // Block email ports
            allowed_ips: vec![],
            blocked_ips: vec![],
        }
    }

    /// Allow all ports (permissive policy)
    pub fn allow_all() -> Self {
        Self {
            allowed_ports: vec![],
            blocked_ports: vec![],
            allowed_ips: vec![],
            blocked_ips: vec![],
        }
    }

    /// Check if connection to destination is allowed
    pub fn allows(&self, addr: &SocketAddr) -> bool {
        let port = addr.port();
        let ip = addr.ip();

        if self.blocked_ips.contains(&ip) {
            return false;
        }

        if !self.allowed_ips.is_empty() && !self.allowed_ips.contains(&ip) {
            return false;
        }

        if self.blocked_ports.contains(&port) {
            return false;
        }

        if self.allowed_ports.is_empty() {
            true
        } else {
            self.allowed_ports.contains(&port)
        }
    }
}

/// Node descriptor containing all information about a relay node
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct NodeDescriptor {
    // Identity
    pub node_id: String,
    pub node_type: NodeType,

    // Network
    #[schema(value_type = String, example = "127.0.0.1:9001")]
    pub address: SocketAddr,
    pub public_key: PublicKey,

    // Capabilities
    pub bandwidth: u64, // bytes per second
    pub exit_policy: Option<ExitPolicy>,
}

impl NodeDescriptor {
    pub fn new(
        node_id: String,
        node_type: NodeType,
        address: SocketAddr,
        public_key: PublicKey,
        bandwidth: u64,
        exit_policy: Option<ExitPolicy>,
    ) -> Self {
        Self {
            node_id,
            node_type,
            address,
            public_key,
            bandwidth,
            exit_policy,
        }
    }

    /// Serialize to JSON
    ///
    /// # Errors
    /// Returns a serde_json error if serialization fails
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON
    ///
    /// # Errors
    /// Returns a serde_json error if JSON is invalid or doesn't match the schema
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_type_display() {
        assert_eq!(NodeType::Entry.to_string(), "entry");
        assert_eq!(NodeType::Middle.to_string(), "middle");
        assert_eq!(NodeType::Exit.to_string(), "exit");
    }

    #[test]
    fn test_node_type_from_str() {
        use std::str::FromStr;
        assert_eq!(NodeType::from_str("entry").unwrap(), NodeType::Entry);
        assert_eq!(NodeType::from_str("MIDDLE").unwrap(), NodeType::Middle);
        assert!(NodeType::from_str("invalid").is_err());
    }

    #[test]
    fn test_exit_policy_allows() {
        let policy = ExitPolicy::default_policy();

        // Should allow HTTP
        let http_addr = "93.184.216.34:80".parse().unwrap();
        assert!(policy.allows(&http_addr));

        // Should allow HTTPS
        let https_addr = "93.184.216.34:443".parse().unwrap();
        assert!(policy.allows(&https_addr));

        // Should block SMTP
        let smtp_addr = "93.184.216.34:25".parse().unwrap();
        assert!(!policy.allows(&smtp_addr));
    }

    #[test]
    fn test_exit_policy_ip_filtering() {
        // Test IP-based filtering
        let mut policy = ExitPolicy::default_policy();
        let blocked_ip: IpAddr = "192.168.1.1".parse().unwrap();
        policy.blocked_ips.push(blocked_ip);

        let blocked_addr = "192.168.1.1:80".parse().unwrap();
        assert!(!policy.allows(&blocked_addr));

        let allowed_addr = "93.184.216.34:80".parse().unwrap();
        assert!(policy.allows(&allowed_addr));
    }

    #[test]
    fn test_exit_policy_allowed_ips() {
        // Test allowlist - if list is non-empty, only those IPs allowed
        let mut policy = ExitPolicy::default_policy();
        let allowed_ip: IpAddr = "1.1.1.1".parse().unwrap();
        policy.allowed_ips.push(allowed_ip);

        let allowed_addr = "1.1.1.1:443".parse().unwrap();
        assert!(policy.allows(&allowed_addr));

        let disallowed_addr = "8.8.8.8:443".parse().unwrap();
        assert!(!policy.allows(&disallowed_addr));
    }

    #[test]
    fn test_public_key_hex() {
        let bytes = [1u8; 32];
        let pk = PublicKey::new(bytes);
        let hex = pk.to_hex();
        assert_eq!(hex.len(), 64);

        let pk2 = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn test_node_descriptor_json() {
        let pubkey = PublicKey::new([0u8; 32]);
        let addr = "127.0.0.1:9001".parse().unwrap();

        let node = NodeDescriptor::new(
            "node-1".to_string(),
            NodeType::Entry,
            addr,
            pubkey,
            1_000_000,
            None,
        );

        let json = node.to_json().unwrap();
        let node2 = NodeDescriptor::from_json(&json).unwrap();

        assert_eq!(node.node_id, node2.node_id);
        assert_eq!(node.node_type, node2.node_type);
    }
}
