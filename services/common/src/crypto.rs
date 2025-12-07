use serde::{Deserialize, Serialize};

/// Session key for encrypted communication between nodes (from class diagram lines 257-260)
///
/// Contains separate keys for forward (client to server) and backward (server to client) communication
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKey {
    pub forward: [u8; 16],  // AES-128 key for forward direction
    pub backward: [u8; 16], // AES-128 key for backward direction
}

impl SessionKey {
    /// Create a new session key from forward and backward keys
    pub fn new(forward: [u8; 16], backward: [u8; 16]) -> Self {
        Self { forward, backward }
    }

    /// Create from a single shared key (derive forward and backward)
    /// This is a simplified approach - in production, use proper KDF
    pub fn from_shared(shared: &[u8; 32]) -> Self {
        let mut forward = [0u8; 16];
        let mut backward = [0u8; 16];

        forward.copy_from_slice(&shared[0..16]);
        backward.copy_from_slice(&shared[16..32]);

        Self { forward, backward }
    }

    /// Convert to 32-byte array (for storage/transmission)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..16].copy_from_slice(&self.forward);
        bytes[16..32].copy_from_slice(&self.backward);
        bytes
    }

    /// Create from 32-byte array
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut forward = [0u8; 16];
        let mut backward = [0u8; 16];

        forward.copy_from_slice(&bytes[0..16]);
        backward.copy_from_slice(&bytes[16..32]);

        Self { forward, backward }
    }

    /// Create a zero key (for testing)
    pub fn zero() -> Self {
        Self {
            forward: [0u8; 16],
            backward: [0u8; 16],
        }
    }
}

impl Default for SessionKey {
    fn default() -> Self {
        Self::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_key_creation() {
        let forward = [1u8; 16];
        let backward = [2u8; 16];

        let key = SessionKey::new(forward, backward);

        assert_eq!(key.forward, forward);
        assert_eq!(key.backward, backward);
    }

    #[test]
    fn test_session_key_from_shared() {
        let shared = [0xAB; 32];
        let key = SessionKey::from_shared(&shared);

        assert_eq!(&key.forward, &shared[0..16]);
        assert_eq!(&key.backward, &shared[16..32]);
    }

    #[test]
    fn test_session_key_to_from_bytes() {
        let key = SessionKey::new([1u8; 16], [2u8; 16]);
        let bytes = key.to_bytes();
        let key2 = SessionKey::from_bytes(&bytes);

        assert_eq!(key, key2);
    }

    #[test]
    fn test_session_key_zero() {
        let key = SessionKey::zero();
        assert_eq!(key.forward, [0u8; 16]);
        assert_eq!(key.backward, [0u8; 16]);
    }

    #[test]
    fn test_session_key_default() {
        let key = SessionKey::default();
        assert_eq!(key, SessionKey::zero());
    }
}
