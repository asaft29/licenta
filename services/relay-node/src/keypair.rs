use common::PublicKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tor_llcrypto::pk::curve25519::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

/// A cryptographic key pair for a relay node using Tor's official curve25519 implementation
/// Uses tor-llcrypto from the Tor Project's arti implementation
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public: PublicKey,
    secret_bytes: [u8; 32],
}

impl KeyPair {
    /// Generate a new random keypair using X25519
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public_x25519 = X25519PublicKey::from(&secret);

        // Convert X25519 public key to our PublicKey format
        let public = PublicKey {
            bytes: *public_x25519.as_bytes(),
        };

        // Store the secret bytes for later use
        let secret_bytes = secret.to_bytes();

        Self {
            public,
            secret_bytes,
        }
    }

    /// Create a keypair from existing secret key bytes
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public_x25519 = X25519PublicKey::from(&secret);

        let public = PublicKey {
            bytes: *public_x25519.as_bytes(),
        };

        Self {
            public,
            secret_bytes: bytes,
        }
    }

    /// Get the public key (safe to share)
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Perform Diffie-Hellman key exchange with a client's ephemeral public key
    /// Returns the shared secret that can be used to derive session keys
    pub fn diffie_hellman(&self, their_public: &[u8; 32]) -> [u8; 32] {
        let their_public_key = X25519PublicKey::from(*their_public);

        // Recreate static secret from bytes
        let secret = StaticSecret::from(self.secret_bytes);
        let shared_secret = secret.diffie_hellman(&their_public_key);

        // Hash the shared secret to derive a uniform 32-byte key
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);

        key
    }
}

/// This struct is currently only used in tests, but will be used by the Tor client
/// Relay nodes use the persistent `KeyPair` struct instead.
#[allow(dead_code)]
pub struct EphemeralKeyPair {
    pub public: PublicKey,
    secret: EphemeralSecret,
}

impl EphemeralKeyPair {
    /// Generate a new ephemeral keypair (should be used once and discarded)
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_x25519 = X25519PublicKey::from(&secret);

        let public = PublicKey {
            bytes: *public_x25519.as_bytes(),
        };

        Self { public, secret }
    }

    /// Perform DH exchange with a relay's static public key
    pub fn diffie_hellman(self, their_public: &[u8; 32]) -> [u8; 32] {
        let their_public_key = X25519PublicKey::from(*their_public);
        let shared_secret = self.secret.diffie_hellman(&their_public_key);

        // Hash the shared secret to derive a uniform 32-byte key
        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);

        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diffie_hellman_exchange() {
        // Relay generates static keypair
        let relay_kp = KeyPair::generate();

        // Client generates ephemeral keypair
        let client_kp = EphemeralKeyPair::generate();

        // Client sends their public key to relay
        let client_public = client_kp.public.bytes;

        // Relay computes shared secret
        let relay_shared = relay_kp.diffie_hellman(&client_public);

        // Client computes shared secret
        let client_shared = client_kp.diffie_hellman(&relay_kp.public.bytes);

        // Both should derive the same shared secret
        assert_eq!(relay_shared, client_shared);
    }

    #[test]
    fn test_ephemeral_keypair_generation() {
        let e1 = EphemeralKeyPair::generate();
        let e2 = EphemeralKeyPair::generate();

        // Different ephemeral keys each time
        assert_ne!(e1.public.bytes, e2.public.bytes);
    }

    #[test]
    fn test_public_key_deterministic_from_secret() {
        let secret_bytes = [99u8; 32];

        let k1 = KeyPair::from_secret_bytes(secret_bytes);
        let k2 = KeyPair::from_secret_bytes(secret_bytes);

        // Same secret should produce same public key
        assert_eq!(k1.public.bytes, k2.public.bytes);
    }
}
