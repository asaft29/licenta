use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::anyhow;
use ctr::Ctr128BE;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
type Aes128Ctr = Ctr128BE<Aes128>;

/// Session key for encrypted communication between nodes
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

/// Encrypt data using AES-128 in CTR mode
/// Returns encrypted data (same length as input)
pub fn aes_encrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    // 1. Generate a random 16-byte IV
    let mut iv = [0u8; 16];
    rand::rng().fill(&mut iv);

    // 2. Initialize cipher with the Key and random IV
    let mut cipher = Aes128Ctr::new(key.into(), &iv.into());

    // 3. Encrypt the data
    let mut ciphertext = data.to_vec();
    cipher.apply_keystream(&mut ciphertext);

    // 4. Prepend the IV to the output
    // Result format: [IV ... IV | Ciphertext ... Ciphertext]
    let mut output = Vec::with_capacity(16 + ciphertext.len());
    output.extend_from_slice(&iv);
    output.extend_from_slice(&ciphertext);

    output
}

/// Decrypt data using AES-128 in CTR mode
/// Returns decrypted data (same length as input)
/// Note: CTR mode encryption and decryption are the same operation
pub fn aes_decrypt(data: &[u8], key: &[u8; 16]) -> anyhow::Result<Vec<u8>> {
    // 1. Validate length (must have at least the IV)
    if data.len() < 16 {
        return Err(anyhow!(
            "Invalid ciphertext: length {} is too short (min 16)",
            data.len()
        ));
    }

    // 2. Extract the IV (first 16 bytes)
    let iv_slice = &data[0..16];
    let ciphertext = &data[16..];

    // 3. Initialize cipher with the Key and EXTRACTED IV
    let mut cipher = Aes128Ctr::new(key.into(), iv_slice.into());

    // 4. Decrypt (CTR decryption is the same operation as encryption)
    let mut plaintext = ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

/// Derive session key from shared secret using SHA-256
/// Takes a 32-byte shared secret and produces forward/backward keys
pub fn derive_session_key(shared_secret: &[u8; 32]) -> SessionKey {
    SessionKey::from_shared(shared_secret)
}

/// Hash data using SHA-256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
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

    #[test]
    fn test_aes_encrypt_decrypt() -> anyhow::Result<()> {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext = b"Hello, World!";

        let ciphertext = aes_encrypt(plaintext, &key);
        assert_ne!(ciphertext, plaintext);

        let decrypted = aes_decrypt(&ciphertext, &key)?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn test_aes_ctr_symmetry() -> anyhow::Result<()> {
        let key = [42u8; 16];
        let data = b"This is a test message for AES-128 CTR mode";

        // Encrypt
        let encrypted = aes_encrypt(data, &key);

        // Decrypt (should be same as encrypt in CTR mode)
        let decrypted = aes_decrypt(&encrypted, &key)?;

        assert_eq!(&decrypted, data);
        Ok(())
    }

    #[test]
    fn test_derive_session_key() {
        let shared_secret = [0xAB; 32];
        let session_key = derive_session_key(&shared_secret);

        // Should derive consistent keys
        assert_eq!(
            session_key.forward,
            SessionKey::from_shared(&shared_secret).forward
        );
        assert_eq!(
            session_key.backward,
            SessionKey::from_shared(&shared_secret).backward
        );
    }

    #[test]
    fn test_sha256() {
        let data = b"test data";
        let hash1 = sha256(data);
        let hash2 = sha256(data);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Different input should produce different hash
        let hash3 = sha256(b"different data");
        assert_ne!(hash1, hash3);
    }
}
