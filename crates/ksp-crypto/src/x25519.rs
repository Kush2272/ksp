//! X25519 Elliptic Curve Diffie-Hellman key exchange.
//!
//! Provides ephemeral keypair generation and shared secret computation
//! for forward secrecy as specified in RFC-0001 Section 8.2.
//!
//! Each session generates a fresh ephemeral keypair. Private keys are
//! zeroized after computing the shared secret.

use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroize;

use ksp_core::X25519_PUBLIC_KEY_SIZE;
use ksp_core::error::KspError;

/// An ephemeral X25519 keypair for key exchange.
///
/// The private key is consumed (moved) when computing the shared secret,
/// ensuring it cannot be reused.
pub struct EphemeralKeypair {
    /// The ephemeral private key. Consumed on shared secret computation.
    secret: EphemeralSecret,
    /// The corresponding public key, sent to the peer during handshake.
    pub public_key: PublicKey,
}

impl std::fmt::Debug for EphemeralKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EphemeralKeypair")
            .field("public_key", &self.public_key)
            .field("secret", &"<redacted private key>")
            .finish()
    }
}

impl EphemeralKeypair {
    /// Generate a new ephemeral X25519 keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret);
        Self { secret, public_key }
    }

    /// Get the public key bytes for transmission during handshake.
    pub fn public_key_bytes(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        self.public_key.to_bytes()
    }

    /// Compute the shared secret with the peer's public key.
    ///
    /// **Consumes** the ephemeral keypair — the private key is destroyed
    /// after this call, ensuring forward secrecy.
    pub fn diffie_hellman(
        self,
        peer_public_key: &[u8; X25519_PUBLIC_KEY_SIZE],
    ) -> Result<SharedSecretBytes, KspError> {
        let peer_pk = PublicKey::from(*peer_public_key);
        let shared = self.secret.diffie_hellman(&peer_pk);
        let bytes = shared.to_bytes();
        if bytes == [0u8; 32] {
            return Err(KspError::CryptoError(
                "weak shared secret (all-zero output)".into(),
            ));
        }
        Ok(SharedSecretBytes { bytes })
    }
}

/// The shared secret derived from X25519 key exchange.
///
/// This is used as input to HKDF for deriving session keys.
/// Implements `Zeroize` to securely erase from memory when dropped.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SharedSecretBytes {
    bytes: [u8; 32],
}

impl SharedSecretBytes {
    /// Get the raw shared secret bytes (for HKDF input).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Convenience function: compute a shared secret from our secret and their public key.
pub fn compute_shared_secret(
    our_keypair: EphemeralKeypair,
    their_public_key: &[u8; X25519_PUBLIC_KEY_SIZE],
) -> Result<SharedSecretBytes, KspError> {
    our_keypair.diffie_hellman(their_public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = EphemeralKeypair::generate();
        let pub_bytes = kp.public_key_bytes();
        // Public key should not be all zeros
        assert_ne!(pub_bytes, [0u8; 32]);
    }

    #[test]
    fn test_shared_secret_agreement() {
        // Simulate two endpoints
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();

        let alice_pub = alice.public_key_bytes();
        let bob_pub = bob.public_key_bytes();

        // Both compute the same shared secret
        let alice_secret = alice.diffie_hellman(&bob_pub).unwrap();
        let bob_secret = bob.diffie_hellman(&alice_pub).unwrap();

        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    }

    #[test]
    fn test_different_keypairs_different_secrets() {
        let alice = EphemeralKeypair::generate();
        let bob = EphemeralKeypair::generate();
        let charlie = EphemeralKeypair::generate();

        let bob_pub = bob.public_key_bytes();
        let charlie_pub = charlie.public_key_bytes();

        let secret_ab = alice.diffie_hellman(&bob_pub).unwrap();
        let secret_bc = bob.diffie_hellman(&charlie_pub).unwrap();

        // Different key pairs produce different secrets
        assert_ne!(secret_ab.as_bytes(), secret_bc.as_bytes());
    }
}
