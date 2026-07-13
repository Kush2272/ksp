//! HKDF-SHA256 key derivation for KSP.
//!
//! Derives four separate session keys from the X25519 shared secret
//! as specified in RFC-0001 Section 8.3.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use ksp_core::constants::{
    HKDF_LABEL_CLIENT_WRITE_IV, HKDF_LABEL_CLIENT_WRITE_KEY, HKDF_LABEL_SERVER_WRITE_IV,
    HKDF_LABEL_SERVER_WRITE_KEY,
};
use ksp_core::error::KspError;

type HmacSha256 = Hmac<Sha256>;

/// Compute HMAC-SHA256 of the handshake transcript for HandshakeFinish.
pub fn compute_finished_mac(key: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is valid");
    mac.update(transcript);
    let result = mac.finalize();
    let mut verify_data = [0u8; 32];
    verify_data.copy_from_slice(&result.into_bytes());
    verify_data
}

/// Session keys derived from the X25519 shared secret via HKDF-SHA256.
///
/// Four separate keys provide domain separation:
/// - `client_write_key`: Used by the client to encrypt, server to decrypt
/// - `server_write_key`: Used by the server to encrypt, client to decrypt
/// - `client_write_iv`: Base IV for client→server nonce construction
/// - `server_write_iv`: Base IV for server→client nonce construction
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct DerivedKeys {
    /// AES-256 / ChaCha20 key for client→server direction (32 bytes)
    pub client_write_key: [u8; 32],
    /// AES-256 / ChaCha20 key for server→client direction (32 bytes)
    pub server_write_key: [u8; 32],
    /// Base IV for client→server nonce construction (12 bytes)
    pub client_write_iv: [u8; 12],
    /// Base IV for server→client nonce construction (12 bytes)
    pub server_write_iv: [u8; 12],
}

impl std::fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("client_write_key", &"<redacted>")
            .field("server_write_key", &"<redacted>")
            .field("client_write_iv", &"<redacted>")
            .field("server_write_iv", &"<redacted>")
            .finish()
    }
}

/// Derive session keys from the shared secret and random values.
///
/// As specified in RFC-0001 Section 8.3:
/// ```text
/// salt = client_random || server_random  (64 bytes)
/// PRK = HKDF-Extract(salt, shared_secret)
/// client_write_key = HKDF-Expand(PRK, "ksp1 client write key", 32)
/// server_write_key = HKDF-Expand(PRK, "ksp1 server write key", 32)
/// client_write_iv  = HKDF-Expand(PRK, "ksp1 client write iv",  12)
/// server_write_iv  = HKDF-Expand(PRK, "ksp1 server write iv",  12)
/// ```
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<DerivedKeys, KspError> {
    // Salt = client_random || server_random
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_random);
    salt[32..].copy_from_slice(server_random);

    // Extract: PRK = HKDF-Extract(salt, shared_secret)
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);

    // Expand: derive each key
    let mut client_write_key = [0u8; 32];
    hk.expand(HKDF_LABEL_CLIENT_WRITE_KEY, &mut client_write_key)
        .map_err(|e| KspError::CryptoError(format!("HKDF expand failed: {}", e)))?;

    let mut server_write_key = [0u8; 32];
    hk.expand(HKDF_LABEL_SERVER_WRITE_KEY, &mut server_write_key)
        .map_err(|e| KspError::CryptoError(format!("HKDF expand failed: {}", e)))?;

    let mut client_write_iv = [0u8; 12];
    hk.expand(HKDF_LABEL_CLIENT_WRITE_IV, &mut client_write_iv)
        .map_err(|e| KspError::CryptoError(format!("HKDF expand failed: {}", e)))?;

    let mut server_write_iv = [0u8; 12];
    hk.expand(HKDF_LABEL_SERVER_WRITE_IV, &mut server_write_iv)
        .map_err(|e| KspError::CryptoError(format!("HKDF expand failed: {}", e)))?;

    // Zeroize the salt
    salt.zeroize();

    Ok(DerivedKeys {
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_keys() {
        let shared_secret = [0x42u8; 32];
        let client_random = [0xAA; 32];
        let server_random = [0xBB; 32];

        let keys = derive_session_keys(&shared_secret, &client_random, &server_random).unwrap();

        // Keys should be non-zero
        assert_ne!(keys.client_write_key, [0u8; 32]);
        assert_ne!(keys.server_write_key, [0u8; 32]);
        assert_ne!(keys.client_write_iv, [0u8; 12]);
        assert_ne!(keys.server_write_iv, [0u8; 12]);

        // Client and server keys should differ (different labels)
        assert_ne!(keys.client_write_key, keys.server_write_key);
        assert_ne!(keys.client_write_iv, keys.server_write_iv);
    }

    #[test]
    fn test_deterministic_derivation() {
        let shared_secret = [0x42u8; 32];
        let client_random = [0xAA; 32];
        let server_random = [0xBB; 32];

        let keys1 = derive_session_keys(&shared_secret, &client_random, &server_random).unwrap();
        let keys2 = derive_session_keys(&shared_secret, &client_random, &server_random).unwrap();

        // Same inputs should produce same outputs
        assert_eq!(keys1.client_write_key, keys2.client_write_key);
        assert_eq!(keys1.server_write_key, keys2.server_write_key);
    }

    #[test]
    fn test_different_randoms_different_keys() {
        let shared_secret = [0x42u8; 32];
        let client_random = [0xAA; 32];
        let server_random1 = [0xBB; 32];
        let server_random2 = [0xCC; 32];

        let keys1 = derive_session_keys(&shared_secret, &client_random, &server_random1).unwrap();
        let keys2 = derive_session_keys(&shared_secret, &client_random, &server_random2).unwrap();

        assert_ne!(keys1.client_write_key, keys2.client_write_key);
    }
}
