//! AEAD encryption and decryption for KSP.
//!
//! Supports both AES-256-GCM and ChaCha20-Poly1305 as specified in RFC-0001 Section 8.
//! The cipher suite is negotiated during the handshake. Both provide:
//! - 256-bit keys
//! - 96-bit (12-byte) nonces
//! - 128-bit (16-byte) authentication tags
//! - Additional Authenticated Data (AAD) = packet header

use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesNonce, aead::Aead};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit as ChaChaKeyInit, Nonce as ChaChaPolNonce, aead::Aead as ChaChaAead,
};

use ksp_core::capability::CipherSuite;
use ksp_core::constants::{AUTH_TAG_SIZE, NONCE_SIZE};
use ksp_core::error::KspError;

/// Trait abstracting over AEAD cipher implementations.
///
/// Both AES-256-GCM and ChaCha20-Poly1305 implement this interface.
pub trait AeadCipher: Send + Sync {
    /// Encrypt plaintext with the given nonce and AAD.
    ///
    /// Returns `(ciphertext, auth_tag)` where the tag is 16 bytes.
    fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; AUTH_TAG_SIZE]), KspError>;

    /// Decrypt ciphertext with the given nonce, AAD, and auth tag.
    ///
    /// Returns plaintext on success, or a deliberately vague error on failure
    /// (to prevent oracle attacks as per RFC-0001 Section 8.6).
    fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        auth_tag: &[u8; AUTH_TAG_SIZE],
        aad: &[u8],
    ) -> Result<Vec<u8>, KspError>;

    /// The cipher suite this implementation represents.
    fn cipher_suite(&self) -> CipherSuite;
}

/// AES-256-GCM cipher implementation.
///
/// Preferred when hardware AES-NI is available (most modern x86_64 CPUs).
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

impl Aes256GcmCipher {
    /// Create a new AES-256-GCM cipher with the given 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256-GCM key must be 32 bytes");
        Self { cipher }
    }
}

impl AeadCipher for Aes256GcmCipher {
    fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; AUTH_TAG_SIZE]), KspError> {
        let aes_nonce = AesNonce::from_slice(nonce);

        // aes-gcm concatenates ciphertext + tag in the output
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        let combined = self
            .cipher
            .encrypt(aes_nonce, payload)
            .map_err(|_| KspError::CryptoError("AES-256-GCM encryption failed".into()))?;

        // Split: last 16 bytes are the tag
        let tag_start = combined.len() - AUTH_TAG_SIZE;
        let ciphertext = combined[..tag_start].to_vec();
        let mut tag = [0u8; AUTH_TAG_SIZE];
        tag.copy_from_slice(&combined[tag_start..]);

        Ok((ciphertext, tag))
    }

    fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        auth_tag: &[u8; AUTH_TAG_SIZE],
        aad: &[u8],
    ) -> Result<Vec<u8>, KspError> {
        let aes_nonce = AesNonce::from_slice(nonce);

        // Reconstruct the combined ciphertext + tag
        let mut combined = Vec::with_capacity(ciphertext.len() + AUTH_TAG_SIZE);
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(auth_tag);

        let payload = aes_gcm::aead::Payload {
            msg: &combined,
            aad,
        };
        self.cipher
            .decrypt(aes_nonce, payload)
            // Deliberately vague error — prevents oracle attacks (RFC-0001 §8.6)
            .map_err(|_| KspError::AuthenticationFailed)
    }

    fn cipher_suite(&self) -> CipherSuite {
        CipherSuite::Aes256Gcm
    }
}

/// ChaCha20-Poly1305 cipher implementation.
///
/// Preferred on platforms without hardware AES acceleration (e.g., ARM without ARMv8 Crypto).
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create a new ChaCha20-Poly1305 cipher with the given 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key).expect("ChaCha20 key must be 32 bytes");
        Self { cipher }
    }
}

impl AeadCipher for ChaCha20Poly1305Cipher {
    fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; AUTH_TAG_SIZE]), KspError> {
        let chacha_nonce = ChaChaPolNonce::from_slice(nonce);

        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        };
        let combined = self
            .cipher
            .encrypt(chacha_nonce, payload)
            .map_err(|_| KspError::CryptoError("ChaCha20-Poly1305 encryption failed".into()))?;

        let tag_start = combined.len() - AUTH_TAG_SIZE;
        let ciphertext = combined[..tag_start].to_vec();
        let mut tag = [0u8; AUTH_TAG_SIZE];
        tag.copy_from_slice(&combined[tag_start..]);

        Ok((ciphertext, tag))
    }

    fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        auth_tag: &[u8; AUTH_TAG_SIZE],
        aad: &[u8],
    ) -> Result<Vec<u8>, KspError> {
        let chacha_nonce = ChaChaPolNonce::from_slice(nonce);

        let mut combined = Vec::with_capacity(ciphertext.len() + AUTH_TAG_SIZE);
        combined.extend_from_slice(ciphertext);
        combined.extend_from_slice(auth_tag);

        let payload = chacha20poly1305::aead::Payload {
            msg: &combined,
            aad,
        };
        self.cipher
            .decrypt(chacha_nonce, payload)
            .map_err(|_| KspError::AuthenticationFailed)
    }

    fn cipher_suite(&self) -> CipherSuite {
        CipherSuite::ChaCha20Poly1305
    }
}

/// Create an AEAD cipher from a cipher suite and key.
pub fn create_cipher(suite: CipherSuite, key: &[u8; 32]) -> Box<dyn AeadCipher> {
    match suite {
        CipherSuite::Aes256Gcm => Box::new(Aes256GcmCipher::new(key)),
        CipherSuite::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Cipher::new(key)),
    }
}

/// Convenience function: encrypt plaintext using the specified cipher suite.
pub fn encrypt(
    suite: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; AUTH_TAG_SIZE]), KspError> {
    let cipher = create_cipher(suite, key);
    cipher.encrypt(nonce, plaintext, aad)
}

/// Convenience function: decrypt ciphertext using the specified cipher suite.
pub fn decrypt(
    suite: CipherSuite,
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    auth_tag: &[u8; AUTH_TAG_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>, KspError> {
    let cipher = create_cipher(suite, key);
    cipher.decrypt(nonce, ciphertext, auth_tag, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    fn test_nonce() -> [u8; NONCE_SIZE] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ]
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"Hello, KSP!";
        let aad = b"header data";

        let (ciphertext, tag) =
            encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();

        // Ciphertext should differ from plaintext
        assert_ne!(&ciphertext, &plaintext[..]);

        let decrypted =
            decrypt(CipherSuite::Aes256Gcm, &key, &nonce, &ciphertext, &tag, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"Hello, KSP!";
        let aad = b"header data";

        let (ciphertext, tag) =
            encrypt(CipherSuite::ChaCha20Poly1305, &key, &nonce, plaintext, aad).unwrap();

        let decrypted = decrypt(
            CipherSuite::ChaCha20Poly1305,
            &key,
            &nonce,
            &ciphertext,
            &tag,
            aad,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"secret data";
        let aad = b"header";

        let (mut ciphertext, tag) =
            encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();

        // Tamper with ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = decrypt(CipherSuite::Aes256Gcm, &key, &nonce, &ciphertext, &tag, aad);
        assert!(matches!(result, Err(KspError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampered_aad_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"secret data";
        let aad = b"original header";

        let (ciphertext, tag) =
            encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();

        // Try to decrypt with different AAD
        let result = decrypt(
            CipherSuite::Aes256Gcm,
            &key,
            &nonce,
            &ciphertext,
            &tag,
            b"tampered header",
        );
        assert!(matches!(result, Err(KspError::AuthenticationFailed)));
    }

    #[test]
    fn test_tampered_tag_fails() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"secret data";
        let aad = b"header";

        let (ciphertext, mut tag) =
            encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();

        // Tamper with tag
        tag[0] ^= 0xFF;

        let result = decrypt(CipherSuite::Aes256Gcm, &key, &nonce, &ciphertext, &tag, aad);
        assert!(matches!(result, Err(KspError::AuthenticationFailed)));
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] ^= 0xFF;
        let nonce = test_nonce();
        let plaintext = b"secret data";
        let aad = b"header";

        let (ciphertext, tag) =
            encrypt(CipherSuite::Aes256Gcm, &key1, &nonce, plaintext, aad).unwrap();

        let result = decrypt(
            CipherSuite::Aes256Gcm,
            &key2,
            &nonce,
            &ciphertext,
            &tag,
            aad,
        );
        assert!(matches!(result, Err(KspError::AuthenticationFailed)));
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = test_key();
        let nonce1 = test_nonce();
        let mut nonce2 = test_nonce();
        nonce2[0] ^= 0xFF;
        let plaintext = b"secret data";
        let aad = b"header";

        let (ciphertext, tag) =
            encrypt(CipherSuite::Aes256Gcm, &key, &nonce1, plaintext, aad).unwrap();

        let result = decrypt(
            CipherSuite::Aes256Gcm,
            &key,
            &nonce2,
            &ciphertext,
            &tag,
            aad,
        );
        assert!(matches!(result, Err(KspError::AuthenticationFailed)));
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let nonce = test_nonce();
        let aad = b"header";

        let (ciphertext, tag) = encrypt(CipherSuite::Aes256Gcm, &key, &nonce, b"", aad).unwrap();

        assert!(ciphertext.is_empty());

        let decrypted =
            decrypt(CipherSuite::Aes256Gcm, &key, &nonce, &ciphertext, &tag, aad).unwrap();

        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_cross_cipher_incompatible() {
        let key = test_key();
        let nonce = test_nonce();
        let plaintext = b"secret data";
        let aad = b"header";

        let (ciphertext, tag) =
            encrypt(CipherSuite::Aes256Gcm, &key, &nonce, plaintext, aad).unwrap();

        // Try to decrypt AES ciphertext with ChaCha20
        let result = decrypt(
            CipherSuite::ChaCha20Poly1305,
            &key,
            &nonce,
            &ciphertext,
            &tag,
            aad,
        );
        assert!(matches!(result, Err(KspError::AuthenticationFailed)));
    }
}
