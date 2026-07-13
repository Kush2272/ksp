//! # KSP Crypto
//!
//! Cryptographic primitives for the Kush Secure Protocol.
//!
//! - **X25519**: Ephemeral Diffie-Hellman key exchange for forward secrecy
//! - **AEAD**: AES-256-GCM and ChaCha20-Poly1305 authenticated encryption
//! - **KDF**: HKDF-SHA256 key derivation from shared secrets
//! - **Nonce**: Counter-based nonce generation (TLS 1.3 style)
//! - **Certificate**: Ed25519-signed KSP certificates

pub mod aead;
pub mod certificate;
pub mod kdf;
pub mod nonce;
pub mod x25519;

pub use aead::{AeadCipher, decrypt, encrypt};
pub use certificate::KspCertificate;
pub use kdf::{DerivedKeys, compute_finished_mac, derive_session_keys};
pub use nonce::NonceGenerator;
pub use x25519::{EphemeralKeypair, compute_shared_secret};
