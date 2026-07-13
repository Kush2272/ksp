//! Capability negotiation for KSP.
//!
//! Capabilities allow endpoints to advertise and negotiate optional features
//! without changing the protocol version. Defined in RFC-0001 Section 6.

use crate::error::KspError;

bitflags::bitflags! {
    /// Capability flags as defined in RFC-0001 Section 6.2.
    ///
    /// Encoded as a 32-bit bitfield transmitted during the handshake.
    /// Negotiation computes the intersection of client and server capabilities.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Capabilities: u32 {
        /// Supports AES-256-GCM cipher suite
        const AES_256_GCM        = 0b0000_0000_0000_0000_0000_0000_0000_0001;
        /// Supports ChaCha20-Poly1305 cipher suite
        const CHACHA20_POLY1305  = 0b0000_0000_0000_0000_0000_0000_0000_0010;
        /// Supports zstd payload compression
        const COMPRESSION_ZSTD   = 0b0000_0000_0000_0000_0000_0000_0000_0100;
        /// Supports stream multiplexing
        const MULTIPLEXING       = 0b0000_0000_0000_0000_0000_0000_0000_1000;
        /// Supports hybrid post-quantum key exchange (X25519 + ML-KEM)
        const POST_QUANTUM       = 0b0000_0000_0000_0000_0000_0000_0001_0000;
        /// Supports bidirectional streaming
        const STREAMING          = 0b0000_0000_0000_0000_0000_0000_0010_0000;
        /// Supports session ticket-based resumption
        const SESSION_RESUMPTION = 0b0000_0000_0000_0000_0000_0000_0100_0000;
        /// Supports mutual (client) authentication
        const MUTUAL_AUTH        = 0b0000_0000_0000_0000_0000_0000_1000_0000;
        /// Supports optimized file transfer mode
        const FILE_TRANSFER      = 0b0000_0000_0000_0000_0000_0001_0000_0000;
    }
}

/// Mask covering cipher suite capability bits (bits 0–1).
const CIPHER_MASK: u32 = Capabilities::AES_256_GCM.bits() | Capabilities::CHACHA20_POLY1305.bits();

/// The cipher suite selected during negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// AES-256-GCM — preferred when hardware AES-NI is available
    Aes256Gcm,
    /// ChaCha20-Poly1305 — preferred on platforms without AES hardware acceleration
    ChaCha20Poly1305,
}

impl CipherSuite {
    /// Get the capability flag for this cipher suite.
    pub fn capability_flag(&self) -> Capabilities {
        match self {
            CipherSuite::Aes256Gcm => Capabilities::AES_256_GCM,
            CipherSuite::ChaCha20Poly1305 => Capabilities::CHACHA20_POLY1305,
        }
    }

    /// Wire ID for the cipher suite (used in certificate and handshake messages).
    pub fn id(&self) -> u8 {
        match self {
            CipherSuite::Aes256Gcm => 0x01,
            CipherSuite::ChaCha20Poly1305 => 0x02,
        }
    }

    /// Parse from wire ID.
    pub fn from_id(id: u8) -> Option<CipherSuite> {
        match id {
            0x01 => Some(CipherSuite::Aes256Gcm),
            0x02 => Some(CipherSuite::ChaCha20Poly1305),
            _ => None,
        }
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherSuite::Aes256Gcm => write!(f, "KSP_X25519_AES256GCM_SHA256"),
            CipherSuite::ChaCha20Poly1305 => {
                write!(f, "KSP_X25519_CHACHA20POLY1305_SHA256")
            }
        }
    }
}

/// Negotiate capabilities between client and server.
///
/// As specified in RFC-0001 Section 6.3:
/// 1. Compute the intersection of client and server capabilities.
/// 2. For cipher suites, the server selects exactly one (server preference).
/// 3. At least one cipher suite MUST be mutually supported.
///
/// Returns `(negotiated_capabilities, selected_cipher_suite)`.
pub fn negotiate_capabilities(
    client: Capabilities,
    server: Capabilities,
) -> Result<(Capabilities, CipherSuite), KspError> {
    // Compute intersection of all capabilities
    let mut negotiated = client & server;

    // Select cipher suite — server preference order: AES-256-GCM, then ChaCha20
    let cipher = if negotiated.contains(Capabilities::AES_256_GCM) {
        // Clear the other cipher bit — we select exactly one
        negotiated.remove(Capabilities::CHACHA20_POLY1305);
        CipherSuite::Aes256Gcm
    } else if negotiated.contains(Capabilities::CHACHA20_POLY1305) {
        CipherSuite::ChaCha20Poly1305
    } else {
        return Err(KspError::CapabilityMismatch);
    };

    Ok((negotiated, cipher))
}

/// Default capabilities for a KSP endpoint.
///
/// Supports both cipher suites and all standard features.
pub fn default_capabilities() -> Capabilities {
    Capabilities::AES_256_GCM
        | Capabilities::CHACHA20_POLY1305
        | Capabilities::COMPRESSION_ZSTD
        | Capabilities::MULTIPLEXING
        | Capabilities::STREAMING
        | Capabilities::SESSION_RESUMPTION
}

impl std::fmt::Display for Capabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return write!(f, "(none)");
        }
        let mut parts = Vec::new();
        if self.contains(Capabilities::AES_256_GCM) {
            parts.push("AES-256-GCM");
        }
        if self.contains(Capabilities::CHACHA20_POLY1305) {
            parts.push("ChaCha20-Poly1305");
        }
        if self.contains(Capabilities::COMPRESSION_ZSTD) {
            parts.push("Compression(zstd)");
        }
        if self.contains(Capabilities::MULTIPLEXING) {
            parts.push("Multiplexing");
        }
        if self.contains(Capabilities::POST_QUANTUM) {
            parts.push("PostQuantum");
        }
        if self.contains(Capabilities::STREAMING) {
            parts.push("Streaming");
        }
        if self.contains(Capabilities::SESSION_RESUMPTION) {
            parts.push("SessionResumption");
        }
        if self.contains(Capabilities::MUTUAL_AUTH) {
            parts.push("MutualAuth");
        }
        if self.contains(Capabilities::FILE_TRANSFER) {
            parts.push("FileTransfer");
        }
        write!(f, "{}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_both_aes() {
        let client = Capabilities::AES_256_GCM | Capabilities::STREAMING;
        let server = Capabilities::AES_256_GCM | Capabilities::MULTIPLEXING;

        let (caps, cipher) = negotiate_capabilities(client, server).unwrap();
        assert_eq!(cipher, CipherSuite::Aes256Gcm);
        assert!(caps.contains(Capabilities::AES_256_GCM));
        assert!(!caps.contains(Capabilities::STREAMING)); // server doesn't support it
        assert!(!caps.contains(Capabilities::MULTIPLEXING)); // client doesn't support it
    }

    #[test]
    fn test_negotiate_prefers_aes() {
        let client = Capabilities::AES_256_GCM | Capabilities::CHACHA20_POLY1305;
        let server = Capabilities::AES_256_GCM | Capabilities::CHACHA20_POLY1305;

        let (caps, cipher) = negotiate_capabilities(client, server).unwrap();
        assert_eq!(cipher, CipherSuite::Aes256Gcm);
        // ChaCha20 should be cleared since we selected AES
        assert!(!caps.contains(Capabilities::CHACHA20_POLY1305));
    }

    #[test]
    fn test_negotiate_falls_back_to_chacha() {
        let client = Capabilities::CHACHA20_POLY1305 | Capabilities::STREAMING;
        let server = Capabilities::CHACHA20_POLY1305 | Capabilities::STREAMING;

        let (caps, cipher) = negotiate_capabilities(client, server).unwrap();
        assert_eq!(cipher, CipherSuite::ChaCha20Poly1305);
        assert!(caps.contains(Capabilities::STREAMING));
    }

    #[test]
    fn test_negotiate_no_common_cipher() {
        let client = Capabilities::AES_256_GCM;
        let server = Capabilities::CHACHA20_POLY1305;

        assert!(matches!(
            negotiate_capabilities(client, server),
            Err(KspError::CapabilityMismatch)
        ));
    }

    #[test]
    fn test_cipher_suite_id_roundtrip() {
        assert_eq!(
            CipherSuite::from_id(CipherSuite::Aes256Gcm.id()),
            Some(CipherSuite::Aes256Gcm)
        );
        assert_eq!(
            CipherSuite::from_id(CipherSuite::ChaCha20Poly1305.id()),
            Some(CipherSuite::ChaCha20Poly1305)
        );
        assert_eq!(CipherSuite::from_id(0xFF), None);
    }
}
