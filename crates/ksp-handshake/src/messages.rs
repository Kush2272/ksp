//! Handshake message types for KSP.
//!
//! Binary-encoded messages exchanged during the handshake phase
//! as defined in RFC-0001 Section 7.2.

use ksp_core::capability::Capabilities;
use ksp_core::constants::{RANDOM_SIZE, SESSION_ID_SIZE, X25519_PUBLIC_KEY_SIZE};
use ksp_core::error::KspError;
use ksp_core::version::ProtocolVersion;
use ksp_crypto::KspCertificate;

/// ClientHello — the first message in the handshake.
///
/// Sent by the client to propose protocol versions, capabilities,
/// and provide its ephemeral key exchange public key.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// List of protocol versions supported by the client, in preference order.
    pub supported_versions: Vec<ProtocolVersion>,
    /// Client's capability flags.
    pub capabilities: Capabilities,
    /// 32 bytes of cryptographically random data for key derivation salt.
    pub client_random: [u8; RANDOM_SIZE],
    /// Client's ephemeral X25519 public key.
    pub ephemeral_public_key: [u8; X25519_PUBLIC_KEY_SIZE],
}

impl ClientHello {
    /// Serialize to binary payload format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Number of versions (1 byte)
        buf.push(self.supported_versions.len() as u8);

        // Each version as 1 byte
        for v in &self.supported_versions {
            buf.push(v.to_wire());
        }

        // Capabilities (4 bytes)
        buf.extend_from_slice(&self.capabilities.bits().to_be_bytes());

        // Client random (32 bytes)
        buf.extend_from_slice(&self.client_random);

        // Ephemeral public key (32 bytes)
        buf.extend_from_slice(&self.ephemeral_public_key);

        buf
    }

    /// Deserialize from binary payload.
    pub fn deserialize(buf: &[u8]) -> Result<Self, KspError> {
        let mut pos = 0;

        if buf.is_empty() {
            return Err(KspError::InvalidPacket("ClientHello is empty".into()));
        }

        // Number of versions
        let num_versions = buf[pos] as usize;
        pos += 1;

        if buf.len() < pos + num_versions {
            return Err(KspError::InvalidPacket(
                "ClientHello truncated at versions".into(),
            ));
        }

        let mut supported_versions = Vec::with_capacity(num_versions);
        for _ in 0..num_versions {
            supported_versions.push(ProtocolVersion::from_wire(buf[pos]));
            pos += 1;
        }

        // Capabilities
        if buf.len() < pos + 4 {
            return Err(KspError::InvalidPacket(
                "ClientHello truncated at capabilities".into(),
            ));
        }
        let caps_bits = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        let capabilities = Capabilities::from_bits_truncate(caps_bits);
        pos += 4;

        // Client random
        if buf.len() < pos + RANDOM_SIZE {
            return Err(KspError::InvalidPacket(
                "ClientHello truncated at random".into(),
            ));
        }
        let mut client_random = [0u8; RANDOM_SIZE];
        client_random.copy_from_slice(&buf[pos..pos + RANDOM_SIZE]);
        pos += RANDOM_SIZE;

        // Ephemeral public key
        if buf.len() < pos + X25519_PUBLIC_KEY_SIZE {
            return Err(KspError::InvalidPacket(
                "ClientHello truncated at public key".into(),
            ));
        }
        let mut ephemeral_public_key = [0u8; X25519_PUBLIC_KEY_SIZE];
        ephemeral_public_key.copy_from_slice(&buf[pos..pos + X25519_PUBLIC_KEY_SIZE]);

        Ok(ClientHello {
            supported_versions,
            capabilities,
            client_random,
            ephemeral_public_key,
        })
    }
}

/// ServerHello — the server's response to ClientHello.
///
/// Contains the server's selected version, capabilities, ephemeral key,
/// and the assigned session ID.
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// The selected protocol version (must be in client's supported list).
    pub selected_version: ProtocolVersion,
    /// The negotiated capabilities (intersection with server preference).
    pub selected_capabilities: Capabilities,
    /// 32 bytes of cryptographically random data for key derivation salt.
    pub server_random: [u8; RANDOM_SIZE],
    /// Server's ephemeral X25519 public key.
    pub ephemeral_public_key: [u8; X25519_PUBLIC_KEY_SIZE],
    /// Assigned session ID (UUID v4).
    pub session_id: [u8; SESSION_ID_SIZE],
}

impl ServerHello {
    /// Serialize to binary payload format.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Selected version (1 byte)
        buf.push(self.selected_version.to_wire());

        // Selected capabilities (4 bytes)
        buf.extend_from_slice(&self.selected_capabilities.bits().to_be_bytes());

        // Server random (32 bytes)
        buf.extend_from_slice(&self.server_random);

        // Ephemeral public key (32 bytes)
        buf.extend_from_slice(&self.ephemeral_public_key);

        // Session ID (16 bytes)
        buf.extend_from_slice(&self.session_id);

        buf
    }

    /// Deserialize from binary payload.
    pub fn deserialize(buf: &[u8]) -> Result<Self, KspError> {
        let expected_len = 1 + 4 + RANDOM_SIZE + X25519_PUBLIC_KEY_SIZE + SESSION_ID_SIZE;
        if buf.len() < expected_len {
            return Err(KspError::InvalidPacket(format!(
                "ServerHello too short: {} < {}",
                buf.len(),
                expected_len
            )));
        }

        let mut pos = 0;

        let selected_version = ProtocolVersion::from_wire(buf[pos]);
        pos += 1;

        let caps_bits = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        let selected_capabilities = Capabilities::from_bits_truncate(caps_bits);
        pos += 4;

        let mut server_random = [0u8; RANDOM_SIZE];
        server_random.copy_from_slice(&buf[pos..pos + RANDOM_SIZE]);
        pos += RANDOM_SIZE;

        let mut ephemeral_public_key = [0u8; X25519_PUBLIC_KEY_SIZE];
        ephemeral_public_key.copy_from_slice(&buf[pos..pos + X25519_PUBLIC_KEY_SIZE]);
        pos += X25519_PUBLIC_KEY_SIZE;

        let mut session_id = [0u8; SESSION_ID_SIZE];
        session_id.copy_from_slice(&buf[pos..pos + SESSION_ID_SIZE]);

        Ok(ServerHello {
            selected_version,
            selected_capabilities,
            server_random,
            ephemeral_public_key,
            session_id,
        })
    }
}

/// HandshakeFinish — sent by both sides to verify key agreement.
///
/// Contains an HMAC of the entire handshake transcript, proving both
/// sides derived the same session keys.
#[derive(Debug, Clone)]
pub struct HandshakeFinish {
    /// HMAC-SHA256 of the handshake transcript (32 bytes).
    pub verify_data: [u8; 32],
}

impl HandshakeFinish {
    pub fn serialize(&self) -> Vec<u8> {
        self.verify_data.to_vec()
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, KspError> {
        if buf.len() < 32 {
            return Err(KspError::InvalidPacket("HandshakeFinish too short".into()));
        }
        let mut verify_data = [0u8; 32];
        verify_data.copy_from_slice(&buf[..32]);
        Ok(HandshakeFinish { verify_data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ksp_core::capability::Capabilities;

    #[test]
    fn test_client_hello_roundtrip() {
        let hello = ClientHello {
            supported_versions: vec![ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 1)],
            capabilities: Capabilities::AES_256_GCM | Capabilities::STREAMING,
            client_random: [0xAA; RANDOM_SIZE],
            ephemeral_public_key: [0xBB; X25519_PUBLIC_KEY_SIZE],
        };

        let bytes = hello.serialize();
        let deserialized = ClientHello::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.supported_versions.len(), 2);
        assert_eq!(
            deserialized.supported_versions[0],
            ProtocolVersion::new(1, 0)
        );
        assert_eq!(
            deserialized.supported_versions[1],
            ProtocolVersion::new(1, 1)
        );
        assert_eq!(deserialized.capabilities, hello.capabilities);
        assert_eq!(deserialized.client_random, hello.client_random);
        assert_eq!(
            deserialized.ephemeral_public_key,
            hello.ephemeral_public_key
        );
    }

    #[test]
    fn test_server_hello_roundtrip() {
        let hello = ServerHello {
            selected_version: ProtocolVersion::new(1, 0),
            selected_capabilities: Capabilities::AES_256_GCM,
            server_random: [0xCC; RANDOM_SIZE],
            ephemeral_public_key: [0xDD; X25519_PUBLIC_KEY_SIZE],
            session_id: [0xEE; SESSION_ID_SIZE],
        };

        let bytes = hello.serialize();
        let deserialized = ServerHello::deserialize(&bytes).unwrap();

        assert_eq!(deserialized.selected_version, hello.selected_version);
        assert_eq!(
            deserialized.selected_capabilities,
            hello.selected_capabilities
        );
        assert_eq!(deserialized.server_random, hello.server_random);
        assert_eq!(deserialized.session_id, hello.session_id);
    }

    #[test]
    fn test_handshake_finish_roundtrip() {
        let finish = HandshakeFinish {
            verify_data: [0xFF; 32],
        };
        let bytes = finish.serialize();
        let deserialized = HandshakeFinish::deserialize(&bytes).unwrap();
        assert_eq!(deserialized.verify_data, finish.verify_data);
    }
}
