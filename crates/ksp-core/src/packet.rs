//! KSP binary packet format — serialization and deserialization.
//!
//! Implements the 48-byte fixed header + variable payload + 16-byte auth tag
//! wire format as defined in RFC-0001 Section 4.
//!
//! All multi-byte integers are big-endian (network byte order).

use bytes::{Buf, BufMut, BytesMut};

use crate::constants::{AUTH_TAG_SIZE, HEADER_SIZE, MAX_PAYLOAD_SIZE, NONCE_SIZE, SESSION_ID_SIZE};
use crate::error::KspError;
use crate::types::{Flags, PacketType};
use crate::version::ProtocolVersion;

/// A KSP packet — the fundamental unit of communication.
///
/// Wire format (RFC-0001 Section 4.1):
/// ```text
/// [Header: 48 bytes][Encrypted Payload: variable][Auth Tag: 16 bytes]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KspPacket {
    /// Protocol version (encoded as single byte)
    pub version: ProtocolVersion,
    /// Packet type code
    pub packet_type: PacketType,
    /// Bitfield flags
    pub flags: Flags,
    /// Session ID (16 bytes, UUID v4). All zeros for initial ClientHello.
    pub session_id: [u8; SESSION_ID_SIZE],
    /// Stream ID. 0 = connection-level control frame.
    /// Odd = client-initiated, Even = server-initiated.
    pub stream_id: u32,
    /// Monotonically increasing per-session sequence number.
    pub sequence: u64,
    /// AEAD nonce used to encrypt this packet's payload.
    pub nonce: [u8; NONCE_SIZE],
    /// The payload bytes (plaintext during handshake, ciphertext after).
    pub payload: Vec<u8>,
    /// AEAD authentication tag (16 bytes). Empty for plaintext handshake messages.
    pub auth_tag: Vec<u8>,
}

impl KspPacket {
    /// Create a new packet with the given parameters.
    pub fn new(
        version: ProtocolVersion,
        packet_type: PacketType,
        flags: Flags,
        session_id: [u8; SESSION_ID_SIZE],
        stream_id: u32,
        sequence: u64,
        nonce: [u8; NONCE_SIZE],
        payload: Vec<u8>,
        auth_tag: Vec<u8>,
    ) -> Self {
        Self {
            version,
            packet_type,
            flags,
            session_id,
            stream_id,
            sequence,
            nonce,
            payload,
            auth_tag,
        }
    }

    /// Create a new packet with empty session ID and nonce (for ClientHello).
    pub fn new_handshake(packet_type: PacketType, payload: Vec<u8>) -> Self {
        Self {
            version: crate::CURRENT_VERSION,
            packet_type,
            flags: Flags::empty(),
            session_id: [0u8; SESSION_ID_SIZE],
            stream_id: 0,
            sequence: 0,
            nonce: [0u8; NONCE_SIZE],
            payload,
            auth_tag: Vec::new(),
        }
    }

    /// Serialize the header into bytes (used as AAD for AEAD).
    ///
    /// Returns exactly 48 bytes.
    pub fn header_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = self.version.to_wire();
        buf[1] = self.packet_type as u8;
        buf[2..4].copy_from_slice(&self.flags.bits().to_be_bytes());
        buf[4..8].copy_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf[8..24].copy_from_slice(&self.session_id);
        buf[24..28].copy_from_slice(&self.stream_id.to_be_bytes());
        buf[28..36].copy_from_slice(&self.sequence.to_be_bytes());
        buf[36..48].copy_from_slice(&self.nonce);
        buf
    }

    /// Serialize the entire packet to bytes for transmission.
    ///
    /// Wire layout: `[header: 48 bytes][payload: N bytes][auth_tag: 0 or 16 bytes]`
    pub fn serialize(&self) -> Vec<u8> {
        let total = HEADER_SIZE + self.payload.len() + self.auth_tag.len();
        let mut buf = Vec::with_capacity(total);

        // Header
        buf.extend_from_slice(&self.header_bytes());

        // Payload
        buf.extend_from_slice(&self.payload);

        // Auth tag
        buf.extend_from_slice(&self.auth_tag);

        buf
    }

    /// Serialize into an existing `BytesMut` buffer.
    pub fn serialize_into(&self, buf: &mut BytesMut) {
        let total = HEADER_SIZE + self.payload.len() + self.auth_tag.len();
        buf.reserve(total);

        buf.extend_from_slice(&self.header_bytes());
        buf.extend_from_slice(&self.payload);
        buf.extend_from_slice(&self.auth_tag);
    }

    /// Deserialize a packet from bytes.
    ///
    /// Returns `(packet, bytes_consumed)` on success.
    ///
    /// # Errors
    /// - `InsufficientData` if the buffer doesn't contain a complete packet.
    /// - `UnknownPacketType` if the type byte is unrecognized.
    /// - `PayloadTooLarge` if the payload length exceeds the maximum.
    pub fn deserialize(buf: &[u8]) -> Result<(KspPacket, usize), KspError> {
        // Need at least the header
        if buf.len() < HEADER_SIZE {
            return Err(KspError::InsufficientData {
                needed: HEADER_SIZE,
                available: buf.len(),
            });
        }

        // Parse header fields
        let version = ProtocolVersion::from_wire(buf[0]);
        let packet_type = PacketType::from_u8(buf[1])?;
        let flags = Flags::from_bits_truncate(u16::from_be_bytes([buf[2], buf[3]]));
        let payload_length = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        // Validate payload length
        if payload_length > MAX_PAYLOAD_SIZE {
            return Err(KspError::PayloadTooLarge {
                size: payload_length,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let mut session_id = [0u8; SESSION_ID_SIZE];
        session_id.copy_from_slice(&buf[8..24]);

        let stream_id = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let sequence = u64::from_be_bytes([
            buf[28], buf[29], buf[30], buf[31], buf[32], buf[33], buf[34], buf[35],
        ]);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&buf[36..48]);

        // Determine if this packet has an auth tag
        let has_auth_tag = flags.contains(Flags::ENCRYPTED);
        let tag_size = if has_auth_tag { AUTH_TAG_SIZE } else { 0 };

        let total_size = HEADER_SIZE + payload_length as usize + tag_size;

        if buf.len() < total_size {
            return Err(KspError::InsufficientData {
                needed: total_size,
                available: buf.len(),
            });
        }

        // Extract payload
        let payload_start = HEADER_SIZE;
        let payload_end = payload_start + payload_length as usize;
        let payload = buf[payload_start..payload_end].to_vec();

        // Extract auth tag
        let auth_tag = if has_auth_tag {
            buf[payload_end..payload_end + AUTH_TAG_SIZE].to_vec()
        } else {
            Vec::new()
        };

        let packet = KspPacket {
            version,
            packet_type,
            flags,
            session_id,
            stream_id,
            sequence,
            nonce,
            payload,
            auth_tag,
        };

        Ok((packet, total_size))
    }

    /// Total wire size of this packet.
    pub fn wire_size(&self) -> usize {
        HEADER_SIZE + self.payload.len() + self.auth_tag.len()
    }

    /// Returns a human-readable summary for logging/debugging.
    pub fn summary(&self) -> String {
        format!(
            "KSP v{} {} [{}] seq={} stream={} payload={}B",
            self.version,
            self.packet_type,
            self.flags,
            self.sequence,
            self.stream_id,
            self.payload.len(),
        )
    }
}

impl std::fmt::Display for KspPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CURRENT_VERSION;

    #[test]
    fn test_serialize_deserialize_roundtrip() {
        let packet = KspPacket {
            version: CURRENT_VERSION,
            packet_type: PacketType::Data,
            flags: Flags::ENCRYPTED,
            session_id: [0xAA; SESSION_ID_SIZE],
            stream_id: 1,
            sequence: 42,
            nonce: [0xBB; NONCE_SIZE],
            payload: vec![0x01, 0x02, 0x03, 0x04],
            auth_tag: vec![0xCC; AUTH_TAG_SIZE],
        };

        let bytes = packet.serialize();
        let (deserialized, consumed) = KspPacket::deserialize(&bytes).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(deserialized.version, packet.version);
        assert_eq!(deserialized.packet_type, packet.packet_type);
        assert_eq!(deserialized.flags, packet.flags);
        assert_eq!(deserialized.session_id, packet.session_id);
        assert_eq!(deserialized.stream_id, packet.stream_id);
        assert_eq!(deserialized.sequence, packet.sequence);
        assert_eq!(deserialized.nonce, packet.nonce);
        assert_eq!(deserialized.payload, packet.payload);
        assert_eq!(deserialized.auth_tag, packet.auth_tag);
    }

    #[test]
    fn test_plaintext_packet_no_auth_tag() {
        let packet = KspPacket {
            version: CURRENT_VERSION,
            packet_type: PacketType::ClientHello,
            flags: Flags::empty(),
            session_id: [0; SESSION_ID_SIZE],
            stream_id: 0,
            sequence: 1,
            nonce: [0; NONCE_SIZE],
            payload: b"hello".to_vec(),
            auth_tag: Vec::new(),
        };

        let bytes = packet.serialize();
        assert_eq!(bytes.len(), HEADER_SIZE + 5); // no auth tag

        let (deserialized, consumed) = KspPacket::deserialize(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(deserialized.payload, b"hello");
        assert!(deserialized.auth_tag.is_empty());
    }

    #[test]
    fn test_header_bytes_size() {
        let packet = KspPacket::new_handshake(PacketType::ClientHello, vec![]);
        let header = packet.header_bytes();
        assert_eq!(header.len(), HEADER_SIZE);
    }

    #[test]
    fn test_insufficient_data() {
        let result = KspPacket::deserialize(&[0u8; 10]);
        assert!(matches!(result, Err(KspError::InsufficientData { .. })));
    }

    #[test]
    fn test_payload_too_large() {
        let mut buf = [0u8; HEADER_SIZE];
        // Set payload length to MAX + 1
        let too_large = MAX_PAYLOAD_SIZE + 1;
        buf[4..8].copy_from_slice(&too_large.to_be_bytes());
        buf[0] = CURRENT_VERSION.to_wire();
        buf[1] = PacketType::Data as u8;

        let result = KspPacket::deserialize(&buf);
        assert!(matches!(result, Err(KspError::PayloadTooLarge { .. })));
    }

    #[test]
    fn test_unknown_packet_type() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = CURRENT_VERSION.to_wire();
        buf[1] = 0xFE; // Unknown type

        let result = KspPacket::deserialize(&buf);
        assert!(matches!(result, Err(KspError::UnknownPacketType(0xFE))));
    }

    #[test]
    fn test_wire_size() {
        let packet = KspPacket {
            version: CURRENT_VERSION,
            packet_type: PacketType::Data,
            flags: Flags::ENCRYPTED,
            session_id: [0; SESSION_ID_SIZE],
            stream_id: 0,
            sequence: 0,
            nonce: [0; NONCE_SIZE],
            payload: vec![0; 100],
            auth_tag: vec![0; AUTH_TAG_SIZE],
        };

        assert_eq!(packet.wire_size(), HEADER_SIZE + 100 + AUTH_TAG_SIZE);
    }

    #[test]
    fn test_multiple_packets_in_buffer() {
        let p1 = KspPacket::new_handshake(PacketType::ClientHello, b"one".to_vec());
        let p2 = KspPacket::new_handshake(PacketType::ServerHello, b"two".to_vec());

        let mut combined = p1.serialize();
        combined.extend_from_slice(&p2.serialize());

        let (d1, consumed1) = KspPacket::deserialize(&combined).unwrap();
        assert_eq!(d1.payload, b"one");

        let (d2, consumed2) = KspPacket::deserialize(&combined[consumed1..]).unwrap();
        assert_eq!(d2.payload, b"two");

        assert_eq!(consumed1 + consumed2, combined.len());
    }

    #[test]
    fn test_display() {
        let packet = KspPacket {
            version: CURRENT_VERSION,
            packet_type: PacketType::Data,
            flags: Flags::ENCRYPTED | Flags::COMPRESSED,
            session_id: [0; SESSION_ID_SIZE],
            stream_id: 3,
            sequence: 42,
            nonce: [0; NONCE_SIZE],
            payload: vec![0; 256],
            auth_tag: vec![0; AUTH_TAG_SIZE],
        };

        let display = format!("{}", packet);
        assert!(display.contains("Data"));
        assert!(display.contains("ENCRYPTED"));
        assert!(display.contains("COMPRESSED"));
        assert!(display.contains("seq=42"));
        assert!(display.contains("stream=3"));
    }
}
