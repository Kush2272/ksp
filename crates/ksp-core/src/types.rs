//! Packet types and flags for KSP.
//!
//! Defines all packet type codes (RFC-0001 Section 4.3) and
//! packet flags (RFC-0001 Section 4.4).

use crate::error::KspError;

/// Packet type codes as defined in RFC-0001 Section 4.3.
///
/// Each KSP frame carries a single-byte type code identifying its purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    // --- Handshake ---
    /// Client initiates handshake with version/capability proposal
    ClientHello = 0x01,
    /// Server responds with selected version/capabilities + ephemeral key
    ServerHello = 0x02,
    /// Key exchange contribution
    KeyExchange = 0x03,
    /// Server's KSP certificate
    Certificate = 0x04,
    /// Client authentication credentials (encrypted)
    AuthRequest = 0x05,
    /// Authentication result (encrypted)
    AuthResponse = 0x06,
    /// Handshake verification (encrypted)
    HandshakeFinish = 0x07,

    // --- Data ---
    /// Application data (encrypted)
    Data = 0x10,
    /// Acknowledgement of received data
    DataAck = 0x11,

    // --- Streaming ---
    /// Open a new stream
    StreamOpen = 0x20,
    /// Data on a specific stream
    StreamData = 0x21,
    /// Gracefully close a stream
    StreamClose = 0x22,
    /// Abruptly terminate a stream
    StreamReset = 0x23,

    // --- Control ---
    /// Connection liveness probe
    KeepAlive = 0x30,
    /// Response to KeepAlive
    KeepAliveAck = 0x31,
    /// Flow control window increase
    WindowUpdate = 0x32,
    /// Graceful connection shutdown
    GoAway = 0x33,

    // --- Session ---
    /// Request to resume a previous session
    SessionResume = 0x40,
    /// Encrypted session ticket for future resumption
    SessionTicket = 0x41,

    // --- Error ---
    /// Error notification
    Error = 0xFF,
}

impl PacketType {
    /// Parse a packet type from its wire byte.
    pub fn from_u8(value: u8) -> Result<PacketType, KspError> {
        match value {
            0x01 => Ok(PacketType::ClientHello),
            0x02 => Ok(PacketType::ServerHello),
            0x03 => Ok(PacketType::KeyExchange),
            0x04 => Ok(PacketType::Certificate),
            0x05 => Ok(PacketType::AuthRequest),
            0x06 => Ok(PacketType::AuthResponse),
            0x07 => Ok(PacketType::HandshakeFinish),
            0x10 => Ok(PacketType::Data),
            0x11 => Ok(PacketType::DataAck),
            0x20 => Ok(PacketType::StreamOpen),
            0x21 => Ok(PacketType::StreamData),
            0x22 => Ok(PacketType::StreamClose),
            0x23 => Ok(PacketType::StreamReset),
            0x30 => Ok(PacketType::KeepAlive),
            0x31 => Ok(PacketType::KeepAliveAck),
            0x32 => Ok(PacketType::WindowUpdate),
            0x33 => Ok(PacketType::GoAway),
            0x40 => Ok(PacketType::SessionResume),
            0x41 => Ok(PacketType::SessionTicket),
            0xFF => Ok(PacketType::Error),
            _ => Err(KspError::UnknownPacketType(value)),
        }
    }

    /// Whether this packet type is part of the handshake sequence.
    pub fn is_handshake(&self) -> bool {
        matches!(
            self,
            PacketType::ClientHello
                | PacketType::ServerHello
                | PacketType::KeyExchange
                | PacketType::Certificate
                | PacketType::AuthRequest
                | PacketType::AuthResponse
                | PacketType::HandshakeFinish
        )
    }

    /// Whether this packet type carries encrypted payload.
    ///
    /// Handshake messages before key exchange are plaintext.
    /// Everything after KeyExchange is encrypted.
    pub fn is_encrypted(&self) -> bool {
        !matches!(
            self,
            PacketType::ClientHello | PacketType::ServerHello | PacketType::Certificate
        )
    }

    /// Whether this packet type is a control frame (exempt from flow control).
    pub fn is_control(&self) -> bool {
        matches!(
            self,
            PacketType::KeepAlive
                | PacketType::KeepAliveAck
                | PacketType::WindowUpdate
                | PacketType::GoAway
                | PacketType::Error
        )
    }

    /// Human-readable name for display and logging.
    pub fn name(&self) -> &'static str {
        match self {
            PacketType::ClientHello => "ClientHello",
            PacketType::ServerHello => "ServerHello",
            PacketType::KeyExchange => "KeyExchange",
            PacketType::Certificate => "Certificate",
            PacketType::AuthRequest => "AuthRequest",
            PacketType::AuthResponse => "AuthResponse",
            PacketType::HandshakeFinish => "HandshakeFinish",
            PacketType::Data => "Data",
            PacketType::DataAck => "DataAck",
            PacketType::StreamOpen => "StreamOpen",
            PacketType::StreamData => "StreamData",
            PacketType::StreamClose => "StreamClose",
            PacketType::StreamReset => "StreamReset",
            PacketType::KeepAlive => "KeepAlive",
            PacketType::KeepAliveAck => "KeepAliveAck",
            PacketType::WindowUpdate => "WindowUpdate",
            PacketType::GoAway => "GoAway",
            PacketType::SessionResume => "SessionResume",
            PacketType::SessionTicket => "SessionTicket",
            PacketType::Error => "Error",
        }
    }
}

impl std::fmt::Display for PacketType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (0x{:02X})", self.name(), *self as u8)
    }
}

bitflags::bitflags! {
    /// Packet flags as defined in RFC-0001 Section 4.4.
    ///
    /// Flags are a 16-bit bitfield in the packet header.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Flags: u16 {
        /// Payload was compressed before encryption
        const COMPRESSED    = 0b0000_0000_0000_0001;
        /// Payload is encrypted (MUST be set after handshake)
        const ENCRYPTED     = 0b0000_0000_0000_0010;
        /// This frame is part of a fragmented message
        const FRAGMENTED    = 0b0000_0000_0000_0100;
        /// Last frame for this stream (half-close)
        const END_STREAM    = 0b0000_0000_0000_1000;
        /// This frame is an acknowledgement
        const ACK           = 0b0000_0000_0001_0000;
        /// Frame contains priority information
        const PRIORITY      = 0b0000_0000_0010_0000;
        /// Payload includes padding bytes
        const PADDED        = 0b0000_0000_0100_0000;
    }
}

impl std::fmt::Display for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return write!(f, "(none)");
        }

        let mut parts = Vec::new();
        if self.contains(Flags::COMPRESSED) {
            parts.push("COMPRESSED");
        }
        if self.contains(Flags::ENCRYPTED) {
            parts.push("ENCRYPTED");
        }
        if self.contains(Flags::FRAGMENTED) {
            parts.push("FRAGMENTED");
        }
        if self.contains(Flags::END_STREAM) {
            parts.push("END_STREAM");
        }
        if self.contains(Flags::ACK) {
            parts.push("ACK");
        }
        if self.contains(Flags::PRIORITY) {
            parts.push("PRIORITY");
        }
        if self.contains(Flags::PADDED) {
            parts.push("PADDED");
        }
        write!(f, "{}", parts.join(" | "))
    }
}
