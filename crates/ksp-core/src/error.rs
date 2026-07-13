//! Error types and error codes for KSP.
//!
//! Error codes match RFC-0001 Section 15. The `KspError` enum
//! provides a unified error type for all KSP operations.

use std::fmt;

/// Result type alias using `KspError`.
pub type Result<T> = std::result::Result<T, KspError>;

/// Unified error type for all KSP operations.
#[derive(Debug, thiserror::Error)]
pub enum KspError {
    /// Invalid or malformed packet
    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    /// Packet payload exceeds maximum size
    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: u32, max: u32 },

    /// Buffer too small to contain a complete packet
    #[error("insufficient data: need {needed} bytes, have {available}")]
    InsufficientData { needed: usize, available: usize },

    /// Unknown or unsupported packet type
    #[error("unknown packet type: 0x{0:02X}")]
    UnknownPacketType(u8),

    /// Cryptographic operation failed
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// AEAD decryption/verification failed — deliberately vague to prevent oracle attacks
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Handshake error
    #[error("handshake error: {0}")]
    HandshakeError(String),

    /// Handshake timed out
    #[error("handshake timeout")]
    HandshakeTimeout,

    /// No mutually supported protocol version
    #[error("version mismatch: no common version")]
    VersionMismatch,

    /// No mutually supported cipher suite
    #[error("capability mismatch: no common cipher suite")]
    CapabilityMismatch,

    /// Certificate validation failed
    #[error("certificate error: {0}")]
    CertificateError(String),

    /// Certificate has expired
    #[error("certificate expired")]
    CertificateExpired,

    /// Replay attack detected
    #[error("replay detected: sequence {0}")]
    ReplayDetected(u64),

    /// Session has expired
    #[error("session expired")]
    SessionExpired,

    /// Stream limit exceeded
    #[error("stream limit exceeded: max {0}")]
    StreamLimitExceeded(u32),

    /// Stream is closed
    #[error("stream {0} is closed")]
    StreamClosed(u32),

    /// Flow control error
    #[error("flow control error: {0}")]
    FlowControlError(String),

    /// I/O error
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),

    /// Protocol-level error received from peer
    #[error("protocol error: {code}")]
    ProtocolError { code: ErrorCode },

    /// Internal error
    #[error("internal error: {0}")]
    InternalError(String),

    /// Connection was closed
    #[error("connection closed")]
    ConnectionClosed,
}

/// Protocol error codes as defined in RFC-0001 Section 15.
///
/// These codes are transmitted on the wire in Error frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// Graceful close, no error
    NoError = 0x00,
    /// Generic protocol violation
    ProtocolError = 0x01,
    /// Implementation fault
    InternalError = 0x02,
    /// Flow control limit exceeded
    FlowControlError = 0x03,
    /// Frame received for closed stream
    StreamClosed = 0x04,
    /// Frame exceeds maximum size
    FrameSizeError = 0x05,
    /// Authentication rejected
    AuthFailed = 0x06,
    /// Handshake exceeded time limit
    HandshakeTimeout = 0x07,
    /// No common protocol version
    VersionMismatch = 0x08,
    /// Replayed packet detected
    ReplayDetected = 0x09,
    /// Server certificate has expired
    CertExpired = 0x0A,
    /// Certificate signature invalid
    CertInvalid = 0x0B,
    /// No common cipher suite
    CapabilityMismatch = 0x0C,
    /// Maximum streams exceeded
    StreamLimit = 0x0D,
    /// Session has timed out
    SessionExpired = 0x0E,
}

impl ErrorCode {
    /// Create an ErrorCode from its wire representation.
    pub fn from_u32(value: u32) -> Option<ErrorCode> {
        match value {
            0x00 => Some(ErrorCode::NoError),
            0x01 => Some(ErrorCode::ProtocolError),
            0x02 => Some(ErrorCode::InternalError),
            0x03 => Some(ErrorCode::FlowControlError),
            0x04 => Some(ErrorCode::StreamClosed),
            0x05 => Some(ErrorCode::FrameSizeError),
            0x06 => Some(ErrorCode::AuthFailed),
            0x07 => Some(ErrorCode::HandshakeTimeout),
            0x08 => Some(ErrorCode::VersionMismatch),
            0x09 => Some(ErrorCode::ReplayDetected),
            0x0A => Some(ErrorCode::CertExpired),
            0x0B => Some(ErrorCode::CertInvalid),
            0x0C => Some(ErrorCode::CapabilityMismatch),
            0x0D => Some(ErrorCode::StreamLimit),
            0x0E => Some(ErrorCode::SessionExpired),
            _ => None,
        }
    }

    /// Whether this error code applies at the connection level (vs stream level).
    pub fn is_connection_level(&self) -> bool {
        matches!(
            self,
            ErrorCode::ProtocolError
                | ErrorCode::InternalError
                | ErrorCode::FrameSizeError
                | ErrorCode::AuthFailed
                | ErrorCode::HandshakeTimeout
                | ErrorCode::VersionMismatch
                | ErrorCode::ReplayDetected
                | ErrorCode::CertExpired
                | ErrorCode::CertInvalid
                | ErrorCode::CapabilityMismatch
                | ErrorCode::SessionExpired
        )
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::NoError => write!(f, "NO_ERROR (0x00)"),
            ErrorCode::ProtocolError => write!(f, "PROTOCOL_ERROR (0x01)"),
            ErrorCode::InternalError => write!(f, "INTERNAL_ERROR (0x02)"),
            ErrorCode::FlowControlError => write!(f, "FLOW_CONTROL_ERROR (0x03)"),
            ErrorCode::StreamClosed => write!(f, "STREAM_CLOSED (0x04)"),
            ErrorCode::FrameSizeError => write!(f, "FRAME_SIZE_ERROR (0x05)"),
            ErrorCode::AuthFailed => write!(f, "AUTH_FAILED (0x06)"),
            ErrorCode::HandshakeTimeout => write!(f, "HANDSHAKE_TIMEOUT (0x07)"),
            ErrorCode::VersionMismatch => write!(f, "VERSION_MISMATCH (0x08)"),
            ErrorCode::ReplayDetected => write!(f, "REPLAY_DETECTED (0x09)"),
            ErrorCode::CertExpired => write!(f, "CERT_EXPIRED (0x0A)"),
            ErrorCode::CertInvalid => write!(f, "CERT_INVALID (0x0B)"),
            ErrorCode::CapabilityMismatch => write!(f, "CAPABILITY_MISMATCH (0x0C)"),
            ErrorCode::StreamLimit => write!(f, "STREAM_LIMIT (0x0D)"),
            ErrorCode::SessionExpired => write!(f, "SESSION_EXPIRED (0x0E)"),
        }
    }
}
