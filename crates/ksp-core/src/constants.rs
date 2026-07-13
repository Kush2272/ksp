//! Protocol constants for KSP v1.0.
//!
//! All constants are defined here to ensure consistency across the codebase
//! and to match the values specified in RFC-0001.

use std::time::Duration;

use crate::version::ProtocolVersion;

/// Current protocol version: 1.0
pub const CURRENT_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);

/// Maximum payload size: 16 MB (16,777,216 bytes)
pub const MAX_PAYLOAD_SIZE: u32 = 16_777_216;

/// Fixed header size: 48 bytes
pub const HEADER_SIZE: usize = 48;

/// AEAD authentication tag size: 16 bytes
pub const AUTH_TAG_SIZE: usize = 16;

/// Session ID size: 16 bytes (UUID v4)
pub const SESSION_ID_SIZE: usize = 16;

/// Nonce size: 12 bytes
pub const NONCE_SIZE: usize = 12;

/// X25519 public key size: 32 bytes
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 public key size: 32 bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 signature size: 64 bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// Client/server random size: 32 bytes
pub const RANDOM_SIZE: usize = 32;

/// Default KSP port
pub const DEFAULT_PORT: u16 = 9876;

/// Keepalive interval
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// Keepalive timeout — if no KeepAliveAck within this period, connection is dead
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Handshake timeout — entire handshake must complete within this period
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Session timeout — session expires after this period of inactivity
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(3600);

/// Maximum concurrent streams per session
pub const MAX_STREAMS_PER_SESSION: u32 = 256;

/// Default flow control window size: 64 KiB
pub const DEFAULT_WINDOW_SIZE: u32 = 65_535;

/// Replay window size in packets
pub const REPLAY_WINDOW_SIZE: u64 = 1024;

/// Maximum authentication retry attempts
pub const MAX_AUTH_RETRIES: u32 = 3;

/// Maximum decryption failures before connection close
pub const MAX_DECRYPT_FAILURES: u32 = 10;

/// HKDF info labels for key derivation (must match RFC-0001 Section 8.3)
pub const HKDF_LABEL_CLIENT_WRITE_KEY: &[u8] = b"ksp1 client write key";
pub const HKDF_LABEL_SERVER_WRITE_KEY: &[u8] = b"ksp1 server write key";
pub const HKDF_LABEL_CLIENT_WRITE_IV: &[u8] = b"ksp1 client write iv";
pub const HKDF_LABEL_SERVER_WRITE_IV: &[u8] = b"ksp1 server write iv";
