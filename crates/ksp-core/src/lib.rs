//! # KSP Core
//!
//! Core types, packet format, and binary encoding for the Kush Secure Protocol.
//!
//! This crate defines the foundational data structures shared across all KSP components:
//! - Binary packet format with serialization/deserialization
//! - Packet types, flags, and capability negotiation
//! - Protocol versioning and version negotiation
//! - Error types and error codes
//! - Protocol constants

pub mod capability;
pub mod constants;
pub mod error;
pub mod packet;
pub mod types;
pub mod version;

pub use capability::Capabilities;
pub use constants::*;
pub use error::{ErrorCode, KspError, Result};
pub use packet::KspPacket;
pub use types::{Flags, PacketType};
pub use version::ProtocolVersion;
