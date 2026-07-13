//! # KSP Handshake
//!
//! Implements the KSP handshake protocol as defined in RFC-0001 Section 7:
//! - Handshake state machine with type-driven transitions
//! - Handshake message types (ClientHello, ServerHello, etc.)
//! - Authentication methods (password, API key, token, mutual)

pub mod auth;
pub mod messages;
pub mod state;

pub use auth::AuthMethod;
pub use messages::*;
pub use state::HandshakeState;
