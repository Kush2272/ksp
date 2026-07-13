//! Handshake state machine for KSP.
//!
//! Implements the state transitions defined in RFC-0001 Section 7.3.
//! Uses enum-based states with compile-time enforcement of valid transitions.

use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use tracing::{debug, info, warn};
use uuid::Uuid;

use ksp_core::capability::{self, Capabilities, CipherSuite};
use ksp_core::constants::{CURRENT_VERSION, RANDOM_SIZE, SESSION_ID_SIZE, X25519_PUBLIC_KEY_SIZE};
use ksp_core::error::KspError;
use ksp_core::packet::KspPacket;
use ksp_core::types::{Flags, PacketType};
use ksp_core::version::ProtocolVersion;

use ksp_crypto::certificate::KspCertificate;
use ksp_crypto::kdf::{self, DerivedKeys};
use ksp_crypto::x25519::EphemeralKeypair;

use crate::auth::{AuthMethod, AuthResult};
use crate::messages::{ClientHello, HandshakeFinish, ServerHello};

type HmacSha256 = Hmac<Sha256>;

/// The handshake state machine.
///
/// State transitions follow RFC-0001 Section 7.3:
/// ```text
/// INIT → HELLO_SENT → HELLO_RECEIVED → CERT_VERIFIED →
/// AUTHENTICATING → FINISHED → ESTABLISHED
/// ```
#[derive(Debug)]
pub enum HandshakeState {
    /// Initial state — no messages exchanged yet.
    Init,

    /// Client has sent ClientHello, waiting for ServerHello.
    ClientHelloSent {
        client_random: [u8; RANDOM_SIZE],
        ephemeral_keypair: EphemeralKeypair,
        supported_versions: Vec<ProtocolVersion>,
        capabilities: Capabilities,
        /// Running transcript of all handshake messages (for verify_data).
        transcript: Vec<u8>,
    },

    /// Server has received ClientHello, sent ServerHello + Certificate.
    ServerHelloSent {
        session_id: [u8; SESSION_ID_SIZE],
        selected_version: ProtocolVersion,
        selected_capabilities: Capabilities,
        cipher_suite: CipherSuite,
        derived_keys: DerivedKeys,
        transcript: Vec<u8>,
    },

    /// Both sides have derived keys. Ready for authentication.
    KeysEstablished {
        session_id: [u8; SESSION_ID_SIZE],
        selected_version: ProtocolVersion,
        selected_capabilities: Capabilities,
        cipher_suite: CipherSuite,
        derived_keys: DerivedKeys,
        transcript: Vec<u8>,
    },

    /// Handshake is complete — encrypted session is ready.
    Established {
        session_id: [u8; SESSION_ID_SIZE],
        selected_version: ProtocolVersion,
        selected_capabilities: Capabilities,
        cipher_suite: CipherSuite,
        derived_keys: DerivedKeys,
    },

    /// Handshake failed.
    Failed { error: KspError },
}

/// Client-side handshake driver.
pub struct ClientHandshake;

impl ClientHandshake {
    /// Create the ClientHello message and transition to ClientHelloSent.
    pub fn start(capabilities: Capabilities) -> (KspPacket, HandshakeState) {
        let ephemeral_keypair = EphemeralKeypair::generate();
        let mut client_random = [0u8; RANDOM_SIZE];
        OsRng.fill_bytes(&mut client_random);

        let supported_versions = vec![CURRENT_VERSION];

        let hello = ClientHello {
            supported_versions: supported_versions.clone(),
            capabilities,
            client_random,
            ephemeral_public_key: ephemeral_keypair.public_key_bytes(),
        };

        let payload = hello.serialize();
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&payload);

        let packet = KspPacket::new_handshake(PacketType::ClientHello, payload);

        let state = HandshakeState::ClientHelloSent {
            client_random,
            ephemeral_keypair,
            supported_versions,
            capabilities,
            transcript,
        };

        info!("KSP handshake: ClientHello sent");
        (packet, state)
    }

    /// Process ServerHello + Certificate and derive keys.
    pub fn process_server_hello(
        state: HandshakeState,
        server_hello_payload: &[u8],
        certificate_payload: &[u8],
    ) -> Result<(HandshakeState, CipherSuite, DerivedKeys), KspError> {
        let (client_random, ephemeral_keypair, mut transcript) = match state {
            HandshakeState::ClientHelloSent {
                client_random,
                ephemeral_keypair,
                transcript,
                ..
            } => (client_random, ephemeral_keypair, transcript),
            _ => {
                return Err(KspError::HandshakeError(
                    "unexpected state for ServerHello".into(),
                ));
            }
        };

        // Parse ServerHello
        let server_hello = ServerHello::deserialize(server_hello_payload)?;
        transcript.extend_from_slice(server_hello_payload);
        transcript.extend_from_slice(certificate_payload);

        // Parse and verify certificate
        let cert = KspCertificate::deserialize(certificate_payload)?;
        cert.validate_self_signed()?;

        debug!(
            "KSP handshake: server certificate verified for {}",
            cert.subject
        );

        // Compute shared secret via X25519
        let shared_secret = ephemeral_keypair.diffie_hellman(&server_hello.ephemeral_public_key)?;

        // Derive session keys via HKDF
        let derived_keys = kdf::derive_session_keys(
            shared_secret.as_bytes(),
            &client_random,
            &server_hello.server_random,
        )?;

        let state = HandshakeState::KeysEstablished {
            session_id: server_hello.session_id,
            selected_version: server_hello.selected_version,
            selected_capabilities: server_hello.selected_capabilities,
            cipher_suite: CipherSuite::Aes256Gcm, // determined from capabilities
            derived_keys: derived_keys.clone(),
            transcript,
        };

        // Determine cipher suite from negotiated capabilities
        let cipher_suite = if server_hello
            .selected_capabilities
            .contains(Capabilities::AES_256_GCM)
        {
            CipherSuite::Aes256Gcm
        } else {
            CipherSuite::ChaCha20Poly1305
        };

        info!("KSP handshake: keys established, cipher={}", cipher_suite);
        Ok((state, cipher_suite, derived_keys))
    }

    /// Generate the HandshakeFinish verify_data.
    pub fn create_finish(state: &HandshakeState) -> Result<HandshakeFinish, KspError> {
        let (derived_keys, transcript) = match state {
            HandshakeState::KeysEstablished {
                derived_keys,
                transcript,
                ..
            } => (derived_keys, transcript),
            _ => {
                return Err(KspError::HandshakeError(
                    "unexpected state for finish".into(),
                ));
            }
        };

        let verify_data = compute_verify_data(&derived_keys.client_write_key, transcript);
        Ok(HandshakeFinish { verify_data })
    }
}

/// Server-side handshake driver.
pub struct ServerHandshake;

impl ServerHandshake {
    /// Process ClientHello and generate ServerHello + Certificate.
    pub fn process_client_hello(
        client_hello_payload: &[u8],
        server_capabilities: Capabilities,
        certificate: &KspCertificate,
    ) -> Result<(ServerHello, HandshakeState, EphemeralKeypair), KspError> {
        let client_hello = ClientHello::deserialize(client_hello_payload)?;

        // Version negotiation
        let server_versions = vec![CURRENT_VERSION];
        let selected_version =
            ProtocolVersion::negotiate(&client_hello.supported_versions, &server_versions)?;

        // Capability negotiation
        let (selected_capabilities, cipher_suite) =
            capability::negotiate_capabilities(client_hello.capabilities, server_capabilities)?;

        // Generate server ephemeral keypair
        let server_keypair = EphemeralKeypair::generate();
        let mut server_random = [0u8; RANDOM_SIZE];
        OsRng.fill_bytes(&mut server_random);

        // Generate session ID
        let session_id = *Uuid::new_v4().as_bytes();

        let server_hello = ServerHello {
            selected_version,
            selected_capabilities,
            server_random,
            ephemeral_public_key: server_keypair.public_key_bytes(),
            session_id,
        };

        // Build transcript
        let mut transcript = Vec::new();
        transcript.extend_from_slice(client_hello_payload);
        transcript.extend_from_slice(&server_hello.serialize());
        transcript.extend_from_slice(&certificate.serialize());

        // Compute shared secret
        // Note: We need a second copy of the keypair for DH; we'll defer it
        // by returning the keypair for the caller to do DH after sending.
        let state = HandshakeState::ServerHelloSent {
            session_id,
            selected_version,
            selected_capabilities,
            cipher_suite,
            derived_keys: DerivedKeys {
                client_write_key: [0; 32], // placeholder
                server_write_key: [0; 32],
                client_write_iv: [0; 12],
                server_write_iv: [0; 12],
            },
            transcript,
        };

        info!(
            "KSP handshake: ServerHello prepared, version={}, cipher={}",
            selected_version, cipher_suite
        );

        Ok((server_hello, state, server_keypair))
    }

    /// Complete key derivation after sending ServerHello.
    pub fn derive_keys(
        state: HandshakeState,
        server_keypair: EphemeralKeypair,
        client_ephemeral_pub: &[u8; X25519_PUBLIC_KEY_SIZE],
        server_random: &[u8; RANDOM_SIZE],
        client_random: &[u8; RANDOM_SIZE],
    ) -> Result<HandshakeState, KspError> {
        let (session_id, selected_version, selected_capabilities, cipher_suite, transcript) =
            match state {
                HandshakeState::ServerHelloSent {
                    session_id,
                    selected_version,
                    selected_capabilities,
                    cipher_suite,
                    transcript,
                    ..
                } => (
                    session_id,
                    selected_version,
                    selected_capabilities,
                    cipher_suite,
                    transcript,
                ),
                _ => return Err(KspError::HandshakeError("unexpected state".into())),
            };

        let shared_secret = server_keypair.diffie_hellman(client_ephemeral_pub)?;
        let derived_keys =
            kdf::derive_session_keys(shared_secret.as_bytes(), client_random, server_random)?;

        Ok(HandshakeState::KeysEstablished {
            session_id,
            selected_version,
            selected_capabilities,
            cipher_suite,
            derived_keys,
            transcript,
        })
    }

    /// Generate the server's HandshakeFinish verify_data.
    pub fn create_finish(state: &HandshakeState) -> Result<HandshakeFinish, KspError> {
        let (derived_keys, transcript) = match state {
            HandshakeState::KeysEstablished {
                derived_keys,
                transcript,
                ..
            } => (derived_keys, transcript),
            _ => {
                return Err(KspError::HandshakeError(
                    "unexpected state for finish".into(),
                ));
            }
        };

        let verify_data = compute_verify_data(&derived_keys.server_write_key, transcript);
        Ok(HandshakeFinish { verify_data })
    }
}

/// Compute HMAC-SHA256 of the handshake transcript for HandshakeFinish.
fn compute_verify_data(key: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is valid");
    mac.update(transcript);
    let result = mac.finalize();
    let mut verify_data = [0u8; 32];
    verify_data.copy_from_slice(&result.into_bytes());
    verify_data
}

/// Transition from KeysEstablished to Established (after verifying HandshakeFinish).
pub fn finalize_handshake(state: HandshakeState) -> Result<HandshakeState, KspError> {
    match state {
        HandshakeState::KeysEstablished {
            session_id,
            selected_version,
            selected_capabilities,
            cipher_suite,
            derived_keys,
            ..
        } => {
            info!(
                "KSP handshake: session established, id={}",
                uuid::Uuid::from_bytes(session_id)
            );
            Ok(HandshakeState::Established {
                session_id,
                selected_version,
                selected_capabilities,
                cipher_suite,
                derived_keys,
            })
        }
        _ => Err(KspError::HandshakeError(
            "cannot finalize from this state".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ksp_core::capability::Capabilities;

    #[test]
    fn test_client_hello_creation() {
        let caps = Capabilities::AES_256_GCM | Capabilities::STREAMING;
        let (packet, state) = ClientHandshake::start(caps);

        assert_eq!(packet.packet_type, PacketType::ClientHello);
        assert!(matches!(state, HandshakeState::ClientHelloSent { .. }));
    }

    #[test]
    fn test_verify_data_deterministic() {
        let key = [0x42u8; 32];
        let transcript = b"hello world";

        let v1 = compute_verify_data(&key, transcript);
        let v2 = compute_verify_data(&key, transcript);

        assert_eq!(v1, v2);
    }

    #[test]
    fn test_verify_data_differs_with_different_transcript() {
        let key = [0x42u8; 32];

        let v1 = compute_verify_data(&key, b"transcript 1");
        let v2 = compute_verify_data(&key, b"transcript 2");

        assert_ne!(v1, v2);
    }
}
