//! Session state management for KSP.
//!
//! A session encapsulates all state for an encrypted KSP connection.

use std::time::Instant;

use ksp_core::capability::{Capabilities, CipherSuite};
use ksp_core::constants::SESSION_ID_SIZE;
use ksp_core::version::ProtocolVersion;

use ksp_crypto::kdf::DerivedKeys;
use ksp_crypto::nonce::NonceGenerator;

use crate::flow_control::ConnectionFlowControl;
use crate::keepalive::KeepaliveTracker;
use crate::replay::ReplayWindow;
use crate::stream::StreamManager;

/// A KSP session — the top-level state for an encrypted connection.
pub struct Session {
    /// Unique session identifier (UUID v4).
    pub id: [u8; SESSION_ID_SIZE],
    /// Negotiated protocol version.
    pub version: ProtocolVersion,
    /// Negotiated capabilities.
    pub capabilities: Capabilities,
    /// Selected cipher suite.
    pub cipher_suite: CipherSuite,
    /// Session encryption keys.
    pub keys: DerivedKeys,
    /// Nonce generator for our outgoing packets.
    pub send_nonce: NonceGenerator,
    /// Replay window for incoming packets.
    pub recv_replay: ReplayWindow,
    /// Stream manager for multiplexed streams.
    pub streams: StreamManager,
    /// Connection-level flow control.
    pub flow_control: ConnectionFlowControl,
    /// Keep-alive tracker.
    pub keepalive: KeepaliveTracker,
    /// When this session was established.
    pub created_at: Instant,
    /// Whether this is the client side (affects which keys to use for send/recv).
    pub is_client: bool,
}

impl Session {
    /// Create a new session from handshake results.
    pub fn new(
        id: [u8; SESSION_ID_SIZE],
        version: ProtocolVersion,
        capabilities: Capabilities,
        cipher_suite: CipherSuite,
        keys: DerivedKeys,
        is_client: bool,
    ) -> Self {
        // Client sends with client_write_iv, server sends with server_write_iv
        let send_iv = if is_client {
            keys.client_write_iv
        } else {
            keys.server_write_iv
        };

        Self {
            id,
            version,
            capabilities,
            cipher_suite,
            keys,
            send_nonce: NonceGenerator::new(send_iv),
            recv_replay: ReplayWindow::new(),
            streams: StreamManager::new(),
            flow_control: ConnectionFlowControl::new(),
            keepalive: KeepaliveTracker::new(),
            created_at: Instant::now(),
            is_client,
        }
    }

    /// Get the encryption key for outgoing packets.
    pub fn send_key(&self) -> &[u8; 32] {
        if self.is_client {
            &self.keys.client_write_key
        } else {
            &self.keys.server_write_key
        }
    }

    /// Get the decryption key for incoming packets.
    pub fn recv_key(&self) -> &[u8; 32] {
        if self.is_client {
            &self.keys.server_write_key
        } else {
            &self.keys.client_write_key
        }
    }

    /// Get the IV for verifying incoming nonces.
    pub fn recv_iv(&self) -> &[u8; 12] {
        if self.is_client {
            &self.keys.server_write_iv
        } else {
            &self.keys.client_write_iv
        }
    }

    /// How long this session has been active.
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Whether this session has exceeded its timeout.
    pub fn is_expired(&self) -> bool {
        self.age() > ksp_core::constants::SESSION_TIMEOUT
    }

    /// Session ID as a UUID string.
    pub fn id_string(&self) -> String {
        uuid::Uuid::from_bytes(self.id).to_string()
    }

    /// Encrypt a payload and construct a KSP packet.
    pub fn encrypt_packet(
        &self,
        packet_type: ksp_core::PacketType,
        flags: ksp_core::Flags,
        stream_id: u32,
        sequence: u64,
        nonce: [u8; 12],
        plaintext: &[u8],
    ) -> Result<ksp_core::KspPacket, ksp_core::KspError> {
        let ciphertext_len = plaintext.len();
        let mut temp_packet = ksp_core::KspPacket::new(
            self.version,
            packet_type,
            flags | ksp_core::Flags::ENCRYPTED,
            self.id,
            stream_id,
            sequence,
            nonce,
            vec![0; ciphertext_len],
            vec![0; 16],
        );
        let aad = temp_packet.header_bytes();

        let (ciphertext, tag) =
            ksp_crypto::aead::encrypt(self.cipher_suite, self.send_key(), &nonce, plaintext, &aad)?;

        temp_packet.payload = ciphertext;
        temp_packet.auth_tag = tag.to_vec();

        Ok(temp_packet)
    }

    /// Decrypt a KSP packet, verifying sequence (replay check) and expected nonce.
    pub fn decrypt_packet(
        &mut self,
        packet: &ksp_core::KspPacket,
    ) -> Result<Vec<u8>, ksp_core::KspError> {
        if !packet.flags.contains(ksp_core::Flags::ENCRYPTED) {
            return Err(ksp_core::KspError::CryptoError(
                "packet is not encrypted".into(),
            ));
        }

        // Verify the nonce matches what we expect for this sequence number
        let expected_nonce = self.construct_expected_nonce(packet.sequence);
        if packet.nonce != expected_nonce {
            return Err(ksp_core::KspError::CryptoError("nonce mismatch".into()));
        }

        // Check for replay and update sliding window
        self.recv_replay.check_and_update(packet.sequence)?;

        let tag: [u8; 16] = packet
            .auth_tag
            .as_slice()
            .try_into()
            .map_err(|_| ksp_core::KspError::CryptoError("invalid auth tag length".into()))?;

        ksp_crypto::aead::decrypt(
            self.cipher_suite,
            self.recv_key(),
            &packet.nonce,
            &packet.payload,
            &tag,
            &packet.header_bytes(),
        )
    }

    /// Construct expected nonce from recv_iv and sequence.
    pub fn construct_expected_nonce(&self, sequence: u64) -> [u8; 12] {
        let mut nonce = *self.recv_iv();
        let seq_bytes = sequence.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }
}
