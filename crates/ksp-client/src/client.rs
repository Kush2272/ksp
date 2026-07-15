//! KSP Client SDK API (`KspClient`).
//!
//! Provides a clean, reusable asynchronous client interface for connecting to
//! KSP servers, executing the full cryptographic handshake, and transferring data.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use ksp_core::capability::{Capabilities, CipherSuite};
use ksp_core::constants::HEADER_SIZE;
use ksp_core::error::KspError;
use ksp_core::packet::KspPacket;
use ksp_core::types::{Flags, PacketType};

use ksp_crypto::certificate::KspCertificate;
use ksp_crypto::kdf;
use ksp_crypto::x25519::EphemeralKeypair;

use ksp_handshake::auth::{AuthMethod, AuthResult};
use ksp_handshake::messages::{ClientHello, HandshakeFinish, ServerHello};

use ksp_transport::session::Session;

/// An authenticated, encrypted KSP client connection.
pub struct KspClient {
    /// The underlying TCP stream connected to the server.
    pub stream: TcpStream,
    /// The active cryptographic session state (keys, sequence counters, replay window).
    pub session: Session,
    /// The validated server certificate.
    pub server_cert: KspCertificate,
    /// The negotiated cipher suite.
    pub cipher_suite: CipherSuite,
}

impl KspClient {
    /// Read a single raw `KspPacket` from a TCP stream.
    pub async fn read_raw_packet(stream: &mut TcpStream) -> Result<(KspPacket, usize), KspError> {
        let mut header_buf = [0u8; HEADER_SIZE];
        match stream.read_exact(&mut header_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(KspError::ConnectionClosed);
            }
            Err(e) => return Err(e.into()),
        }

        let payload_length =
            u32::from_be_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]]);

        if payload_length > ksp_core::constants::MAX_PAYLOAD_SIZE {
            return Err(KspError::PayloadTooLarge {
                size: payload_length,
                max: ksp_core::constants::MAX_PAYLOAD_SIZE,
            });
        }

        let flags = Flags::from_bits_truncate(u16::from_be_bytes([header_buf[2], header_buf[3]]));
        let tag_size = if flags.contains(Flags::ENCRYPTED) {
            16
        } else {
            0
        };

        let remaining = payload_length as usize + tag_size;
        let mut payload_buf = vec![0u8; remaining];
        stream.read_exact(&mut payload_buf).await?;

        let mut full_buf = Vec::with_capacity(HEADER_SIZE + remaining);
        full_buf.extend_from_slice(&header_buf);
        full_buf.extend_from_slice(&payload_buf);

        ksp_core::record_pcap_if_active(&full_buf);
        KspPacket::deserialize(&full_buf)
    }

    /// Send a raw `KspPacket` across a TCP stream.
    pub async fn send_raw_packet(
        stream: &mut TcpStream,
        packet: &KspPacket,
    ) -> Result<(), KspError> {
        let bytes = packet.serialize();
        ksp_core::record_pcap_if_active(&bytes);
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Connect to a KSP server and perform the full cryptographic handshake.
    pub async fn connect(addr: SocketAddr) -> Result<Self, KspError> {
        info!("Connecting to KSP server at {}", addr);
        let mut stream = TcpStream::connect(addr).await?;
        info!("TCP connected to {}", addr);

        // ── Step 1: Send ClientHello ──
        let client_capabilities = ksp_core::capability::default_capabilities();
        let ephemeral_keypair = EphemeralKeypair::generate();
        let mut client_random = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut client_random);

        let client_hello = ClientHello {
            supported_versions: vec![ksp_core::CURRENT_VERSION],
            capabilities: client_capabilities,
            client_random,
            ephemeral_public_key: ephemeral_keypair.public_key_bytes(),
        };

        let hello_packet =
            KspPacket::new_handshake(PacketType::ClientHello, client_hello.serialize());
        Self::send_raw_packet(&mut stream, &hello_packet).await?;
        info!("Sent ClientHello");

        // ── Step 2: Receive ServerHello ──
        let (server_hello_packet, _) = Self::read_raw_packet(&mut stream).await?;
        if server_hello_packet.packet_type != PacketType::ServerHello {
            return Err(KspError::HandshakeError("expected ServerHello".into()));
        }
        let server_hello = ServerHello::deserialize(&server_hello_packet.payload)?;
        info!(
            "Received ServerHello: version={}, caps={}",
            server_hello.selected_version, server_hello.selected_capabilities
        );

        // ── Step 3: Receive Certificate & Binding Signature ──
        let (cert_packet, _) = Self::read_raw_packet(&mut stream).await?;
        if cert_packet.packet_type != PacketType::Certificate {
            return Err(KspError::HandshakeError("expected Certificate".into()));
        }
        let cert_payload = &cert_packet.payload;
        if cert_payload.len() < 64 {
            return Err(KspError::HandshakeError(
                "Certificate message truncated".into(),
            ));
        }
        let cert_bytes_len = cert_payload.len() - 64;
        let certificate = KspCertificate::deserialize(&cert_payload[..cert_bytes_len])?;
        let binding_signature_bytes: [u8; 64] = cert_payload[cert_bytes_len..].try_into().unwrap();

        // Verify certificate self-signed signature
        certificate.validate_self_signed()?;
        info!(
            "Server certificate identity validated: {}",
            certificate.subject
        );

        // Verify key-exchange binding signature
        let mut binding_data = Vec::with_capacity(32 * 4);
        binding_data.extend_from_slice(&client_random);
        binding_data.extend_from_slice(&server_hello.server_random);
        binding_data.extend_from_slice(&client_hello.ephemeral_public_key);
        binding_data.extend_from_slice(&server_hello.ephemeral_public_key);

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let verifying_key = VerifyingKey::from_bytes(&certificate.public_key)
            .map_err(|e| KspError::CertificateError(format!("invalid server public key: {}", e)))?;
        let signature = Signature::from_bytes(&binding_signature_bytes);
        verifying_key
            .verify(&binding_data, &signature)
            .map_err(|_| {
                KspError::CertificateError(
                    "MITM alert: server did not sign the key exchange".into(),
                )
            })?;
        info!("Cryptographic binding of key exchange verified!");

        // ── Step 4: Derive Session Keys ──
        let shared_secret = ephemeral_keypair.diffie_hellman(&server_hello.ephemeral_public_key)?;
        let derived_keys = kdf::derive_session_keys(
            shared_secret.as_bytes(),
            &client_random,
            &server_hello.server_random,
        )?;

        let cipher_suite = if server_hello
            .selected_capabilities
            .contains(Capabilities::AES_256_GCM)
        {
            CipherSuite::Aes256Gcm
        } else {
            CipherSuite::ChaCha20Poly1305
        };

        info!("Session keys derived, cipher={}", cipher_suite);

        // ── Step 5: Send AuthRequest ──
        let auth_method = AuthMethod::None;
        let auth_payload = auth_method.serialize();

        let mut session = Session::new(
            server_hello.session_id,
            server_hello.selected_version,
            server_hello.selected_capabilities,
            cipher_suite,
            derived_keys,
            true, // client side
        );

        let (seq, nonce) = session.send_nonce.next();
        let auth_packet = session.encrypt_packet(
            PacketType::AuthRequest,
            Flags::empty(),
            0,
            seq,
            nonce,
            &auth_payload,
        )?;
        Self::send_raw_packet(&mut stream, &auth_packet).await?;
        info!("Sent AuthRequest (encrypted)");

        // ── Step 6: Receive AuthResponse ──
        let (auth_response_packet, _) = Self::read_raw_packet(&mut stream).await?;
        if auth_response_packet.packet_type != PacketType::AuthResponse {
            return Err(KspError::HandshakeError("expected AuthResponse".into()));
        }
        let auth_response_payload = session.decrypt_packet(&auth_response_packet)?;
        let auth_result = AuthResult::deserialize(&auth_response_payload)?;
        if auth_result == AuthResult::Failed {
            return Err(KspError::HandshakeError(
                "server rejected authentication".into(),
            ));
        }
        info!("Authentication verified by server");

        // ── Step 7: Exchange HandshakeFinish ──
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&hello_packet.payload);
        transcript.extend_from_slice(&server_hello_packet.payload);
        transcript.extend_from_slice(cert_payload);

        let client_verify_data =
            ksp_crypto::compute_finished_mac(&session.keys.client_write_key, &transcript);
        let client_finish = HandshakeFinish {
            verify_data: client_verify_data,
        };
        let (seq, nonce) = session.send_nonce.next();
        let client_finish_packet = session.encrypt_packet(
            PacketType::HandshakeFinish,
            Flags::empty(),
            0,
            seq,
            nonce,
            &client_finish.serialize(),
        )?;
        Self::send_raw_packet(&mut stream, &client_finish_packet).await?;
        debug!("Sent client HandshakeFinish");

        let (server_finish_packet, _) = Self::read_raw_packet(&mut stream).await?;
        if server_finish_packet.packet_type != PacketType::HandshakeFinish {
            return Err(KspError::HandshakeError(
                "expected server HandshakeFinish".into(),
            ));
        }
        let server_finish_payload = session.decrypt_packet(&server_finish_packet)?;
        let server_finish = HandshakeFinish::deserialize(&server_finish_payload)?;

        let expected_server_verify =
            ksp_crypto::compute_finished_mac(&session.keys.server_write_key, &transcript);
        if server_finish.verify_data != expected_server_verify {
            return Err(KspError::HandshakeError(
                "server HandshakeFinish verification failed".into(),
            ));
        }
        info!("Server HandshakeFinish verified. Channel securely established!");

        Ok(Self {
            stream,
            session,
            server_cert: certificate,
            cipher_suite,
        })
    }

    /// Send an encrypted application data payload over a specific stream ID.
    pub async fn send_data(&mut self, stream_id: u32, payload: &[u8]) -> Result<(), KspError> {
        let (seq, nonce) = self.session.send_nonce.next();
        let data_packet = self.session.encrypt_packet(
            PacketType::Data,
            Flags::empty(),
            stream_id,
            seq,
            nonce,
            payload,
        )?;
        Self::send_raw_packet(&mut self.stream, &data_packet).await
    }

    /// Send any encrypted packet (e.g. StreamOpen, StreamClose, Ping/Data).
    pub async fn send_packet(
        &mut self,
        packet_type: PacketType,
        stream_id: u32,
        payload: &[u8],
    ) -> Result<(), KspError> {
        let (seq, nonce) = self.session.send_nonce.next();
        let packet = self.session.encrypt_packet(
            packet_type,
            Flags::empty(),
            stream_id,
            seq,
            nonce,
            payload,
        )?;
        Self::send_raw_packet(&mut self.stream, &packet).await
    }

    /// Read and decrypt an incoming packet from the server.
    pub async fn receive_packet(&mut self) -> Result<(KspPacket, Vec<u8>), KspError> {
        let (packet, _) = Self::read_raw_packet(&mut self.stream).await?;
        if packet.flags.contains(Flags::ENCRYPTED) {
            let plaintext = self.session.decrypt_packet(&packet)?;
            Ok((packet, plaintext))
        } else {
            Ok((packet.clone(), packet.payload))
        }
    }

    /// Gracefully close the KSP session by sending a GoAway frame.
    pub async fn close(&mut self) -> Result<(), KspError> {
        let goaway = KspPacket::new_handshake(PacketType::GoAway, Vec::new());
        let _ = Self::send_raw_packet(&mut self.stream, &goaway).await;
        info!("Session closed gracefully");
        Ok(())
    }
}
