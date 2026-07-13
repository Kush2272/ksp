//! KSP Server — async TCP server with encrypted session handling.
//!
//! Accepts connections, performs the KSP handshake, and manages
//! encrypted sessions with stream multiplexing.

use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use ksp_core::capability::{self, Capabilities, CipherSuite};
use ksp_core::constants::{DEFAULT_PORT, HEADER_SIZE};
use ksp_core::error::KspError;
use ksp_core::packet::KspPacket;
use ksp_core::types::{Flags, PacketType};

use ksp_crypto::aead::{self, create_cipher};
use ksp_crypto::certificate::KspCertificate;
use ksp_crypto::kdf;
use ksp_crypto::nonce::NonceGenerator;
use ksp_crypto::x25519::EphemeralKeypair;

use ksp_handshake::auth::{AuthMethod, AuthResult};
use ksp_handshake::messages::{ClientHello, HandshakeFinish, ServerHello};

use ksp_transport::replay::ReplayWindow;
use ksp_transport::session::Session;

/// KSP Server configuration.
pub struct ServerConfig {
    /// Address to bind to.
    pub bind_addr: SocketAddr,
    /// Server capabilities.
    pub capabilities: Capabilities,
    /// Server certificate and signing key.
    pub certificate: KspCertificate,
    /// Signing key for the certificate.
    pub signing_key: ed25519_dalek::SigningKey,
}

/// Start the KSP server.
pub async fn run_server(config: ServerConfig) -> Result<(), KspError> {
    let listener = TcpListener::bind(config.bind_addr).await?;
    info!("KSP server listening on {}", config.bind_addr);
    info!("Certificate: {}", config.certificate);
    info!("Capabilities: {}", config.capabilities);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New connection from {}", addr);
                let cert = config.certificate.clone();
                let caps = config.capabilities;
                let key = config.signing_key.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, addr, cert, caps, key).await {
                        warn!("Connection from {} failed: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

/// Handle a single KSP connection.
async fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    certificate: KspCertificate,
    server_capabilities: Capabilities,
    signing_key: ed25519_dalek::SigningKey,
) -> Result<(), KspError> {
    // ── Step 1: Receive ClientHello ──
    let (client_hello_packet, _) = read_packet(&mut stream).await?;
    if client_hello_packet.packet_type != PacketType::ClientHello {
        return Err(KspError::HandshakeError("expected ClientHello".into()));
    }
    let client_hello = ClientHello::deserialize(&client_hello_packet.payload)?;
    debug!(
        "Received ClientHello from {}: versions={:?}, caps={}",
        addr, client_hello.supported_versions, client_hello.capabilities
    );

    // ── Step 2: Version + Capability negotiation ──
    let selected_version = ksp_core::version::ProtocolVersion::negotiate(
        &client_hello.supported_versions,
        &[ksp_core::CURRENT_VERSION],
    )?;
    let (selected_caps, cipher_suite) =
        capability::negotiate_capabilities(client_hello.capabilities, server_capabilities)?;

    // ── Step 3: Generate server ephemeral keypair ──
    let server_keypair = EphemeralKeypair::generate();
    let mut server_random = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_random);
    let session_id = *uuid::Uuid::new_v4().as_bytes();

    let server_hello = ServerHello {
        selected_version,
        selected_capabilities: selected_caps,
        server_random,
        ephemeral_public_key: server_keypair.public_key_bytes(),
        session_id,
    };

    // ── Step 4: Send ServerHello ──
    let server_hello_packet =
        KspPacket::new_handshake(PacketType::ServerHello, server_hello.serialize());
    send_packet(&mut stream, &server_hello_packet).await?;
    debug!(
        "Sent ServerHello: version={}, cipher={}",
        selected_version, cipher_suite
    );

    // ── Step 5: Send Certificate (with key-exchange binding signature) ──
    let mut binding_data = Vec::with_capacity(32 * 4);
    binding_data.extend_from_slice(&client_hello.client_random);
    binding_data.extend_from_slice(&server_random);
    binding_data.extend_from_slice(&client_hello.ephemeral_public_key);
    binding_data.extend_from_slice(&server_hello.ephemeral_public_key);

    use ed25519_dalek::Signer;
    let binding_signature = signing_key.sign(&binding_data).to_bytes();

    let mut cert_payload = certificate.serialize();
    cert_payload.extend_from_slice(&binding_signature);

    let cert_packet = KspPacket::new_handshake(PacketType::Certificate, cert_payload.clone());
    send_packet(&mut stream, &cert_packet).await?;
    debug!("Sent Certificate with cryptographic binding to key exchange");

    // ── Step 6: Compute shared secret and derive keys ──
    let shared_secret = server_keypair.diffie_hellman(&client_hello.ephemeral_public_key)?;
    let derived_keys = kdf::derive_session_keys(
        shared_secret.as_bytes(),
        &client_hello.client_random,
        &server_random,
    )?;
    info!("Session keys derived for {}", addr);

    // ── Step 7: Create session ──
    let mut session = Session::new(
        session_id,
        selected_version,
        selected_caps,
        cipher_suite,
        derived_keys,
        false, // server side
    );

    // ── Step 8: Receive AuthRequest (encrypted) ──
    let (auth_packet, _) = read_packet(&mut stream).await?;
    if auth_packet.packet_type == PacketType::AuthRequest {
        let plaintext = session.decrypt_packet(&auth_packet)?;
        let auth_method = AuthMethod::deserialize(&plaintext)?;
        debug!("Received auth request: method=0x{:02X}", auth_method.code());

        // Real authentication check
        let auth_result = match auth_method {
            AuthMethod::None => AuthResult::Success,
            AuthMethod::ApiKey { key } => {
                if key == b"secret_ksp_key" {
                    AuthResult::Success
                } else {
                    AuthResult::Failed
                }
            }
            AuthMethod::Password {
                username,
                password_hash,
            } => {
                if username == "kush" && password_hash == b"secret_hash" {
                    AuthResult::Success
                } else {
                    AuthResult::Failed
                }
            }
            AuthMethod::Token { token } => {
                if token == b"secret_token" {
                    AuthResult::Success
                } else {
                    AuthResult::Failed
                }
            }
            _ => AuthResult::Failed,
        };

        // Encrypt and send AuthResponse
        let (seq, nonce) = session.send_nonce.next();
        let auth_response_packet = session.encrypt_packet(
            PacketType::AuthResponse,
            Flags::empty(),
            0,
            seq,
            nonce,
            &auth_result.serialize(),
        )?;
        send_packet(&mut stream, &auth_response_packet).await?;

        if auth_result == AuthResult::Failed {
            warn!("Authentication failed for {}", addr);
            return Err(KspError::ProtocolError {
                code: ksp_core::ErrorCode::AuthFailed,
            });
        }
        debug!("Sent AuthResponse: Success");
    }

    // ── Step 9: Exchange HandshakeFinish ──
    // Build the transcript (ClientHello + ServerHello + Certificate)
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&client_hello_packet.payload);
    transcript.extend_from_slice(&server_hello_packet.payload);
    transcript.extend_from_slice(&cert_payload); // using the cert payload with signature

    // Receive client's HandshakeFinish
    let (client_finish_packet, _) = read_packet(&mut stream).await?;
    if client_finish_packet.packet_type != PacketType::HandshakeFinish {
        return Err(KspError::HandshakeError("expected HandshakeFinish".into()));
    }
    let client_finish_payload = session.decrypt_packet(&client_finish_packet)?;
    let client_finish = HandshakeFinish::deserialize(&client_finish_payload)?;

    // Verify client's verify_data
    let expected_client_verify =
        ksp_crypto::compute_finished_mac(&session.keys.client_write_key, &transcript);
    if client_finish.verify_data != expected_client_verify {
        return Err(KspError::HandshakeError(
            "client HandshakeFinish verification failed".into(),
        ));
    }
    debug!("Client HandshakeFinish verified");

    // Send server's HandshakeFinish
    let server_verify_data =
        ksp_crypto::compute_finished_mac(&session.keys.server_write_key, &transcript);
    let server_finish = HandshakeFinish {
        verify_data: server_verify_data,
    };
    let (seq, nonce) = session.send_nonce.next();
    let server_finish_packet = session.encrypt_packet(
        PacketType::HandshakeFinish,
        Flags::empty(),
        0,
        seq,
        nonce,
        &server_finish.serialize(),
    )?;
    send_packet(&mut stream, &server_finish_packet).await?;
    debug!("Sent Server HandshakeFinish");

    info!(
        "Session established: id={}, cipher={}, version={}",
        session.id_string(),
        cipher_suite,
        selected_version
    );

    // ── Step 10: Data loop (echo server) ──
    loop {
        let (packet, _) = match read_packet(&mut stream).await {
            Ok(p) => p,
            Err(KspError::ConnectionClosed) => {
                info!("Client {} disconnected", addr);
                break;
            }
            Err(e) => {
                warn!("Error reading from {}: {}", addr, e);
                break;
            }
        };

        match packet.packet_type {
            PacketType::Data | PacketType::StreamData => {
                // Decrypt, verify nonce and sequence replay check using Session helper
                let plaintext = session.decrypt_packet(&packet)?;

                debug!(
                    "Received {} bytes on stream {} from {}",
                    plaintext.len(),
                    packet.stream_id,
                    addr
                );

                // Echo: encrypt and send back using Session helper
                let (seq, nonce) = session.send_nonce.next();
                let response = session.encrypt_packet(
                    PacketType::Data,
                    Flags::empty(),
                    packet.stream_id,
                    seq,
                    nonce,
                    &plaintext,
                )?;
                send_packet(&mut stream, &response).await?;
            }
            PacketType::KeepAlive => {
                // Respond with KeepAliveAck
                let ack = KspPacket::new_handshake(PacketType::KeepAliveAck, Vec::new());
                send_packet(&mut stream, &ack).await?;
                session.keepalive.record_activity();
            }
            PacketType::GoAway => {
                info!("Received GoAway from {}", addr);
                break;
            }
            _ => {
                debug!("Ignoring packet type {} from {}", packet.packet_type, addr);
            }
        }
    }

    info!("Connection closed: {}", addr);
    Ok(())
}

/// Read a single KSP packet from a TCP stream.
async fn read_packet(stream: &mut TcpStream) -> Result<(KspPacket, usize), KspError> {
    // Read header first
    let mut header_buf = [0u8; HEADER_SIZE];
    match stream.read_exact(&mut header_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(KspError::ConnectionClosed);
        }
        Err(e) => return Err(e.into()),
    }

    // Parse payload length from header
    let payload_length =
        u32::from_be_bytes([header_buf[4], header_buf[5], header_buf[6], header_buf[7]]);

    // Prevent OOM memory allocation DoS
    if payload_length > ksp_core::constants::MAX_PAYLOAD_SIZE {
        return Err(KspError::PayloadTooLarge {
            size: payload_length,
            max: ksp_core::constants::MAX_PAYLOAD_SIZE,
        });
    }

    // Check if encrypted (has auth tag)
    let flags = ksp_core::types::Flags::from_bits_truncate(u16::from_be_bytes([
        header_buf[2],
        header_buf[3],
    ]));
    let tag_size = if flags.contains(Flags::ENCRYPTED) {
        16
    } else {
        0
    };

    // Read payload + tag
    let remaining = payload_length as usize + tag_size;
    let mut payload_buf = vec![0u8; remaining];
    stream.read_exact(&mut payload_buf).await?;

    // Combine and deserialize
    let mut full_buf = Vec::with_capacity(HEADER_SIZE + remaining);
    full_buf.extend_from_slice(&header_buf);
    full_buf.extend_from_slice(&payload_buf);

    KspPacket::deserialize(&full_buf)
}

/// Send a KSP packet over a TCP stream.
async fn send_packet(stream: &mut TcpStream, packet: &KspPacket) -> Result<(), KspError> {
    let bytes = packet.serialize();
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

fn load_or_generate_cert()
-> Result<(KspCertificate, ed25519_dalek::SigningKey), Box<dyn std::error::Error>> {
    let cert_path = std::path::Path::new("server.cert");
    let key_path = std::path::Path::new("server.key");

    if cert_path.exists() && key_path.exists() {
        info!("Loading existing certificate and key from files...");
        let cert_bytes = std::fs::read(cert_path)?;
        let key_bytes = std::fs::read(key_path)?;
        let certificate = KspCertificate::deserialize(&cert_bytes)?;
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| KspError::CertificateError("invalid key length".into()))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
        Ok((certificate, signing_key))
    } else {
        info!("Generating new self-signed certificate and key...");
        let (certificate, signing_key) =
            KspCertificate::generate_self_signed("ksp://localhost", 365);
        std::fs::write(cert_path, certificate.serialize())?;
        std::fs::write(key_path, signing_key.to_bytes())?;
        info!("Saved certificate to server.cert and key to server.key");
        Ok((certificate, signing_key))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load or generate a persistent self-signed certificate
    let (certificate, signing_key) = load_or_generate_cert()?;

    let config = ServerConfig {
        bind_addr: format!("0.0.0.0:{}", DEFAULT_PORT).parse().unwrap(),
        capabilities: ksp_core::capability::default_capabilities(),
        certificate,
        signing_key,
    };

    info!("Starting KSP server on port {}", DEFAULT_PORT);
    run_server(config).await?;

    Ok(())
}
