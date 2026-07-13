//! KSP Client — connects to a KSP server, performs handshake, and sends encrypted data.

use std::net::SocketAddr;

use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info};

use ksp_core::capability::{Capabilities, CipherSuite};
use ksp_core::constants::{DEFAULT_PORT, HEADER_SIZE};
use ksp_core::error::KspError;
use ksp_core::packet::KspPacket;
use ksp_core::types::{Flags, PacketType};

use ksp_crypto::certificate::KspCertificate;
use ksp_crypto::kdf;
use ksp_crypto::x25519::EphemeralKeypair;

use ksp_handshake::auth::{AuthMethod, AuthResult};
use ksp_handshake::messages::{ClientHello, HandshakeFinish, ServerHello};

use ksp_transport::session::Session;

/// Read a single KSP packet from a TCP stream.
async fn read_packet(stream: &mut TcpStream) -> Result<(KspPacket, usize), KspError> {
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

    // Prevent OOM memory allocation DoS
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

    KspPacket::deserialize(&full_buf)
}

/// Send a KSP packet over a TCP stream.
async fn send_packet(stream: &mut TcpStream, packet: &KspPacket) -> Result<(), KspError> {
    let bytes = packet.serialize();
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr: SocketAddr = format!("127.0.0.1:{}", DEFAULT_PORT).parse().unwrap();
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

    let hello_packet = KspPacket::new_handshake(PacketType::ClientHello, client_hello.serialize());
    send_packet(&mut stream, &hello_packet).await?;
    info!("Sent ClientHello");

    // ── Step 2: Receive ServerHello ──
    let (server_hello_packet, _) = read_packet(&mut stream).await?;
    if server_hello_packet.packet_type != PacketType::ServerHello {
        return Err(KspError::HandshakeError("expected ServerHello".into()).into());
    }
    let server_hello = ServerHello::deserialize(&server_hello_packet.payload)?;
    info!(
        "Received ServerHello: version={}, caps={}",
        server_hello.selected_version, server_hello.selected_capabilities
    );

    // ── Step 3: Receive Certificate (and key-exchange binding signature) ──
    let (cert_packet, _) = read_packet(&mut stream).await?;
    if cert_packet.packet_type != PacketType::Certificate {
        return Err(KspError::HandshakeError("expected Certificate".into()).into());
    }
    let cert_payload = &cert_packet.payload;
    if cert_payload.len() < 64 {
        return Err(KspError::HandshakeError("Certificate message truncated".into()).into());
    }
    let cert_bytes_len = cert_payload.len() - 64;
    let certificate = KspCertificate::deserialize(&cert_payload[..cert_bytes_len])?;
    let binding_signature_bytes: [u8; 64] = cert_payload[cert_bytes_len..].try_into().unwrap();

    // Verify certificate validity
    certificate.validate_self_signed()?;
    info!(
        "Server certificate identity validated: {}",
        certificate.subject
    );

    // Verify the server's signature binds the cert to this specific key exchange
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
            KspError::CertificateError("MITM alert: server did not sign the key exchange".into())
        })?;
    info!("Cryptographic binding of key exchange verified!");

    // ── Step 4: Compute shared secret and derive keys ──
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
    send_packet(&mut stream, &auth_packet).await?;
    info!("Sent AuthRequest (encrypted)");

    // ── Step 6: Receive AuthResponse ──
    let (auth_response_packet, _) = read_packet(&mut stream).await?;
    if auth_response_packet.packet_type != PacketType::AuthResponse {
        return Err(KspError::HandshakeError("expected AuthResponse".into()).into());
    }
    let auth_response_payload = session.decrypt_packet(&auth_response_packet)?;
    let auth_result = AuthResult::deserialize(&auth_response_payload)?;
    if auth_result == AuthResult::Failed {
        return Err(KspError::HandshakeError("server rejected authentication".into()).into());
    }
    info!("Authentication verified by server");

    // ── Step 7: Exchange HandshakeFinish ──
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&hello_packet.payload);
    transcript.extend_from_slice(&server_hello_packet.payload);
    transcript.extend_from_slice(cert_payload); // using the cert payload with signature

    // Send client HandshakeFinish
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
    send_packet(&mut stream, &client_finish_packet).await?;
    debug!("Sent client HandshakeFinish");

    // Receive and verify server HandshakeFinish
    let (server_finish_packet, _) = read_packet(&mut stream).await?;
    if server_finish_packet.packet_type != PacketType::HandshakeFinish {
        return Err(KspError::HandshakeError("expected server HandshakeFinish".into()).into());
    }
    let server_finish_payload = session.decrypt_packet(&server_finish_packet)?;
    let server_finish = HandshakeFinish::deserialize(&server_finish_payload)?;

    let expected_server_verify =
        ksp_crypto::compute_finished_mac(&session.keys.server_write_key, &transcript);
    if server_finish.verify_data != expected_server_verify {
        return Err(
            KspError::HandshakeError("server HandshakeFinish verification failed".into()).into(),
        );
    }
    info!("Server HandshakeFinish verified. Channel securely established!");

    // ── Step 8: Interactive data loop ──
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║           KSP Encrypted Session Active           ║");
    println!("║  Session: {}  ║", session.id_string());
    println!("║  Cipher:  {:41}║", format!("{}", cipher_suite));
    println!(
        "║  Version: {:41}║",
        format!("{}", server_hello.selected_version)
    );
    println!("╚══════════════════════════════════════════════════╝");
    println!("\nType messages to send (encrypted). Press Ctrl+C to exit.\n");

    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.is_empty() {
            continue;
        }

        // Encrypt and send using Session helper
        let (seq, nonce) = session.send_nonce.next();
        let data_packet = session.encrypt_packet(
            PacketType::Data,
            Flags::empty(),
            1,
            seq,
            nonce,
            line.as_bytes(),
        )?;
        send_packet(&mut stream, &data_packet).await?;
        debug!("Sent {} bytes (encrypted)", line.len());

        // Read echo response
        let (response, _) = read_packet(&mut stream).await?;
        if response.packet_type == PacketType::Data {
            let plaintext = session.decrypt_packet(&response)?;
            let text = String::from_utf8_lossy(&plaintext);
            println!("← Echo: {}", text);
        }
    }

    // Send GoAway
    let goaway = KspPacket::new_handshake(PacketType::GoAway, Vec::new());
    send_packet(&mut stream, &goaway).await?;
    info!("Session closed gracefully");

    Ok(())
}
