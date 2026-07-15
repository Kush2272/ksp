//! KSP Server SDK API (`KspServer`).
//!
//! Provides `ServerConfig`, `run_server`, `handle_connection`, and related
//! server-side asynchronous capabilities.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use ksp_core::capability::{self, Capabilities};
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

/// Authentication configuration for checking incoming client credentials.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Expected API key for `AuthMethod::ApiKey`. If None, falls back to checking `KSP_API_KEY` env var.
    pub expected_api_key: Option<Vec<u8>>,
    /// Expected credentials `(username, password_hash)` for `AuthMethod::Password`. If None, falls back to checking `KSP_AUTH_USER` & `KSP_AUTH_HASH` env vars.
    pub expected_credentials: Option<(String, Vec<u8>)>,
    /// Expected bearer token for `AuthMethod::Token`. If None, falls back to checking `KSP_AUTH_TOKEN` env var.
    pub expected_token: Option<Vec<u8>>,
    /// Whether to allow `AuthMethod::None` (anonymous authentication). Defaults to true unless explicitly restricted.
    pub allow_anonymous: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            expected_api_key: None,
            expected_credentials: None,
            expected_token: None,
            allow_anonymous: true,
        }
    }
}

impl AuthConfig {
    /// Load authentication constraints from environment variables.
    pub fn from_env() -> Self {
        let expected_api_key = std::env::var("KSP_API_KEY").ok().map(|s| s.into_bytes());
        let expected_credentials = match (std::env::var("KSP_AUTH_USER"), std::env::var("KSP_AUTH_HASH")) {
            (Ok(u), Ok(h)) => Some((u, h.into_bytes())),
            _ => None,
        };
        let expected_token = std::env::var("KSP_AUTH_TOKEN").ok().map(|s| s.into_bytes());
        let allow_anonymous = std::env::var("KSP_ALLOW_ANONYMOUS")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        Self {
            expected_api_key,
            expected_credentials,
            expected_token,
            allow_anonymous,
        }
    }
}

/// KSP Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    /// Address to bind to.
    pub bind_addr: SocketAddr,
    /// Server capabilities.
    pub capabilities: Capabilities,
    /// Server certificate and signing key.
    pub certificate: KspCertificate,
    /// Signing key for the certificate.
    pub signing_key: ed25519_dalek::SigningKey,
    /// Optional HTTP/TCP gateway target for reverse proxy forwarding (`ksp gateway`).
    pub gateway_target: Option<SocketAddr>,
    /// Optional output file path or sink for incoming data transfer (`ksp transfer receive`).
    pub output_sink: Option<std::path::PathBuf>,
    /// Authentication constraints for incoming connections.
    pub auth_config: AuthConfig,
}

/// Read a single KSP packet from a TCP stream.
pub async fn read_packet(stream: &mut TcpStream) -> Result<(KspPacket, usize), KspError> {
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

/// Send a KSP packet over a TCP stream.
pub async fn send_packet(stream: &mut TcpStream, packet: &KspPacket) -> Result<(), KspError> {
    let bytes = packet.serialize();
    ksp_core::record_pcap_if_active(&bytes);
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Load or generate a persistent self-signed certificate and key.
pub fn load_or_generate_cert()
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(key_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(key_path, perms);
            }
        }
        info!("Saved certificate to server.cert and key to server.key");
        Ok((certificate, signing_key))
    }
}

/// Handle a single KSP connection over a TCP stream.
pub async fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    certificate: KspCertificate,
    server_capabilities: Capabilities,
    signing_key: ed25519_dalek::SigningKey,
    gateway_target: Option<SocketAddr>,
    output_sink: Option<std::path::PathBuf>,
    auth_config: AuthConfig,
) -> Result<(), KspError> {
    let (client_hello_packet, _) = read_packet(&mut stream).await?;
    if client_hello_packet.packet_type != PacketType::ClientHello {
        return Err(KspError::HandshakeError("expected ClientHello".into()));
    }
    let client_hello = ClientHello::deserialize(&client_hello_packet.payload)?;
    debug!(
        "Received ClientHello from {}: versions={:?}, caps={}",
        addr, client_hello.supported_versions, client_hello.capabilities
    );

    let selected_version = ksp_core::version::ProtocolVersion::negotiate(
        &client_hello.supported_versions,
        &[ksp_core::CURRENT_VERSION],
    )?;
    let (selected_caps, cipher_suite) =
        capability::negotiate_capabilities(client_hello.capabilities, server_capabilities)?;

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

    let server_hello_packet =
        KspPacket::new_handshake(PacketType::ServerHello, server_hello.serialize());
    send_packet(&mut stream, &server_hello_packet).await?;
    debug!(
        "Sent ServerHello: version={}, cipher={}",
        selected_version, cipher_suite
    );

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

    let shared_secret = server_keypair.diffie_hellman(&client_hello.ephemeral_public_key)?;
    let derived_keys = kdf::derive_session_keys(
        shared_secret.as_bytes(),
        &client_hello.client_random,
        &server_random,
    )?;
    info!("Session keys derived for {}", addr);

    let mut session = Session::new(
        session_id,
        selected_version,
        selected_caps,
        cipher_suite,
        derived_keys,
        false, // server side
    );

    let (auth_packet, _) = read_packet(&mut stream).await?;
    if auth_packet.packet_type == PacketType::AuthRequest {
        let plaintext = session.decrypt_packet(&auth_packet)?;
        let auth_method = AuthMethod::deserialize(&plaintext)?;
        debug!("Received auth request: method=0x{:02X}", auth_method.code());

        let auth_result = match auth_method {
            AuthMethod::None => {
                if auth_config.allow_anonymous {
                    AuthResult::Success
                } else {
                    AuthResult::Failed
                }
            }
            AuthMethod::ApiKey { key } => {
                let expected = auth_config
                    .expected_api_key
                    .clone()
                    .or_else(|| std::env::var("KSP_API_KEY").ok().map(|s| s.into_bytes()));
                match expected {
                    Some(exp) if key == exp => AuthResult::Success,
                    _ => AuthResult::Failed,
                }
            }
            AuthMethod::Password {
                username,
                password_hash,
            } => {
                let expected = auth_config.expected_credentials.clone().or_else(|| {
                    let u = std::env::var("KSP_AUTH_USER").ok()?;
                    let p = std::env::var("KSP_AUTH_HASH").ok()?.into_bytes();
                    Some((u, p))
                });
                match expected {
                    Some((exp_u, exp_h)) if username == exp_u && password_hash == exp_h => {
                        AuthResult::Success
                    }
                    _ => AuthResult::Failed,
                }
            }
            AuthMethod::Token { token } => {
                let expected = auth_config
                    .expected_token
                    .clone()
                    .or_else(|| std::env::var("KSP_AUTH_TOKEN").ok().map(|s| s.into_bytes()));
                match expected {
                    Some(exp) if token == exp => AuthResult::Success,
                    _ => AuthResult::Failed,
                }
            }
            _ => AuthResult::Failed,
        };

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

    let mut transcript = Vec::new();
    transcript.extend_from_slice(&client_hello_packet.payload);
    transcript.extend_from_slice(&server_hello_packet.payload);
    transcript.extend_from_slice(&cert_payload);

    let (client_finish_packet, _) = read_packet(&mut stream).await?;
    if client_finish_packet.packet_type != PacketType::HandshakeFinish {
        return Err(KspError::HandshakeError("expected HandshakeFinish".into()));
    }
    let client_finish_payload = session.decrypt_packet(&client_finish_packet)?;
    let client_finish = HandshakeFinish::deserialize(&client_finish_payload)?;

    let expected_client_verify =
        ksp_crypto::compute_finished_mac(&session.keys.client_write_key, &transcript);
    if client_finish.verify_data != expected_client_verify {
        return Err(KspError::HandshakeError(
            "client HandshakeFinish verification failed".into(),
        ));
    }
    debug!("Client HandshakeFinish verified");

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

    use sha2::Digest;
    let mut stream_hasher = sha2::Sha256::new();

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
                let plaintext = session.decrypt_packet(&packet)?;

                if packet.stream_id == 1 || (packet.stream_id == 4 && serde_json::from_slice::<serde_json::Value>(&plaintext).map(|v| v.get("op").is_some()).unwrap_or(false)) {
                    if let Ok(req) = serde_json::from_slice::<serde_json::Value>(&plaintext)
                        && let Some(op) = req.get("op").and_then(|v| v.as_str())
                    {
                        match op {
                            "FILE_HEADER" => {
                                info!(
                                    "Receiving file {} from {} on control stream {}",
                                    req.get("filename")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("file"),
                                    addr,
                                    packet.stream_id
                                );
                                if let Some(ref sink_path) = output_sink {
                                    if let Some(parent) = sink_path.parent() {
                                        let _ = std::fs::create_dir_all(parent);
                                    }
                                    let _ = std::fs::File::create(sink_path);
                                }
                                stream_hasher = sha2::Sha256::new();
                                let ack = serde_json::json!({"op": "FILE_ACK", "status": "receiving"});
                                let (seq, nonce) = session.send_nonce.next();
                                let resp = session.encrypt_packet(
                                    PacketType::Data,
                                    Flags::empty(),
                                    packet.stream_id,
                                    seq,
                                    nonce,
                                    ack.to_string().as_bytes(),
                                )?;
                                send_packet(&mut stream, &resp).await?;
                                continue;
                            }
                            "FILE_EOF" => {
                                let computed_sha256 = if let Some(ref sink_path) = output_sink
                                    && let Ok(mut f) = std::fs::File::open(sink_path)
                                {
                                    let mut h = sha2::Sha256::new();
                                    let mut b = [0u8; 8192];
                                    use std::io::Read;
                                    while let Ok(n) = f.read(&mut b) {
                                        if n == 0 { break; }
                                        h.update(&b[..n]);
                                    }
                                    hex::encode(h.finalize())
                                } else {
                                    hex::encode(stream_hasher.clone().finalize())
                                };

                                let expected = req.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
                                let verified = !expected.is_empty() && computed_sha256.eq_ignore_ascii_case(expected);

                                if !verified && !expected.is_empty() {
                                    warn!(
                                        "SHA-256 mismatch from {}: expected {}, computed {}",
                                        addr, expected, computed_sha256
                                    );
                                    if let Some(ref sink_path) = output_sink {
                                        let _ = std::fs::remove_file(sink_path);
                                    }
                                    let ack = serde_json::json!({
                                        "op": "FILE_ACK",
                                        "status": "corrupted",
                                        "verified": false,
                                        "sha256": computed_sha256
                                    });
                                    let (seq, nonce) = session.send_nonce.next();
                                    let resp = session.encrypt_packet(
                                        PacketType::Data,
                                        Flags::empty(),
                                        packet.stream_id,
                                        seq,
                                        nonce,
                                        ack.to_string().as_bytes(),
                                    )?;
                                    send_packet(&mut stream, &resp).await?;
                                    continue;
                                }

                                info!(
                                    "Completed receiving file from {} (computed receiver SHA-256: {}, verified against sender: {})",
                                    addr, computed_sha256, verified
                                );
                                let ack = serde_json::json!({
                                    "op": "FILE_ACK",
                                    "status": "ok",
                                    "verified": verified,
                                    "sha256": computed_sha256
                                });
                                let (seq, nonce) = session.send_nonce.next();
                                let resp = session.encrypt_packet(
                                    PacketType::Data,
                                    Flags::empty(),
                                    packet.stream_id,
                                    seq,
                                    nonce,
                                    ack.to_string().as_bytes(),
                                )?;
                                send_packet(&mut stream, &resp).await?;
                                continue;
                            }
                            "FILE_CHECKPOINT" => {
                                let actual_offset = output_sink
                                    .as_ref()
                                    .and_then(|p| std::fs::metadata(p).ok())
                                    .map(|m| m.len())
                                    .unwrap_or(0);
                                let ack =
                                    serde_json::json!({"op": "FILE_CHECKPOINT_RESP", "offset": actual_offset});
                                let (seq, nonce) = session.send_nonce.next();
                                let resp = session.encrypt_packet(
                                    PacketType::Data,
                                    Flags::empty(),
                                    packet.stream_id,
                                    seq,
                                    nonce,
                                    ack.to_string().as_bytes(),
                                )?;
                                send_packet(&mut stream, &resp).await?;
                                continue;
                            }
                            _ => {}
                        }
                    }
                }

                if let Some(backend_addr) = gateway_target {
                    if let Ok(mut backend_socket) = TcpStream::connect(backend_addr).await {
                        let _ = backend_socket.write_all(&plaintext).await;
                        let mut resp_buf = vec![0u8; 32768];
                        if let Ok(n) = backend_socket.read(&mut resp_buf).await
                            && n > 0
                        {
                            let (seq, nonce) = session.send_nonce.next();
                            let response = session.encrypt_packet(
                                PacketType::Data,
                                Flags::empty(),
                                packet.stream_id,
                                seq,
                                nonce,
                                &resp_buf[..n],
                            )?;
                            send_packet(&mut stream, &response).await?;
                        }
                    }
                    continue;
                }

                stream_hasher.update(&plaintext);

                if let Some(ref sink_path) = output_sink
                    && let Ok(mut f) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(sink_path)
                {
                    use std::io::Write;
                    let _ = f.write_all(&plaintext);
                }

                debug!(
                    "Received {} bytes on stream {} from {}",
                    plaintext.len(),
                    packet.stream_id,
                    addr
                );

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

/// Start the KSP echo loop server on the bound address.
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
                let gw = config.gateway_target;
                let sink = config.output_sink.clone();
                let auth = config.auth_config.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, addr, cert, caps, key, gw, sink, auth).await
                    {
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
