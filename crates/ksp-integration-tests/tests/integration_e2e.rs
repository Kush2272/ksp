use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ksp_core::capability::{Capabilities, CipherSuite};
use ksp_core::constants::HEADER_SIZE;
use ksp_core::error::KspError;
use ksp_core::packet::KspPacket;
use ksp_core::types::{Flags, PacketType};
use ksp_core::version::ProtocolVersion;

use ksp_crypto::certificate::KspCertificate;
use ksp_crypto::kdf;
use ksp_crypto::x25519::EphemeralKeypair;

use ksp_handshake::auth::{AuthMethod, AuthResult};
use ksp_handshake::messages::{ClientHello, HandshakeFinish, ServerHello};

use ksp_transport::session::Session;

async fn read_packet(stream: &mut TcpStream) -> Result<(KspPacket, usize), KspError> {
    let mut header_buf = [0u8; HEADER_SIZE];
    stream.read_exact(&mut header_buf).await?;

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

    KspPacket::deserialize(&full_buf)
}

async fn send_packet(stream: &mut TcpStream, packet: &KspPacket) -> Result<(), KspError> {
    let bytes = packet.serialize();
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn run_mock_server(
    listener: TcpListener,
    certificate: KspCertificate,
    signing_key: ed25519_dalek::SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut stream, _) = listener.accept().await?;

    // ── Step 1: Receive ClientHello ──
    let (client_hello_packet, _) = read_packet(&mut stream).await?;
    let client_hello = ClientHello::deserialize(&client_hello_packet.payload)?;

    // ── Step 2: Version + Capability negotiation ──
    let selected_version = ProtocolVersion::negotiate(
        &client_hello.supported_versions,
        &[ksp_core::CURRENT_VERSION],
    )?;
    let (selected_caps, cipher_suite) = ksp_core::capability::negotiate_capabilities(
        client_hello.capabilities,
        Capabilities::AES_256_GCM | Capabilities::CHACHA20_POLY1305,
    )?;

    // ── Step 3: Generate server ephemeral keypair ──
    let server_keypair = EphemeralKeypair::generate();
    let mut server_random = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_random);
    let session_id = [0x77u8; 16];

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

    // ── Step 5: Send Certificate ──
    let mut binding_data = Vec::new();
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

    // ── Step 6: Derive keys ──
    let shared_secret = server_keypair.diffie_hellman(&client_hello.ephemeral_public_key)?;
    let derived_keys = kdf::derive_session_keys(
        shared_secret.as_bytes(),
        &client_hello.client_random,
        &server_random,
    )?;

    let mut session = Session::new(
        session_id,
        selected_version,
        selected_caps,
        cipher_suite,
        derived_keys,
        false, // server
    );

    // ── Step 8: Receive AuthRequest ──
    let (auth_packet, _) = read_packet(&mut stream).await?;
    let plaintext = session.decrypt_packet(&auth_packet)?;
    let auth_method = AuthMethod::deserialize(&plaintext)?;
    assert_eq!(auth_method, AuthMethod::None);

    // Send Success AuthResponse
    let auth_result = AuthResult::Success;
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

    // ── Step 9: Exchange HandshakeFinish ──
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&client_hello_packet.payload);
    transcript.extend_from_slice(&server_hello_packet.payload);
    transcript.extend_from_slice(&cert_payload);

    // Receive client HandshakeFinish
    let (client_finish_packet, _) = read_packet(&mut stream).await?;
    let client_finish_payload = session.decrypt_packet(&client_finish_packet)?;
    let client_finish = HandshakeFinish::deserialize(&client_finish_payload)?;

    let expected_client_verify =
        ksp_crypto::compute_finished_mac(&session.keys.client_write_key, &transcript);
    assert_eq!(client_finish.verify_data, expected_client_verify);

    // Send server HandshakeFinish
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

    // ── Step 10: Echo message ──
    let (data_packet, _) = read_packet(&mut stream).await?;
    let received_plaintext = session.decrypt_packet(&data_packet)?;
    assert_eq!(received_plaintext, b"ping");

    // Echo back
    let (seq, nonce) = session.send_nonce.next();
    let response = session.encrypt_packet(
        PacketType::Data,
        Flags::empty(),
        data_packet.stream_id,
        seq,
        nonce,
        &received_plaintext,
    )?;
    send_packet(&mut stream, &response).await?;

    // Receive GoAway
    let (goaway_packet, _) = read_packet(&mut stream).await?;
    assert_eq!(goaway_packet.packet_type, PacketType::GoAway);

    Ok(())
}

#[tokio::test]
async fn test_e2e_tcp_handshake_and_echo() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let (certificate, signing_key) = KspCertificate::generate_self_signed("ksp://localhost", 365);
    let certificate_clone = certificate.clone();

    // Spawn server
    let server_handle = tokio::spawn(async move {
        run_mock_server(listener, certificate_clone, signing_key)
            .await
            .unwrap();
    });

    // Run client client code inline
    let mut stream = TcpStream::connect(local_addr).await.unwrap();

    // ── Client Step 1: Send ClientHello ──
    let client_caps = Capabilities::AES_256_GCM;
    let client_ephemeral = EphemeralKeypair::generate();
    let mut client_random = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut client_random);

    let client_hello = ClientHello {
        supported_versions: vec![ksp_core::CURRENT_VERSION],
        capabilities: client_caps,
        client_random,
        ephemeral_public_key: client_ephemeral.public_key_bytes(),
    };

    let hello_payload = client_hello.serialize();
    let hello_packet = KspPacket::new_handshake(PacketType::ClientHello, hello_payload.clone());
    send_packet(&mut stream, &hello_packet).await.unwrap();

    // ── Client Step 2: Receive ServerHello ──
    let (server_hello_packet, _) = read_packet(&mut stream).await.unwrap();
    let server_hello = ServerHello::deserialize(&server_hello_packet.payload).unwrap();

    // ── Client Step 3: Receive Certificate & verify binding ──
    let (cert_packet, _) = read_packet(&mut stream).await.unwrap();
    let cert_payload = &cert_packet.payload;
    let cert_bytes_len = cert_payload.len() - 64;
    let certificate_received =
        KspCertificate::deserialize(&cert_payload[..cert_bytes_len]).unwrap();
    let binding_signature_bytes: [u8; 64] = cert_payload[cert_bytes_len..].try_into().unwrap();

    certificate_received.validate_self_signed().unwrap();
    assert_eq!(certificate_received.public_key, certificate.public_key);

    let mut binding_data = Vec::new();
    binding_data.extend_from_slice(&client_random);
    binding_data.extend_from_slice(&server_hello.server_random);
    binding_data.extend_from_slice(&client_hello.ephemeral_public_key);
    binding_data.extend_from_slice(&server_hello.ephemeral_public_key);

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let verifying_key = VerifyingKey::from_bytes(&certificate_received.public_key).unwrap();
    let signature = Signature::from_bytes(&binding_signature_bytes);
    verifying_key.verify(&binding_data, &signature).unwrap();

    // ── Client Step 4: Derive keys ──
    let shared_secret = client_ephemeral
        .diffie_hellman(&server_hello.ephemeral_public_key)
        .unwrap();
    let derived_keys = kdf::derive_session_keys(
        shared_secret.as_bytes(),
        &client_random,
        &server_hello.server_random,
    )
    .unwrap();

    let cipher_suite = CipherSuite::Aes256Gcm;
    let mut session = Session::new(
        server_hello.session_id,
        server_hello.selected_version,
        server_hello.selected_capabilities,
        cipher_suite,
        derived_keys,
        true, // client
    );

    // ── Client Step 5: Send AuthRequest ──
    let auth_method = AuthMethod::None;
    let auth_payload = auth_method.serialize();
    let (seq, nonce) = session.send_nonce.next();
    let auth_packet = session
        .encrypt_packet(
            PacketType::AuthRequest,
            Flags::empty(),
            0,
            seq,
            nonce,
            &auth_payload,
        )
        .unwrap();
    send_packet(&mut stream, &auth_packet).await.unwrap();

    // ── Client Step 6: Receive AuthResponse ──
    let (auth_response_packet, _) = read_packet(&mut stream).await.unwrap();
    let auth_response_payload = session.decrypt_packet(&auth_response_packet).unwrap();
    let auth_result = AuthResult::deserialize(&auth_response_payload).unwrap();
    assert_eq!(auth_result, AuthResult::Success);

    // ── Client Step 7: Exchange HandshakeFinish ──
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&hello_payload);
    transcript.extend_from_slice(&server_hello_packet.payload);
    transcript.extend_from_slice(cert_payload);

    // Send client HandshakeFinish
    let client_verify_data =
        ksp_crypto::compute_finished_mac(&session.keys.client_write_key, &transcript);
    let client_finish = HandshakeFinish {
        verify_data: client_verify_data,
    };
    let (seq, nonce) = session.send_nonce.next();
    let client_finish_packet = session
        .encrypt_packet(
            PacketType::HandshakeFinish,
            Flags::empty(),
            0,
            seq,
            nonce,
            &client_finish.serialize(),
        )
        .unwrap();
    send_packet(&mut stream, &client_finish_packet)
        .await
        .unwrap();

    // Receive and verify server HandshakeFinish
    let (server_finish_packet, _) = read_packet(&mut stream).await.unwrap();
    let server_finish_payload = session.decrypt_packet(&server_finish_packet).unwrap();
    let server_finish = HandshakeFinish::deserialize(&server_finish_payload).unwrap();

    let expected_server_verify =
        ksp_crypto::compute_finished_mac(&session.keys.server_write_key, &transcript);
    assert_eq!(server_finish.verify_data, expected_server_verify);

    // ── Client Step 8: Send encrypted data and receive echo ──
    let (seq, nonce) = session.send_nonce.next();
    let data_packet = session
        .encrypt_packet(PacketType::Data, Flags::empty(), 1, seq, nonce, b"ping")
        .unwrap();
    send_packet(&mut stream, &data_packet).await.unwrap();

    // Receive echo
    let (response_packet, _) = read_packet(&mut stream).await.unwrap();
    let response_plaintext = session.decrypt_packet(&response_packet).unwrap();
    assert_eq!(response_plaintext, b"ping");

    // Send GoAway
    let goaway = KspPacket::new_handshake(PacketType::GoAway, Vec::new());
    send_packet(&mut stream, &goaway).await.unwrap();

    server_handle.await.unwrap();
}

#[tokio::test]
async fn test_client_server_sdk_roundtrip() {
    use ksp_client::KspClient;
    use ksp_server::{ServerConfig, run_server};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // Free port for KspServer binding

    let (cert, key) = KspCertificate::generate_self_signed("ksp://test-sdk", 365);
    let config = ServerConfig {
        bind_addr: addr,
        capabilities: ksp_core::capability::default_capabilities(),
        certificate: cert,
        signing_key: key,
        gateway_target: None,
        output_sink: None,
    };

    let server_task = tokio::spawn(async move {
        let _ = run_server(config).await;
    });

    // Wait briefly for server bind
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut client = KspClient::connect(addr)
        .await
        .expect("SDK Connect should succeed");

    // Test multiple stream roundtrips
    for stream_id in 1..=5 {
        let msg = format!("Hello SDK Stream #{}", stream_id);
        client
            .send_data(stream_id, msg.as_bytes())
            .await
            .expect("Send data OK");

        let (pkt, payload) = client.receive_packet().await.expect("Receive echo OK");
        assert_eq!(pkt.stream_id, stream_id);
        assert_eq!(String::from_utf8_lossy(&payload), msg);
    }

    client.close().await.expect("Client close OK");
    server_task.abort();
}

#[tokio::test]
async fn test_concurrent_multi_stream_transfer() {
    use ksp_client::KspClient;
    use ksp_server::{ServerConfig, run_server};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (cert, key) = KspCertificate::generate_self_signed("ksp://test-transfer", 365);
    let config = ServerConfig {
        bind_addr: addr,
        capabilities: ksp_core::capability::default_capabilities(),
        certificate: cert,
        signing_key: key,
        gateway_target: None,
        output_sink: None,
    };

    let server_task = tokio::spawn(async move {
        let _ = run_server(config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut client = KspClient::connect(addr).await.expect("SDK Connect OK");

    // Concurrent sending of 10 virtual streams over the multiplexed session
    let mut tasks = Vec::new();
    for sid in 100..110 {
        let payload = vec![sid as u8; 1024]; // 1 KB payload per stream
        client
            .send_data(sid, &payload)
            .await
            .expect("Stream transmission OK");
        tasks.push((sid, payload));
    }

    for (sid, expected_payload) in tasks {
        let (pkt, response) = client
            .receive_packet()
            .await
            .expect("Receive stream echo OK");
        assert_eq!(pkt.stream_id, sid);
        assert_eq!(response, expected_payload);
    }

    let _ = client.close().await;
    server_task.abort();
}

#[tokio::test]
async fn test_proxy_and_gateway_tunnel() {
    use ksp_server::{ServerConfig, run_server};

    // 1. Start a mock HTTP backend server (echo target)
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();

    let http_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = http_listener.accept().await {
            let mut buf = [0u8; 1024];
            if let Ok(n) = socket.read(&mut buf).await
                && n > 0
            {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    n,
                    String::from_utf8_lossy(&buf[..n])
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        }
    });

    // 2. Start KSP Gateway server pointing to http_addr
    let ksp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ksp_addr = ksp_listener.local_addr().unwrap();
    drop(ksp_listener);

    let (cert, key) = KspCertificate::generate_self_signed("ksp://test-gateway", 365);
    let config = ServerConfig {
        bind_addr: ksp_addr,
        capabilities: ksp_core::capability::default_capabilities(),
        certificate: cert,
        signing_key: key,
        gateway_target: Some(http_addr),
        output_sink: None,
    };

    let gateway_task = tokio::spawn(async move {
        let _ = run_server(config).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3. Connect via KspClient and verify traffic is proxied to/from HTTP backend
    let mut client = ksp_client::KspClient::connect(ksp_addr)
        .await
        .expect("Gateway connect OK");
    let http_req = b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    client
        .send_data(1, http_req)
        .await
        .expect("Send request through gateway OK");

    let (_pkt, resp) = client
        .receive_packet()
        .await
        .expect("Receive gateway response OK");
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(resp_str.contains("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("GET /api/v1/health"));

    let _ = client.close().await;
    http_task.abort();
    gateway_task.abort();
}
