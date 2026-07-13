use ksp_core::capability::{Capabilities, CipherSuite};
use ksp_core::constants::{CURRENT_VERSION, RANDOM_SIZE};
use ksp_core::error::KspError;
use ksp_core::types::{Flags, PacketType};
use ksp_core::version::ProtocolVersion;

use ksp_crypto::certificate::KspCertificate;
use ksp_crypto::kdf::{self, compute_finished_mac};
use ksp_crypto::x25519::EphemeralKeypair;

use ksp_handshake::messages::{ClientHello, HandshakeFinish, ServerHello};

use ksp_transport::session::Session;

#[test]
fn test_version_negotiation_success() {
    let client_versions = vec![ProtocolVersion::new(2, 0), ProtocolVersion::new(1, 0)];
    let server_versions = vec![ProtocolVersion::new(1, 1), ProtocolVersion::new(1, 0)];

    let result = ProtocolVersion::negotiate(&client_versions, &server_versions).unwrap();
    assert_eq!(result, ProtocolVersion::new(1, 0));
}

#[test]
fn test_version_negotiation_failure() {
    let client_versions = vec![ProtocolVersion::new(2, 0)];
    let server_versions = vec![ProtocolVersion::new(1, 0)];

    let result = ProtocolVersion::negotiate(&client_versions, &server_versions);
    assert!(matches!(result, Err(KspError::VersionMismatch)));
}

#[test]
fn test_capability_negotiation_aes() {
    let client =
        Capabilities::AES_256_GCM | Capabilities::CHACHA20_POLY1305 | Capabilities::STREAMING;
    let server = Capabilities::AES_256_GCM | Capabilities::MULTIPLEXING;

    let (negotiated, cipher) =
        ksp_core::capability::negotiate_capabilities(client, server).unwrap();
    assert_eq!(cipher, CipherSuite::Aes256Gcm);
    assert!(negotiated.contains(Capabilities::AES_256_GCM));
    assert!(!negotiated.contains(Capabilities::CHACHA20_POLY1305));
    assert!(!negotiated.contains(Capabilities::STREAMING));
}

#[test]
fn test_capability_negotiation_chacha_fallback() {
    let client = Capabilities::CHACHA20_POLY1305;
    let server = Capabilities::AES_256_GCM | Capabilities::CHACHA20_POLY1305;

    let (negotiated, cipher) =
        ksp_core::capability::negotiate_capabilities(client, server).unwrap();
    assert_eq!(cipher, CipherSuite::ChaCha20Poly1305);
    assert!(negotiated.contains(Capabilities::CHACHA20_POLY1305));
}

#[test]
fn test_full_handshake_crypto_flow() {
    // 1. Generate server cert
    let (server_cert, server_signing_key) =
        KspCertificate::generate_self_signed("ksp://localhost", 365);
    server_cert.validate_self_signed().unwrap();

    // 2. ClientHello
    let client_caps = Capabilities::AES_256_GCM | Capabilities::STREAMING;
    let client_ephemeral = EphemeralKeypair::generate();
    let mut client_random = [0u8; RANDOM_SIZE];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut client_random);

    let client_hello = ClientHello {
        supported_versions: vec![CURRENT_VERSION],
        capabilities: client_caps,
        client_random,
        ephemeral_public_key: client_ephemeral.public_key_bytes(),
    };
    let client_hello_bytes = client_hello.serialize();

    // 3. Server receives ClientHello and responds with ServerHello
    let client_hello_received = ClientHello::deserialize(&client_hello_bytes).unwrap();
    let server_versions = vec![CURRENT_VERSION];
    let selected_version =
        ProtocolVersion::negotiate(&client_hello_received.supported_versions, &server_versions)
            .unwrap();
    let (selected_caps, cipher_suite) = ksp_core::capability::negotiate_capabilities(
        client_hello_received.capabilities,
        Capabilities::AES_256_GCM | Capabilities::CHACHA20_POLY1305,
    )
    .unwrap();

    let server_ephemeral = EphemeralKeypair::generate();
    let mut server_random = [0u8; RANDOM_SIZE];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut server_random);
    let session_id = [0x55u8; 16];

    let server_hello = ServerHello {
        selected_version,
        selected_capabilities: selected_caps,
        server_random,
        ephemeral_public_key: server_ephemeral.public_key_bytes(),
        session_id,
    };
    let server_hello_bytes = server_hello.serialize();

    // 4. Server computes binding signature
    let mut binding_data = Vec::new();
    binding_data.extend_from_slice(&client_random);
    binding_data.extend_from_slice(&server_random);
    binding_data.extend_from_slice(&client_hello.ephemeral_public_key);
    binding_data.extend_from_slice(&server_hello.ephemeral_public_key);

    use ed25519_dalek::Signer;
    let binding_signature = server_signing_key.sign(&binding_data).to_bytes();

    let mut cert_payload = server_cert.serialize();
    cert_payload.extend_from_slice(&binding_signature);

    // 5. Client receives ServerHello + Certificate and verifies binding
    let server_hello_received = ServerHello::deserialize(&server_hello_bytes).unwrap();

    // Split cert and signature
    let cert_bytes_len = cert_payload.len() - 64;
    let cert_received = KspCertificate::deserialize(&cert_payload[..cert_bytes_len]).unwrap();
    let signature_received: [u8; 64] = cert_payload[cert_bytes_len..].try_into().unwrap();

    // Validate cert
    cert_received.validate_self_signed().unwrap();

    // Verify key exchange binding signature
    let mut client_binding_data = Vec::new();
    client_binding_data.extend_from_slice(&client_random);
    client_binding_data.extend_from_slice(&server_hello_received.server_random);
    client_binding_data.extend_from_slice(&client_hello.ephemeral_public_key);
    client_binding_data.extend_from_slice(&server_hello_received.ephemeral_public_key);

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let verifying_key = VerifyingKey::from_bytes(&cert_received.public_key).unwrap();
    let signature = Signature::from_bytes(&signature_received);
    verifying_key
        .verify(&client_binding_data, &signature)
        .unwrap();

    // 6. Both compute shared secret
    let client_shared = client_ephemeral
        .diffie_hellman(&server_hello_received.ephemeral_public_key)
        .unwrap();
    let server_shared = server_ephemeral
        .diffie_hellman(&client_hello_received.ephemeral_public_key)
        .unwrap();
    assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());

    // 7. Derive keys
    let client_keys =
        kdf::derive_session_keys(client_shared.as_bytes(), &client_random, &server_random).unwrap();
    let server_keys =
        kdf::derive_session_keys(server_shared.as_bytes(), &client_random, &server_random).unwrap();

    // 8. Create client & server sessions
    let mut client_session = Session::new(
        session_id,
        selected_version,
        selected_caps,
        cipher_suite,
        client_keys,
        true,
    );
    let mut server_session = Session::new(
        session_id,
        selected_version,
        selected_caps,
        cipher_suite,
        server_keys,
        false,
    );

    // 9. HandshakeFinish HMAC verification
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&client_hello_bytes);
    transcript.extend_from_slice(&server_hello_bytes);
    transcript.extend_from_slice(&cert_payload);

    let client_finished_mac = compute_finished_mac(client_session.send_key(), &transcript);
    let server_finished_mac = compute_finished_mac(server_session.send_key(), &transcript);

    // Client sends finished, server decrypts & verifies
    let (seq, nonce) = client_session.send_nonce.next();
    let finish_msg = HandshakeFinish {
        verify_data: client_finished_mac,
    };
    let finish_packet = client_session
        .encrypt_packet(
            PacketType::HandshakeFinish,
            Flags::empty(),
            0,
            seq,
            nonce,
            &finish_msg.serialize(),
        )
        .unwrap();

    let decrypted_finish = server_session.decrypt_packet(&finish_packet).unwrap();
    let finish_deserialized = HandshakeFinish::deserialize(&decrypted_finish).unwrap();
    assert_eq!(finish_deserialized.verify_data, client_finished_mac);

    // Server sends finished, client decrypts & verifies
    let (seq, nonce) = server_session.send_nonce.next();
    let server_finish_msg = HandshakeFinish {
        verify_data: server_finished_mac,
    };
    let server_finish_packet = server_session
        .encrypt_packet(
            PacketType::HandshakeFinish,
            Flags::empty(),
            0,
            seq,
            nonce,
            &server_finish_msg.serialize(),
        )
        .unwrap();

    let decrypted_server_finish = client_session
        .decrypt_packet(&server_finish_packet)
        .unwrap();
    let server_finish_deserialized =
        HandshakeFinish::deserialize(&decrypted_server_finish).unwrap();
    assert_eq!(server_finish_deserialized.verify_data, server_finished_mac);
}
