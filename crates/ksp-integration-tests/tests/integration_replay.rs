use ksp_core::capability::{Capabilities, CipherSuite};
use ksp_core::error::KspError;
use ksp_core::types::{Flags, PacketType};
use ksp_core::version::ProtocolVersion;

use ksp_crypto::kdf;
use ksp_transport::session::Session;

fn setup_test_sessions() -> (Session, Session) {
    let session_id = [0xAA; 16];
    let version = ProtocolVersion::new(1, 0);
    let caps = Capabilities::AES_256_GCM;
    let cipher_suite = CipherSuite::Aes256Gcm;

    let shared_secret = [0x55u8; 32];
    let client_random = [0x11u8; 32];
    let server_random = [0x22u8; 32];

    let client_keys =
        kdf::derive_session_keys(&shared_secret, &client_random, &server_random).unwrap();
    let server_keys =
        kdf::derive_session_keys(&shared_secret, &client_random, &server_random).unwrap();

    let client = Session::new(session_id, version, caps, cipher_suite, client_keys, true);
    let server = Session::new(session_id, version, caps, cipher_suite, server_keys, false);

    (client, server)
}

#[test]
fn test_successful_decryption() {
    let (client, mut server) = setup_test_sessions();

    let (seq, nonce) = client.send_nonce.next();
    let plaintext = b"Hello, secure world!";

    let packet = client
        .encrypt_packet(PacketType::Data, Flags::empty(), 1, seq, nonce, plaintext)
        .unwrap();

    let decrypted = server.decrypt_packet(&packet).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_replay_attack_rejected() {
    let (client, mut server) = setup_test_sessions();

    let (seq, nonce) = client.send_nonce.next();
    let plaintext = b"Hello, secure world!";

    let packet = client
        .encrypt_packet(PacketType::Data, Flags::empty(), 1, seq, nonce, plaintext)
        .unwrap();

    // First decryption succeeds
    let decrypted = server.decrypt_packet(&packet).unwrap();
    assert_eq!(decrypted, plaintext);

    // Replay of the exact same packet should be rejected by replay window
    let result = server.decrypt_packet(&packet);
    assert!(matches!(result, Err(KspError::ReplayDetected(s)) if s == seq));
}

#[test]
fn test_nonce_tampering_rejected() {
    let (client, mut server) = setup_test_sessions();

    let (seq, nonce) = client.send_nonce.next();
    let plaintext = b"Hello, secure world!";

    let mut packet = client
        .encrypt_packet(PacketType::Data, Flags::empty(), 1, seq, nonce, plaintext)
        .unwrap();

    // Tamper with the nonce in the packet header
    packet.nonce[0] ^= 0xFF;

    // Decryption should fail due to nonce mismatch
    let result = server.decrypt_packet(&packet);
    assert!(matches!(result, Err(KspError::CryptoError(msg)) if msg.contains("nonce mismatch")));
}

#[test]
fn test_seq_tampering_rejected() {
    let (client, mut server) = setup_test_sessions();

    let (seq, nonce) = client.send_nonce.next();
    let plaintext = b"Hello, secure world!";

    let mut packet = client
        .encrypt_packet(PacketType::Data, Flags::empty(), 1, seq, nonce, plaintext)
        .unwrap();

    // Tamper with sequence number in the header (change to seq + 1)
    packet.sequence += 1;

    // This should trigger expected nonce mismatch (since expected nonce uses IV XOR sequence)
    let result = server.decrypt_packet(&packet);
    assert!(matches!(result, Err(KspError::CryptoError(msg)) if msg.contains("nonce mismatch")));
}
