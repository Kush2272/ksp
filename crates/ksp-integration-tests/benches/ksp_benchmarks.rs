use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use ksp_core::capability::{Capabilities, CipherSuite};
use ksp_core::constants::{CURRENT_VERSION, RANDOM_SIZE};
use ksp_core::packet::KspPacket;
use ksp_core::types::{Flags, PacketType};

use ksp_crypto::certificate::KspCertificate;
use ksp_crypto::kdf::{self, compute_finished_mac};
use ksp_crypto::x25519::EphemeralKeypair;

use ksp_handshake::messages::{ClientHello, ServerHello};
use ksp_transport::session::Session;

/// Benchmark the complete KSP cryptographic handshake setup.
fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");

    let (server_cert, server_signing_key) =
        KspCertificate::generate_self_signed("ksp://localhost", 365);
    let client_caps = Capabilities::AES_256_GCM;

    group.bench_function("ksp_handshake_setup", |b| {
        b.iter(|| {
            // 1. ClientHello
            let client_ephemeral = EphemeralKeypair::generate();
            let mut client_random = [0u8; RANDOM_SIZE];
            client_random[0] = 42; // static for bench

            let client_hello = ClientHello {
                supported_versions: vec![CURRENT_VERSION],
                capabilities: client_caps,
                client_random,
                ephemeral_public_key: client_ephemeral.public_key_bytes(),
            };
            let client_hello_bytes = client_hello.serialize();

            // 2. ServerHello
            let client_hello_received = ClientHello::deserialize(&client_hello_bytes).unwrap();
            let selected_version = CURRENT_VERSION;
            let selected_caps = Capabilities::AES_256_GCM;

            let server_ephemeral = EphemeralKeypair::generate();
            let mut server_random = [0u8; RANDOM_SIZE];
            server_random[0] = 24;
            let session_id = [0x99u8; 16];

            let server_hello = ServerHello {
                selected_version,
                selected_capabilities: selected_caps,
                server_random,
                ephemeral_public_key: server_ephemeral.public_key_bytes(),
                session_id,
            };
            let server_hello_bytes = server_hello.serialize();

            // 3. Server signs key exchange
            let mut binding_data = Vec::new();
            binding_data.extend_from_slice(&client_random);
            binding_data.extend_from_slice(&server_random);
            binding_data.extend_from_slice(&client_hello.ephemeral_public_key);
            binding_data.extend_from_slice(&server_hello.ephemeral_public_key);

            use ed25519_dalek::Signer;
            let _binding_signature = server_signing_key.sign(&binding_data).to_bytes();

            // 4. Key Exchange DH and Derivation
            let server_hello_received = ServerHello::deserialize(&server_hello_bytes).unwrap();
            let client_shared = client_ephemeral
                .diffie_hellman(&server_hello_received.ephemeral_public_key)
                .unwrap();
            let _client_keys =
                kdf::derive_session_keys(client_shared.as_bytes(), &client_random, &server_random)
                    .unwrap();
        })
    });

    group.finish();
}

/// Benchmark packet serialization and deserialization.
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    let payload = vec![0xAA; 1024]; // 1 KB payload
    let packet = KspPacket {
        version: CURRENT_VERSION,
        packet_type: PacketType::Data,
        flags: Flags::ENCRYPTED,
        session_id: [0x55; 16],
        stream_id: 1,
        sequence: 42,
        nonce: [0xBB; 12],
        payload,
        auth_tag: vec![0xCC; 16],
    };

    group.bench_function("serialize_1kb", |b| {
        b.iter(|| {
            let _bytes = black_box(&packet).serialize();
        })
    });

    let bytes = packet.serialize();
    group.bench_function("deserialize_1kb", |b| {
        b.iter(|| {
            let _parsed = KspPacket::deserialize(black_box(&bytes)).unwrap();
        })
    });

    group.finish();
}

/// Benchmark AEAD encryption and decryption throughput.
fn bench_aead_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_throughput");

    let sizes = [1024, 65536, 1048576]; // 1 KB, 64 KB, 1 MB
    let key = [0x42u8; 32];
    let nonce = [0x55u8; 12];
    let aad = [0xAAu8; 48];

    for &size in &sizes {
        let plaintext = vec![0x77; size];

        // Benchmark AES-256-GCM
        group.bench_with_input(
            BenchmarkId::new("aes_256_gcm_encrypt", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    let _cipher =
                        ksp_crypto::aead::encrypt(CipherSuite::Aes256Gcm, &key, &nonce, pt, &aad)
                            .unwrap();
                })
            },
        );

        let (ciphertext, tag) =
            ksp_crypto::aead::encrypt(CipherSuite::Aes256Gcm, &key, &nonce, &plaintext, &aad)
                .unwrap();

        group.bench_with_input(
            BenchmarkId::new("aes_256_gcm_decrypt", size),
            &ciphertext,
            |b, ct| {
                b.iter(|| {
                    let _plain = ksp_crypto::aead::decrypt(
                        CipherSuite::Aes256Gcm,
                        &key,
                        &nonce,
                        ct,
                        &tag,
                        &aad,
                    )
                    .unwrap();
                })
            },
        );

        // Benchmark ChaCha20-Poly1305
        group.bench_with_input(
            BenchmarkId::new("chacha20_poly1305_encrypt", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    let _cipher = ksp_crypto::aead::encrypt(
                        CipherSuite::ChaCha20Poly1305,
                        &key,
                        &nonce,
                        pt,
                        &aad,
                    )
                    .unwrap();
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_handshake,
    bench_serialization,
    bench_aead_throughput
);
criterion_main!(benches);
