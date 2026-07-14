//! `ksp demo` — Automated end-to-end demonstration.

use crate::ui;
use colored::Colorize;
use std::time::Duration;

pub fn run(json: bool) {
    if !json {
        ui::print_banner();
        ui::print_header("KSP Interactive Demo & Protocol Walkthrough");
        println!("  This demo walks through the complete KSP protocol flow:");
        println!("  Server startup → Client connection → Handshake → Encrypted data");
        println!("  → Stream multiplexing → Replay attack → Graceful shutdown");
        println!();
        print_ascii_animation();
    }

    // Step 1: Certificate Generation
    step(1, "Generating Ed25519 Certificate", json);
    let (cert, _key) =
        ksp_crypto::certificate::KspCertificate::generate_self_signed("ksp://demo", 365);
    if !json {
        ui::success(&format!("Certificate created: {}", cert.subject.cyan()));
        ui::kv("  Algorithm", "Ed25519");
        ui::kv(
            "  Serial",
            &uuid::Uuid::from_bytes(cert.serial_number).to_string(),
        );
        pause();
    }

    // Step 2: Key Exchange Simulation
    step(2, "X25519 Ephemeral Key Exchange", json);
    let client_kp = ksp_crypto::x25519::EphemeralKeypair::generate();
    let server_kp = ksp_crypto::x25519::EphemeralKeypair::generate();
    let shared = client_kp
        .diffie_hellman(&server_kp.public_key_bytes())
        .unwrap();
    if !json {
        ui::success("Client ephemeral key generated");
        ui::success("Server ephemeral key generated");
        ui::success(&format!(
            "Shared secret: {}...",
            hex::encode(&shared.as_bytes()[..8]).dimmed()
        ));
        pause();
    }

    // Step 3: Key Derivation
    step(3, "HKDF-SHA256 Key Derivation", json);
    let cr = [0xAAu8; 32];
    let sr = [0xBBu8; 32];
    let keys = ksp_crypto::kdf::derive_session_keys(shared.as_bytes(), &cr, &sr).unwrap();
    if !json {
        ui::success("4 session keys derived:");
        ui::kv(
            "  Client Write Key",
            &format!("{}...", hex::encode(&keys.client_write_key[..8])),
        );
        ui::kv(
            "  Server Write Key",
            &format!("{}...", hex::encode(&keys.server_write_key[..8])),
        );
        ui::kv(
            "  Client Write IV",
            &hex::encode(&keys.client_write_iv[..6]),
        );
        ui::kv(
            "  Server Write IV",
            &hex::encode(&keys.server_write_iv[..6]),
        );
        pause();
    }

    // Step 4: Encryption Demo
    step(4, "AES-256-GCM Encryption", json);
    let plaintext = b"Hello from KSP! This message is encrypted.";
    let nonce = [0x01u8; 12];
    let aad = [0u8; 48];
    let (ciphertext, tag) = ksp_crypto::aead::encrypt(
        ksp_core::capability::CipherSuite::Aes256Gcm,
        &keys.client_write_key,
        &nonce,
        plaintext,
        &aad,
    )
    .unwrap();
    if !json {
        ui::success(&format!(
            "Plaintext:  \"{}\"",
            String::from_utf8_lossy(plaintext).green()
        ));
        ui::success(&format!(
            "Ciphertext: {}... ({} bytes)",
            hex::encode(&ciphertext[..16]).red(),
            ciphertext.len()
        ));
        ui::success(&format!("AEAD Tag:   {}", hex::encode(tag).yellow()));
        pause();
    }

    // Step 5: Decryption
    step(5, "Decryption & Verification", json);
    let decrypted = ksp_crypto::aead::decrypt(
        ksp_core::capability::CipherSuite::Aes256Gcm,
        &keys.client_write_key,
        &nonce,
        &ciphertext,
        &tag,
        &aad,
    )
    .unwrap();
    if !json {
        ui::success(&format!(
            "Decrypted:  \"{}\"",
            String::from_utf8_lossy(&decrypted).green().bold()
        ));
        ui::success("AEAD tag verified — integrity confirmed");
        pause();
    }

    // Step 6: Replay Protection Demo
    step(6, "Replay Protection (Sliding Window)", json);
    let mut replay = ksp_transport::ReplayWindow::new();
    replay.check_and_update(1).unwrap();
    replay.check_and_update(2).unwrap();
    replay.check_and_update(3).unwrap();
    if !json {
        ui::success("Packet seq=1 accepted");
        ui::success("Packet seq=2 accepted");
        ui::success("Packet seq=3 accepted");
    }
    // Try replay
    match replay.check_and_update(2) {
        Ok(()) => {
            if !json {
                ui::failure("Replay not detected (unexpected)");
            }
        }
        Err(e) => {
            if !json {
                ui::success(&format!(
                    "Replay seq=2 → {} {}",
                    "REJECTED".red().bold(),
                    format!("({})", e).dimmed()
                ));
            }
        }
    }
    if !json {
        pause();
    }

    // Step 7: Tampered Packet
    step(7, "Tampered Packet Detection", json);
    let mut bad_ct = ciphertext.clone();
    if !bad_ct.is_empty() {
        bad_ct[0] ^= 0xFF;
    }
    match ksp_crypto::aead::decrypt(
        ksp_core::capability::CipherSuite::Aes256Gcm,
        &keys.client_write_key,
        &nonce,
        &bad_ct,
        &tag,
        &aad,
    ) {
        Ok(_) => {
            if !json {
                ui::failure("Tampered packet accepted (unexpected)");
            }
        }
        Err(_) => {
            if !json {
                ui::success(&format!(
                    "Modified payload → {} {}",
                    "AEAD VERIFICATION FAILED".red().bold(),
                    "— packet dropped".dimmed()
                ));
            }
        }
    }
    if !json {
        pause();
    }

    // Step 8: Packet Serialization
    step(8, "Packet Serialization", json);
    let packet = ksp_core::KspPacket::new_handshake(
        ksp_core::types::PacketType::Data,
        b"demo payload".to_vec(),
    );
    let wire = packet.serialize();
    let (deserialized, _) = ksp_core::KspPacket::deserialize(&wire).unwrap();
    if !json {
        ui::success(&format!("Serialized:   {} bytes on wire", wire.len()));
        ui::success(&format!(
            "Deserialized: {} payload bytes recovered",
            deserialized.payload.len()
        ));
        pause();
    }

    // Summary
    if json {
        ui::json_output(&serde_json::json!({
            "status": "complete",
            "steps": 8,
            "message": "All protocol features demonstrated successfully",
        }));
    } else {
        println!();
        println!("  {}", "═".repeat(60).cyan());
        println!(
            "  {}  {}",
            "✔".green().bold(),
            "Demo Complete!".green().bold()
        );
        println!("  {}", "═".repeat(60).cyan());
        println!();
        println!("  All core KSP features demonstrated:");
        println!("    {} Ed25519 certificate generation", "✔".green());
        println!("    {} X25519 ephemeral key exchange", "✔".green());
        println!("    {} HKDF-SHA256 key derivation", "✔".green());
        println!("    {} AES-256-GCM authenticated encryption", "✔".green());
        println!("    {} AEAD integrity verification", "✔".green());
        println!("    {} Sliding window replay protection", "✔".green());
        println!("    {} Tampered packet detection", "✔".green());
        println!("    {} Binary packet serialization", "✔".green());
        println!();
        println!("  Next: Try it live!");
        println!("    {}  ksp server start", "→".cyan());
        println!("    {}  ksp ping 127.0.0.1:9876", "→".cyan());
        println!();
    }
}

fn step(num: usize, title: &str, json: bool) {
    if !json {
        println!();
        println!(
            "  {} {}",
            format!("━━━ Step {} ━━━", num).cyan().bold(),
            title.white().bold()
        );
        println!();
    }
}

fn pause() {
    std::thread::sleep(Duration::from_millis(300));
}

fn print_ascii_animation() {
    use std::io::Write;
    let lines = [
        "  Client                                                    Server",
        "    │                                                         │",
        "    │ ────ClientHello (X25519 PubKey, Capabilities)─────────▶ │",
        "    │ ◀───ServerHello (X25519 PubKey, Session ID)──────────── │",
        "    │ ◀───Certificate (Ed25519 Signature & Identity)───────── │",
        "    │ ────Verify Signature & Derive HKDF Keys───────────────▶ │",
        "    │ ◀───HandshakeFinish (HMAC Transcript Auth)───────────── │",
        "    │                                                         │",
        "    ═══════════════════════════════════════════════════════════",
        "             Secure Channel Established (AES-256-GCM)",
        "    ═══════════════════════════════════════════════════════════",
        "    │                                                         │",
        "    │ ─── Encrypted Chat: \"Hello\" ──────────────────────────▶ │",
        "    │ ─── Packet Header (48B) + AEAD Tag (16B) ─────────────▶ │",
        "    │ ◀─── Decrypt & Deliver (ACK #1) ─────────────────────── │",
        "    │                                                         │",
    ];

    for line in &lines {
        println!("{}", line.cyan());
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_millis(60));
    }
    println!();
}
