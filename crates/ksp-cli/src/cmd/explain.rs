//! `ksp explain <topic>` — Educational protocol explainer.
//!
//! Explains KSP concepts with step-by-step breakdowns and RFC references.

use crate::ui;
use colored::Colorize;

pub fn run(topic: &str, json: bool) {
    let topic_lower = topic.to_lowercase();

    let explanation = match topic_lower.as_str() {
        "handshake" => explain_handshake(),
        "replay" | "replay-protection" => explain_replay(),
        "aead" | "encryption" => explain_aead(),
        "certificate" | "cert" | "certs" => explain_certificate(),
        "kdf" | "key-derivation" => explain_kdf(),
        "nonce" | "nonces" => explain_nonce(),
        "streams" | "stream" | "multiplexing" => explain_streams(),
        "flow-control" | "flow" => explain_flow_control(),
        "packet" | "packets" => explain_packet(),
        _ => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": "Unknown topic"}),
                );
            } else {
                ui::failure(&format!("Unknown topic: '{}'", topic));
                println!();
                println!("  Available topics:");
                let topics = [
                    "handshake",
                    "replay",
                    "aead",
                    "certificate",
                    "kdf",
                    "nonce",
                    "streams",
                    "flow-control",
                    "packet",
                ];
                for t in &topics {
                    println!("    {}  ksp explain {}", "•".cyan(), t.bold());
                }
            }
            return;
        }
    };

    if json {
        ui::json_output(&serde_json::json!({
            "topic": topic,
            "steps": explanation.iter().map(|(step, purpose, rfc)| {
                serde_json::json!({"step": step, "purpose": purpose, "rfc": rfc})
            }).collect::<Vec<_>>(),
        }));
    } else {
        ui::print_header(&format!("KSP Explain: {}", topic));
        for (i, (step, purpose, rfc)) in explanation.iter().enumerate() {
            println!(
                "  {}  {}",
                format!("Step {}", i + 1).cyan().bold(),
                step.white().bold()
            );
            println!("     {} {}", "Purpose:".dimmed(), purpose);
            println!("     {} {}", "RFC:".dimmed(), rfc.yellow());
            println!();
        }
    }
}

fn explain_handshake() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "ClientHello",
            "Client proposes supported protocol versions, capabilities, and sends ephemeral X25519 public key",
            "RFC-0001 Section 4.2",
        ),
        (
            "ServerHello",
            "Server selects version & cipher suite, sends its own ephemeral key and session ID",
            "RFC-0001 Section 4.3",
        ),
        (
            "Certificate",
            "Server sends Ed25519 certificate with a binding signature proving it controls the key exchange",
            "RFC-0001 Section 9",
        ),
        (
            "Key Derivation",
            "Both sides compute X25519 shared secret, then derive 4 keys via HKDF-SHA256",
            "RFC-0001 Section 8.3",
        ),
        (
            "AuthRequest",
            "Client sends encrypted authentication credentials (None, API Key, Password, or Token)",
            "RFC-0001 Section 10",
        ),
        (
            "AuthResponse",
            "Server validates credentials and sends encrypted success/failure response",
            "RFC-0001 Section 10",
        ),
        (
            "HandshakeFinish",
            "Both sides exchange HMAC-SHA256 over the handshake transcript to prevent downgrade attacks",
            "RFC-0001 Section 4.7",
        ),
        (
            "Secure Channel",
            "Session is now established with AES-256-GCM or ChaCha20-Poly1305 encryption",
            "RFC-0001 Section 8",
        ),
    ]
}

fn explain_replay() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "Sequence Numbers",
            "Every packet has a monotonically increasing 64-bit sequence number",
            "RFC-0001 Section 14.1",
        ),
        (
            "Sliding Window",
            "Receiver maintains a 1024-bit bitmap tracking recently seen sequence numbers",
            "RFC-0001 Section 14.2",
        ),
        (
            "Accept/Reject Logic",
            "If seq > highest: advance window and accept. If within window: check bitmap. If too old: reject",
            "RFC-0001 Section 14.2",
        ),
        (
            "Counter-based Nonces",
            "AEAD nonces are derived from base IV XOR sequence number, making nonce reuse mathematically impossible",
            "RFC-0001 Section 8.4",
        ),
    ]
}

fn explain_aead() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "Algorithm Selection",
            "KSP supports AES-256-GCM (hardware-accelerated) and ChaCha20-Poly1305 (software-optimized)",
            "RFC-0001 Section 8.1",
        ),
        (
            "Key Size",
            "Both ciphers use 256-bit (32-byte) symmetric keys derived from HKDF",
            "RFC-0001 Section 8.2",
        ),
        (
            "Nonce Construction",
            "12-byte nonces: base_iv XOR sequence_number ensures uniqueness",
            "RFC-0001 Section 8.4",
        ),
        (
            "AAD (Additional Authenticated Data)",
            "The 48-byte packet header is authenticated but not encrypted, preventing header tampering",
            "RFC-0001 Section 8.5",
        ),
        (
            "Authentication Tag",
            "16-byte AEAD tag appended to each encrypted packet for integrity verification",
            "RFC-0001 Section 8.5",
        ),
        (
            "Deliberate Error Vagueness",
            "Decryption errors return generic 'authentication failed' to prevent oracle attacks",
            "RFC-0001 Section 8.6",
        ),
    ]
}

fn explain_certificate() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "Ed25519 Signing",
            "Certificates are signed with Ed25519 (fast, 64-byte signatures, 32-byte keys)",
            "RFC-0001 Section 9.1",
        ),
        (
            "Self-Signed",
            "Default mode uses self-signed certificates; CA chain support is future work",
            "RFC-0001 Section 9.2",
        ),
        (
            "Binding Signature",
            "During handshake, server signs (client_random || server_random || both DH keys) to prevent MITM",
            "RFC-0001 Section 9.3",
        ),
        (
            "Validity Period",
            "Certificates have not_before/not_after timestamps enforced during validation",
            "RFC-0001 Section 9.4",
        ),
    ]
}

fn explain_kdf() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "HKDF-SHA256",
            "Key derivation uses HMAC-based Key Derivation Function with SHA-256",
            "RFC-0001 Section 8.3",
        ),
        (
            "Salt",
            "Salt = client_random || server_random (64 bytes of randomness)",
            "RFC-0001 Section 8.3",
        ),
        (
            "Four Keys Derived",
            "client_write_key, server_write_key, client_write_iv, server_write_iv — domain-separated labels",
            "RFC-0001 Section 8.3",
        ),
        (
            "Zeroization",
            "All intermediate key material is securely zeroed after use via Zeroize trait",
            "RFC-0001 Section 12",
        ),
    ]
}

fn explain_nonce() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "Construction",
            "nonce = base_iv XOR (0x00000000 || sequence_number_be)",
            "RFC-0001 Section 8.4",
        ),
        (
            "Uniqueness Guarantee",
            "Since sequence numbers are monotonically increasing, each nonce is used exactly once",
            "RFC-0001 Section 8.4",
        ),
        (
            "Replay Prevention",
            "Nonce reuse would break AEAD security; counter-based construction makes this impossible",
            "RFC-0001 Section 8.4",
        ),
    ]
}

fn explain_streams() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "Multiplexing",
            "Multiple logical streams share a single encrypted connection (like HTTP/2)",
            "RFC-0001 Section 11",
        ),
        (
            "Stream IDs",
            "Odd = client-initiated, Even = server-initiated, 0 = connection control",
            "RFC-0001 Section 11.2",
        ),
        (
            "State Machine",
            "Idle → Open → HalfClosedLocal/Remote → Closed",
            "RFC-0001 Section 11.3",
        ),
        (
            "Flow Control",
            "Per-stream and connection-level sliding window flow control",
            "RFC-0001 Section 13",
        ),
    ]
}

fn explain_flow_control() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "Window-based",
            "Each stream has a send_window and recv_window (default 64 KiB)",
            "RFC-0001 Section 13.1",
        ),
        (
            "WINDOW_UPDATE",
            "Receiver sends WINDOW_UPDATE frames to increase sender's permitted bytes",
            "RFC-0001 Section 13.2",
        ),
        (
            "Backpressure",
            "If send_window reaches 0, sender must wait for WINDOW_UPDATE before sending more",
            "RFC-0001 Section 13.3",
        ),
    ]
}

fn explain_packet() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        (
            "Wire Format",
            "48-byte fixed header + variable payload + 16-byte AEAD auth tag",
            "RFC-0001 Section 4.1",
        ),
        (
            "Header Fields",
            "version (1B), type (1B), flags (2B), payload_len (4B), session_id (16B), stream_id (4B), sequence (8B), nonce (12B)",
            "RFC-0001 Section 4.2",
        ),
        (
            "Big-Endian",
            "All multi-byte integers are network byte order (big-endian)",
            "RFC-0001 Section 4.1",
        ),
        (
            "Max Payload",
            "16 MB maximum payload size to prevent allocation DoS attacks",
            "RFC-0001 Section 4.5",
        ),
    ]
}
