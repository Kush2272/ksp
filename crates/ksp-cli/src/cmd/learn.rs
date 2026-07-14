//! `ksp learn <topic>` & `ksp rfc <action>` — Educational lessons and RFC reference tools.

use crate::ui;
use colored::Colorize;

pub fn run_learn(topic: &str, json: bool) {
    if topic.is_empty() || topic == "list" {
        if json {
            println!("{}", serde_json::json!({"lessons": ["handshake", "replay", "aead", "streams", "zero-rtt", "certificates"]}));
            return;
        }
        ui::header("KSP Interactive Curriculum — Available Lessons");
        let lessons = [
            ("handshake", "Step-by-step cryptographic exchange & X25519 DH key derivation"),
            ("replay", "1024-bit sliding window bitmap & 64-bit sequence counter checks"),
            ("aead", "Authenticated encryption using AES-256-GCM & ChaCha20-Poly1305"),
            ("streams", "Logical multiplexing, priority frames & flow control windows"),
            ("zero-rtt", "Pre-Shared Key (PSK) resumption tickets & 0-RTT application delivery"),
            ("certificates", "Ed25519 identity verification & binding signatures against MITM"),
        ];
        for (name, desc) in &lessons {
            println!("  {} {:<16} — {}", "•".cyan(), name.yellow().bold(), desc.white());
        }
        println!();
        println!("  {} Run `ksp learn <topic>` to start an interactive lesson.", "ℹ".blue());
        println!();
        return;
    }

    if json {
        println!("{}", serde_json::json!({"topic": topic, "status": "lesson_loaded"}));
        return;
    }

    // Call explain module for rich breakdown plus interactive quiz simulation
    crate::cmd::explain::run(topic, false);

    println!("  {}", "Interactive Key Takeaway:".yellow().bold());
    match topic.to_lowercase().as_str() {
        "handshake" => println!("  • Handshake guarantees perfect forward secrecy using ephemeral X25519 keys."),
        "replay" => println!("  • Replay protection requires zero dynamic memory allocations per packet checked."),
        "aead" => println!("  • AEAD tag verifies header integrity (AAD) and payload confidentiality in one pass."),
        "streams" => println!("  • Multiple logical channels share 1 physical TCP/UDP socket without head-of-line blocking."),
        "zero-rtt" => println!("  • 0-RTT resumption reduces handshake latency from 1 RTT down to 0 ms for known servers."),
        "certificates" => println!("  • Ed25519 signatures bind the exact handshake randoms to prevent relay attacks."),
        _ => println!("  • Review RFC-0001 for complete normative specifications."),
    }
    println!();
}

pub fn run_rfc(action: &str, query: &str, json: bool) {
    let sections = [
        ("4.1", "Protocol Overview & Architecture", "KSP operates over TCP/UDP/TLS providing multiplexed secure streams."),
        ("4.2", "ClientHello Message Format", "Defines supported protocol versions, capabilities, and X25519 public key."),
        ("4.3", "ServerHello Message Format", "Defines selected cipher suite, compression, and server DH public key."),
        ("6.5", "Handshake Transcript Binding", "HMAC-SHA256 verification over all previous handshake frames."),
        ("7.1", "Authenticated Encryption Engine", "AES-256-GCM and ChaCha20-Poly1305 AEAD tag verification before processing."),
        ("7.4", "Deterministic Nonce Construction", "12-byte nonces computed via Base_IV XOR 64-bit sequence counter."),
        ("8.3", "Sliding Window Replay Protection", "1024-bit bitmap rejecting old or duplicate sequence numbers constant-time."),
        ("9.1", "Ed25519 Certificate Specification", "64-byte Ed25519 signatures ensuring identity and key ownership."),
        ("10.0", "Authentication Credentials", "Supported mechanisms: API Key, Password, Token, and Mutual TLS."),
        ("14.0", "Multiplexed Streams & Flow Control", "64 KB credit-based sliding windows preventing buffer exhaustion."),
    ];

    if action.is_empty() || action == "list" {
        if json {
            let list: Vec<_> = sections.iter().map(|(id, title, _)| serde_json::json!({"id": id, "title": title})).collect();
            println!("{}", serde_json::json!({"sections": list}));
            return;
        }
        ui::header("KSP RFC-0001 Reference Table of Contents");
        for (id, title, _) in &sections {
            println!("  {:<6} {:<38}", format!("§ {}", id).green().bold(), title.white().bold());
        }
        println!();
        println!("  {} Use `ksp rfc search <query>` or `ksp rfc read <section_id>`.", "ℹ".blue());
        println!();
        return;
    }

    if action == "search" {
        let q = query.to_lowercase();
        let matches: Vec<_> = sections.iter()
            .filter(|(id, title, desc)| id.contains(&q) || title.to_lowercase().contains(&q) || desc.to_lowercase().contains(&q))
            .collect();

        if json {
            let list: Vec<_> = matches.iter().map(|(id, title, desc)| serde_json::json!({"id": id, "title": title, "desc": desc})).collect();
            println!("{}", serde_json::json!({"matches": list}));
            return;
        }

        ui::header(&format!("RFC-0001 Search Results for '{}'", query));
        if matches.is_empty() {
            println!("  {} No RFC sections matched your search.", "ℹ".blue());
        } else {
            for (id, title, desc) in &matches {
                println!("  {} {}", format!("§ {}", id).green().bold(), title.yellow().bold());
                println!("     {}", desc.dimmed());
                println!();
            }
        }
        return;
    }

    // Default: lookup/read section
    let target = if query.is_empty() { action } else { query };
    if let Some((id, title, desc)) = sections.iter().find(|(id, _, _)| *id == target || format!("§{}", id) == target || format!("section {}", id) == target.to_lowercase()) {
        if json {
            println!("{}", serde_json::json!({"id": id, "title": title, "content": desc}));
            return;
        }
        ui::header(&format!("RFC-0001 Section {} — {}", id, title));
        println!("  {}\n", desc.white());
    } else {
        if json {
            println!("{}", serde_json::json!({"error": "Section not found"}));
        } else {
            println!("  {} RFC Section '{}' not found. Run `ksp rfc list` to see all sections.", "✘".red(), target);
        }
    }
    println!();
}
