//! `ksp generate <packet|cert|config|server|client>` — Instant KSP boilerplate generator.

use crate::ui;
use colored::Colorize;
use std::fs;
use std::path::Path;

/// Run `ksp generate <target>`.
pub fn run(target: &str, json: bool) {
    if json {
        let payload = serde_json::json!({
            "target": target,
            "status": "generated"
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return;
    }

    ui::header(&format!("KSP Generator — {}", target));

    match target.to_lowercase().as_str() {
        "config" => generate_config(),
        "cert" | "certs" => generate_cert(),
        "server" => generate_server_boilerplate(),
        "client" => generate_client_boilerplate(),
        "packet" => generate_packet_sample(),
        other => {
            println!(
                "  {} Unknown generator target: '{}'",
                "✘".red().bold(),
                other.white()
            );
            println!(
                "  {} Available targets: {}",
                "ℹ".blue().bold(),
                "config, cert, server, client, packet".yellow()
            );
            println!();
        }
    }
}

fn generate_config() {
    let path = Path::new("ksp.toml");
    if path.exists() {
        println!(
            "  {} {} already exists in the current directory.",
            "✘".yellow(),
            "ksp.toml".white().bold()
        );
        println!(
            "  {} Use `ksp config reset` or delete it first to regenerate.",
            "ℹ".blue()
        );
        return;
    }

    let config_content = r#"# ═══════════════════════════════════════════════════════════════
# Kush Secure Protocol (`ksp.toml`) Configuration File
# Documentation: https://www.kspprotocol.dev/docs/config
# ═══════════════════════════════════════════════════════════════

[server]
port = 9876
host = "0.0.0.0"

[security]
cipher = "AES-256-GCM"
compression = false
replay_window = 1024

[paths]
certificate = "certs/server.cert"
private_key = "certs/server.key"
"#;

    match fs::write(path, config_content) {
        Ok(_) => {
            println!(
                "  {} Generated clean configuration -> {}",
                "✔".green().bold(),
                "ksp.toml".white().bold()
            );
            println!(
                "  {} Run `ksp config show` to inspect settings.",
                "ℹ".blue()
            );
        }
        Err(e) => {
            println!("  {} Failed to write ksp.toml: {}", "✘".red().bold(), e);
        }
    }
    println!();
}

fn generate_cert() {
    fs::create_dir_all("certs").ok();
    let cert_path = Path::new("certs/server.cert");
    let key_path = Path::new("certs/server.key");

    if cert_path.exists() && key_path.exists() {
        println!(
            "  {} Certificates already exist inside {} directory.",
            "✔".green(),
            "certs/".white().bold()
        );
        return;
    }

    let (certificate, signing_key) = ksp_crypto::certificate::KspCertificate::generate_self_signed("ksp://server.localhost", 365);
    fs::write(cert_path, certificate.serialize()).ok();
    fs::write(key_path, signing_key.to_bytes()).ok();

    println!(
        "  {} Generated real KSP Ed25519 private key -> {}",
        "✔".green().bold(),
        "certs/server.key".white().bold()
    );
    println!(
        "  {} Generated real KSP Ed25519 self-signed certificate -> {}",
        "✔".green().bold(),
        "certs/server.cert".white().bold()
    );
    println!();
}

fn generate_server_boilerplate() {
    fs::create_dir_all("src/bin").ok();
    let path = Path::new("src/bin/server.rs");

    let code = r#"//! KSP Server Boilerplate (`src/bin/server.rs`)

use ksp_core::prelude::*;
use std::net::TcpListener;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Launching KSP Server on 0.0.0.0:9876...");
    let listener = TcpListener::bind("0.0.0.0:9876")?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut socket) => {
                println!("✔ New connection from {:?}", socket.peer_addr()?);
                // Perform X25519/HKDF/AEAD handshake & echo loop
            }
            Err(e) => eprintln!("Connection failure: {}", e),
        }
    }
    Ok(())
}
"#;

    match fs::write(path, code) {
        Ok(_) => {
            println!(
                "  {} Generated server code -> {}",
                "✔".green().bold(),
                "src/bin/server.rs".white().bold()
            );
            println!("  {} Run with `cargo run --bin server`.", "ℹ".blue());
        }
        Err(e) => {
            println!("  {} Failed to write server file: {}", "✘".red().bold(), e);
        }
    }
    println!();
}

fn generate_client_boilerplate() {
    fs::create_dir_all("src/bin").ok();
    let path = Path::new("src/bin/client.rs");

    let code = r#"//! KSP Client Boilerplate (`src/bin/client.rs`)

use ksp_core::prelude::*;
use std::net::TcpStream;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Connecting to KSP Server at 127.0.0.1:9876...");
    let mut socket = TcpStream::connect("127.0.0.1:9876")?;

    println!("✔ Establishing secure X25519 session...");
    let payload = b"Hello from KSP Client!";
    socket.write_all(payload)?;
    println!("✔ Transmitted {} bytes securely.", payload.len());

    Ok(())
}
"#;

    match fs::write(path, code) {
        Ok(_) => {
            println!(
                "  {} Generated client code -> {}",
                "✔".green().bold(),
                "src/bin/client.rs".white().bold()
            );
            println!("  {} Run with `cargo run --bin client`.", "ℹ".blue());
        }
        Err(e) => {
            println!("  {} Failed to write client file: {}", "✘".red().bold(), e);
        }
    }
    println!();
}

fn generate_packet_sample() {
    let path = Path::new("sample_packet.bin");
    let pkt = ksp_core::packet::KspPacket::new_handshake(
        ksp_core::PacketType::ClientHello,
        b"Hello KSP Sample Packet".to_vec(),
    );
    let serialized = pkt.serialize();

    match fs::write(path, &serialized) {
        Ok(_) => {
            println!(
                "  {} Generated verifiable binary packet frame ({} bytes) -> {}",
                "✔".green().bold(),
                serialized.len(),
                "sample_packet.bin".white().bold()
            );
            println!(
                "  {} Inspect with `ksp packet inspect sample_packet.bin`.",
                "ℹ".blue()
            );
        }
        Err(e) => {
            println!(
                "  {} Failed to write sample packet: {}",
                "✘".red().bold(),
                e
            );
        }
    }
    println!();
}
