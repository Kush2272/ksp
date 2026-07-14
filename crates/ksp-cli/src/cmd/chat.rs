//! `ksp chat [address]` — Encrypted real-time chat over KSP.
//!
//! Provides both a chat client (`ksp chat <address>`) and a quick local
//! chat host (`ksp chat new` / `ksp chat start`).

use crate::ui;
use colored::Colorize;
use ksp_client::KspClient;
use ksp_core::types::PacketType;
use std::net::SocketAddr;
use tokio::io::{self, AsyncBufReadExt, BufReader};

pub fn run(address: &str, json: bool) {
    if !json {
        ui::print_header("KSP Encrypted Chat");
    }

    // Check if user requested starting a new local chat server (`ksp chat new` / `start` / `listen`)
    if address.eq_ignore_ascii_case("new")
        || address.eq_ignore_ascii_case("start")
        || address.eq_ignore_ascii_case("server")
        || address.eq_ignore_ascii_case("listen")
    {
        run_chat_server(9876, json);
        return;
    }

    // Otherwise, connect as a chat client
    let addr_str = crate::cmd::env::resolve_target_address(address);

    let addr: SocketAddr = match std::net::ToSocketAddrs::to_socket_addrs(&addr_str)
        .ok()
        .and_then(|mut i| i.next())
    {
        Some(a) => a,
        None => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": format!("Invalid address syntax: '{}'", addr_str)}),
                );
            } else {
                ui::failure(&format!(
                    "Invalid or unresolvable socket address '{}'.\n  💡 Tip: Provide an IP:PORT (e.g. `127.0.0.1:9876`), or run `ksp chat new` to start a local chat node.",
                    addr_str
                ));
            }
            return;
        }
    };

    if !json {
        println!(
            "  {} Connecting to KSP chat peer at {}...",
            "→".cyan(),
            addr_str.white().bold()
        );
        println!(
            "  {} All messages are end-to-end encrypted with X25519 key exchange + AES-256-GCM.",
            "🔒".green()
        );
        println!();
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        connect_chat_client(addr, json).await;
    });
}

/// Start a quick local KSP chat host server node (`ksp chat new`).
fn run_chat_server(port: u16, json: bool) {
    if json {
        crate::cmd::server::run_start(port, "127.0.0.1", false, true);
        return;
    }

    ui::success(&format!(
        "KSP Encrypted Chat Node initialized on 127.0.0.1:{}",
        port
    ));
    println!(
        "  {} End-to-end X25519 + AES-256-GCM / ChaCha20-Poly1305 encryption active",
        "🔒".green()
    );
    println!(
        "  {} Waiting for incoming peer chat connections...",
        "⏳".cyan().bold()
    );
    println!();
    println!(
        "  {} To join this chat session from another terminal or device, run:",
        "💡".blue().bold()
    );
    println!(
        "       {}\n",
        format!("ksp chat 127.0.0.1:{}", port).cyan().bold()
    );
    println!("  {}", "─".repeat(60).dimmed());

    // Launch standard KSP server on requested port (`127.0.0.1:9876`)
    crate::cmd::server::run_start(port, "127.0.0.1", false, false);
}

/// Connect to an active KSP chat server (`ksp chat [address]`).
async fn connect_chat_client(addr: SocketAddr, json: bool) {
    let spin = if !json {
        Some(ui::spinner(
            "Performing X25519 handshake and establishing session...",
        ))
    } else {
        None
    };

    let mut client = match KspClient::connect(addr).await {
        Ok(c) => {
            if let Some(sp) = spin {
                sp.finish_and_clear();
            }
            crate::cmd::telemetry::TelemetrySnapshot::record_connection(
                &c.session.id_string(),
                &format!("{}", c.cipher_suite),
            );
            c
        }
        Err(e) => {
            if let Some(sp) = spin {
                sp.finish_and_clear();
            }
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": e.to_string()}));
            } else {
                ui::failure(&format!(
                    "Could not connect to KSP chat node at {} ({})",
                    addr, e
                ));
                println!();
                println!(
                    "  {} No KSP chat server or peer found listening on port {}.",
                    "⚠".yellow().bold(),
                    addr.port()
                );
                println!(
                    "  {} To start a new chat server node in this terminal, run:",
                    "💡".blue().bold()
                );
                println!("       {}\n", "ksp chat new".cyan().bold());
                println!(
                    "  {} Or to start the general KSP background server, run:",
                    "💡".blue().bold()
                );
                println!(
                    "       {}\n",
                    format!("ksp server start --port {}", addr.port())
                        .cyan()
                        .bold()
                );
            }
            return;
        }
    };

    if json {
        ui::json_output(&serde_json::json!({
            "status": "connected",
            "mode": "chat",
            "session_id": client.session.id_string(),
            "cipher_suite": format!("{}", client.cipher_suite),
            "peer": addr.to_string(),
        }));
        return;
    }

    ui::success("Connected to chat peer and handshake verified!");
    println!(
        "  {} Session ID: {}",
        "ℹ".cyan(),
        client.session.id_string().white().bold()
    );
    println!(
        "  {} Cipher:     {}",
        "└─▶".dimmed(),
        format!("{}", client.cipher_suite).cyan()
    );
    println!();
    println!("Type messages below and press Enter to send. Type '/quit' or 'exit' to leave.");
    println!("{}", "─".repeat(60).dimmed());

    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("/quit")
            || trimmed.eq_ignore_ascii_case("exit")
            || trimmed.eq_ignore_ascii_case("quit")
        {
            break;
        }

        if let Err(e) = client.send_data(1, line.as_bytes()).await {
            ui::failure(&format!("Send failed: {}", e));
            break;
        }

        match client.receive_packet().await {
            Ok((packet, plaintext)) => {
                if packet.packet_type == PacketType::Data
                    || packet.packet_type == PacketType::StreamData
                {
                    let text = String::from_utf8_lossy(&plaintext);
                    println!(
                        "  {} {}",
                        "💬 [Encrypted Echo]:".cyan().bold(),
                        text.white()
                    );
                } else if packet.packet_type == PacketType::GoAway {
                    ui::info("Chat peer closed connection (GoAway received)");
                    break;
                }
            }
            Err(e) => {
                ui::failure(&format!("Connection dropped: {}", e));
                break;
            }
        }
    }

    let _ = client.close().await;
    ui::info("Chat session closed.");
}
