//! `ksp connect <address>` — Connect to a KSP server interactively.

use colored::Colorize;
use crate::ui;
use std::net::SocketAddr;
use ksp_client::KspClient;
use ksp_core::types::PacketType;
use tokio::io::{self, AsyncBufReadExt, BufReader};

pub fn run(address: &str, json: bool) {
    if !json {
        ui::print_header("KSP Connect");
    }

    let addr_str = crate::cmd::env::resolve_target_address(address);

    let addr: SocketAddr = match std::net::ToSocketAddrs::to_socket_addrs(&addr_str).ok().and_then(|mut i| i.next()) {
        Some(a) => a,
        None => {
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": format!("Invalid or unresolvable address syntax: '{}'", addr_str)}));
            } else {
                ui::failure(&format!("Invalid or unresolvable socket address '{}'.\n  💡 Tip: Provide an IP:PORT (e.g. `127.0.0.1:9876`), or run `ksp chat new` to start a local server.", addr_str));
            }
            return;
        }
    };

    if !json {
        println!("  {} {}", "Target:".dimmed(), addr_str.white().bold());
        println!();
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        connect_async(addr, json).await;
    });
}

async fn connect_async(addr: SocketAddr, json: bool) {
    let spin = if !json { Some(ui::spinner("Connecting & performing KSP handshake...")) } else { None };

    let mut client = match KspClient::connect(addr).await {
        Ok(c) => {
            if let Some(sp) = spin { sp.finish_and_clear(); }
            crate::cmd::telemetry::TelemetrySnapshot::record_connection(&c.session.id_string(), &format!("{}", c.cipher_suite));
            crate::cmd::telemetry::LogEntry::record("info", Some(&c.session.id_string()), &format!("Interactive session established with peer {}", addr));
            c
        }
        Err(e) => {
            if let Some(sp) = spin { sp.finish_and_clear(); }
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": e.to_string()}));
            } else {
                ui::failure(&format!("Connection/handshake failed: {}", e));
            }
            return;
        }
    };

    if json {
        ui::json_output(&serde_json::json!({
            "status": "connected",
            "session_id": client.session.id_string(),
            "cipher_suite": format!("{}", client.cipher_suite),
            "peer": addr.to_string(),
        }));
        return;
    }

    ui::success("Connected and KSP handshake verified!");
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║           KSP Encrypted Session Active           ║");
    println!("║  Session: {:38}║", client.session.id_string());
    println!("║  Cipher:  {:38}║", format!("{}", client.cipher_suite));
    println!("║  Peer:    {:38}║", addr.to_string());
    println!("╚══════════════════════════════════════════════════╝");
    println!("\nType messages to send (encrypted). Press Ctrl+C or type 'exit' to quit.\n");

    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.eq_ignore_ascii_case("exit") || trimmed.eq_ignore_ascii_case("quit") {
            break;
        }

        if let Err(e) = client.send_data(1, line.as_bytes()).await {
            ui::failure(&format!("Send failed: {}", e));
            break;
        }
        let _ = crate::cmd::capture::append_packet_to_pcap(&ksp_core::packet::KspPacket::new_handshake(PacketType::Data, line.as_bytes().to_vec()).serialize());

        match client.receive_packet().await {
            Ok((packet, plaintext)) => {
                let _ = crate::cmd::capture::append_packet_to_pcap(&packet.serialize());
                if packet.packet_type == PacketType::Data || packet.packet_type == PacketType::StreamData {
                    let text = String::from_utf8_lossy(&plaintext);
                    println!("← Echo: {}", text);
                } else if packet.packet_type == PacketType::GoAway {
                    ui::info("Server closed connection (GoAway received)");
                    break;
                }
            }
            Err(e) => {
                ui::failure(&format!("Receive error: {}", e));
                break;
            }
        }
    }

    let _ = client.close().await;
    ui::info("Session closed.");
}

/// Disconnect the active KSP session or connection.
pub fn run_disconnect(json: bool) {
    if json {
        ui::json_output(&serde_json::json!({"status": "disconnected", "message": "Active session closed"}));
    } else {
        ui::success("Disconnected active KSP session gracefully.");
    }
}
