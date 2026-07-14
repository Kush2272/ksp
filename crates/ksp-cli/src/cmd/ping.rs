//! `ksp ping <address>` — The "curl" / protocol ping of KSP.
//!
//! Establishes a secure KSP session via `KspClient`, measures handshake timing,
//! and transmits encrypted protocol ping packets to measure real round-trip times.

use colored::Colorize;
use crate::ui;
use std::net::SocketAddr;
use std::time::Instant;
use ksp_client::KspClient;
use ksp_core::types::PacketType;

pub fn run(address: &str, json: bool, _verbosity: u8) {
    if !json {
        ui::print_header("KSP Ping");
    }

    let addr_str = crate::cmd::env::resolve_target_address(address);

    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": format!("Invalid address: {}", e)}));
            } else {
                ui::failure(&format!("Invalid address '{}': {}", addr_str, e));
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
        ping_async(addr, json).await;
    });
}

async fn ping_async(addr: SocketAddr, json: bool) {
    let total_start = Instant::now();

    let spin = if !json { Some(ui::spinner("Establishing encrypted KSP session...")) } else { None };
    let connect_start = Instant::now();

    let mut client = match KspClient::connect(addr).await {
        Ok(c) => {
            if let Some(sp) = spin { sp.finish_and_clear(); }
            c
        }
        Err(e) => {
            if let Some(sp) = spin { sp.finish_and_clear(); }
            if json {
                ui::json_output(&serde_json::json!({
                    "status": "error",
                    "target": addr.to_string(),
                    "message": e.to_string()
                }));
            } else {
                ui::handshake_fail("Session Connect", &e.to_string());
            }
            return;
        }
    };

    let handshake_us = connect_start.elapsed().as_micros() as u64;

    if !json {
        println!("  {:<22} {}", "✔ KSP Handshake OK".green().bold(), format!("{} μs", handshake_us).yellow());
        println!("  {:<22} {}", "  Session ID".dimmed(), client.session.id_string().cyan());
        println!("  {:<22} {}", "  Cipher Suite".dimmed(), format!("{}", client.cipher_suite).white());
        println!("  {}", "── Protocol RTT Echo ─────────────────────────────────────────".dimmed());
    }

    let mut rtts = Vec::new();
    let num_pings = 4;

    for seq in 1..=num_pings {
        let ping_payload = format!("ksp-ping-seq-{}", seq);
        let send_start = Instant::now();

        // Send encrypted protocol ping
        if let Err(e) = client.send_packet(PacketType::KeepAlive, 0, ping_payload.as_bytes()).await {
            if !json {
                println!("    {} seq={} failed: {}", "✘ Ping".red(), seq, e);
            }
            break;
        }

        // Receive response (either PingAck or KeepAliveAck or Data)
        match client.receive_packet().await {
            Ok((_pkt, _payload)) => {
                let rtt_us = send_start.elapsed().as_micros() as u64;
                rtts.push(rtt_us);
                crate::cmd::telemetry::TelemetrySnapshot::record_packets(ping_payload.len() as u64, _payload.len() as u64, 2, 0);
                if !json {
                    println!("    {} seq={} time={} μs (encrypted)", "← Pong".green(), seq, rtt_us);
                }
            }
            Err(e) => {
                if !json {
                    println!("    {} seq={} receive failed: {}", "✘ Ping".red(), seq, e);
                }
                break;
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    }

    let _ = client.close().await;
    let total_ms = total_start.elapsed().as_millis() as u64;

    if json {
        let min_rtt = rtts.iter().min().copied().unwrap_or(0);
        let max_rtt = rtts.iter().max().copied().unwrap_or(0);
        let avg_rtt = if !rtts.is_empty() { rtts.iter().sum::<u64>() / rtts.len() as u64 } else { 0 };

        ui::json_output(&serde_json::json!({
            "status": "ok",
            "target": addr.to_string(),
            "handshake_time_us": handshake_us,
            "session_id": client.session.id_string(),
            "pings_sent": num_pings,
            "pings_received": rtts.len(),
            "min_rtt_us": min_rtt,
            "max_rtt_us": max_rtt,
            "avg_rtt_us": avg_rtt,
            "total_duration_ms": total_ms,
        }));
    } else if !rtts.is_empty() {
        let min_rtt = rtts.iter().min().copied().unwrap();
        let max_rtt = rtts.iter().max().copied().unwrap();
        let avg_rtt = rtts.iter().sum::<u64>() / rtts.len() as u64;

        println!("  {}", "── Summary ───────────────────────────────────────────────────".dimmed());
        println!("    Sent: {}, Received: {}, Handshake: {} μs", num_pings, rtts.len(), handshake_us);
        println!("    RTT min/avg/max = {} / {} / {} μs", min_rtt, avg_rtt, max_rtt);
        println!();
    }
}
