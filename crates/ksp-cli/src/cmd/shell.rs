//! `ksp shell` — Real stateful KSP REPL console (`ksp (addr)>`).
//!
//! Holds a real live `KspClient` connection across commands (`connect`, `ping`, `send`, `transfer`, `inspect`, `disconnect`).

use crate::ui;
use colored::Colorize;
use ksp_client::KspClient;
use ksp_core::types::PacketType;
use std::io::{self, Write};
use std::net::SocketAddr;

pub fn run_shell(json: bool) {
    if json {
        ui::json_output(
            &serde_json::json!({"status": "error", "message": "Interactive shell requires TTY/console mode"}),
        );
        return;
    }

    ui::print_header("KSP Stateful Interactive Shell (REPL)");
    println!(
        "  {} Welcome to the KSP Developer Console v{}. Type `help` or `exit`.\n",
        "ℹ".blue(),
        ksp_core::CURRENT_VERSION
    );

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut active_client: Option<KspClient> = None;
        let mut target_label: Option<String> = None;

        loop {
            let prompt_prefix = match &target_label {
                Some(addr) => format!("ksp ({})> ", addr.green().bold()),
                None => "ksp> ".cyan().bold().to_string(),
            };

            print!("  {}", prompt_prefix);
            let _ = io::stdout().flush();

            let mut input = String::new();
            if io::stdin().read_line(&mut input).is_err() {
                break;
            }

            let trimmed = input.trim();
            if trimmed.is_empty() {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            let cmd = parts[0].to_lowercase();

            match cmd.as_str() {
                "exit" | "quit" | "q" => {
                    if let Some(mut client) = active_client.take() {
                        let _ = client.close().await;
                        println!("  {} Closed active KSP session before exit...", "✔".green());
                    }
                    println!("  Goodbye! 🚀");
                    break;
                }
                "help" | "?" => {
                    println!("  {}", "Available Stateful Interactive Commands:".yellow().bold());
                    println!("    {} connect <address>       Connect & authenticate real KSP session", "•".cyan());
                    println!("    {} disconnect              Close current server connection", "•".cyan());
                    println!("    {} ping                    Ping over active connection & check RTT", "•".cyan());
                    println!("    {} send <id> <text>        Send encrypted payload over stream <id>", "•".cyan());
                    println!("    {} inspect                 Inspect active session crypto state", "•".cyan());
                    println!("    {} transfer <file>         Send a file over active session", "•".cyan());
                    println!("    {} status                  Show daemon & session telemetry", "•".cyan());
                    println!("    {} clear                   Clear console screen", "•".cyan());
                    println!("    {} exit / quit             Exit KSP interactive shell\n", "•".cyan());
                }
                "clear" | "cls" => {
                    print!("\x1B[2J\x1B[1;1H");
                    let _ = io::stdout().flush();
                }
                "connect" => {
                    if active_client.is_some() {
                        println!("  {} Already connected! Use `disconnect` first.\n", "⚠".yellow());
                        continue;
                    }
                    let target = if parts.len() > 1 { parts[1] } else { "127.0.0.1:9876" };
                    let resolved = crate::cmd::env::resolve_target_address(target);
                    let addr: SocketAddr = match resolved.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            println!("  {} Invalid target address '{}': {}\n", "✘".red(), resolved, e);
                            continue;
                        }
                    };

                    print!("  Connecting and verifying KSP handshake to {}...", resolved);
                    let _ = io::stdout().flush();
                    match KspClient::connect(addr).await {
                        Ok(c) => {
                            println!("\r  {} Connected to KSP server at {} (Session ID: {})", "✔".green().bold(), resolved.white().bold(), c.session.id_string().cyan());
                            println!("\n    Cipher Suite:  {}", format!("{}", c.cipher_suite).yellow());
                            println!("    Replay Window: Active (1024 packets)");
                            println!();
                            target_label = Some(resolved);
                            active_client = Some(c);
                        }
                        Err(e) => {
                            println!("\r  {} Failed to connect to {}: {}\n", "✘".red().bold(), resolved, e);
                        }
                    }
                }
                "disconnect" => {
                    if let Some(mut client) = active_client.take() {
                        let _ = client.close().await;
                        target_label = None;
                        println!("  {} Disconnected active session.\n", "✔".green().bold());
                    } else {
                        println!("  {} Not currently connected.\n", "ℹ".blue());
                    }
                }
                "ping" => {
                    if let Some(ref mut client) = active_client {
                        let start = std::time::Instant::now();
                        if let Ok(()) = client.send_packet(PacketType::KeepAlive, 0, b"shell_ping").await
                            && let Ok((_pkt, _)) = client.receive_packet().await {
                                let rtt_us = start.elapsed().as_micros();
                                println!("  {} Pong received in {} μs over encrypted tunnel\n", "←".green(), rtt_us);
                                continue;
                            }
                        println!("  {} Ping timed out or failed over active session.\n", "✘".red());
                    } else {
                        println!("  {} Not connected. Connect first with `connect <addr>` or use standard `ksp ping` outside REPL.\n", "⚠".yellow());
                    }
                }
                "send" => {
                    if parts.len() < 3 {
                        println!("  Usage: send <stream_id> <message text>\n");
                        continue;
                    }
                    let sid: u32 = parts[1].parse().unwrap_or(1);
                    let msg = parts[2..].join(" ");
                    if let Some(ref mut client) = active_client {
                        if let Ok(()) = client.send_data(sid, msg.as_bytes()).await {
                            if let Ok((_pkt, payload)) = tokio::time::timeout(std::time::Duration::from_secs(2), client.receive_packet()).await.unwrap_or(Err(ksp_core::error::KspError::ConnectionClosed)) {
                                println!("  {} Echo response on Stream #{}: {}\n", "←".green(), sid, String::from_utf8_lossy(&payload));
                            } else {
                                println!("  {} Sent {} bytes on Stream #{}\n", "✔".green(), msg.len(), sid);
                            }
                        } else {
                            println!("  {} Failed to transmit data over active session.\n", "✘".red());
                        }
                    } else {
                        println!("  {} Not connected. Run `connect <addr>` first.\n", "⚠".yellow());
                    }
                }
                "inspect" => {
                    if let Some(ref client) = active_client {
                        println!("\n  ╔════════════════════════════════════════════════════════════╗");
                        println!("  ║             Active KSP Session Cryptographic State        ║");
                        println!("  ╠════════════════════════════════════════════════════════════╣");
                        println!("  ║  Session UUID:       {:<38}║", client.session.id_string());
                        println!("  ║  Protocol Version:   KSP v{:<34}║", ksp_core::CURRENT_VERSION);
                        println!("  ║  Negotiated Cipher:  {:<38}║", format!("{}", client.cipher_suite));
                        println!("  ║  Send Sequence #:    {:<38}║", client.session.send_nonce.current_counter());
                        println!("  ║  Replay Protection:  Active (1024-bit bitmap window)     ║");
                        println!("  ╚════════════════════════════════════════════════════════════╝\n");
                    } else {
                        println!("  {} Not connected. Run `connect <addr>` first.\n", "⚠".yellow());
                    }
                }
                "status" => {
                    crate::cmd::daemon::run_status(false);
                }
                "transfer" => {
                    if parts.len() < 2 {
                        println!("  Usage: transfer <filepath>\n");
                        continue;
                    }
                    if let Some(ref target) = target_label {
                        crate::cmd::transfer::run_send(parts[1], target, false);
                    } else {
                        println!("  {} Connect to a peer first with `connect <addr>` before transferring.\n", "⚠".yellow());
                    }
                }
                _ => {
                    println!("  {} Unknown shell command: '{}'. Type `help` for commands.\n", "✘".red(), cmd);
                }
            }
        }
    });
}
