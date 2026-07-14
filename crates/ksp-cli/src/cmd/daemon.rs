//! `ksp daemon start|stop|status` — Local IPC & telemetry control plane daemon (`127.0.0.1:9899`).
//!
//! Provides background local IPC queries (`status`, `sessions`, `metrics`, `logs`, `stop`)
//! for `ksp dashboard`, `ksp logs`, `ksp metrics`, and session inspectors.

use colored::Colorize;
use crate::ui;
use crate::cmd::telemetry::{TelemetrySnapshot, LogEntry};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const DAEMON_IPC_PORT: u16 = 9899;

pub fn run_start(verbose: bool, json: bool) {
    if !json {
        ui::print_header("KSP Daemon (Control Plane)");
        println!("  {} Starting local IPC telemetry control plane on port {}...", "🔄".yellow(), DAEMON_IPC_PORT);
    }

    if verbose {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .try_init();
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Initialize or update telemetry state
        TelemetrySnapshot::init_server();
        LogEntry::record("info", None, "KSP Daemon IPC control plane started");

        let listener = match TcpListener::bind(format!("127.0.0.1:{}", DAEMON_IPC_PORT)).await {
            Ok(l) => l,
            Err(e) => {
                if json {
                    ui::json_output(&serde_json::json!({"status": "error", "message": format!("Port {} busy: {}", DAEMON_IPC_PORT, e)}));
                } else {
                    ui::failure(&format!("Failed to bind daemon IPC port {}: {}", DAEMON_IPC_PORT, e));
                }
                return;
            }
        };

        if json {
            ui::json_output(&serde_json::json!({"status": "running", "port": DAEMON_IPC_PORT, "ipc": "tcp://127.0.0.1:9899"}));
        } else {
            ui::success(&format!("Daemon IPC listening on tcp://127.0.0.1:{}", DAEMON_IPC_PORT));
            println!("  {} Press Ctrl+C or send IPC stop command to shutdown.\n", "ℹ".blue());
        }

        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    tokio::spawn(async move {
                        let _ = handle_ipc_request(&mut stream).await;
                    });
                    let _ = addr;
                }
                Err(_) => break,
            }
        }
    });
}

async fn handle_ipc_request(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let req_str = String::from_utf8_lossy(&buf[..n]);
    let req: serde_json::Value = match serde_json::from_str(&req_str) {
        Ok(v) => v,
        Err(_) => serde_json::json!({"cmd": req_str.trim()}),
    };

    let cmd = req.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
    let response = match cmd {
        "status" | "info" => {
            let snap = TelemetrySnapshot::read();
            serde_json::to_string(&snap)?
        }
        "sessions" => {
            let snap = TelemetrySnapshot::read();
            serde_json::to_string(&serde_json::json!({"sessions": snap.sessions, "active_count": snap.active_sessions}))?
        }
        "metrics" => {
            let snap = TelemetrySnapshot::read();
            let mut prom = String::new();
            prom.push_str("# HELP ksp_active_sessions Number of currently connected KSP client sessions\n");
            prom.push_str("# TYPE ksp_active_sessions gauge\n");
            prom.push_str(&format!("ksp_active_sessions {}\n", snap.active_sessions));
            prom.push_str("# HELP ksp_total_bytes_sent Total payload bytes transmitted across all sessions\n");
            prom.push_str("# TYPE ksp_total_bytes_sent counter\n");
            prom.push_str(&format!("ksp_total_bytes_sent {}\n", snap.total_bytes_sent));
            prom.push_str("# HELP ksp_total_bytes_recv Total payload bytes received across all sessions\n");
            prom.push_str("# TYPE ksp_total_bytes_recv counter\n");
            prom.push_str(&format!("ksp_total_bytes_recv {}\n", snap.total_bytes_recv));
            prom.push_str("# HELP ksp_total_packets Total encrypted protocol packets processed\n");
            prom.push_str("# TYPE ksp_total_packets counter\n");
            prom.push_str(&format!("ksp_total_packets {}\n", snap.total_packets));
            prom.push_str("# HELP ksp_replay_attempts_blocked Total sliding-window replay attacks dropped\n");
            prom.push_str("# TYPE ksp_replay_attempts_blocked counter\n");
            prom.push_str(&format!("ksp_replay_attempts_blocked {}\n", snap.replay_attempts_blocked));
            prom
        }
        "logs" => {
            let level = req.get("level").and_then(|v| v.as_str());
            let session = req.get("session").and_then(|v| v.as_str());
            let limit = req.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let logs = LogEntry::query(level, session, limit);
            serde_json::to_string(&serde_json::json!({"logs": logs}))?
        }
        "stop" => {
            let _ = stream.write_all(b"{\"status\":\"stopping\"}\n").await;
            let _ = stream.flush().await;
            std::process::exit(0);
        }
        _ => serde_json::to_string(&serde_json::json!({"error": "unknown_command", "cmd": cmd}))?,
    };

    stream.write_all(response.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

pub fn run_status(json: bool) {
    if !json {
        ui::print_header("KSP Daemon Status");
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        match TcpStream::connect(format!("127.0.0.1:{}", DAEMON_IPC_PORT)).await {
            Ok(mut stream) => {
                let _ = stream.write_all(b"{\"cmd\":\"status\"}\n").await;
                let mut resp_buf = Vec::new();
                let _ = stream.read_to_end(&mut resp_buf).await;
                let resp_str = String::from_utf8_lossy(&resp_buf);
                if json {
                    println!("{}", resp_str.trim());
                } else if let Ok(snap) = serde_json::from_str::<TelemetrySnapshot>(&resp_str) {
                    ui::success("Daemon IPC control plane is ONLINE (`tcp://127.0.0.1:9899`)");
                    ui::kv("Status", &snap.status.green().bold().to_string());
                    ui::kv("Active Sessions", &snap.active_sessions.to_string());
                    ui::kv("Active Streams", &snap.active_streams.to_string());
                    ui::kv("Total Packets", &snap.total_packets.to_string());
                    ui::kv("Bytes Transferred", &format!("{} B sent / {} B recv", snap.total_bytes_sent, snap.total_bytes_recv));
                    ui::kv("Replays Blocked", &snap.replay_attempts_blocked.to_string());
                    println!();
                } else {
                    ui::success("Daemon IPC is ONLINE");
                }
            }
            Err(_) => {
                if json {
                    ui::json_output(&serde_json::json!({"running": false, "port": DAEMON_IPC_PORT}));
                } else {
                    ui::info("Daemon IPC control plane is OFFLINE (`127.0.0.1:9899` not listening)");
                    ui::info("Start background daemon with: ksp daemon start");
                }
            }
        }
    });
}

pub fn run_stop(json: bool) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        match TcpStream::connect(format!("127.0.0.1:{}", DAEMON_IPC_PORT)).await {
            Ok(mut stream) => {
                let _ = stream.write_all(b"{\"cmd\":\"stop\"}\n").await;
                if json {
                    ui::json_output(&serde_json::json!({"status": "stopped", "message": "Daemon shutdown requested"}));
                } else {
                    ui::success("Sent IPC shutdown command to active KSP Daemon.");
                }
            }
            Err(_) => {
                if json {
                    ui::json_output(&serde_json::json!({"status": "error", "message": "Daemon is not running"}));
                } else {
                    ui::info("Daemon is not currently running.");
                }
            }
        }
    });
}
