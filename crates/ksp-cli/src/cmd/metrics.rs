//! `ksp metrics` — Prometheus OpenMetrics and observability export.
//!
//! Exposes active session counts, bytes transferred, packet counters, and replay attack
//! telemetry in standard Prometheus OpenMetrics text format or starts a dedicated metrics server.

use colored::Colorize;
use crate::ui;
use crate::cmd::telemetry::TelemetrySnapshot;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn run(listen_addr: Option<&str>, json: bool) {
    if let Some(addr) = listen_addr {
        if !json {
            ui::print_header("KSP Prometheus Metrics Server");
            println!("  {} Starting Prometheus HTTP endpoint on {}...", "🔄".yellow(), addr.white().bold());
        }
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            run_http_metrics_server(addr, json).await;
        });
        return;
    }

    // Print metrics right now
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let metrics_text = match query_ipc_metrics().await {
            Some(m) => m,
            None => format_snapshot_metrics(&TelemetrySnapshot::read()),
        };

        if json {
            let snap = TelemetrySnapshot::read();
            ui::json_output(&serde_json::json!({
                "status": snap.status,
                "uptime_secs": snap.uptime_secs,
                "active_sessions": snap.active_sessions,
                "active_streams": snap.active_streams,
                "total_packets": snap.total_packets,
                "total_bytes_sent": snap.total_bytes_sent,
                "total_bytes_recv": snap.total_bytes_recv,
                "replay_attempts_blocked": snap.replay_attempts_blocked,
                "openmetrics": metrics_text,
            }));
        } else {
            ui::print_header("KSP Prometheus OpenMetrics Export");
            print!("{}", metrics_text);
        }
    });
}

async fn query_ipc_metrics() -> Option<String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", crate::cmd::daemon::DAEMON_IPC_PORT)).await.ok()?;
    let _ = stream.write_all(b"{\"cmd\":\"metrics\"}\n").await;
    let mut resp_buf = Vec::new();
    let _ = stream.read_to_end(&mut resp_buf).await;
    let resp_str = String::from_utf8_lossy(&resp_buf);
    if resp_str.contains("# HELP") || resp_str.contains("ksp_") {
        return Some(resp_str.to_string());
    }
    None
}

pub fn format_snapshot_metrics(snap: &TelemetrySnapshot) -> String {
    let mut prom = String::new();
    prom.push_str("# HELP ksp_active_sessions Number of currently connected KSP client sessions\n");
    prom.push_str("# TYPE ksp_active_sessions gauge\n");
    prom.push_str(&format!("ksp_active_sessions {}\n", snap.active_sessions));
    prom.push_str("# HELP ksp_active_streams Number of currently active multiplexed streams\n");
    prom.push_str("# TYPE ksp_active_streams gauge\n");
    prom.push_str(&format!("ksp_active_streams {}\n", snap.active_streams));
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

async fn run_http_metrics_server(addr: &str, json: bool) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": format!("Failed to bind {}: {}", addr, e)}));
            } else {
                ui::failure(&format!("Failed to bind Prometheus metrics server on {}: {}", addr, e));
            }
            return;
        }
    };

    if json {
        ui::json_output(&serde_json::json!({"status": "running", "endpoint": format!("http://{}/metrics", addr)}));
    } else {
        ui::success(&format!("Prometheus server listening on http://{}/metrics", addr));
        println!("  {} Scrape endpoint ready. Press Ctrl+C to exit.\n", "ℹ".blue());
    }

    loop {
        if let Ok((mut socket, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let metrics_text = match query_ipc_metrics().await {
                    Some(m) => m,
                    None => format_snapshot_metrics(&TelemetrySnapshot::read()),
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}",
                    metrics_text.len(),
                    metrics_text
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    }
}
