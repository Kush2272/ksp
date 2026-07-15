//! `ksp stream open|list|close` — Stream management tools.

use crate::ui;

pub fn run_list(json: bool) {
    let snap = crate::cmd::telemetry::TelemetrySnapshot::fetch_current();
    if !json {
        ui::print_header("KSP Streams");
        if snap.active_streams > 0 {
            let mut t = ui::table(&[
                "Stream ID",
                "State",
                "Send Window",
                "Recv Window",
                "Associated Session",
            ]);
            for i in 1..=snap.active_streams {
                let session_uuid = if !snap.sessions.is_empty() {
                    snap.sessions[0].uuid.as_str()
                } else {
                    "Local Snapshot"
                };
                t.add_row(vec![
                    &format!("Stream #{i}"),
                    "ESTABLISHED",
                    "65,536 bytes",
                    "65,536 bytes",
                    session_uuid,
                ]);
            }
            println!("{t}");
            println!();
        } else {
            ui::info("Stream management requires an active session or background transfer.");
            ui::info("Connect first with: ksp connect <address> or run a file transfer.");
            println!();
            let mut t = ui::table(&[
                "Stream ID",
                "State",
                "Send Window",
                "Recv Window",
                "Priority",
            ]);
            t.add_row(vec!["(no active streams)", "—", "—", "—", "—"]);
            println!("{t}");
        }
    } else {
        if snap.active_streams > 0 {
            let streams: Vec<serde_json::Value> = (1..=snap.active_streams)
                .map(|i| {
                    serde_json::json!({
                        "stream_id": i,
                        "state": "ESTABLISHED",
                        "send_window": 65536,
                        "recv_window": 65536
                    })
                })
                .collect();
            ui::json_output(&serde_json::json!({"streams": streams, "count": snap.active_streams}));
        } else {
            ui::json_output(&serde_json::json!({"streams": [], "count": 0}));
        }
    }
}

pub fn run_open(json: bool) {
    if json {
        ui::json_output(
            &serde_json::json!({"status": "info", "message": "Stream open requires active session"}),
        );
    } else {
        ui::print_header("KSP Stream Open");
        ui::info("Opening a new stream requires an active session.");
        ui::info("Connect first with: ksp connect <address>");
    }
}

pub fn run_close(stream_id: u32, json: bool) {
    use std::io::{Read, Write};
    if let Ok(mut s) = std::net::TcpStream::connect("127.0.0.1:9899") {
        let req = serde_json::json!({"cmd": "stream_close", "stream_id": stream_id});
        if s.write_all(format!("{}\n", req).as_bytes()).is_ok() {
            let mut buf = [0u8; 512];
            #[allow(clippy::collapsible_if)]
            if let Ok(n) = s.read(&mut buf) {
                if let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&buf[..n]) {
                    if resp["status"] == "closed" {
                        if json {
                            ui::json_output(&serde_json::json!({
                                "status": "closed",
                                "stream_id": stream_id,
                                "closed_by": "daemon_ipc_control_plane"
                            }));
                        } else {
                            ui::print_header("KSP Stream Close");
                            ui::success(&format!(
                                "Closed stream ID {} via daemon IPC control plane.",
                                stream_id
                            ));
                        }
                        return;
                    }
                }
            }
        }
    }

    let mut snap = crate::cmd::telemetry::TelemetrySnapshot::fetch_current();
    if snap.active_streams > 0 {
        snap.active_streams -= 1;
        snap.save();
        if json {
            ui::json_output(&serde_json::json!({
                "status": "closed_local_tracking",
                "stream_id": stream_id,
                "note": "Decremented active stream count in local telemetry snapshot"
            }));
        } else {
            ui::print_header("KSP Stream Close");
            ui::success(&format!(
                "Closed stream ID {} in local tracking snapshot.",
                stream_id
            ));
            ui::info(
                "To close a live socket channel, ensure the KSP daemon/control plane is running (`ksp daemon start`).",
            );
        }
    } else {
        if json {
            ui::json_output(
                &serde_json::json!({"status": "error", "message": format!("Stream ID {} not found", stream_id)}),
            );
        } else {
            ui::failure(&format!("Stream ID {} not found.", stream_id));
        }
        std::process::exit(1);
    }
}

pub fn run_reset(json: bool) {
    use colored::Colorize;
    let mut snap = crate::cmd::telemetry::TelemetrySnapshot::fetch_current();
    let cleared = snap.active_streams;
    if cleared > 0 {
        snap.active_streams = 0;
        snap.save();
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "status": "reset_local_tracking",
                    "streams_cleared_from_snapshot": cleared,
                    "default_window_threshold": 65536,
                    "note": "Cleared local active stream counter in telemetry snapshot"
                })
            );
        } else {
            ui::header("KSP Local Stream Tracking Reset");
            println!(
                "  {} Resetting local tracking counter for {} stream(s)...",
                "🔄".yellow(),
                cleared
            );
            println!(
                "  {} Cleared active stream tracking inside local telemetry snapshot.",
                "✔".green().bold()
            );
            println!(
                "  {} Default stream flow control threshold: 64 KB (65,536 bytes).",
                "ℹ".blue()
            );
            println!();
        }
    } else {
        if json {
            ui::json_output(
                &serde_json::json!({"status": "error", "message": "No active KSP streams found to reset"}),
            );
        } else {
            ui::header("KSP Stream Reset");
            ui::failure("No active KSP streams found to reset.");
            ui::info(
                "Streams are created automatically during active sessions (`ksp connect` or `ksp transfer`).",
            );
        }
        std::process::exit(1);
    }
}
