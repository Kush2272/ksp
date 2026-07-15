//! `ksp session list|inspect|close` — Session management tools.

use crate::ui;
use colored::Colorize;

pub fn run_list(json: bool) {
    let snap = crate::cmd::telemetry::TelemetrySnapshot::fetch_current();
    if !json {
        ui::print_header("KSP Active Sessions");
        if !snap.sessions.is_empty() {
            let mut t = ui::table(&[
                "Session UUID",
                "Age",
                "Cipher",
                "Packets/Streams",
                "Bytes",
                "Status",
            ]);
            for s in &snap.sessions {
                t.add_row(vec![
                    &s.uuid,
                    "Active",
                    &s.cipher,
                    &format!("{} streams", s.streams),
                    &ui::format_bytes(s.bytes_transferred),
                    &s.status,
                ]);
            }
            println!("{t}");
            println!();
            ui::info("To inspect detailed session state, run: ksp session inspect <id>");
        } else {
            println!("  (no active sessions)");
            println!();
            ui::info("Sessions will appear when KSP clients connect to a running server.");
        }
    } else {
        ui::json_output(
            &serde_json::json!({"sessions": snap.sessions, "count": snap.sessions.len()}),
        );
    }
}

pub fn run_inspect(id: Option<&str>, json: bool) {
    let snap = crate::cmd::telemetry::TelemetrySnapshot::fetch_current();
    let target_id = match id {
        Some(i) => i,
        None => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": "Missing session ID argument"}),
                );
            } else {
                ui::failure("Please specify a session UUID: ksp session inspect <id>");
            }
            std::process::exit(1);
        }
    };

    if let Some(s) = snap.sessions.iter().find(|s| s.uuid == target_id) {
        if !json {
            ui::print_header("KSP Session Inspection");
            println!(
                "  {}",
                "════════════════════════════════════════════════════════════".cyan()
            );
            ui::kv("UUID", &s.uuid);
            ui::kv("Status", &s.status);
            ui::kv("Version", &format!("KSP v{}", ksp_core::CURRENT_VERSION));
            ui::kv("Cipher", &s.cipher);
            ui::kv("Streams", &format!("{}", s.streams));
            ui::kv("Bytes Transferred", &ui::format_bytes(s.bytes_transferred));
            ui::kv("RTT", &format!("{:.2} ms", s.rtt_ms));
            println!(
                "  {}",
                "════════════════════════════════════════════════════════════".cyan()
            );
            println!();
        } else {
            ui::json_output(&serde_json::json!({
                "uuid": s.uuid,
                "status": s.status,
                "version": ksp_core::CURRENT_VERSION.to_string(),
                "cipher": s.cipher,
                "streams": s.streams,
                "bytes_transferred": s.bytes_transferred,
                "rtt_ms": s.rtt_ms
            }));
        }
    } else {
        if json {
            ui::json_output(
                &serde_json::json!({"status": "error", "message": format!("Session not found: {}", target_id)}),
            );
        } else {
            ui::failure(&format!("Session not found: {}", target_id));
        }
        std::process::exit(1);
    }
}

pub fn run_close(session_id: &str, json: bool) {
    use std::io::{Read, Write};
    if let Ok(mut s) = std::net::TcpStream::connect("127.0.0.1:9899") {
        let req = serde_json::json!({"cmd": "session_close", "uuid": session_id});
        if s.write_all(format!("{}\n", req).as_bytes()).is_ok() {
            let mut buf = [0u8; 512];
            #[allow(clippy::collapsible_if)]
            if let Ok(n) = s.read(&mut buf) {
                if let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&buf[..n]) {
                    if resp["status"] == "closed" {
                        if json {
                            ui::json_output(&serde_json::json!({
                                "status": "closed",
                                "uuid": session_id,
                                "closed_by": "daemon_ipc_control_plane"
                            }));
                        } else {
                            ui::print_header("KSP Session Close");
                            ui::success(&format!(
                                "Closed session UUID via daemon IPC control plane: {}",
                                session_id
                            ));
                        }
                        return;
                    }
                }
            }
        }
    }

    let mut snap = crate::cmd::telemetry::TelemetrySnapshot::fetch_current();
    let orig_len = snap.sessions.len();
    snap.sessions.retain(|s| s.uuid != session_id);
    if snap.sessions.len() < orig_len {
        snap.active_sessions = snap.sessions.len() as u32;
        snap.save();
        if json {
            ui::json_output(&serde_json::json!({
                "status": "closed_local_tracking",
                "uuid": session_id,
                "note": "Removed session entry from local telemetry snapshot"
            }));
        } else {
            ui::print_header("KSP Session Close");
            ui::success(&format!(
                "Successfully removed session entry from local tracking: {}",
                session_id
            ));
            ui::info(
                "To close a live network stream, ensure the KSP daemon/control plane is running (`ksp daemon start`).",
            );
        }
    } else {
        if json {
            ui::json_output(
                &serde_json::json!({"status": "error", "message": format!("Session not found: {}", session_id)}),
            );
        } else {
            ui::failure(&format!("Session not found: {}", session_id));
        }
        std::process::exit(1);
    }
}

pub fn run_resume(session_id: &str, json: bool) {
    let snap = crate::cmd::telemetry::TelemetrySnapshot::fetch_current();
    if snap.sessions.iter().any(|s| s.uuid == session_id) {
        if json {
            ui::json_output(&serde_json::json!({
                "status": "found_local_session",
                "uuid": session_id,
                "note": "Session entry active in local state; use `ksp connect` to perform live 0-RTT PSK resumption"
            }));
        } else {
            ui::header("KSP Session Resumption Check");
            ui::kv("Session UUID", session_id);
            ui::success("Session entry found and verified in local tracking state.");
            ui::info(
                "To perform a live 0-RTT PSK handshake over TCP, run `ksp connect <target>` with this session ticket.",
            );
            println!();
        }
    } else {
        if json {
            ui::json_output(&serde_json::json!({
                "status": "error",
                "message": format!("Cannot resume session {}: no resumption ticket or session state found", session_id)
            }));
        } else {
            ui::failure(&format!(
                "Cannot resume session {}: no resumption ticket or session state found",
                session_id
            ));
        }
        std::process::exit(1);
    }
}
