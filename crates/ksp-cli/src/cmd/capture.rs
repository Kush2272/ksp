//! `ksp capture start|stop|export|live` — Real PCAP 2.4 packet capture & live KSP frame inspector.
//!
//! Writes standard 24-byte PCAP 2.4 global headers (`0xa1b2c3d4`, DLT_USER0 = 147) and records live
//! KSP frames with 16-byte PCAP packet headers.

use crate::ui;
use colored::Colorize;
use ksp_core::packet::KspPacket;
pub use ksp_core::{
    PCAP_GLOBAL_HEADER, append_packet_to_pcap, get_capture_file, get_capture_pid_file,
};
use std::fs::{self, File};
use std::io::Read;

pub fn run_start(_port: u16, json: bool) {
    let pcap_path = get_capture_file();
    let pid_path = get_capture_pid_file();

    if let Err(e) = fs::write(&pcap_path, PCAP_GLOBAL_HEADER) {
        if !json {
            ui::failure(&format!("Failed to write PCAP 2.4 header: {}", e));
        }
        return;
    }
    let _ = fs::write(&pid_path, format!("{}", std::process::id()));

    // Record initial capture session event
    crate::cmd::telemetry::LogEntry::record(
        "info",
        None,
        "PCAP capture hook initialized for KSP traffic (DLT 147 USER0)",
    );

    if json {
        ui::json_output(&serde_json::json!({
            "status": "recording_enabled",
            "capture_mode": "application-layer buffer (records ksp connect / transfer packets across the workspace)",
            "pcap_version": "2.4",
            "dlt": 147,
            "file": pcap_path.display().to_string()
        }));
        return;
    }

    ui::print_header("KSP Packet Capture (PCAP 2.4)");
    ui::kv("Capture Output", &pcap_path.display().to_string());
    ui::kv(
        "Recording Hook",
        "ksp_core::record_pcap_if_active (application-layer)",
    );
    ui::kv("Link-Layer Header", "DLT 147 (USER0 / KSP Protocol Frame)");
    ui::kv("Snaplen", "65,535 bytes");
    println!();
    println!(
        "  {} Initialized live KSP PCAP 2.4 application-layer capture file (no OS-level capture hook)",
        "✔".green().bold()
    );
    println!(
        "  {} Packets sent or received via `ksp connect` and `ksp transfer` across the workspace will be recorded automatically.",
        "ℹ".blue()
    );
    println!(
        "  {} Run `ksp capture stop` or `ksp capture export` when done.\n",
        "ℹ".blue()
    );
}

pub fn run_stop(json: bool) {
    let pcap_path = get_capture_file();
    let pid_path = get_capture_pid_file();
    let _ = fs::remove_file(pid_path);

    let metadata = fs::metadata(&pcap_path);
    let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);

    // Calculate approximate packet count from PCAP headers (24 global + N * (16 header + frame))
    let mut packets = 0u64;
    if let Ok(mut f) = File::open(&pcap_path) {
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() && buf.len() > 24 {
            let mut offset = 24;
            while offset + 16 <= buf.len() {
                let incl_len = u32::from_le_bytes([
                    buf[offset + 8],
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                ]) as usize;
                if offset + 16 + incl_len <= buf.len() {
                    packets += 1;
                    offset += 16 + incl_len;
                } else {
                    break;
                }
            }
        }
    }

    if json {
        ui::json_output(&serde_json::json!({
            "status": "stopped",
            "file": pcap_path.display().to_string(),
            "bytes_captured": size,
            "packets_recorded": packets
        }));
        return;
    }

    ui::print_header("KSP Packet Capture Stopped");
    println!(
        "  {} Finalized PCAP 2.4 buffer: {} ({} frames recorded)",
        "✔".green().bold(),
        ui::format_bytes(size),
        packets
    );
    println!(
        "  {} Inspect live or export with `ksp capture export --format pcap`.\n",
        "ℹ".blue()
    );
}

pub fn run_export(format: &str, output: &str, json: bool) {
    let pcap_path = get_capture_file();
    let out_file = if output.is_empty() {
        format!("ksp_capture.{}", format)
    } else {
        output.to_string()
    };

    let data = match fs::read(&pcap_path) {
        Ok(d) => d,
        Err(e) => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": format!("Cannot read capture buffer: {}", e)}),
                );
            } else {
                ui::failure(&format!("Cannot read capture buffer: {}", e));
            }
            return;
        }
    };

    if format.eq_ignore_ascii_case("json") {
        // Parse PCAP and export structured JSON
        let mut frames = Vec::new();
        if data.len() > 24 {
            let mut offset = 24;
            let mut id = 1;
            while offset + 16 <= data.len() {
                let ts_sec = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                let ts_usec = u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                let incl_len = u32::from_le_bytes([
                    data[offset + 8],
                    data[offset + 9],
                    data[offset + 10],
                    data[offset + 11],
                ]) as usize;
                if offset + 16 + incl_len <= data.len() {
                    let frame_bytes = &data[offset + 16..offset + 16 + incl_len];
                    if let Ok((pkt, _)) = KspPacket::deserialize(frame_bytes) {
                        frames.push(serde_json::json!({
                            "id": id,
                            "timestamp": format!("{}.{:06}", ts_sec, ts_usec),
                            "type": format!("{}", pkt.packet_type),
                            "flags": pkt.flags.bits(),
                            "stream_id": pkt.stream_id,
                            "payload_bytes": pkt.payload.len(),
                        }));
                    }
                    id += 1;
                    offset += 16 + incl_len;
                } else {
                    break;
                }
            }
        }
        let json_out = serde_json::json!({"pcap_version": "2.4", "frames": frames});
        let _ = fs::write(
            &out_file,
            serde_json::to_string_pretty(&json_out).unwrap_or_default(),
        );
    } else {
        let _ = fs::copy(&pcap_path, &out_file);
    }

    if json {
        ui::json_output(
            &serde_json::json!({"status": "exported", "format": format, "file": out_file}),
        );
        return;
    }

    ui::success(&format!(
        "Exported PCAP capture buffer to {} (Format: {})",
        out_file.white().bold(),
        format.cyan()
    ));
    println!();
}

pub fn run_live(json: bool) {
    if json {
        ui::json_output(
            &serde_json::json!({"status": "error", "message": "Live mode requires interactive terminal"}),
        );
        return;
    }

    ui::print_header("KSP Live Frame Stream Inspector");
    println!(
        "  {}\n",
        "Press Ctrl+C to stop live packet inspection stream...".dimmed()
    );

    let pcap_path = get_capture_file();
    let mut last_pos = 24usize; // Skip global header initially

    if !pcap_path.exists() {
        let _ = fs::write(&pcap_path, PCAP_GLOBAL_HEADER);
    }

    let mut counter = 0;
    loop {
        if let Ok(data) = fs::read(&pcap_path)
            && data.len() > last_pos + 16
        {
            while last_pos + 16 <= data.len() {
                let ts_sec = u32::from_le_bytes([
                    data[last_pos],
                    data[last_pos + 1],
                    data[last_pos + 2],
                    data[last_pos + 3],
                ]);
                let ts_usec = u32::from_le_bytes([
                    data[last_pos + 4],
                    data[last_pos + 5],
                    data[last_pos + 6],
                    data[last_pos + 7],
                ]);
                let incl_len = u32::from_le_bytes([
                    data[last_pos + 8],
                    data[last_pos + 9],
                    data[last_pos + 10],
                    data[last_pos + 11],
                ]) as usize;
                if last_pos + 16 + incl_len <= data.len() {
                    let frame_bytes = &data[last_pos + 16..last_pos + 16 + incl_len];
                    if let Ok((pkt, _)) = KspPacket::deserialize(frame_bytes) {
                        counter += 1;
                        let ptype_str = format!("{}", pkt.packet_type);
                        let color_type = match ptype_str.as_str() {
                            "ClientHello" | "ServerHello" => ptype_str.yellow().bold(),
                            "HandshakeFinish" => ptype_str.green().bold(),
                            "Data" | "StreamData" => ptype_str.cyan().bold(),
                            _ => ptype_str.white().bold(),
                        };
                        let ts_formatted = format!("{}.{:03}", ts_sec % 86400, ts_usec / 1000);
                        let info = format!(
                            "Stream #{:<3} | Flags: 0x{:02X} | Payload: {} B",
                            pkt.stream_id,
                            pkt.flags.bits(),
                            pkt.payload.len()
                        );
                        println!(
                            "  {:<6} {} [{:<16}] {:<40}",
                            format!("#{}", counter).dimmed(),
                            ts_formatted.dimmed(),
                            color_type,
                            info
                        );
                    }
                    last_pos += 16 + incl_len;
                } else {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
}
