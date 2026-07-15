//! `ksp transfer send|receive|resume` — Real encrypted chunked file transfer over `KspClient` / `KspServer`.
//!
//! Streams file chunks over KSP `PacketType::Data` (`stream_id = 4`) with live `sha2::Sha256` integrity verification
//! and checkpoint/resume support.

use crate::ui;
use colored::Colorize;
use ksp_client::KspClient;
use ksp_core::types::PacketType;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::path::Path;

const CHUNK_SIZE: usize = 65536; // 64 KB per KSP data packet

pub fn run_send(file: &str, address: &str, json: bool) {
    let path = Path::new(file);
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": format!("Cannot open file '{}': {}", file, e)}),
                );
            } else {
                ui::failure(&format!("Cannot open file '{}': {}", file, e));
            }
            return;
        }
    };

    let metadata = match f.metadata() {
        Ok(m) => m,
        Err(e) => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": format!("Cannot read metadata: {}", e)}),
                );
            } else {
                ui::failure(&format!("Cannot read metadata for '{}': {}", file, e));
            }
            return;
        }
    };

    let file_size = metadata.len();
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("transfer.dat");
    let target_addr_str = crate::cmd::env::resolve_target_address(address);
    let target_addr: SocketAddr = match target_addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": format!("Invalid target address {}: {}", target_addr_str, e)}),
                );
            } else {
                ui::failure(&format!("Invalid address '{}': {}", target_addr_str, e));
            }
            return;
        }
    };

    if !json {
        ui::print_header("KSP File Transfer — Send");
        ui::kv("File", filename);
        ui::kv("Size", &ui::format_bytes(file_size));
        ui::kv("Target Peer", &target_addr_str);
        println!();
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let spin = if !json { Some(ui::spinner("Connecting and establishing KSP secure channel...")) } else { None };
        let mut client = match KspClient::connect(target_addr).await {
            Ok(c) => {
                if let Some(sp) = spin { sp.finish_and_clear(); }
                c
            }
            Err(e) => {
                if let Some(sp) = spin { sp.finish_and_clear(); }
                if json {
                    ui::json_output(&serde_json::json!({"status": "error", "message": format!("Connection failed: {}", e)}));
                } else {
                    ui::failure(&format!("Failed to connect to {}: {}", target_addr_str, e));
                    ui::info("Ensure a KSP server or `ksp transfer receive` peer is running and accessible.");
                }
                return;
            }
        };

        // Step 1: Compute full SHA-256 hash before transmission
        let spin_hash = if !json { Some(ui::spinner("Computing live SHA-256 integrity digest...")) } else { None };
        let mut hasher = Sha256::new();
        let mut hash_buf = [0u8; CHUNK_SIZE];
        while let Ok(n) = f.read(&mut hash_buf) {
            if n == 0 { break; }
            hasher.update(&hash_buf[..n]);
        }
        let sha256_hex = hex::encode(hasher.finalize());
        let _ = f.seek(SeekFrom::Start(0));
        if let Some(sp) = spin_hash { sp.finish_and_clear(); }

        if !json {
            ui::kv("SHA-256 Digest", &sha256_hex.yellow().to_string());
            println!();
        }

        // Step 2: Send FILE_HEADER
        let header_json = serde_json::json!({
            "op": "FILE_HEADER",
            "filename": filename,
            "size": file_size,
            "sha256": sha256_hex
        });
        if let Err(e) = client.send_packet(PacketType::Data, 1, header_json.to_string().as_bytes()).await {
            if !json { ui::failure(&format!("Failed to send file header: {}", e)); }
            return;
        }

        // Step 3: Stream chunks
        let pb = if !json { Some(ui::progress_bar(file_size, "Streaming Encrypted Chunks")) } else { None };
        let start_time = std::time::Instant::now();
        let mut total_sent = 0u64;
        let mut chunk_buf = [0u8; CHUNK_SIZE];

        while let Ok(n) = f.read(&mut chunk_buf) {
            if n == 0 { break; }
            if let Err(e) = client.send_packet(PacketType::Data, 2, &chunk_buf[..n]).await {
                if let Some(ref p) = pb { p.finish_and_clear(); }
                if !json { ui::failure(&format!("Error sending chunk at offset {}: {}", total_sent, e)); }
                return;
            }
            total_sent += n as u64;
            if let Some(ref p) = pb { p.set_position(total_sent); }
        }

        // Step 4: Send FILE_EOF
        let eof_json = serde_json::json!({"op": "FILE_EOF", "sha256": sha256_hex});
        let _ = client.send_packet(PacketType::Data, 1, eof_json.to_string().as_bytes()).await;

        if let Some(ref p) = pb { p.finish_with_message("Chunks Delivered"); }

        // Step 5: Wait for FILE_ACK or echo response
        let mut verified_remote = false;
        #[allow(clippy::collapsible_if)]
        if let Ok((_pkt, payload)) = tokio::time::timeout(std::time::Duration::from_secs(5), client.receive_packet()).await.unwrap_or(Err(ksp_core::error::KspError::ConnectionClosed)) {
            if let Ok(ack_val) = serde_json::from_slice::<serde_json::Value>(&payload) {
                if ack_val.get("op").and_then(|v| v.as_str()) == Some("FILE_ACK") {
                    verified_remote = ack_val.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
                }
            }
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let speed_mbs = if elapsed > 0.001 { (file_size as f64 / 1_048_576.0) / elapsed } else { 0.0 };

        crate::cmd::telemetry::TelemetrySnapshot::record_packets(file_size, 256, file_size.div_ceil(CHUNK_SIZE as u64) + 2, 0);
        crate::cmd::telemetry::LogEntry::record("info", Some(&client.session.id_string()), &format!("Transferred file {} ({} B) to {}", filename, file_size, target_addr_str));

        if json {
            ui::json_output(&serde_json::json!({
                "status": if verified_remote { "ok" } else { "unverified" },
                "file": filename,
                "size": file_size,
                "sha256": sha256_hex,
                "elapsed_sec": elapsed,
                "speed_mbps": speed_mbs,
                "verified": verified_remote,
            }));
        } else {
            println!();
            if verified_remote {
                ui::summary_ok(&format!("Transfer complete: {} delivered in {:.2}s ({:.2} MB/s | SHA-256 Verified by receiver ✔)", ui::format_bytes(file_size), elapsed, speed_mbs));
            } else {
                ui::summary_ok(&format!("Transfer finished: {} sent in {:.2}s ({:.2} MB/s | SHA-256 verification not confirmed by receiver)", ui::format_bytes(file_size), elapsed, speed_mbs));
            }
        }
    });
}

pub fn run_resume(file: &str, address: &str, json: bool) {
    let path = Path::new(file);
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": format!("Cannot open file '{}': {}", file, e)}),
                );
            } else {
                ui::failure(&format!("Cannot open file '{}': {}", file, e));
            }
            return;
        }
    };

    let metadata = match f.metadata() {
        Ok(m) => m,
        Err(e) => {
            if !json {
                ui::failure(&format!("Cannot read metadata: {}", e));
            }
            return;
        }
    };

    let file_size = metadata.len();
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("transfer.dat");
    let target_addr_str = crate::cmd::env::resolve_target_address(address);
    let target_addr: SocketAddr = match target_addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            if !json {
                ui::failure(&format!("Invalid address '{}': {}", target_addr_str, e));
            }
            return;
        }
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut client = match KspClient::connect(target_addr).await {
            Ok(c) => c,
            Err(e) => {
                if json {
                    ui::json_output(&serde_json::json!({"status": "error", "message": format!("Connection failed: {}", e)}));
                } else {
                    ui::failure(&format!("Failed to connect to {}: {}", target_addr_str, e));
                }
                return;
            }
        };

        let mut hasher = Sha256::new();
        let mut hash_buf = [0u8; CHUNK_SIZE];
        while let Ok(n) = f.read(&mut hash_buf) {
            if n == 0 { break; }
            hasher.update(&hash_buf[..n]);
        }
        let sha256_hex = hex::encode(hasher.finalize());

        let check_json = serde_json::json!({
            "op": "FILE_CHECKPOINT",
            "filename": filename,
            "sha256": sha256_hex
        });
        let _ = client.send_packet(PacketType::Data, 1, check_json.to_string().as_bytes()).await;

        let mut resumed_offset = 0u64;
        if let Ok((_pkt, payload)) = tokio::time::timeout(std::time::Duration::from_secs(3), client.receive_packet()).await.unwrap_or(Err(ksp_core::error::KspError::ConnectionClosed))
            && let Ok(resp) = serde_json::from_slice::<serde_json::Value>(&payload)
                && let Some(offset) = resp.get("offset").and_then(|v| v.as_u64()) {
                    resumed_offset = offset.min(file_size);
                }

        let _ = f.seek(SeekFrom::Start(resumed_offset));

        if !json {
            ui::print_header("KSP File Transfer — Resumption Mode");
            ui::kv("File", filename);
            ui::kv("Target", &target_addr_str);
            ui::kv("Total Size", &ui::format_bytes(file_size));
            ui::kv("SHA-256 Digest", &sha256_hex.yellow().to_string());
            println!();
            if resumed_offset > 0 {
                println!("  {} Resuming chunk stream from receiver-confirmed byte offset {}...", "🔄".yellow(), ui::format_bytes(resumed_offset));
            } else {
                println!("  {} Starting chunk stream from byte offset 0 (no remote checkpoint offset found)...", "🔄".yellow());
            }
            println!();
        }

        let pb = if !json { Some(ui::progress_bar(file_size, "Resuming Encrypted Chunks")) } else { None };
        if let Some(ref p) = pb { p.set_position(resumed_offset); }

        let start_time = std::time::Instant::now();
        let mut total_sent = resumed_offset;
        let mut chunk_buf = [0u8; CHUNK_SIZE];

        while let Ok(n) = f.read(&mut chunk_buf) {
            if n == 0 { break; }
            if let Err(e) = client.send_packet(PacketType::Data, 2, &chunk_buf[..n]).await {
                if let Some(ref p) = pb { p.finish_and_clear(); }
                if !json { ui::failure(&format!("Error sending chunk at offset {}: {}", total_sent, e)); }
                return;
            }
            total_sent += n as u64;
            if let Some(ref p) = pb { p.set_position(total_sent); }
        }

        let eof_json = serde_json::json!({"op": "FILE_EOF", "sha256": sha256_hex});
        let _ = client.send_packet(PacketType::Data, 1, eof_json.to_string().as_bytes()).await;

        if let Some(ref p) = pb { p.finish_with_message("Resumed Chunks Delivered"); }

        let mut verified_remote = false;
        #[allow(clippy::collapsible_if)]
        if let Ok((_pkt, payload)) = tokio::time::timeout(std::time::Duration::from_secs(5), client.receive_packet()).await.unwrap_or(Err(ksp_core::error::KspError::ConnectionClosed)) {
            if let Ok(ack_val) = serde_json::from_slice::<serde_json::Value>(&payload) {
                if ack_val.get("op").and_then(|v| v.as_str()) == Some("FILE_ACK") {
                    verified_remote = ack_val.get("verified").and_then(|v| v.as_bool()).unwrap_or(false);
                }
            }
        }

        let elapsed = start_time.elapsed().as_secs_f64();
        let speed_mbs = if elapsed > 0.001 { ((file_size - resumed_offset) as f64 / 1_048_576.0) / elapsed } else { 0.0 };

        if json {
            ui::json_output(&serde_json::json!({
                "status": if verified_remote { "ok" } else { "unverified" },
                "resumed": resumed_offset > 0,
                "resumed_from": resumed_offset,
                "total_size": file_size,
                "sha256": sha256_hex,
                "elapsed_sec": elapsed,
                "speed_mbps": speed_mbs,
                "verified": verified_remote
            }));
        } else {
            println!();
            if verified_remote {
                ui::summary_ok(&format!("Resumed transfer complete: {} delivered (resumed {} from offset {}) at {:.2} MB/s | SHA-256 Verified by receiver ✔", ui::format_bytes(file_size), ui::format_bytes(file_size - resumed_offset), ui::format_bytes(resumed_offset), speed_mbs));
            } else {
                ui::summary_ok(&format!("Resumed transfer finished: {} delivered (resumed {} from offset {}) at {:.2} MB/s | SHA-256 verification not confirmed by receiver", ui::format_bytes(file_size), ui::format_bytes(file_size - resumed_offset), ui::format_bytes(resumed_offset), speed_mbs));
            }
        }
    });
}

pub fn run_receive(port: u16, output: Option<&str>, json: bool) {
    let addr_str = format!("0.0.0.0:{}", port);
    if !json {
        ui::print_header("KSP File Receiver");
        if let Some(out_path) = output {
            println!("  {} Saving received stream to `{}`", "💾".cyan(), out_path);
        }
        println!(
            "  {} Starting local KSP receiver endpoint on {}...",
            "📥".yellow(),
            addr_str
        );
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        use ksp_server::{load_or_generate_cert, run_server, ServerConfig};
        let bind_addr: SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return,
        };

        let (cert, key) = match load_or_generate_cert() {
            Ok((c, k)) => (c, k),
            Err(e) => {
                if !json { ui::failure(&format!("Failed to init receiver certificate: {}", e)); }
                return;
            }
        };

        if !json {
            ui::success(&format!("KSP File Receiver listening on {}", addr_str));
            println!("  {} Senders can transmit files using: ksp transfer send <file> --to <your-ip>:{}\n", "ℹ".blue(), port);
        } else {
            ui::json_output(&serde_json::json!({"status": "listening", "port": port, "output": output}));
        }

        let config = ServerConfig {
            bind_addr,
            certificate: cert,
            signing_key: key,
            capabilities: ksp_core::capability::default_capabilities(),
            gateway_target: None,
            output_sink: output.map(std::path::PathBuf::from),
            auth_config: ksp_server::AuthConfig::from_env(),
        };

        let _ = run_server(config).await;
    });
}
