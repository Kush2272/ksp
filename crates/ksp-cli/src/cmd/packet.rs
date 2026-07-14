//! `ksp packet inspect|decode|build|encode` — Packet developer tools.

use colored::Colorize;
use crate::ui;
use ksp_core::packet::KspPacket;

pub fn run_inspect(file: &str, json: bool) {
    if !json {
        ui::print_header("KSP Packet Inspector");
    }

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": e.to_string()}));
            } else {
                ui::failure(&format!("Failed to read '{}': {}", file, e));
            }
            return;
        }
    };

    match KspPacket::deserialize(&data) {
        Ok((packet, consumed)) => {
            if json {
                ui::json_output(&serde_json::json!({
                    "version": packet.version.to_string(),
                    "type": packet.packet_type.name(),
                    "flags": packet.flags.to_string(),
                    "session_id": hex::encode(packet.session_id),
                    "stream_id": packet.stream_id,
                    "sequence": packet.sequence,
                    "nonce": hex::encode(packet.nonce),
                    "payload_size": packet.payload.len(),
                    "auth_tag": if packet.auth_tag.is_empty() { "none".into() } else { hex::encode(&packet.auth_tag) },
                    "wire_size": consumed,
                }));
            } else {
                let mut t = ui::table(&["Field", "Value"]);
                t.add_row(vec!["Version", &packet.version.to_string()]);
                t.add_row(vec!["Type", packet.packet_type.name()]);
                t.add_row(vec!["Flags", &packet.flags.to_string()]);
                t.add_row(vec!["Session ID", &uuid::Uuid::from_bytes(packet.session_id).to_string()]);
                t.add_row(vec!["Stream ID", &packet.stream_id.to_string()]);
                t.add_row(vec!["Sequence", &packet.sequence.to_string()]);
                t.add_row(vec!["Nonce", &hex::encode(packet.nonce)]);
                t.add_row(vec!["Payload", &format!("{} bytes", packet.payload.len())]);
                t.add_row(vec!["AEAD Tag", &if packet.auth_tag.is_empty() {
                    "(none — plaintext)".to_string()
                } else {
                    format!("{} (Valid)", hex::encode(&packet.auth_tag))
                }]);
                t.add_row(vec!["Wire Size", &format!("{} bytes", consumed)]);
                println!("{t}");
            }
        }
        Err(e) => {
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": e.to_string()}));
            } else {
                ui::failure(&format!("Failed to parse packet: {}", e));
            }
        }
    }
}

pub fn run_decode(file: &str, json: bool) {
    if !json {
        ui::print_header("KSP Packet Decoder");
    }

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": e.to_string()}));
            } else {
                ui::failure(&format!("Failed to read '{}': {}", file, e));
            }
            return;
        }
    };

    if !json {
        ui::print_section("Raw Hex");
        ui::hex_dump(&data, 16);
    }

    if data.len() >= 48 {
        if !json {
            ui::print_section("Header (48 bytes)");
            ui::hex_dump(&data[..48], 4);

            println!();
            ui::kv("Version byte", &format!("0x{:02X}", data[0]));
            ui::kv("Type byte", &format!("0x{:02X} ({})", data[1],
                ksp_core::types::PacketType::from_u8(data[1])
                    .map(|p| p.name().to_string())
                    .unwrap_or("Unknown".into())
            ));
            ui::kv("Flags", &format!("0x{:04X}", u16::from_be_bytes([data[2], data[3]])));
            ui::kv("Payload length", &format!("{} bytes",
                u32::from_be_bytes([data[4], data[5], data[6], data[7]])
            ));
        }

        if data.len() > 48 {
            let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
            let payload_end = (48 + payload_len).min(data.len());

            if !json {
                ui::print_section(&format!("Payload ({} bytes)", payload_end - 48));
                ui::hex_dump(&data[48..payload_end], 8);
            }

            if payload_end < data.len() {
                if !json {
                    ui::print_section(&format!("Authentication Tag ({} bytes)", data.len() - payload_end));
                    ui::hex_dump(&data[payload_end..], 2);
                }
            }
        }
    }

    if json {
        ui::json_output(&serde_json::json!({
            "raw_hex": hex::encode(&data),
            "size": data.len(),
        }));
    }
}

pub fn run_build(output: &str, json: bool) {
    if !json {
        ui::print_header("KSP Packet Builder");
    }

    let types = vec![
        "ClientHello", "ServerHello", "Data", "KeepAlive",
        "StreamOpen", "StreamClose", "GoAway",
    ];

    if !json {
        println!("  Select packet type:");
        for (i, t) in types.iter().enumerate() {
            println!("    {}  {}", format!("{}", i + 1).cyan().bold(), t);
        }
        println!();
    }

    let selection = dialoguer::Select::new()
        .with_prompt("  Packet type")
        .items(&types)
        .default(0)
        .interact()
        .unwrap_or(0);

    let packet_type = match selection {
        0 => ksp_core::types::PacketType::ClientHello,
        1 => ksp_core::types::PacketType::ServerHello,
        2 => ksp_core::types::PacketType::Data,
        3 => ksp_core::types::PacketType::KeepAlive,
        4 => ksp_core::types::PacketType::StreamOpen,
        5 => ksp_core::types::PacketType::StreamClose,
        6 => ksp_core::types::PacketType::GoAway,
        _ => ksp_core::types::PacketType::Data,
    };

    let payload_input: String = dialoguer::Input::new()
        .with_prompt("  Payload (text or hex with 0x prefix)")
        .default("Hello KSP!".into())
        .interact_text()
        .unwrap_or_default();

    let payload = if payload_input.starts_with("0x") {
        hex::decode(&payload_input[2..]).unwrap_or_else(|_| payload_input.as_bytes().to_vec())
    } else {
        payload_input.as_bytes().to_vec()
    };

    let packet = KspPacket::new_handshake(packet_type, payload);
    let bytes = packet.serialize();

    std::fs::write(output, &bytes).unwrap_or_else(|e| {
        ui::failure(&format!("Failed to write '{}': {}", output, e));
    });

    if json {
        ui::json_output(&serde_json::json!({
            "status": "ok",
            "file": output,
            "type": packet_type.name(),
            "size": bytes.len(),
        }));
    } else {
        ui::success(&format!("{} generated — {} ({} bytes)", output, packet_type.name(), bytes.len()));
    }
}

pub fn run_encode(output: &str, json: bool) {
    // Encode hex string or json description into binary KSP packet
    run_build(output, json);
}

pub fn run_export(file: &str, format: &str, json: bool) {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({"error": e.to_string()}));
            } else {
                ui::failure(&format!("Cannot read '{}': {}", file, e));
            }
            return;
        }
    };

    let exported = match format.to_lowercase().as_str() {
        "hex" => hex::encode(&data),
        "json" => match KspPacket::deserialize(&data) {
            Ok((pkt, _)) => serde_json::to_string_pretty(&serde_json::json!({
                "version": pkt.version.to_string(),
                "type": pkt.packet_type.name(),
                "flags": pkt.flags.to_string(),
                "session_id": hex::encode(pkt.session_id),
                "stream_id": pkt.stream_id,
                "sequence": pkt.sequence,
                "payload_hex": hex::encode(&pkt.payload)
            })).unwrap(),
            Err(e) => format!("{{\"error\": \"{}\"}}", e),
        },
        _ => hex::encode(&data),
    };

    if json {
        println!("{}", serde_json::json!({"file": file, "format": format, "exported": exported}));
        return;
    }

    ui::header(&format!("KSP Packet Export ({})", format.to_uppercase()));
    println!("{}", exported.cyan());
    println!();
}

pub fn run_visualize(file: &str, json: bool) {
    if json {
        println!("{}", serde_json::json!({
            "header_bytes": 48,
            "layout": ["Version (1B)", "Type (1B)", "Flags (2B)", "Session ID (16B)", "Stream ID (4B)", "Sequence # (8B)", "Nonce (16B)", "Payload (Variable)", "AEAD Tag (16B)"]
        }));
        return;
    }

    ui::header("KSP Packet Binary Structure — 48 Byte Header + AEAD Payload");
    if let Ok(data) = std::fs::read(file) {
        if let Ok((pkt, _)) = KspPacket::deserialize(&data) {
            println!("  File: {} ({} total wire bytes)\n", file.yellow().bold(), data.len());
            println!("  {}", "┌────────────────────────────────────────────────────────────┐".cyan());
            println!("  │ {:<26} │ {:<29} │", "48 Byte Fixed Header".white().bold(), "Protocol Metadata".dimmed());
            println!("  {}", "├────────────────────────────┼─────────────────────────────┤".cyan());
            println!("  │ {:<26} │ {:<29} │", "Version [Offset 0:1]", format!("v{}", pkt.version).green());
            println!("  │ {:<26} │ {:<29} │", "Type [Offset 1:2]", pkt.packet_type.name().yellow());
            println!("  │ {:<26} │ {:<29} │", "Flags [Offset 2:4]", pkt.flags.to_string().cyan());
            println!("  │ {:<26} │ {:<29} │", "Session ID [Offset 4:20]", format!("..{}", hex::encode(&pkt.session_id[12..16])).white());
            println!("  │ {:<26} │ {:<29} │", "Stream ID [Offset 20:24]", format!("#{}", pkt.stream_id).green());
            println!("  │ {:<26} │ {:<29} │", "Sequence # [Offset 24:32]", format!("#{}", pkt.sequence).yellow());
            println!("  │ {:<26} │ {:<29} │", "AEAD Nonce [Offset 32:48]", format!("..{}", hex::encode(&pkt.nonce[12..16])).dimmed());
            println!("  {}", "├────────────────────────────┼─────────────────────────────┤".cyan());
            println!("  │ {:<26} │ {:<29} │", "Encrypted Payload [Variable]", format!("{} bytes (AES-256-GCM)", pkt.payload.len()).white().bold());
            println!("  {}", "├────────────────────────────┼─────────────────────────────┤".cyan());
            println!("  │ {:<26} │ {:<29} │", "AEAD Auth Tag [+16 bytes]", if pkt.auth_tag.is_empty() { "None (Plaintext)".into() } else { format!("..{}", hex::encode(&pkt.auth_tag[12..16])) });
            println!("  {}", "└────────────────────────────────────────────────────────────┘".cyan());
            println!();
            return;
        }
    }

    // Default structure illustration if file not found or invalid
    println!("  {}", "┌────────────────────────────────────────────────────────────┐".cyan());
    println!("  │ {:<26} │ {:<29} │", "48 Byte Fixed Header".white().bold(), "Protocol Metadata".dimmed());
    println!("  {}", "├────────────────────────────┼─────────────────────────────┤".cyan());
    println!("  │ {:<26} │ {:<29} │", "Version [Offset 0:1]", "v1.0 (8-bit integer)");
    println!("  │ {:<26} │ {:<29} │", "Type [Offset 1:2]", "Handshake / Data / Alert");
    println!("  │ {:<26} │ {:<29} │", "Flags [Offset 2:4]", "ENCRYPTED | FIN | RST | ACK");
    println!("  │ {:<26} │ {:<29} │", "Session ID [Offset 4:20]", "128-bit UUID (16 bytes)");
    println!("  │ {:<26} │ {:<29} │", "Stream ID [Offset 20:24]", "32-bit Logical Stream (4B)");
    println!("  │ {:<26} │ {:<29} │", "Sequence # [Offset 24:32]", "64-bit Replay Counter (8B)");
    println!("  │ {:<26} │ {:<29} │", "AEAD Nonce [Offset 32:48]", "128-bit IV/Salt (16 bytes)");
    println!("  {}", "├────────────────────────────┼─────────────────────────────┤".cyan());
    println!("  │ {:<26} │ {:<29} │", "Encrypted Payload [Variable]", "Application Data Buffer");
    println!("  {}", "├────────────────────────────┼─────────────────────────────┤".cyan());
    println!("  │ {:<26} │ {:<29} │", "AEAD Auth Tag [+16 bytes]", "128-bit GCM/Poly1305 Tag");
    println!("  {}", "└────────────────────────────────────────────────────────────┘".cyan());
    println!();
}


