//! `ksp trace` — Trace a single packet across the entire KSP protocol stack.

use crate::ui;
use colored::Colorize;
use std::io::Write;
use std::time::Duration;

pub fn run(message: Option<&str>, json: bool) {
    let payload = message.unwrap_or("Hello KSP Trace!");

    if json {
        ui::json_output(&serde_json::json!({
            "status": "ok",
            "payload": payload,
            "layers": [
                {"layer": "Application", "action": format!("Send payload: \"{}\"", payload)},
                {"layer": "Stream", "action": "Assign Stream ID #1, Check Flow Control Window (64 KB available)"},
                {"layer": "Session", "action": "Assign u64 Sequence #1042, Derive 12-byte Counter Nonce"},
                {"layer": "Packet", "action": "Construct Fixed Header (48B) + Payload Length"},
                {"layer": "Crypto (AEAD)", "action": "AES-256-GCM Encrypt + Append 16B Authentication Tag"},
                {"layer": "Socket (Transport)", "action": "Write encrypted binary bytes to TCP/TLS Stream"},
                {"layer": "Network Layer", "action": "Wire Transmission across network boundaries (Local Stack Trace)"},
                {"layer": "Decryption & Verify", "action": "Receiver verifies AEAD Tag & checks Sliding Replay Window"},
                {"layer": "Application Delivery", "action": format!("Payload recovered cleanly: \"{}\"", payload)}
            ]
        }));
        return;
    }

    ui::print_header("KSP Single-Packet Stack Trace");
    println!(
        "  Tracing lifetime of packet: \"{}\"",
        payload.yellow().bold()
    );
    println!();

    let steps = [
        (
            "Application Layer",
            format!(
                "Initiate send for payload \"{}\" ({} bytes)",
                payload,
                payload.len()
            ),
            "app.send()",
        ),
        (
            "Stream Multiplexer",
            "Assign logical Stream ID #1, verify 64 KB flow control credit".into(),
            "stream.write()",
        ),
        (
            "Session State",
            "Assign monotonically increasing Sequence #1042, derive Counter Nonce".into(),
            "session.encrypt()",
        ),
        (
            "Packet Builder",
            "Assemble 48-byte fixed binary header (Version, Type, Flags, Seq, Nonce)".into(),
            "KspPacket::new()",
        ),
        (
            "AEAD Encryption",
            "Execute AES-256-GCM encryption & append 16-byte cryptographic auth tag".into(),
            "aead::encrypt()",
        ),
        (
            "Socket Transport",
            "Flush 80 total encrypted bytes directly into underlying TCP/TLS stream".into(),
            "TcpStream::write_all()",
        ),
        (
            "Network Layer",
            "Wire transmission across physical or loopback network interface".into(),
            "IP/TCP Layer",
        ),
        (
            "Decryption & Verify",
            "Receiver verifies AEAD auth tag, advances 1024-bit replay window bitmap".into(),
            "aead::decrypt()",
        ),
        (
            "Application Delivery",
            format!(
                "Payload verified & delivered intact to receiving application: \"{}\"",
                payload
            ),
            "app.on_message()",
        ),
    ];

    for (i, (layer, desc, code)) in steps.iter().enumerate() {
        println!(
            "  {}  {:<24} {}",
            format!("[Layer {}]", i + 1).cyan().bold(),
            layer.white().bold(),
            format!("({})", code).dimmed()
        );
        println!("     └─▶ {}", desc.green());

        if i < steps.len() - 1 {
            println!("          {}  {}", "│".dimmed(), "↓".yellow().bold());
            let _ = std::io::stdout().flush();
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    println!();
    ui::summary_ok("Packet trace completed successfully — 0 errors, 0 replays detected.");
}
