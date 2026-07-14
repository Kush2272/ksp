//! `ksp validate <file>` — Validate a KSP packet binary file.

use crate::ui;
use colored::Colorize;

pub fn run(file: &str, json: bool) {
    if !json {
        ui::print_header("KSP Packet Validator");
    }

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            ui::failure(&format!("Cannot read '{}': {}", file, e));
            return;
        }
    };

    let mut checks = Vec::new();

    // 1. Length check
    let len_ok = data.len() >= 48;
    checks.push((
        "Minimum Length (≥48 bytes)",
        len_ok,
        format!("{} bytes", data.len()),
    ));

    if !len_ok {
        output_results(&checks, json);
        return;
    }

    // 2. Version check
    let version = ksp_core::version::ProtocolVersion::from_wire(data[0]);
    let version_ok = version.major >= 1 && version.major <= 15;
    checks.push(("Protocol Version", version_ok, format!("v{}", version)));

    // 3. Packet type
    let type_ok = ksp_core::types::PacketType::from_u8(data[1]).is_ok();
    let type_name = ksp_core::types::PacketType::from_u8(data[1])
        .map(|t| t.name().to_string())
        .unwrap_or("Unknown".into());
    checks.push((
        "Packet Type",
        type_ok,
        format!("0x{:02X} ({})", data[1], type_name),
    ));

    // 4. Header fields
    let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let payload_ok = payload_len <= ksp_core::constants::MAX_PAYLOAD_SIZE;
    checks.push((
        "Payload Length",
        payload_ok,
        format!("{} bytes", payload_len),
    ));

    // 5. Nonce (non-zero for encrypted packets)
    let flags = ksp_core::types::Flags::from_bits_truncate(u16::from_be_bytes([data[2], data[3]]));
    let nonce_bytes = &data[36..48];
    let encrypted = flags.contains(ksp_core::types::Flags::ENCRYPTED);
    let nonce_ok = if encrypted {
        nonce_bytes.iter().any(|b| *b != 0)
    } else {
        true
    };
    checks.push((
        "Nonce",
        nonce_ok,
        if encrypted {
            "Present (encrypted packet)"
        } else {
            "N/A (plaintext)"
        }
        .into(),
    ));

    // 6. Tag presence
    let tag_size = if encrypted { 16 } else { 0 };
    let expected_total = 48 + payload_len as usize + tag_size;
    let total_ok = data.len() >= expected_total;
    checks.push((
        "AEAD Tag",
        total_ok,
        if encrypted {
            format!("{} bytes expected", tag_size)
        } else {
            "N/A (plaintext)".into()
        },
    ));

    // 7. Full deserialization
    let deser_ok = ksp_core::KspPacket::deserialize(&data).is_ok();
    checks.push((
        "Full Deserialization",
        deser_ok,
        if deser_ok { "Success" } else { "Failed" }.into(),
    ));

    output_results(&checks, json);
}

fn output_results(checks: &[(&str, bool, String)], json: bool) {
    if json {
        let results: Vec<serde_json::Value> = checks.iter()
            .map(|(name, ok, detail)| serde_json::json!({"check": name, "passed": ok, "detail": detail}))
            .collect();
        let all_ok = checks.iter().all(|(_, ok, _)| *ok);
        ui::json_output(
            &serde_json::json!({"status": if all_ok { "valid" } else { "invalid" }, "checks": results}),
        );
    } else {
        for (name, ok, detail) in checks {
            if *ok {
                ui::success(&format!("{:<28} {}", name, detail.dimmed()));
            } else {
                ui::failure(&format!("{:<28} {}", name, detail));
            }
        }
        let all_ok = checks.iter().all(|(_, ok, _)| *ok);
        if all_ok {
            ui::summary_ok("Packet is valid!");
        } else {
            ui::summary_fail("Packet validation failed.");
        }
    }
}
