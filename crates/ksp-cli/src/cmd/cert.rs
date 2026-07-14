//! `ksp cert generate|inspect|verify` — Certificate management tools.

use crate::ui;
use colored::Colorize;

pub fn run_generate(subject: &str, days: u32, output: &str, json: bool) {
    if !json {
        ui::print_header("KSP Certificate Generator");
    }

    let (cert, signing_key) =
        ksp_crypto::certificate::KspCertificate::generate_self_signed(subject, days);

    let cert_path = format!("{}.cert", output);
    let key_path = format!("{}.key", output);

    let cert_bytes = cert.serialize();
    std::fs::write(&cert_path, &cert_bytes).unwrap_or_else(|e| {
        ui::failure(&format!("Failed to write {}: {}", cert_path, e));
    });
    std::fs::write(&key_path, signing_key.to_bytes()).unwrap_or_else(|e| {
        ui::failure(&format!("Failed to write {}: {}", key_path, e));
    });
    crate::cmd::set_secure_key_permissions(std::path::Path::new(&key_path));

    if json {
        ui::json_output(&serde_json::json!({
            "status": "ok",
            "subject": subject,
            "validity_days": days,
            "cert_file": cert_path,
            "key_file": key_path,
            "public_key": hex::encode(cert.public_key),
            "serial": uuid::Uuid::from_bytes(cert.serial_number).to_string(),
        }));
    } else {
        ui::success(&format!("Certificate:  {}", cert_path.green()));
        ui::success(&format!("Private key:  {}", key_path.green()));
        println!();
        ui::kv("Subject", subject);
        ui::kv("Issuer", "self-signed");
        ui::kv("Validity", &format!("{} days", days));
        ui::kv("Algorithm", "Ed25519");
        ui::kv(
            "Serial",
            &uuid::Uuid::from_bytes(cert.serial_number).to_string(),
        );
        ui::kv(
            "Public Key",
            &hex::encode(&cert.public_key[..16]).to_string(),
        );
        ui::summary_ok("Certificate generated successfully!");
    }
}

pub fn run_inspect(file: &str, json: bool) {
    if !json {
        ui::print_header("KSP Certificate Inspector");
    }

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            ui::failure(&format!("Failed to read '{}': {}", file, e));
            return;
        }
    };

    let cert = match ksp_crypto::certificate::KspCertificate::deserialize(&data) {
        Ok(c) => c,
        Err(e) => {
            ui::failure(&format!("Invalid certificate: {}", e));
            return;
        }
    };

    if json {
        ui::json_output(&serde_json::json!({
            "version": cert.version,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "public_key": hex::encode(cert.public_key),
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "serial": uuid::Uuid::from_bytes(cert.serial_number).to_string(),
            "expired": cert.is_expired(),
            "signature": hex::encode(&cert.signature[..32]),
        }));
    } else {
        let mut t = ui::table(&["Field", "Value"]);
        t.add_row(vec!["Version", &cert.version.to_string()]);
        t.add_row(vec!["Subject", &cert.subject]);
        t.add_row(vec!["Issuer", &cert.issuer]);
        t.add_row(vec!["Public Key", &hex::encode(&cert.public_key[..16])]);
        t.add_row(vec!["Not Before", &format_timestamp(cert.not_before)]);
        t.add_row(vec!["Not After", &format_timestamp(cert.not_after)]);
        t.add_row(vec![
            "Serial",
            &uuid::Uuid::from_bytes(cert.serial_number).to_string(),
        ]);
        t.add_row(vec![
            "Expired",
            &if cert.is_expired() {
                "Yes ✘".to_string()
            } else {
                "No ✔".to_string()
            },
        ]);
        t.add_row(vec![
            "Signature",
            &format!("{}...", &hex::encode(&cert.signature[..16])),
        ]);
        println!("{t}");
    }
}

pub fn run_verify(file: &str, json: bool) {
    if !json {
        ui::print_header("KSP Certificate Verification");
    }

    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            ui::failure(&format!("Failed to read '{}': {}", file, e));
            return;
        }
    };

    let cert = match ksp_crypto::certificate::KspCertificate::deserialize(&data) {
        Ok(c) => c,
        Err(e) => {
            ui::failure(&format!("Invalid certificate format: {}", e));
            return;
        }
    };

    let mut checks = Vec::new();

    // Signature
    let sig_ok = cert.verify_self_signed().is_ok();
    checks.push(("Signature", sig_ok));

    // Expiration
    let not_expired = !cert.is_expired();
    checks.push(("Expiration", not_expired));

    // Not yet valid
    let valid_now = !cert.is_not_yet_valid();
    checks.push(("Valid Period", valid_now));

    // Full validation
    let full_ok = cert.validate_self_signed().is_ok();
    checks.push(("Full Validation", full_ok));

    if json {
        let results: Vec<serde_json::Value> = checks
            .iter()
            .map(|(name, ok)| serde_json::json!({"check": name, "passed": ok}))
            .collect();
        ui::json_output(
            &serde_json::json!({"status": if full_ok { "valid" } else { "invalid" }, "checks": results}),
        );
    } else {
        for (name, ok) in &checks {
            if *ok {
                ui::success(name);
            } else {
                ui::failure(name);
            }
        }
        if full_ok {
            ui::summary_ok("Certificate is valid!");
        } else {
            ui::summary_fail("Certificate validation failed.");
        }
    }
}

fn format_timestamp(ts: u64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

pub fn run_renew(file: &str, days: u32, json: bool) {
    let data = match std::fs::read(file) {
        Ok(d) => d,
        Err(e) => {
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": e.to_string()}));
            } else {
                ui::failure(&format!("Cannot read certificate '{}': {}", file, e));
            }
            return;
        }
    };

    let cert = match ksp_crypto::certificate::KspCertificate::deserialize(&data) {
        Ok(c) => c,
        Err(e) => {
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": e.to_string()}));
            } else {
                ui::failure(&format!("Invalid certificate format in '{}': {}", file, e));
            }
            return;
        }
    };

    let prefix = file.trim_end_matches(".cert").trim_end_matches(".crt");
    run_generate(&cert.subject, days, prefix, json);
}
