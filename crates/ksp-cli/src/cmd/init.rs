//! `ksp init` — Initialize a KSP project in the current directory.

use crate::config::KspConfig;
use crate::ui;
use colored::Colorize;
use std::path::Path;

pub fn run(json: bool) {
    if !json {
        ui::print_header("Initialize KSP Project");
    }

    let cwd = std::env::current_dir().unwrap_or_default();

    // Check if already initialized
    if cwd.join("ksp.toml").exists() {
        if json {
            ui::json_output(
                &serde_json::json!({"status": "error", "message": "Already initialized"}),
            );
        } else {
            ui::warning("ksp.toml already exists in this directory.");
            ui::info("Use `ksp config` to modify settings.");
        }
        return;
    }

    let steps = vec![
        ("Creating ksp.toml", init_config(&cwd)),
        ("Creating certs/ directory", init_certs_dir(&cwd)),
        ("Generating self-signed certificate", init_certificate(&cwd)),
        ("Creating .ksp/ directory", init_ksp_dir(&cwd)),
    ];

    let mut all_ok = true;
    for (step, result) in &steps {
        match result {
            Ok(()) => {
                if !json {
                    ui::success(step);
                }
            }
            Err(e) => {
                if !json {
                    ui::failure(&format!("{}: {}", step, e));
                }
                all_ok = false;
            }
        }
    }

    if json {
        ui::json_output(&serde_json::json!({
            "status": if all_ok { "ok" } else { "error" },
            "directory": cwd.display().to_string(),
        }));
    } else if all_ok {
        ui::summary_ok("KSP project initialized successfully!");
        println!("  Next steps:");
        println!(
            "    {}  Start the server:   {}",
            "→".cyan(),
            "ksp server start".bold()
        );
        println!(
            "    {}  Run diagnostics:    {}",
            "→".cyan(),
            "ksp doctor".bold()
        );
        println!(
            "    {}  Connect a client:   {}",
            "→".cyan(),
            "ksp connect 127.0.0.1:9876".bold()
        );
        println!();
    } else {
        ui::summary_fail("Initialization completed with errors.");
    }
}

fn init_config(dir: &Path) -> Result<(), String> {
    let config = KspConfig::default();
    let toml = config.to_toml();
    std::fs::write(dir.join("ksp.toml"), toml)
        .map_err(|e| format!("Failed to write ksp.toml: {}", e))
}

fn init_certs_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir.join("certs"))
        .map_err(|e| format!("Failed to create certs/: {}", e))
}

fn init_certificate(dir: &Path) -> Result<(), String> {
    let (cert, signing_key) =
        ksp_crypto::certificate::KspCertificate::generate_self_signed("ksp://localhost", 365);

    std::fs::write(dir.join("certs/server.cert"), cert.serialize())
        .map_err(|e| format!("Failed to write certificate: {}", e))?;

    let key_path = dir.join("certs/server.key");
    std::fs::write(&key_path, signing_key.to_bytes())
        .map_err(|e| format!("Failed to write key: {}", e))?;
    crate::cmd::set_secure_key_permissions(&key_path);

    Ok(())
}

fn init_ksp_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir.join(".ksp")).map_err(|e| format!("Failed to create .ksp/: {}", e))
}
