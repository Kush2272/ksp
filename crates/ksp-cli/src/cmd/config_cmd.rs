//! `ksp config set|get` — Configuration management.

use crate::config::KspConfig;
use crate::ui;
use colored::Colorize;

pub fn run_get(key: &str, json: bool) {
    let config_path = match KspConfig::find_config() {
        Some(p) => p,
        None => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": "No ksp.toml found"}),
                );
            } else {
                ui::failure("No ksp.toml found. Run `ksp init` first.");
            }
            return;
        }
    };

    let config = match KspConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            ui::failure(&format!("Failed to load config: {}", e));
            return;
        }
    };

    let value = match key {
        "port" => config.server.port.to_string(),
        "host" => config.server.host.clone(),
        "cipher" => config.security.cipher.clone(),
        "compression" => config.security.compression.to_string(),
        "replay_window" => config.security.replay_window.to_string(),
        "cert_file" => config.security.cert_file.clone(),
        "key_file" => config.security.key_file.clone(),
        "log_level" | "level" => config.logging.level.clone(),
        "name" => config.project.name.clone(),
        _ => {
            if json {
                ui::json_output(&serde_json::json!({"status": "error", "message": "Unknown key"}));
            } else {
                ui::failure(&format!("Unknown config key: '{}'", key));
            }
            return;
        }
    };

    if json {
        ui::json_output(&serde_json::json!({"key": key, "value": value}));
    } else {
        ui::kv(key, &value);
    }
}

pub fn run_set(key: &str, value: &str, json: bool) {
    let config_path = match KspConfig::find_config() {
        Some(p) => p,
        None => {
            ui::failure("No ksp.toml found. Run `ksp init` first.");
            return;
        }
    };

    let mut config = match KspConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            ui::failure(&format!("Failed to load config: {}", e));
            return;
        }
    };

    match key {
        "port" => config.server.port = value.parse().unwrap_or(9876),
        "host" => config.server.host = value.to_string(),
        "cipher" => config.security.cipher = value.to_string(),
        "compression" => config.security.compression = value == "true",
        "replay_window" => config.security.replay_window = value.parse().unwrap_or(1024),
        "log_level" | "level" => config.logging.level = value.to_string(),
        "name" => config.project.name = value.to_string(),
        _ => {
            ui::failure(&format!("Unknown config key: '{}'", key));
            return;
        }
    }

    match std::fs::write(&config_path, config.to_toml()) {
        Ok(()) => {
            if json {
                ui::json_output(&serde_json::json!({"status": "ok", "key": key, "value": value}));
            } else {
                ui::success(&format!("{} = {}", key.cyan(), value.green().bold()));
            }
        }
        Err(e) => {
            ui::failure(&format!("Failed to save config: {}", e));
        }
    }
}

pub fn run_show(json: bool) {
    let config_path = match KspConfig::find_config() {
        Some(p) => p,
        None => {
            if json {
                ui::json_output(
                    &serde_json::json!({"status": "error", "message": "No ksp.toml found"}),
                );
            } else {
                ui::failure("No ksp.toml found. Run `ksp init` first.");
            }
            return;
        }
    };

    let config = match KspConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            ui::failure(&format!("Failed to load config: {}", e));
            return;
        }
    };

    if json {
        ui::json_output(&serde_json::json!({
            "project": {"name": config.project.name, "version": config.project.version},
            "server": {"host": config.server.host, "port": config.server.port},
            "security": {"cipher": config.security.cipher, "compression": config.security.compression},
            "logging": {"level": config.logging.level},
        }));
    } else {
        ui::print_header("KSP Configuration");
        ui::kv("Config file", &config_path.display().to_string());
        println!();
        let mut t = ui::table(&["Setting", "Value"]);
        t.add_row(vec!["Project Name", &config.project.name]);
        t.add_row(vec!["Host", &config.server.host]);
        t.add_row(vec!["Port", &config.server.port.to_string()]);
        t.add_row(vec!["Cipher", &config.security.cipher]);
        t.add_row(vec![
            "Compression",
            &config.security.compression.to_string(),
        ]);
        t.add_row(vec![
            "Replay Window",
            &config.security.replay_window.to_string(),
        ]);
        t.add_row(vec!["Certificate", &config.security.cert_file]);
        t.add_row(vec!["Log Level", &config.logging.level]);
        println!("{t}");
    }
}

pub fn run_list(json: bool) {
    // Alias list -> show
    run_show(json);
}

pub fn run_validate(json: bool) {
    let config_path = match KspConfig::find_config() {
        Some(p) => p,
        None => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"status": "error", "message": "No ksp.toml found"})
                );
            } else {
                ui::failure("No ksp.toml found to validate.");
            }
            return;
        }
    };

    let config = match KspConfig::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"status": "invalid", "error": e.to_string()})
                );
            } else {
                ui::failure(&format!("Syntax Error in ksp.toml: {}", e));
            }
            return;
        }
    };

    let mut checks = Vec::new();
    let mut ok = true;

    if config.server.port == 0 {
        checks.push(("Port validation", false, "Port 0 is reserved"));
        ok = false;
    } else {
        checks.push(("Port validation", true, "Valid TCP port"));
    }

    if config.security.replay_window < 64 {
        checks.push(("Replay window", false, "Must be at least 64 bits"));
        ok = false;
    } else {
        checks.push(("Replay window", true, "Sufficient window size"));
    }

    if json {
        println!(
            "{}",
            serde_json::json!({"status": if ok { "valid" } else { "invalid" }, "checks": checks.len()})
        );
        return;
    }

    ui::header("KSP Config Validation (`ksp.toml`)");
    for (name, passed, note) in checks {
        if passed {
            println!(
                "  {} {:<22} {}",
                "✔".green().bold(),
                name.white(),
                note.dimmed()
            );
        } else {
            println!("  {} {:<22} {}", "✘".red().bold(), name.white(), note.red());
        }
    }
    println!();
}

pub fn run_reset(json: bool) {
    let path = std::path::Path::new("ksp.toml");
    let default_config = KspConfig::default();
    match std::fs::write(path, default_config.to_toml()) {
        Ok(_) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"status": "reset", "file": "ksp.toml"})
                );
            } else {
                ui::success("Reset ksp.toml to factory default values.");
            }
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"status": "error", "error": e.to_string()})
                );
            } else {
                ui::failure(&format!("Failed to reset ksp.toml: {}", e));
            }
        }
    }
}
