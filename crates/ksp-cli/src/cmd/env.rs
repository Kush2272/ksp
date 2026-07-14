//! `ksp env list|use <env>` — Target environment switching.

use crate::ui;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

fn get_env_file() -> PathBuf {
    let mut path = crate::config::user_config_dir();
    path.push("active_env");
    path
}

pub fn get_active_env() -> String {
    let file = get_env_file();
    fs::read_to_string(file).unwrap_or_else(|_| "local".to_string())
}

/// Resolve the connection target address based on active environment or user override.
pub fn resolve_target_address(user_override: &str) -> String {
    if !user_override.is_empty() && user_override != "default" {
        if user_override.contains(':') {
            return user_override.to_string();
        } else {
            return format!("{}:{}", user_override, ksp_core::constants::DEFAULT_PORT);
        }
    }
    match get_active_env().to_lowercase().as_str() {
        "production" => "ksp.kspprotocol.dev:443".to_string(),
        "staging" => "staging.kspprotocol.dev:8443".to_string(),
        "demo" => "demo.kspprotocol.dev:9876".to_string(),
        _ => format!("127.0.0.1:{}", ksp_core::constants::DEFAULT_PORT),
    }
}

pub fn run_use(env: &str, json: bool) {
    let valid = ["local", "development", "staging", "production", "demo"];
    if !valid.contains(&env.to_lowercase().as_str()) {
        if json {
            println!(
                "{}",
                serde_json::json!({"error": "invalid_env", "allowed": valid})
            );
        } else {
            println!(
                "  {} Unknown environment '{}'",
                "✘".red().bold(),
                env.white()
            );
            println!(
                "  {} Allowed environments: {}",
                "ℹ".blue(),
                valid.join(", ").yellow()
            );
        }
        return;
    }

    fs::write(get_env_file(), env.to_lowercase()).ok();

    let target_addr = match env.to_lowercase().as_str() {
        "production" => "ksp.kspprotocol.dev:443",
        "staging" => "staging.kspprotocol.dev:8443",
        "demo" => "demo.kspprotocol.dev:9876",
        _ => "127.0.0.1:9876",
    };

    if json {
        println!(
            "{}",
            serde_json::json!({"status": "switched", "env": env, "target_addr": target_addr})
        );
    } else {
        println!(
            "  {} Switched active KSP target environment -> {}",
            "✔".green().bold(),
            env.white().bold()
        );
        println!(
            "  {} Default connection target: {}",
            "└─▶".dimmed(),
            target_addr.cyan().bold()
        );
    }
    println!();
}

pub fn run_list(json: bool) {
    let active = get_active_env();
    let envs = [
        ("local", "127.0.0.1:9876", "Local loopback dev server"),
        (
            "demo",
            "demo.kspprotocol.dev:9876",
            "Public 24/7 demo server",
        ),
        (
            "staging",
            "staging.kspprotocol.dev:8443",
            "Pre-production testing environment",
        ),
        (
            "production",
            "ksp.kspprotocol.dev:443",
            "Live high-throughput cluster",
        ),
    ];

    if json {
        let list: Vec<_> = envs.iter().map(|(name, addr, desc)| {
            serde_json::json!({"name": name, "address": addr, "description": desc, "active": *name == active})
        }).collect();
        println!("{}", serde_json::to_string_pretty(&list).unwrap());
        return;
    }

    ui::header("KSP Target Environments");
    for (name, addr, desc) in &envs {
        if *name == active {
            println!(
                "  {} {:<14} {:<28} {}",
                "✔".green().bold(),
                name.green().bold(),
                addr.cyan(),
                format!("({})", desc).dimmed()
            );
        } else {
            println!(
                "  {} {:<14} {:<28} {}",
                " ".white(),
                name.white(),
                addr.dimmed(),
                format!("({})", desc).dimmed()
            );
        }
    }
    println!(
        "  {}",
        "════════════════════════════════════════════════════════════".cyan()
    );
    println!();
}
