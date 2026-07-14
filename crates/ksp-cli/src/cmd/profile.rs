//! `ksp profile create|switch|list` — Multi-environment profile management.

use crate::ui;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

fn get_profile_dir() -> PathBuf {
    let mut path = crate::config::user_config_dir();
    path.push("profiles");
    fs::create_dir_all(&path).ok();
    path
}

fn get_active_profile_file() -> PathBuf {
    let mut path = get_profile_dir();
    path.push("active_profile");
    path
}

pub fn get_active_profile() -> String {
    let file = get_active_profile_file();
    fs::read_to_string(file).unwrap_or_else(|_| "dev".to_string())
}

pub fn run_create(name: &str, json: bool) {
    let mut path = get_profile_dir();
    path.push(format!("{}.toml", name));

    if path.exists() {
        if json {
            println!("{}", serde_json::json!({"error": "profile_exists", "name": name}));
        } else {
            println!("  {} Profile '{}' already exists.", "✘".red().bold(), name.white());
        }
        return;
    }

    let default_content = match name {
        "production" | "prod" => "[server]\nport = 443\nhost = \"0.0.0.0\"\n[security]\ncipher = \"AES-256-GCM\"\nreplay_window = 4096\n",
        "staging" => "[server]\nport = 8443\nhost = \"0.0.0.0\"\n[security]\ncipher = \"ChaCha20-Poly1305\"\nreplay_window = 2048\n",
        _ => "[server]\nport = 9876\nhost = \"127.0.0.1\"\n[security]\ncipher = \"AES-256-GCM\"\nreplay_window = 1024\n",
    };

    fs::write(&path, default_content).ok();

    if json {
        println!("{}", serde_json::json!({"status": "created", "profile": name}));
    } else {
        println!("  {} Created profile '{}' with default tokens.", "✔".green().bold(), name.white().bold());
        println!("  {} Switch to it using `ksp profile switch {}`.", "ℹ".blue(), name);
    }
    println!();
}

pub fn run_switch(name: &str, json: bool) {
    let mut path = get_profile_dir();
    path.push(format!("{}.toml", name));

    // Create if not exists for user convenience
    if !path.exists() {
        run_create(name, true);
    }

    fs::write(get_active_profile_file(), name).ok();

    if json {
        println!("{}", serde_json::json!({"status": "switched", "active_profile": name}));
    } else {
        println!("  {} Switched active KSP profile -> {}", "✔".green().bold(), name.white().bold());
    }
    println!();
}

pub fn run_list(json: bool) {
    let active = get_active_profile();
    let dir = get_profile_dir();

    let mut profiles = vec!["dev".to_string(), "staging".to_string(), "production".to_string()];
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".toml") {
                    let p = name.trim_end_matches(".toml").to_string();
                    if !profiles.contains(&p) {
                        profiles.push(p);
                    }
                }
            }
        }
    }

    if json {
        println!("{}", serde_json::json!({"profiles": profiles, "active": active}));
        return;
    }

    ui::header("KSP Profiles");
    for p in profiles {
        if p == active {
            println!("  {} {:<16} {}", "✔".green().bold(), p.green().bold(), "(Active Profile)".dimmed());
        } else {
            println!("  {} {:<16}", " ".white(), p.white());
        }
    }
    println!("  {}", "════════════════════════════════════════════════════════════".cyan());
    println!();
}
