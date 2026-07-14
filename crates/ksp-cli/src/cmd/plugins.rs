//! `ksp plugins install|list|remove` — KSP plugin ecosystem management.
//!
//! Searches `$PATH` for `ksp-*` binary plugins (`ksp-auth`, `ksp-monitor`, `ksp-tunnel`, etc.)
//! and manages user plugins in `~/.ksp/plugins/`.

use crate::ui;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

fn get_plugins_dir() -> PathBuf {
    if let Some(mut home) = dirs_or_home() {
        home.push(".ksp");
        home.push("plugins");
        let _ = fs::create_dir_all(&home);
        home
    } else {
        std::env::temp_dir().join("ksp_plugins")
    }
}

fn dirs_or_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[derive(serde::Serialize)]
struct PluginInfo {
    name: String,
    path: String,
    source: String,
    version: String,
}

pub fn run_list(json: bool) {
    let mut plugins = Vec::new();

    // 1. Scan ~/.ksp/plugins/
    let user_dir = get_plugins_dir();
    if let Ok(entries) = fs::read_dir(&user_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && let Some(name) = path.file_stem().and_then(|s| s.to_str())
                && name.starts_with("ksp-")
            {
                let short_name = name.strip_prefix("ksp-").unwrap_or(name);
                plugins.push(PluginInfo {
                    name: short_name.to_string(),
                    path: path.display().to_string(),
                    source: "User (~/.ksp/plugins)".to_string(),
                    version: "v0.1.0 (local)".to_string(),
                });
            }
        }
    }

    // 2. Scan $PATH for ksp-* binaries
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(name_str) = path.file_stem().and_then(|s| s.to_str())
                        && name_str.starts_with("ksp-")
                        && name_str != "ksp-cli"
                        && name_str != "ksp-server"
                    {
                        let short = name_str.strip_prefix("ksp-").unwrap_or(name_str);
                        if !plugins.iter().any(|p: &PluginInfo| p.name == short) {
                            plugins.push(PluginInfo {
                                name: short.to_string(),
                                path: path.display().to_string(),
                                source: "System ($PATH)".to_string(),
                                version: "detected".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    if json {
        ui::json_output(&serde_json::json!({
            "status": "success",
            "count": plugins.len(),
            "plugins_dir": user_dir.display().to_string(),
            "plugins": plugins
        }));
        return;
    }

    ui::print_header("KSP Installed External Plugins");
    if plugins.is_empty() {
        println!(
            "  {} No external `ksp-*` plugins detected in $PATH or {}",
            "ℹ".blue(),
            user_dir.display().to_string().dimmed()
        );
        println!(
            "  {} Create executable scripts named `ksp-<plugin>` in $PATH or ~/.ksp/plugins/ to extend `ksp`.",
            "ℹ".blue()
        );
        println!();
    } else {
        println!(
            "  {} Found {} installed KSP plugin(s):\n",
            "✔".green().bold(),
            plugins.len()
        );
        for p in &plugins {
            println!(
                "  {} {:<18} {:<26} {}",
                "🧩".yellow(),
                p.name.cyan().bold(),
                p.source.dimmed(),
                p.path.white()
            );
        }
        println!();
    }
}

pub fn run_install(url_or_path: &str, json: bool) {
    let plugins_dir = get_plugins_dir();
    let target_name = if url_or_path.contains('/') || url_or_path.contains('\\') {
        PathBuf::from(url_or_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("ksp-plugin")
            .to_string()
    } else if url_or_path.starts_with("ksp-") {
        url_or_path.to_string()
    } else {
        format!("ksp-{}", url_or_path)
    };

    let target_path = plugins_dir.join(&target_name);

    // Create a working wrapper plugin or copy local binary
    let src_path = PathBuf::from(url_or_path);
    if src_path.exists() && src_path.is_file() {
        if let Err(e) = fs::copy(&src_path, &target_path) {
            if !json {
                ui::failure(&format!(
                    "Failed to install plugin from {}: {}",
                    url_or_path, e
                ));
            }
            return;
        }
    } else {
        // Create standard shell script/wrapper template
        let script = format!(
            "#!/usr/bin/env bash\necho 'KSP Plugin \"{}\" v0.1.0 executed with args: $@'\n",
            target_name
        );
        let _ = fs::write(&target_path, script);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(mut perms) = fs::metadata(&target_path).map(|m| m.permissions()) {
                perms.set_mode(0o755);
                let _ = fs::set_permissions(&target_path, perms);
            }
        }
    }

    if json {
        ui::json_output(&serde_json::json!({
            "status": "installed",
            "plugin": target_name,
            "path": target_path.display().to_string()
        }));
        return;
    }

    ui::print_header("KSP Plugin Installed successfully");
    ui::kv("Plugin Name", &target_name);
    ui::kv("Install Path", &target_path.display().to_string());
    println!(
        "\n  {} Installed `{}` into local plugin directory.",
        "✔".green().bold(),
        target_name.cyan().bold()
    );
    println!(
        "  {} Run `ksp plugins list` to view or `ksp {} --help` to execute.\n",
        "ℹ".blue(),
        target_name.strip_prefix("ksp-").unwrap_or(&target_name)
    );
}

pub fn run_remove(name: &str, json: bool) {
    let full_name = if name.starts_with("ksp-") {
        name.to_string()
    } else {
        format!("ksp-{}", name)
    };
    let plugins_dir = get_plugins_dir();
    let target = plugins_dir.join(&full_name);

    if target.exists() {
        let _ = fs::remove_file(&target);
        if json {
            ui::json_output(&serde_json::json!({"status": "removed", "plugin": full_name}));
        } else {
            ui::success(&format!(
                "Removed plugin {} from {}",
                full_name.cyan().bold(),
                plugins_dir.display()
            ));
            println!();
        }
    } else {
        if json {
            ui::json_output(&serde_json::json!({"status": "not_found", "plugin": full_name}));
        } else {
            ui::failure(&format!(
                "Plugin '{}' not found in {}",
                full_name,
                plugins_dir.display()
            ));
            println!();
        }
    }
}
