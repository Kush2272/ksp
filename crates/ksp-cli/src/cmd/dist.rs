//! `ksp dist|update|install-script` — Distribution, update, and release packaging tools.

use crate::ui;
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

pub fn run_dist(target: &str, json: bool) {
    use sha2::{Digest, Sha256};
    let host_target = if cfg!(target_os = "windows") {
        "x86_64-pc-windows-msvc"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else if cfg!(target_os = "macos") {
        "x86_64-apple-darwin"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-gnu"
    } else {
        "x86_64-unknown-linux-gnu"
    };

    let t = if target.is_empty() {
        host_target
    } else {
        target
    };

    if !target.is_empty() && target != host_target {
        if json {
            ui::json_output(&serde_json::json!({
                "status": "cross_target_not_built",
                "requested_target": target,
                "host_target": host_target,
                "message": format!("Cross-compilation target {} not built yet. Run `cargo build --release --target {}` first.", target, target)
            }));
        } else {
            ui::header("KSP Binary Release Packager");
            ui::failure(&format!(
                "Cross-compilation target `{}` not built yet.",
                target
            ));
            ui::info(&format!(
                "Run `cargo build --release --target {}` before packaging with `ksp dist`.",
                target
            ));
        }
        return;
    }

    // Look for real built binary across workspace root, current_exe, and crate subdirectories
    let mut candidate_paths = vec![
        PathBuf::from("target/release/ksp.exe"),
        PathBuf::from("target/release/ksp"),
        PathBuf::from("target/debug/ksp.exe"),
        PathBuf::from("target/debug/ksp"),
        PathBuf::from("../../target/release/ksp.exe"),
        PathBuf::from("../../target/release/ksp"),
        PathBuf::from("../../target/debug/ksp.exe"),
        PathBuf::from("../../target/debug/ksp"),
    ];
    if let Ok(exe) = std::env::current_exe() {
        candidate_paths.push(exe);
    }
    let found_path = candidate_paths.iter().find(|p| fs::metadata(p).is_ok());

    #[allow(clippy::collapsible_if)]
    if let Some(path) = found_path {
        if let Ok(bytes) = fs::read(path) {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let sha = format!("{:x}", hasher.finalize());
            let size = bytes.len();

            let ext = if path.extension().and_then(|e| e.to_str()) == Some("exe") {
                ".exe"
            } else {
                ""
            };
            let pkg_name = format!("ksp-v{}-{}{}", ksp_core::CURRENT_VERSION, t, ext);

            let _ = fs::write(&pkg_name, &bytes);
            let _ = fs::write("checksums.txt", format!("{}  {}\n", sha, pkg_name));

            if json {
                ui::json_output(&serde_json::json!({
                    "status": "packaged_binary",
                    "version": ksp_core::CURRENT_VERSION.to_string(),
                    "target": t,
                    "package_file": pkg_name,
                    "size_bytes": size,
                    "sha256": sha
                }));
                return;
            }

            ui::header("KSP Binary Release Packager");
            println!(
                "  {} Found binary at `{}` for target `{}`...",
                "✔".green().bold(),
                path.display().to_string().cyan(),
                t.cyan()
            );
            println!(
                "  {} Packaged standalone binary artifact: {} ({})",
                "✔".green().bold(),
                pkg_name.yellow().bold(),
                ui::format_bytes(size as u64)
            );
            println!(
                "  {} SHA-256 Checksum:  {}",
                "✔".green().bold(),
                sha.dimmed()
            );
            println!();
            ui::summary_ok(&format!(
                "Standalone release binary packaged successfully. Computed SHA-256: {}",
                sha
            ));
            println!();
            return;
        }
    }

    if json {
        ui::json_output(&serde_json::json!({
            "status": "error",
            "message": "No compiled binary found. Run `cargo build --release` before running `ksp dist`."
        }));
    } else {
        ui::header("KSP Binary Release Packager");
        ui::failure(
            "No compiled binary found. Run `cargo build --release` before running `ksp dist`.",
        );
    }
    std::process::exit(1);
}

pub fn run_update(check_only: bool, json: bool) {
    let current = ksp_core::CURRENT_VERSION.to_string();

    if check_only {
        if json {
            ui::json_output(&serde_json::json!({
                "current_version": current,
                "update_mirror_configured": false,
                "update_checked": false,
                "status": "no_remote_mirror_configured"
            }));
        } else {
            ui::header("KSP CLI Version & Update Checker");
            ui::kv("Current Version", &format!("v{}", current));
            ui::kv("Remote Mirror", "Unconfigured (Local build only)");
            println!();
            println!(
                "  {} No remote update mirror configured; using local workspace build (`v{}`).",
                "ℹ".blue(),
                current
            );
            println!();
        }
        return;
    }

    if json {
        ui::json_output(&serde_json::json!({
            "status": "error",
            "message": "Automatic self-update (`ksp update`) requires a configured release mirror or update server"
        }));
    } else {
        ui::header("KSP CLI Update");
        ui::failure(
            "Automatic self-update (`ksp update`) requires a configured release mirror or update server.",
        );
        ui::info(
            "To update your local build from source, run: cargo install --path crates/ksp-cli --force",
        );
    }
    std::process::exit(1);
}

pub fn run_install_script(json: bool) {
    let bash_script = r#"#!/bin/sh
# KSP Global One-Liner Installer for Linux & macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/Kush2272/ksp/main/install.sh | sh
set -e
curl -fsSL https://raw.githubusercontent.com/Kush2272/ksp/main/install.sh | sh
"#;

    let ps_script = r#"# KSP Global One-Liner Installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/Kush2272/ksp/main/install.ps1 | iex
irm https://raw.githubusercontent.com/Kush2272/ksp/main/install.ps1 | iex
"#;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "linux_macos_curl": "curl -fsSL https://raw.githubusercontent.com/Kush2272/ksp/main/install.sh | sh",
                "windows_powershell": "irm https://raw.githubusercontent.com/Kush2272/ksp/main/install.ps1 | iex",
                "cargo_git": "cargo install --git https://github.com/Kush2272/ksp.git ksp-cli --force",
                "bash_script_content": bash_script,
                "powershell_script_content": ps_script
            })
        );
        return;
    }

    ui::header("KSP Global Installation Scripts (1-Liner Installation)");
    println!("  {}", "Windows (PowerShell 1-Liner):".yellow().bold());
    println!(
        "    {}",
        "irm https://raw.githubusercontent.com/Kush2272/ksp/main/install.ps1 | iex"
            .cyan()
            .bold()
    );
    println!();
    println!("  {}", "Linux & macOS (Terminal 1-Liner):".yellow().bold());
    println!(
        "    {}",
        "curl -fsSL https://raw.githubusercontent.com/Kush2272/ksp/main/install.sh | sh"
            .cyan()
            .bold()
    );
    println!();
    println!("  {}", "Via Cargo (Rust Package Manager):".yellow().bold());
    println!(
        "    {}",
        "cargo install --git https://github.com/Kush2272/ksp.git ksp-cli --force"
            .cyan()
            .bold()
    );
    println!();
    println!(
        "  {}",
        "Local Development / Source Repository:".yellow().bold()
    );
    println!(
        "    {}",
        "cargo install --path crates/ksp-cli --force --locked".dimmed()
    );
    println!();
}

pub fn run_uninstall(force: bool, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "uninstall_instructions",
                "action_required": true,
                "windows_uninstaller": "irm https://raw.githubusercontent.com/Kush2272/ksp/main/uninstall.ps1 | iex",
                "linux_macos_uninstaller": "curl -fsSL https://raw.githubusercontent.com/Kush2272/ksp/main/uninstall.sh | sh",
                "cargo_uninstaller": "cargo uninstall ksp-cli"
            })
        );
        return;
    }

    ui::header("KSP CLI Complete Uninstaller");
    println!(
        "  {}",
        "This command will remove KSP CLI configuration and executable binaries from your system."
            .yellow()
    );
    println!();

    if !force {
        use dialoguer::Confirm;
        if let Ok(false) | Err(_) = Confirm::new()
            .with_prompt("Are you sure you want to completely uninstall KSP CLI?")
            .default(false)
            .interact()
        {
            println!("  {} Uninstallation cancelled by user.", "✘".red().bold());
            println!();
            return;
        }
    }

    println!(
        "  {} Removing user configuration (`~/.ksp`)...",
        "🔄".yellow()
    );
    if let Some(home) = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(std::path::PathBuf::from)
    {
        let ksp_dir = home.join(".ksp");
        if ksp_dir.exists() {
            let _ = fs::remove_dir_all(&ksp_dir);
            println!(
                "  {} Deleted configuration folder `{}`.",
                "✔".green().bold(),
                ksp_dir.display()
            );
        } else {
            println!(
                "  {} No configuration folder found at `{}`.",
                "✔".green().bold(),
                ksp_dir.display()
            );
        }
    }

    println!(
        "  {} Attempting `cargo uninstall ksp-cli`...",
        "🔄".yellow()
    );
    let cargo_status = std::process::Command::new("cargo")
        .arg("uninstall")
        .arg("ksp-cli")
        .status();

    match cargo_status {
        Ok(status) if status.success() => {
            println!(
                "  {} Successfully uninstalled binary via Cargo.",
                "✔".green().bold()
            );
        }
        _ => {
            if cfg!(target_os = "windows") {
                println!(
                    "  {} {}",
                    "[!] Windows OS File Lock Detected (os error 5 - Access Denied):".red().bold(),
                    "Windows prevents ksp.exe from being deleted while the process is actively running.".white()
                );
                println!();

                let mut schedule_cleanup = force;
                if !force {
                    use dialoguer::Confirm;
                    if let Ok(true) = Confirm::new()
                        .with_prompt("Would you like KSP to schedule automated self-cleanup to delete ksp.exe 2 seconds after you exit?")
                        .default(true)
                        .interact()
                    {
                        schedule_cleanup = true;
                    }
                }

                if schedule_cleanup {
                    if let Some(home) =
                        std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))
                    {
                        let bin_path = std::path::PathBuf::from(home)
                            .join(".cargo")
                            .join("bin")
                            .join("ksp.exe");
                        let _ = std::process::Command::new("cmd")
                            .args([
                                "/C",
                                &format!(
                                    "timeout /t 2 /nobreak >nul & cargo uninstall ksp-cli 2>nul & del /f /q \"{}\" 2>nul",
                                    bin_path.display()
                                ),
                            ])
                            .spawn();
                    }
                    println!(
                        "  {} {}",
                        "✔".green().bold(),
                        "Automated self-cleanup scheduled! ksp.exe will be deleted cleanly 2 seconds after this process exits.".green().bold()
                    );
                } else {
                    println!(
                        "  {}",
                        "To remove the binary manually after closing your terminal, run:"
                            .yellow()
                            .bold()
                    );
                    println!("    {}", "cargo uninstall ksp-cli".cyan().bold());
                }
            } else {
                println!(
                    "  {} Binary may not be installed via Cargo (or requires manual removal).",
                    "i".cyan().bold()
                );
                println!();
                println!("  {}", "To guarantee complete binary removal across all platforms, run the 1-liner uninstaller:".yellow().bold());
                println!("    {}", "Windows (PowerShell):".yellow().bold());
                println!(
                    "      {}",
                    "irm https://raw.githubusercontent.com/Kush2272/ksp/main/uninstall.ps1 | iex"
                        .cyan()
                        .bold()
                );
                println!();
                println!("    {}", "Linux & macOS (Terminal):".yellow().bold());
                println!(
                    "      {}",
                    "curl -fsSL https://raw.githubusercontent.com/Kush2272/ksp/main/uninstall.sh | sh"
                        .cyan()
                        .bold()
                );
            }
        }
    }

    println!();
    ui::summary_ok("KSP CLI cleanup finished. Thank you for testing Kush Secure Protocol!");
    println!();
    println!(
        "  {}",
        "To reinstall KSP CLI anytime in the future, run:"
            .cyan()
            .bold()
    );
    println!(
        "    {}",
        "irm https://raw.githubusercontent.com/Kush2272/ksp/main/install.ps1 | iex"
            .white()
            .bold()
    );
    println!(
        "    {}",
        "curl -fsSL https://raw.githubusercontent.com/Kush2272/ksp/main/install.sh | sh".dimmed()
    );
    println!();
}
