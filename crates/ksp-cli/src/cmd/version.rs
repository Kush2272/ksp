//! `ksp version` — Display KSP version and build information.

use crate::ui;
use colored::Colorize;

pub fn run(verbose: u8, json: bool) {
    if json {
        let mut info = serde_json::json!({
            "cli_version": env!("CARGO_PKG_VERSION"),
            "protocol_version": format!("{}", ksp_core::CURRENT_VERSION),
            "edition": "2024",
            "homepage": "https://www.kspprotocol.dev",
        });
        if verbose > 0 {
            info["commit"] =
                serde_json::json!(option_env!("KSP_BUILD_COMMIT").unwrap_or("unknown"));
            info["branch"] = serde_json::json!(option_env!("KSP_BUILD_BRANCH").unwrap_or("main"));
            info["built"] = serde_json::json!(option_env!("KSP_BUILD_DATE").unwrap_or("unknown"));
            info["compiler"] =
                serde_json::json!(option_env!("KSP_BUILD_RUSTC").unwrap_or("unknown"));
            info["features"] = serde_json::json!([
                "AES",
                "ChaCha20",
                "Replay",
                "Compression",
                "Streaming",
                "Gateway"
            ]);
        }
        ui::json_output(&info);
        return;
    }

    ui::print_header("KSP Version Info");

    ui::kv("CLI Version", &format!("v{}", env!("CARGO_PKG_VERSION")));
    ui::kv("Protocol", &format!("KSP v{}", ksp_core::CURRENT_VERSION));

    if verbose > 0 {
        ui::kv(
            "Commit",
            option_env!("KSP_BUILD_COMMIT").unwrap_or("unknown"),
        );
        ui::kv("Branch", option_env!("KSP_BUILD_BRANCH").unwrap_or("main"));
        ui::kv("Built", option_env!("KSP_BUILD_DATE").unwrap_or("unknown"));
        ui::kv(
            "Compiler",
            option_env!("KSP_BUILD_RUSTC").unwrap_or("unknown"),
        );
        ui::kv(
            "Platform",
            &format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        );
        println!();
        println!(
            "  {:<20} {}",
            "Features:".dimmed(),
            "AES, ChaCha20, Replay, Compression, Streaming, Gateway"
                .green()
                .bold()
        );
    } else {
        ui::kv("Edition", "Rust 2024");
        ui::kv("License", "MIT");
        ui::kv("Homepage", "https://www.kspprotocol.dev");
        ui::kv("Repository", "https://github.com/Kush2272/ksp");
    }
    println!();
}
