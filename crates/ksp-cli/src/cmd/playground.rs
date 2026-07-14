//! `ksp playground` — Launch interactive KSP explorer.

use crate::ui;
use colored::Colorize;

pub fn run(json: bool) {
    if !json {
        ui::print_header("KSP Playground");
    }

    let url = "https://www.kspprotocol.dev";

    if json {
        ui::json_output(&serde_json::json!({"status": "ok", "url": url}));
    } else {
        ui::info(&format!("Opening {} in your browser...", url.cyan().bold()));
        println!();

        match open::that(url) {
            Ok(()) => {
                ui::success("Playground launched!");
                ui::info("Explore KSP interactively in your browser.");
            }
            Err(e) => {
                ui::warning(&format!("Could not open browser: {}", e));
                ui::info(&format!("Visit manually: {}", url.cyan().underline()));
            }
        }
    }
}
