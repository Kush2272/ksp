//! `ksp docs` / `ksp rfc` — Open documentation and RFC.

use crate::ui;
use colored::Colorize;

pub fn run(topic: Option<&str>, json: bool) {
    let base_url = "https://www.kspprotocol.dev";

    let url = match topic {
        Some(t) => {
            let t_lower = t.to_lowercase();
            match t_lower.as_str() {
                "rfc" => format!("{}/rfc", base_url),
                "api" => format!("{}/docs/api", base_url),
                "handshake" => format!("{}/docs/handshake", base_url),
                "replay" | "replay-protection" => format!("{}/notes/replay-protection", base_url),
                "packet" | "packets" => format!("{}/docs/packet-format", base_url),
                "benchmarks" | "benchmark" => format!("{}/benchmarks", base_url),
                _ => format!("{}/docs", base_url),
            }
        }
        None => format!("{}/docs", base_url),
    };

    if json {
        ui::json_output(&serde_json::json!({"url": url}));
    } else {
        ui::info(&format!("Opening {} ...", url.cyan().underline()));
        match open::that(&url) {
            Ok(()) => ui::success("Documentation opened in browser."),
            Err(e) => {
                ui::warning(&format!("Could not open browser: {}", e));
                ui::info(&format!("Visit: {}", url));
            }
        }
    }
}
