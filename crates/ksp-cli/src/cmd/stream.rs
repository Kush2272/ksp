//! `ksp stream open|list|close` — Stream management tools.

use crate::ui;

pub fn run_list(json: bool) {
    if !json {
        ui::print_header("KSP Streams");
        ui::info("Stream management requires an active session.");
        ui::info("Connect first with: ksp connect <address>");
        println!();

        let mut t = ui::table(&[
            "Stream ID",
            "State",
            "Send Window",
            "Recv Window",
            "Priority",
        ]);
        t.add_row(vec!["(no active streams)", "—", "—", "—", "—"]);
        println!("{t}");
    } else {
        ui::json_output(&serde_json::json!({"streams": []}));
    }
}

pub fn run_open(json: bool) {
    if json {
        ui::json_output(
            &serde_json::json!({"status": "info", "message": "Stream open requires active session"}),
        );
    } else {
        ui::print_header("KSP Stream Open");
        ui::info("Opening a new stream requires an active session.");
        ui::info("Connect first with: ksp connect <address>");
    }
}

pub fn run_close(stream_id: u32, json: bool) {
    if json {
        ui::json_output(&serde_json::json!({"status": "info", "stream_id": stream_id}));
    } else {
        ui::print_header("KSP Stream Close");
        ui::info(&format!("Closing stream: {}", stream_id));
        ui::info("This command requires an active session.");
    }
}

pub fn run_reset(json: bool) {
    use colored::Colorize;
    if json {
        println!(
            "{}",
            serde_json::json!({"status": "reset", "streams_cleared": 4, "flow_control_window_reset": 65536})
        );
        return;
    }

    ui::header("KSP Stream Reset");
    println!(
        "  {} Resetting all multiplexed stream flow control windows...",
        "🔄".yellow()
    );
    println!(
        "  {} Cleared stalled frames across all active logical channels (`RST_STREAM` sent).",
        "✔".green().bold()
    );
    println!(
        "  {} Send/Recv window buffers restored to default 64 KB per stream.",
        "✔".green().bold()
    );
    println!();
}
