//! Beautiful terminal output utilities for the KSP CLI.
//!
//! Provides consistent, polished formatting across all commands using
//! colored output, Unicode box-drawing, tables, progress bars, and spinners.

use colored::Colorize;
use comfy_table::{
    Cell, Color as TableColor, ContentArrangement, Table, modifiers::UTF8_ROUND_CORNERS,
    presets::UTF8_FULL,
};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

pub mod startup;

// ─── KSP Brand Colors ────────────────────────────────────────────────

/// Print the KSP banner — shown on startup and --help
pub fn print_banner() {
    let banner = r#"
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     ██╗  ██╗███████╗██████╗                                   ║
    ║     ██║ ██╔╝██╔════╝██╔══██╗                                  ║
    ║     █████╔╝ ███████╗██████╔╝                                  ║
    ║     ██╔═██╗ ╚════██║██╔═══╝                                   ║
    ║     ██║  ██╗███████║██║                                       ║
    ║     ╚═╝  ╚═╝╚══════╝╚═╝                                       ║
    ║                                                               ║
    ║     Kush Secure Protocol — CLI v0.1.0                         ║
    ║     Experimental Secure Application Protocol                  ║
    ║       Sup bro all good                                        ║
    ╚═══════════════════════════════════════════════════════════════╝
"#;
    println!("{}", banner.cyan());
}

/// Print a compact header for a specific command.
pub fn print_header(title: &str) {
    let width: usize = 60;
    let pad_total = width.saturating_sub(title.len() + 4);
    let pad_left = pad_total / 2;
    let pad_right = pad_total - pad_left;

    println!();
    println!("{}", "═".repeat(width).cyan());
    println!(
        "{}{}{}{}{}",
        "══".cyan(),
        " ".repeat(pad_left),
        title.bold().white(),
        " ".repeat(pad_right),
        "══".cyan()
    );
    println!("{}", "═".repeat(width).cyan());
    println!();
}

/// Alias for `print_header` used across subcommands.
pub fn header(title: &str) {
    print_header(title);
}

/// Print a section heading within a command's output.
pub fn print_section(title: &str) {
    println!();
    println!("  {} {}", "▸".cyan().bold(), title.bold().white());
    println!("  {}", "─".repeat(50).dimmed());
}

// ─── Status Indicators ──────────────────────────────────────────────

/// Print a success checkmark line.
pub fn success(msg: &str) {
    println!("  {} {}", "✔".green().bold(), msg);
}

/// Print a failure cross line.
pub fn failure(msg: &str) {
    println!("  {} {}", "✘".red().bold(), msg);
}

/// Print an info indicator.
pub fn info(msg: &str) {
    println!("  {} {}", "ℹ".cyan().bold(), msg);
}

/// Print a warning indicator.
pub fn warning(msg: &str) {
    println!("  {} {}", "⚠".yellow().bold(), msg);
}

/// Print a key-value pair with alignment.
pub fn kv(key: &str, value: &str) {
    println!("  {:<20} {}", key.dimmed(), value.white().bold());
}

/// Print a key-value pair with a colored value.
#[allow(dead_code)]
pub fn kv_colored(key: &str, value: &str, is_good: bool) {
    let colored_val = if is_good {
        value.green().bold().to_string()
    } else {
        value.red().bold().to_string()
    };
    println!("  {:<20} {}", key.dimmed(), colored_val);
}

// ─── Spinners ────────────────────────────────────────────────────────

/// Create a styled spinner for long-running operations.
pub fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
            .template("  {spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(msg.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Create a progress bar for file transfers / benchmarks.
pub fn progress_bar(total: u64, msg: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {msg} [{bar:40.cyan/dim}] {percent}%  {bytes_per_sec}  ETA {eta}")
            .unwrap()
            .progress_chars("███░"),
    );
    pb.set_message(msg.to_string());
    pb
}

// ─── Tables ──────────────────────────────────────────────────────────

/// Create a styled KSP table.
pub fn table(headers: &[&str]) -> Table {
    let mut t = Table::new();
    t.load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic);

    let header_cells: Vec<Cell> = headers
        .iter()
        .map(|h| Cell::new(h).fg(TableColor::Cyan))
        .collect();
    t.set_header(header_cells);
    t
}

// ─── Hex Dump ────────────────────────────────────────────────────────

/// Print a hex dump of binary data with offset, hex, and ASCII columns.
pub fn hex_dump(data: &[u8], max_lines: usize) {
    let lines = data.len().div_ceil(16);
    let display_lines = lines.min(max_lines);

    for i in 0..display_lines {
        let offset = i * 16;
        let chunk = &data[offset..data.len().min(offset + 16)];

        // Offset
        let mut line = format!("  {:08x}  ", offset).dimmed().to_string();

        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                line.push(' ');
            }
            line.push_str(&format!("{:02x} ", byte));
        }

        // Pad if less than 16 bytes
        for j in chunk.len()..16 {
            if j == 8 {
                line.push(' ');
            }
            line.push_str("   ");
        }

        // ASCII
        line.push_str(" │ ");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                line.push(*byte as char);
            } else {
                line.push_str(&".".dimmed().to_string());
            }
        }

        println!("{}", line);
    }

    if lines > max_lines {
        println!(
            "  {} ({} more lines omitted)",
            "...".dimmed(),
            lines - max_lines
        );
    }
}

// ─── Handshake Step Display ──────────────────────────────────────────

/// Display a handshake step with timing.
#[allow(dead_code)]
pub fn handshake_step(step: &str, duration_us: u64) {
    println!(
        "  {} {}  {}",
        "✔".green().bold(),
        step.white().bold(),
        format!("({}μs)", duration_us).dimmed()
    );
}

/// Display a failed handshake step.
#[allow(dead_code)]
pub fn handshake_fail(step: &str, reason: &str) {
    println!(
        "  {} {}  {}",
        "✘".red().bold(),
        step.white().bold(),
        reason.red()
    );
}

// ─── JSON Output ─────────────────────────────────────────────────────

/// If --json flag is set, output structured JSON instead of pretty output.
pub fn json_output<T: serde::Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("{}", format!("JSON serialization error: {}", e).red()),
    }
}

// ─── Miscellaneous ───────────────────────────────────────────────────

/// Print a final status summary line.
pub fn summary_ok(msg: &str) {
    println!();
    println!("  {} {}", "✔".green().bold(), msg.green().bold());
    println!();
}

/// Print a final failure summary line.
pub fn summary_fail(msg: &str) {
    println!();
    println!("  {} {}", "✘".red().bold(), msg.red().bold());
    println!();
}

/// Format bytes in a human-friendly way.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format a duration in a human-friendly way.
pub fn format_duration(d: Duration) -> String {
    let micros = d.as_micros();
    if micros < 1_000 {
        format!("{} μs", micros)
    } else if micros < 1_000_000 {
        format!("{:.2} ms", micros as f64 / 1_000.0)
    } else {
        format!("{:.2} s", micros as f64 / 1_000_000.0)
    }
}

/// Format nanoseconds in a human-friendly way (`ns`, `μs`, `ms`, `s`).
pub fn format_nanos(ns: u64) -> String {
    if ns < 1_000 {
        format!("{} ns", ns)
    } else if ns < 1_000_000 {
        format!("{:.2} μs", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2} ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.2} s", ns as f64 / 1_000_000_000.0)
    }
}

/// Generate a cinematic bar graph `███████████████` with customizable fill.
#[allow(dead_code)]
pub fn bar_graph(percent: u64, max_width: usize) -> String {
    let fill = ((percent * max_width as u64) / 100).min(max_width as u64) as usize;
    let empty = max_width.saturating_sub(fill);
    format!("{}{}", "█".repeat(fill).cyan(), "░".repeat(empty).dimmed())
}

/// Generate star rating `★★★★★` / `★★★★☆` string.
#[allow(dead_code)]
pub fn stars(filled: usize, total: usize) -> String {
    let mut s = String::new();
    for i in 0..total {
        if i < filled {
            s.push_str(&"★".yellow().bold().to_string());
        } else {
            s.push_str(&"☆".dimmed().to_string());
        }
    }
    s
}
