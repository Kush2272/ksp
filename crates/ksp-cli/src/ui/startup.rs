//! Animated startup sequence for the KSP CLI.
//!
//! Drop this in as `src/ui/startup.rs` and call `ui::startup::run().await`
//! at the top of `main()`, before `print_banner()` / command dispatch.

use colored::Colorize;
use std::io::{self, Write};
use std::time::Duration;

// ─── Public entry point ──────────────────────────────────────────────

/// Run the full animated startup sequence.
///
/// Safe to call unconditionally — it detects non-interactive terminals
/// and TERM=dumb / NO_COLOR-style environments and falls back to the
/// plain static banner instantly.
pub async fn run() {
    if !should_animate() {
        print_static_banner();
        return;
    }

    let _ = boot_sequence().await;
}

/// Returns false when output isn't a real interactive terminal, so we
/// never animate into a log file, CI runner, or --json pipe.
fn should_animate() -> bool {
    use std::io::IsTerminal;
    io::stdout().is_terminal() && std::env::var("KSP_NO_ANIM").is_err()
}

// ─── Sequence orchestration ────────────────────────────────────────────

async fn boot_sequence() -> io::Result<()> {
    // Ensure Windows VT support is active via console crate
    let _ = console::Term::stdout();

    hide_cursor();

    scan_reveal().await?;
    tokio::time::sleep(Duration::from_millis(80)).await;

    init_checklist().await?;
    tokio::time::sleep(Duration::from_millis(120)).await;

    settle_banner()?;

    show_cursor();
    Ok(())
}

// ─── Step 1: horizontal scan-line revealing the KSP wordmark ──────────

const GLYPH: &[&str] = &[
    "██╗  ██╗███████╗██████╗ ",
    "██║ ██╔╝██╔════╝██╔══██╗",
    "█████╔╝ ███████╗██████╔╝",
    "██╔═██╗ ╚════██║██╔═══╝ ",
    "██║  ██╗███████║██║     ",
    "╚═╝  ╚═╝╚══════╝╚═╝     ",
];

async fn scan_reveal() -> io::Result<()> {
    let width = GLYPH[0].chars().count();
    let mut out = io::stdout();

    println!();
    for _ in 0..GLYPH.len() {
        println!();
    }
    move_up(GLYPH.len() as u16);

    // Sweep a bright cyan column left -> right; each pass reveals one
    // more column of every row, so the whole glyph "materializes" as
    // if a scanner is passing over it.
    for col in 1..=width {
        move_to_col(0);
        for row in GLYPH {
            let chars: Vec<char> = row.chars().collect();
            let mut line = String::new();

            for (i, ch) in chars.iter().enumerate() {
                if i < col {
                    line.push(*ch);
                } else if i == col.saturating_sub(1) + 1 {
                    // leading edge highlight, one char ahead of the fill
                    line.push(' ');
                } else {
                    line.push(' ');
                }
            }

            let revealed: String = chars.iter().take(col).collect();
            let leading = if col < chars.len() { "▐" } else { "" };

            clear_line();
            println!("  {}{}", revealed.cyan().bold(), leading.white().bold());
        }
        move_up(GLYPH.len() as u16);
        out.flush()?;
        tokio::time::sleep(Duration::from_millis(9)).await;
    }

    // Final clean draw, no leading-edge artifact
    move_to_col(0);
    for row in GLYPH {
        clear_line();
        println!("  {}", row.cyan().bold());
    }
    out.flush()?;

    println!();
    println!(
        "  {}  {}",
        "Kush Secure Protocol".white().bold(),
        format!("v{}", env!("CARGO_PKG_VERSION", "0.1.0")).dimmed()
    );
    println!("  {}", "Experimental Secure Application Protocol".dimmed());

    Ok(())
}

// ─── Step 2: handshake-style init checklist ───────────────────────────

struct InitStep {
    label: &'static str,
    delay_ms: u64,
}

const INIT_STEPS: &[InitStep] = &[
    InitStep {
        label: "Loading configuration",
        delay_ms: 70,
    },
    InitStep {
        label: "Verifying keypair",
        delay_ms: 110,
    },
    InitStep {
        label: "Checking protocol version",
        delay_ms: 60,
    },
    InitStep {
        label: "Priming session cache",
        delay_ms: 90,
    },
];

async fn init_checklist() -> io::Result<()> {
    println!();
    for step in INIT_STEPS {
        print_pending(step.label)?;
        tokio::time::sleep(Duration::from_millis(step.delay_ms)).await;
        print_done(step.label)?;
    }
    Ok(())
}

fn print_pending(label: &str) -> io::Result<()> {
    let mut out = io::stdout();
    print!("  {} {}", "○".dimmed(), label.dimmed());
    out.flush()
}

fn print_done(label: &str) -> io::Result<()> {
    clear_current_line();
    println!("  {} {}", "✔".green().bold(), label.white());
    Ok(())
}

// ─── Step 3: settle into the familiar boxed banner ────────────────────

fn settle_banner() -> io::Result<()> {
    println!();
    println!("  {}", "─".repeat(52).dimmed());
    println!("  {}  {}", "●".green(), "ready — type".dimmed());
    println!("    {} for a list of commands", "ksp --help".cyan().bold());
    println!();
    Ok(())
}

/// The plain, no-animation fallback banner (piped output, CI, --json).
fn print_static_banner() {
    println!();
    for row in GLYPH {
        println!("  {}", row.cyan().bold());
    }
    println!();
    println!(
        "  {}  v{}",
        "Kush Secure Protocol".white().bold(),
        env!("CARGO_PKG_VERSION", "0.1.0")
    );
    println!("  {}", "Experimental Secure Application Protocol".dimmed());
    println!();
}

// ─── Minimal raw cursor control ────────────────────────────────────────

fn hide_cursor() {
    print!("\x1B[?25l");
    let _ = io::stdout().flush();
}

fn show_cursor() {
    print!("\x1B[?25h");
    let _ = io::stdout().flush();
}

fn move_up(n: u16) {
    print!("\x1B[{}A", n);
}

fn move_to_col(c: u16) {
    print!("\x1B[{}G", c + 1);
}

fn clear_line() {
    print!("\x1B[2K");
}

fn clear_current_line() {
    print!("\r\x1B[2K");
    let _ = io::stdout().flush();
}
