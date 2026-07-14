//! `ksp about|matrix|coffee|quote|credits|dev|journey` — Memorable & Fun Easter Eggs.

use crate::ui;
use colored::Colorize;
use std::thread;
use std::time::Duration;

/// `ksp about` — Display ASCII logo, philosophy, author, and links.
pub fn run_about(json: bool) {
    if json {
        let payload = serde_json::json!({
            "name": "KSP CLI",
            "philosophy": "Fast, Beautiful, Educational, Scriptable, Interactive, Production-grade",
            "author": "Kush Secure Protocol Team",
            "website": "https://www.kspprotocol.dev",
            "github": "https://github.com/Kush2272/ksp",
            "rfc_version": "v1.0 (RFC-0001)",
            "license": "MIT"
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return;
    }

    println!();
    println!(
        "{}",
        "════════════════════════════════════════════════════════════".cyan()
    );
    println!(
        "{}",
        "██╗  ██╗███████╗██████╗      ██████╗ ██╗      ██╗           "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "██║ ██╔╝██╔════╝██╔══██╗    ██╔════╝ ██║      ██║           "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "█████╔╝ ███████╗██████╔╝    ██║  ███╗██║      ██║           "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "██╔═██╗ ╚════██║██╔═══╝     ██║   ██║██║      ██║           "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "██║  ██╗███████║██║         ╚██████╔╝███████╗ ███████╗      "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "╚═╝  ╚═╝╚══════╝╚═╝          ╚═════╝ ╚══════╝ ╚══════╝      "
            .cyan()
            .bold()
    );
    println!(
        "{}",
        "════════════════════════════════════════════════════════════".cyan()
    );
    println!(
        "  {}",
        "Experimental Secure Application Protocol — v1.0"
            .white()
            .bold()
    );
    println!(
        "  {}",
        "Philosophy: Cargo + Git + Docker + kubectl for Protocols".dimmed()
    );
    println!();
    println!(
        "  {:<16} Kush Secure Protocol Team",
        "Author:".yellow().bold()
    );
    println!(
        "  {:<16} {}",
        "Website:".yellow().bold(),
        "https://www.kspprotocol.dev".underline()
    );
    println!(
        "  {:<16} {}",
        "GitHub:".yellow().bold(),
        "https://github.com/Kush2272/ksp".underline()
    );
    println!(
        "  {:<16} RFC-0001 v1.0 (Experimental)",
        "RFC Standard:".yellow().bold()
    );
    println!("  {:<16} MIT", "License:".yellow().bold());
    println!(
        "{}",
        "════════════════════════════════════════════════════════════".cyan()
    );
    println!();
}

/// `ksp matrix` — Matrix green character simulation.
pub fn run_matrix(json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"matrix": "Entering protocol simulation..."})
        );
        return;
    }

    println!(
        "\n{}",
        "  Initiating Matrix Protocol Simulation...".green().bold()
    );
    let matrix_lines = [
        "01001011 01010011 01010000 00100000 01010011 01000101 01000011 01010101 01010010 01000101",
        "0A 3F 82 9C B4 E1 00 29 4F A8 D3 6E 7B 12 55 88 9A C2 E5 F0 11 34 67 89 AA BB CC DD EE FF",
        "██╗ ███████╗██████╗  ███████╗███████╗ ██████╗ ██╗   ██╗██████╗ ███████╗  X25519 DH KEY",
        "3F 8A C4 11 09 2B 44 8E A1 C0 D9 87 65 43 21 00 EF AB CD 12 34 56 78 9A BC DE F0 12 34 56",
        "01110000 01100001 01100011 01101011 01100101 01110100 00100000 01100101 01101110 01100011",
    ];

    for _ in 0..3 {
        for line in &matrix_lines {
            println!("  {}", line.green());
            thread::sleep(Duration::from_millis(80));
        }
    }

    println!(
        "\n  {} {}\n",
        "✔".green().bold(),
        "Entering secure protocol simulation... Welcome to KSP OS."
            .white()
            .bold()
    );
}

/// `ksp coffee` — Playful nod to HTTP 418.
pub fn run_coffee(json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"status": 418, "message": "I'm a teapot", "action": "Brewing secure packets..."})
        );
        return;
    }
    println!(
        "\n  {} {}\n",
        "☕".yellow(),
        "Brewing secure packets... Done. (HTTP 418 I'm a teapot)"
            .white()
            .bold()
    );
}

/// `ksp quote` — Display a random networking or cryptography quote.
pub fn run_quote(json: bool) {
    let quotes = [
        ("Security is a process, not a product.", "Bruce Schneier"),
        (
            "If you think cryptography is the answer to your problem, then you don't know what your problem is.",
            "Peter Gutmann",
        ),
        (
            "Simplicity is the prerequisite for reliability.",
            "Edsger W. Dijkstra",
        ),
        (
            "The only truly secure system is one that is powered off, cast in a block of concrete and sealed in a lead-lined room.",
            "Gene Spafford",
        ),
        (
            "There are two hard things in computer science: cache invalidation, naming things, and off-by-one errors.",
            "Phil Karlton",
        ),
        (
            "Talk is cheap. Show me the encrypted packets.",
            "Kush Secure Protocol Philosophy",
        ),
    ];

    // Pick pseudorandom quote using SystemTime
    let idx = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(dur) => (dur.as_millis() as usize) % quotes.len(),
        Err(_) => 0,
    };
    let (quote, author) = quotes[idx];

    if json {
        println!("{}", serde_json::json!({"quote": quote, "author": author}));
        return;
    }

    ui::header("KSP Wisdom");
    println!("  {}\n", format!("\"{}\"", quote).cyan().italic());
    println!("    ── {}\n", author.yellow().bold());
    println!(
        "  {}",
        "════════════════════════════════════════════════════════════".cyan()
    );
    println!();
}

/// `ksp credits` — Display underlying dependencies and inspirations.
pub fn run_credits(json: bool) {
    if json {
        let payload = serde_json::json!({
            "team": "Kush Secure Protocol Engineering Team",
            "libraries": ["aes-gcm", "chacha20poly1305", "x25519-dalek", "ed25519-dalek", "hkdf", "sysinfo", "comfy-table", "indicatif", "colored", "clap"],
            "inspirations": ["TLS 1.3", "QUIC", "SSH", "WireGuard"]
        });
        println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        return;
    }

    ui::header("KSP Credits & Acknowledgments");
    println!(
        "  {:<20} Kush Secure Protocol Core Team",
        "Engineering Team:".yellow().bold()
    );
    println!(
        "  {:<20} RFC-0001 (Experimental Secure Application Protocol)",
        "Protocol RFC:".yellow().bold()
    );
    println!();
    println!("  {}", "Core Cryptographic Libraries:".white().bold());
    println!("    ✔ aes-gcm v0.10.3 (AES-256-GCM AEAD engine)");
    println!("    ✔ chacha20poly1305 v0.10.1 (ChaCha20-Poly1305 engine)");
    println!("    ✔ x25519-dalek v2.0.1 (Diffie-Hellman Key Exchange)");
    println!("    ✔ ed25519-dalek v2.2.0 (Digital Signature Authentication)");
    println!("    ✔ hkdf v0.12.4 / sha2 v0.10.9 (Key Derivation Functions)");
    println!();
    println!("  {}", "Architectural Inspirations:".white().bold());
    println!("    ✔ TLS 1.3 (Zero-RTT handshake & HKDF derivation model)");
    println!("    ✔ QUIC (Logical stream multiplexing over datagrams)");
    println!("    ✔ WireGuard (Cryptographic simplicity & noise-based handshakes)");
    println!(
        "  {}",
        "════════════════════════════════════════════════════════════".cyan()
    );
    println!();
}

/// `ksp dev` — Secret developer mode dumping advanced internal data structures.
pub fn run_dev(json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "mode": "secret_dev",
                "hkdf_labels": ["ksp_client_write_key", "ksp_server_write_key", "ksp_client_write_iv", "ksp_server_write_iv"],
                "replay_window_highest_seq": 1042,
                "active_streams": 4
            })
        );
        return;
    }

    ui::header("⚡ Secret Developer Mode Active");
    println!(
        "  {}",
        "Advanced protocol internal structures (Non-Secret State):".dimmed()
    );
    println!();
    println!(
        "  {:<26} ksp_client_write_key | ksp_server_write_key",
        "HKDF Derivation Labels:".yellow().bold()
    );
    println!(
        "  {:<26} 0x4A8E_D102_99BB_341A (96-bit)",
        "IV Counter Base:".yellow().bold()
    );
    println!(
        "  {:<26} 1024-bit Sliding Bitmap [Highest Seq: #1042]",
        "Replay Window Bitmap:".yellow().bold()
    );
    println!(
        "  {:<26} Round-Robin Fair Queueing (4 active streams)",
        "Stream Scheduler:".yellow().bold()
    );
    println!(
        "  {:<26} Zero-copy ByteSlice pool (Max buffer: 65,536 B)",
        "Memory Allocations:".yellow().bold()
    );
    println!(
        "  {}",
        "════════════════════════════════════════════════════════════".cyan()
    );
    println!();
}

/// `ksp journey` — Visual step-by-step animation of 1 packet across 9 layers.
pub fn run_journey(json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "packet": "Hello KSP OS",
                "layers": 9,
                "status": "delivered",
                "latency_ns": 784000
            })
        );
        return;
    }

    ui::header("KSP Protocol Journey — 1 Packet across 9 Layers");
    let steps = [
        (
            "Layer 1: Application Layer",
            "Payload initiated: \"Hello KSP OS\" (12 bytes)",
            45,
        ),
        (
            "Layer 2: Stream Multiplexer",
            "Assigned Logical Stream ID #1 (Flow control OK)",
            32,
        ),
        (
            "Layer 3: Session State",
            "Assigned Sequence #1043, derived Counter Nonce",
            28,
        ),
        (
            "Layer 4: Packet Builder",
            "Constructed 48-byte binary header (Ver: 1, Type: Data)",
            41,
        ),
        (
            "Layer 5: AEAD Encryption",
            "AES-256-GCM encrypted (Payload + 16-byte Auth Tag)",
            63,
        ),
        (
            "Layer 6: Socket Transport",
            "Pushed 76 encrypted bytes into underlying TCP/TLS stream",
            50,
        ),
        (
            "Layer 7: Wire Network",
            "In-flight over physical network interface (180 μs RTT)",
            180,
        ),
        (
            "Layer 8: Replay & Decrypt",
            "Verified AEAD Tag, checked 1024-bit window, decrypted",
            61,
        ),
        (
            "Layer 9: Application Delivery",
            "Delivered intact to receiving client callback: \"Hello KSP OS\"",
            38,
        ),
    ];

    for (layer, desc, dur_ns) in &steps {
        println!(
            "  {} {:<28} {}",
            "✔".green().bold(),
            layer.cyan().bold(),
            desc.white()
        );
        println!(
            "     {} {}",
            "└─ Latency:".dimmed(),
            ui::format_nanos(*dur_ns * 1000)
        );
        thread::sleep(Duration::from_millis(150));
    }

    println!(
        "\n  {} {}\n",
        "🎉".yellow(),
        "Packet Journey completed successfully with 0 errors!"
            .green()
            .bold()
    );
}

/// `ksp dance` — Secure Rickroll Protocol (`curl ascii.live/rick` + animated ASCII loop).
pub fn run_dance(json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "status": "rickrolled",
                "protocol": "RFC-0418 (Secure Dance Exchange)",
                "song": "Never Gonna Give You Up",
                "artist": "Rick Astley",
                "youtube_url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
                "ascii_url": "ascii.live/rick"
            })
        );
        return;
    }

    ui::header("KSP Secure Dance Protocol — RFC-0418");
    let init_steps = [
        "Initiating X25519 Dance Key Exchange...",
        "Handshaking with node dQw4w9WgXcQ...",
        "Verifying Ed25519 Groove Certificate...",
        "Establishing encrypted audio/visual stream...",
    ];

    for step in &init_steps {
        println!("  {} {}", "▸".cyan().bold(), step.white().bold());
        thread::sleep(Duration::from_millis(300));
    }

    println!("\n  {} Connection established! Streaming secure dance packet...\n", "✔".green().bold());
    thread::sleep(Duration::from_millis(500));

    // Try running `curl -s ascii.live/rick` directly in cmd/terminal!
    println!("  {}", "─── Dancing over KSP (Ctrl+C to exit) ───".yellow().bold());
    println!();

    let curl_cmd = if cfg!(target_os = "windows") { "curl.exe" } else { "curl" };
    let status = std::process::Command::new(curl_cmd)
        .args(["-s", "ascii.live/rick"])
        .status();

    // If curl failed or exited or wasn't found, play our self-contained animated ASCII loop right inside cmd!
    if status.is_err() || !status.as_ref().map(|s| s.success()).unwrap_or(false) {
        let frames = [
            r#"
      o
     /|\      "Never gonna give you up!"
     / \
            "#,
            r#"
      \o/
       |      "Never gonna let you down!"
      / \
            "#,
            r#"
      _o_
       |      "Never gonna run around and desert you!"
      / \
            "#,
            r#"
     \o
      |\      "Never gonna make you cry!"
     / \
            "#,
            r#"
      o/
     /|       "Never gonna say goodbye!"
     / \
            "#,
            r#"
      o
     /|\      "Never gonna tell a lie and hurt you!"
     / \
            "#,
        ];

        for _ in 0..3 {
            for frame in &frames {
                ui::header("KSP Secure Dance Protocol — RFC-0418");
                println!("{}", frame.magenta().bold());
                thread::sleep(Duration::from_millis(450));
            }
        }

        println!("\n  {} {}\n", "🕺".yellow(), "You have been securely Rickrolled across all 9 layers of KSP!".green().bold());
        println!("  {} {}\n", "🔗 Watch the full video:".cyan(), "https://www.youtube.com/watch?v=dQw4w9WgXcQ".underline());
    }
}

