//! `ksp monitor`, `ksp dashboard`, and `ksp stats` — Live observability & TUI tools.

use crate::cmd::telemetry::TelemetrySnapshot;
use crate::ui;
use colored::Colorize;
use std::thread;
use std::time::Duration;

pub fn run_monitor(demo: bool, json: bool) {
    let snap = TelemetrySnapshot::fetch_current();
    let has_traffic =
        snap.active_sessions > 0 || !snap.sessions.is_empty() || snap.total_packets > 0;
    let is_active = demo || has_traffic;

    let active_sessions = if demo { 14 } else { snap.active_sessions };
    let packets_sec = if demo {
        "14,209 pkts/s (Simulated --demo)".to_string()
    } else if has_traffic {
        format!("{} pkts/s", snap.total_packets / snap.uptime_secs.max(1))
    } else {
        "0 pkts/s".to_string()
    };
    let avg_rtt = if demo {
        "0.41 ms (Simulated --demo)".to_string()
    } else if !snap.sessions.is_empty() {
        format!("{:.2} ms", snap.sessions[0].rtt_ms)
    } else {
        "N/A".to_string()
    };

    if json {
        let mut obj = serde_json::json!({
            "status": if is_active { "active" } else { "idle" },
            "active_sessions": active_sessions,
            "packets_sec": packets_sec,
            "avg_rtt": avg_rtt,
            "replay_drops": snap.replay_attempts_blocked
        });
        if demo {
            obj["simulated"] = serde_json::Value::Bool(true);
        }
        println!("{}", obj);
        return;
    }

    ui::header("KSP Live Traffic Monitor (`Ctrl+C` to stop)");
    println!(
        "  {:<12} {:<36} {:<15} {:<16} {:<14}",
        "TIME".dimmed(),
        "SESSION UUID".white().bold(),
        "CIPHER".cyan(),
        "THROUGHPUT".yellow(),
        "RTT".green()
    );
    println!("  {}", "─────────────────────────────────────────────────────────────────────────────────────────────".dimmed());

    if demo {
        println!(
            "  {}",
            "[SIMULATED --DEMO SESSIONS — NOT LIVE TRAFFIC]"
                .yellow()
                .bold()
        );
        println!(
            "  {:<12} {:<36} {:<15} {:<16} {:<14}",
            "Just now".green(),
            "d8193ad7-4e01-4c12-91a2-11bc90a8231e [SIM]".yellow(),
            "AES-256-GCM".cyan(),
            "614.2 MB/s".yellow().bold(),
            "0.41 ms".green().bold()
        );
        println!(
            "  {:<12} {:<36} {:<15} {:<16} {:<14}",
            "2s ago".dimmed(),
            "f49281a0-99c2-4211-881b-a49201bc981a [SIM]".white(),
            "AES-256-GCM".cyan(),
            "118.5 MB/s".yellow(),
            "0.44 ms".green()
        );
        println!(
            "  {:<12} {:<36} {:<15} {:<16} {:<14}",
            "5s ago".dimmed(),
            "1109a823-11bc-4e01-91a2-d8193ad74c12 [SIM]".white(),
            "ChaCha20".cyan(),
            "84.1 MB/s".yellow(),
            "0.41 ms".green()
        );
    } else if has_traffic && !snap.sessions.is_empty() {
        for s in &snap.sessions {
            let tput = format!(
                "{}/s",
                ui::format_bytes(s.bytes_transferred / snap.uptime_secs.max(1))
            );
            println!(
                "  {:<12} {:<36} {:<15} {:<16} {:<14}",
                "Active".green(),
                s.uuid.yellow(),
                s.cipher.cyan(),
                tput.yellow().bold(),
                format!("{:.2} ms", s.rtt_ms).green().bold()
            );
        }
    } else {
        println!(
            "  {} No active KSP server sessions connected. Listening for traffic...",
            "ℹ".blue()
        );
        println!(
            "  {:<12} {:<36} {:<15} {:<16} {:<14}",
            "IDLE".dimmed(),
            "None".dimmed(),
            "N/A".dimmed(),
            "0 B/s".yellow(),
            "N/A".green()
        );
    }
    thread::sleep(Duration::from_millis(500));
    println!();
}

pub fn run_stats(demo: bool, json: bool) {
    let snap = TelemetrySnapshot::fetch_current();
    let has_traffic =
        snap.active_sessions > 0 || !snap.sessions.is_empty() || snap.total_packets > 0;
    let is_active = demo || has_traffic || snap.status == "running";

    if json {
        let mut obj = serde_json::json!({
            "uptime_secs": if demo { 142 } else { snap.uptime_secs },
            "total_bytes_sent": if demo { 142000000 } else { snap.total_bytes_sent },
            "total_bytes_recv": if demo { 38000000 } else { snap.total_bytes_recv },
            "total_packets": if demo { 14209 } else { snap.total_packets },
            "replay_attempts_blocked": snap.replay_attempts_blocked,
            "active_sessions": if demo { 14 } else { snap.active_sessions },
            "active_streams": if demo { 56 } else { snap.active_streams },
            "crypto_engine": "AES-256-GCM + Ed25519"
        });
        if demo {
            obj["simulated"] = serde_json::Value::Bool(true);
        }
        println!("{}", obj);
        return;
    }

    ui::header("KSP System & Protocol Telemetry Statistics");
    let mut t = ui::table(&["Metric", "Value", "Notes"]);
    let sessions = if demo { 14 } else { snap.active_sessions };
    let streams = if demo { 56 } else { snap.active_streams };
    let pkts = if demo { 14209 } else { snap.total_packets };
    let bytes_str = if demo {
        "1.8 GB (1.4 GB Sent / 380 MB Recv)".to_string()
    } else {
        format!(
            "{} total ({} Sent / {} Recv)",
            ui::format_bytes(snap.total_bytes_sent + snap.total_bytes_recv),
            ui::format_bytes(snap.total_bytes_sent),
            ui::format_bytes(snap.total_bytes_recv)
        )
    };

    t.add_row(vec![
        "Server Status",
        if demo {
            "Simulated (Demo)"
        } else {
            &snap.status
        },
        if is_active {
            "ksp server daemon active ✔"
        } else {
            "Offline / Idle"
        },
    ]);
    t.add_row(vec![
        "Active Sessions / Streams",
        &format!("{} sessions / {} streams", sessions, streams),
        if sessions > 0 || demo {
            "Client multiplexers established"
        } else {
            "No active connections"
        },
    ]);
    t.add_row(vec![
        "Total Bandwidth Processed",
        &bytes_str,
        "AES-256-GCM / ChaCha20Poly1305 AEAD",
    ]);
    t.add_row(vec![
        "Total Packets Transferred",
        &format!("{} packets", pkts),
        "Authenticated sequence frames",
    ]);
    t.add_row(vec![
        "Replay Attempts Blocked",
        &format!("{} packets", snap.replay_attempts_blocked),
        "1024-bit replay window active",
    ]);
    t.add_row(vec![
        "Average RTT Latency",
        if demo {
            "0.41 ms (Simulated --demo)"
        } else if !snap.sessions.is_empty() {
            let avg =
                snap.sessions.iter().map(|s| s.rtt_ms).sum::<f64>() / (snap.sessions.len() as f64);
            let s_fmt = format!("{:.2} ms (Snapshot Avg)", avg);
            Box::leak(s_fmt.into_boxed_str())
        } else {
            "N/A (Collecting...)"
        },
        if sessions > 0 || demo {
            "Live connection metrics"
        } else {
            "Connect to measure RTT"
        },
    ]);
    println!("{t}");
    println!();
}

pub fn run_dashboard(demo: bool, json: bool) {
    if json {
        run_stats(demo, true);
        return;
    }

    let snap = TelemetrySnapshot::fetch_current();
    let has_traffic =
        snap.active_sessions > 0 || !snap.sessions.is_empty() || snap.total_packets > 0;
    let is_active = demo || has_traffic;

    println!();
    println!("  {}", "╔═══════════════════════════════════════════════════════════════════════════════════════════════╗".cyan());
    println!("  {} {:<93} {}", "║".cyan(), "   🚀 KUSH SECURE PROTOCOL (KSP) v1.0 — REAL-TIME OBSERVABILITY DASHBOARD                      ".white().bold(), "║".cyan());
    println!("  {}", "╠═════════════════════════════════════════════╦═════════════════════════════════════════════════╣".cyan());

    if is_active {
        let sessions = if demo { 14 } else { snap.active_sessions };
        let streams = if demo { 56 } else { snap.active_streams };
        let total_bytes = snap.total_bytes_sent + snap.total_bytes_recv;
        let tput = if demo {
            "614.2 MB/s (Simulated --demo)".to_string()
        } else {
            format!(
                "{}/s",
                ui::format_bytes(total_bytes / snap.uptime_secs.max(1))
            )
        };
        let rtt = if demo {
            "0.41 ms (p99: 0.82 ms) (Simulated --demo)".to_string()
        } else if !snap.sessions.is_empty() {
            format!("{:.2} ms", snap.sessions[0].rtt_ms)
        } else {
            "N/A".to_string()
        };
        let _s1_uuid = if !snap.sessions.is_empty() {
            snap.sessions[0].uuid.clone()
        } else if demo {
            "d8193ad7-4e01-4c12-91a2-11bc90a8231e [SIM]".to_string()
        } else {
            "N/A".to_string()
        };
        let _s1_ciph = if !snap.sessions.is_empty() {
            snap.sessions[0].cipher.clone()
        } else if demo {
            "AES-256-GCM".to_string()
        } else {
            "N/A".to_string()
        };

        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            " TELEMETRY SUMMARY".yellow().bold(),
            "║".cyan(),
            " SLIDING REPLAY PROTECTION BITMAP (1,024 Bits)"
                .green()
                .bold(),
            "║".cyan()
        );
        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            format!("   Active Sessions:  {} (ACTIVE ✔)", sessions).white(),
            "║".cyan(),
            "   [████████████████████████████████████████···]".cyan(),
            "║".cyan()
        );
        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            format!("   Active Streams:   {} channels", streams).white(),
            "║".cyan(),
            format!(
                "   Window Lower Bound: Seq #{}",
                snap.total_packets.saturating_sub(1024)
            )
            .dimmed(),
            "║".cyan()
        );
        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            format!("   Throughput:       {}", tput).yellow().bold(),
            "║".cyan(),
            format!("   Highest Seq Seen:   Seq #{}", snap.total_packets).yellow(),
            "║".cyan()
        );
        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            format!("   Average Latency:  {}", rtt).yellow(),
            "║".cyan(),
            format!(
                "   Replays Rejected:   {} Packets Blocked 🛡",
                snap.replay_attempts_blocked
            )
            .green()
            .bold(),
            "║".cyan()
        );
        println!("  {}", "╠═════════════════════════════════════════════╩═════════════════════════════════════════════════╣".cyan());
        if demo {
            println!("  {} {:<93} {}", "║".cyan(), " SIMULATED SESSION POOL & STREAM MULTIPLEXER STATUS (--DEMO)                                   ".yellow().bold(), "║".cyan());
            println!("  {} {:<93} {}", "║".cyan(), "   ✔ d8193ad7-4e01-4c12-91a2-11bc90a8231e [SIM] | AES-256-GCM | 18 Streams | 412 MB | 0.38 ms ".white(), "║".cyan());
            println!("  {} {:<93} {}", "║".cyan(), "   ✔ f49281a0-99c2-4211-881b-a49201bc981a [SIM] | AES-256-GCM | 12 Streams | 118 MB | 0.44 ms ".white(), "║".cyan());
            println!("  {} {:<93} {}", "║".cyan(), "   ✔ 1109a823-11bc-4e01-91a2-d8193ad74c12 [SIM] | ChaCha20    | 26 Streams | 84 MB  | 0.41 ms ".white(), "║".cyan());
        } else {
            println!("  {} {:<93} {}", "║".cyan(), " ACTIVE SESSION POOL & STREAM MULTIPLEXER STATUS                                               ".yellow().bold(), "║".cyan());
            for s in &snap.sessions {
                let info = format!(
                    "   ✔ {} | {:<11} | {:>2} Streams | {:>6} | {:.2} ms",
                    s.uuid,
                    s.cipher,
                    s.streams,
                    ui::format_bytes(s.bytes_transferred),
                    s.rtt_ms
                );
                println!("  {} {:<93} {}", "║".cyan(), info.white(), "║".cyan());
            }
        }
        println!("  {}", "╠═══════════════════════════════════════════════════════════════════════════════════════════════╣".cyan());
        println!("  {} {:<93} {}", "║".cyan(), " REAL-TIME THROUGHPUT SPARKLINE (Last 10 Seconds)                                              ".green().bold(), "║".cyan());
        let spark_tput = if demo {
            "412 MB/s (Simulated --demo)"
        } else {
            &tput
        };
        let spark_pkts = if demo {
            "Peak: 14,209 pkts/s | Current: 13,850 pkts/s (Simulated --demo)"
        } else {
            &format!(
                "Current: {} pkts/s",
                snap.total_packets / snap.uptime_secs.max(1)
            )
        };
        println!(
            "  {} {:<93} {}",
            "║".cyan(),
            format!("   Throughput:  ▄▅▆▇████▇▆▅▄▃▂  [{}]", spark_tput)
                .yellow()
                .bold(),
            "║".cyan()
        );
        println!(
            "  {} {:<93} {}",
            "║".cyan(),
            format!("   Packet Rate: ▃▄▅▆▇███▇▆▅▄▃▂  [{}]", spark_pkts).yellow(),
            "║".cyan()
        );
        println!("  {}", "╚═══════════════════════════════════════════════════════════════════════════════════════════════╝".cyan());
        println!();
    } else {
        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            " TELEMETRY SUMMARY".yellow().bold(),
            "║".cyan(),
            " SLIDING REPLAY PROTECTION BITMAP (1,024 Bits)"
                .green()
                .bold(),
            "║".cyan()
        );
        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            "   Active Sessions:  0 (IDLE)".white(),
            "║".cyan(),
            "   [···········································]".cyan(),
            "║".cyan()
        );
        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            "   Active Streams:   0 channels".white(),
            "║".cyan(),
            "   Window Lower Bound: Seq #0".dimmed(),
            "║".cyan()
        );
        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            "   Throughput:       0 B/s".yellow().bold(),
            "║".cyan(),
            "   Highest Seq Seen:   Seq #0".yellow(),
            "║".cyan()
        );
        println!(
            "  {} {:<43} {} {:<47} {}",
            "║".cyan(),
            "   Average Latency:  N/A".yellow(),
            "║".cyan(),
            "   Replays Rejected:   0 Packets Blocked 🛡".green().bold(),
            "║".cyan()
        );
        println!("  {}", "╠═════════════════════════════════════════════╩═════════════════════════════════════════════════╣".cyan());
        println!("  {} {:<93} {}", "║".cyan(), " ACTIVE SESSION POOL & STREAM MULTIPLEXER STATUS                                               ".yellow().bold(), "║".cyan());
        println!("  {} {:<93} {}", "║".cyan(), "   No active KSP sessions. Run `ksp connect <host:port>` or `ksp server start` to begin.       ".dimmed(), "║".cyan());
        println!("  {} {:<93} {}", "║".cyan(), "                                                                                               ".dimmed(), "║".cyan());
        println!("  {}", "╠═══════════════════════════════════════════════════════════════════════════════════════════════╣".cyan());
        println!("  {} {:<93} {}", "║".cyan(), " REAL-TIME THROUGHPUT SPARKLINE (Last 10 Seconds)                                              ".green().bold(), "║".cyan());
        println!("  {} {:<93} {}", "║".cyan(), "   Throughput:  [Collecting... no active stream traffic recorded]                              ".yellow().bold(), "║".cyan());
        println!("  {} {:<93} {}", "║".cyan(), "   Packet Rate: [Collecting... waiting for packet transmission]                                ".yellow(), "║".cyan());
        println!("  {}", "╚═══════════════════════════════════════════════════════════════════════════════════════════════╝".cyan());
        println!();
        println!("  {}", "╭─────────────────────────────────────────────────────────────────────────────────────────────╮".dimmed());
        println!("  {} {} {}", "│".dimmed(), "💡 HOW TO DISPLAY LIVE TELEMETRY NUMBERS ON THIS DASHBOARD                                 ".yellow().bold(), "│".dimmed());
        println!("  {}", "├─────────────────────────────────────────────────────────────────────────────────────────────┤".dimmed());
        println!("  {} {} {}", "│".dimmed(), "Option 1 — View a live simulated telemetry stream instantly right now:                        ".white(), "│".dimmed());
        println!("  {} {} {}", "│".dimmed(), "  $ ksp dashboard --demo                                                                      ".cyan().bold(), "│".dimmed());
        println!("  {} {} {}", "│".dimmed(), "                                                                                              │".dimmed(), "│".dimmed());
        println!("  {} {} {}", "│".dimmed(), "Option 2 — Connect real KSP traffic between terminal windows:                                 ".white(), "│".dimmed());
        println!("  {} {} {}", "│".dimmed(), "  Terminal 1 (Start Server):  ksp server start --port 9876                                    ".green(), "│".dimmed());
        println!("  {} {} {}", "│".dimmed(), "  Terminal 2 (Send Traffic):  ksp ping 127.0.0.1:9876   (or `ksp transfer send <file>`)       ".green(), "│".dimmed());
        println!("  {} {} {}", "│".dimmed(), "  Terminal 3 (Dashboard):     ksp dashboard                                                   ".green(), "│".dimmed());
        println!("  {}", "╰─────────────────────────────────────────────────────────────────────────────────────────────╯".dimmed());
        println!();
    }
}
