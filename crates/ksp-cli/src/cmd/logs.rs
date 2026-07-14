//! `ksp logs` — Inspect historical or streaming daemon & session logs over IPC.
//!
//! Supports `--follow` (`-f`), `--json`, `--session <id>`, `--level <trace|debug|info|warn|error>`,
//! and queries the active `ksp daemon` over IPC or reads local persistent log files (`~/.ksp/logs/`).

use crate::cmd::telemetry::LogEntry;
use crate::ui;
use colored::Colorize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub fn run(follow: bool, json: bool, level: Option<&str>, session: Option<&str>, lines: usize) {
    if !json && !follow {
        ui::print_header("KSP Event & Session Logs");
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Try querying via IPC first
        let logs_from_ipc = query_ipc_logs(level, session, lines).await;
        let entries = if let Some(logs) = logs_from_ipc {
            logs
        } else {
            // Fallback to local file query if daemon offline
            LogEntry::query(level, session, lines)
        };

        if json {
            ui::json_output(&serde_json::json!({"logs": entries, "count": entries.len()}));
        } else {
            for entry in &entries {
                let lvl_colored = match entry.level.as_str() {
                    "trace" => entry.level.dimmed(),
                    "debug" => entry.level.cyan(),
                    "info" => entry.level.green(),
                    "warn" => entry.level.yellow().bold(),
                    "error" => entry.level.red().bold(),
                    _ => entry.level.white(),
                };
                let sid_str = match &entry.session_id {
                    Some(s) => format!(" [{}]", s.dimmed()),
                    None => "".to_string(),
                };
                println!(
                    "{} [{:<5}]{} {}",
                    entry.timestamp.dimmed(),
                    lvl_colored,
                    sid_str,
                    entry.message
                );
            }
            if entries.is_empty() {
                ui::info("No log entries found matching filter criteria.");
            }
        }

        if follow {
            if !json {
                println!(
                    "\n{}",
                    "── Following live log stream (Ctrl+C to stop) ──".dimmed()
                );
            }
            let mut last_count = entries.len();
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                let current = LogEntry::query(level, session, lines.max(100));
                if current.len() > last_count {
                    let new_items = &current[last_count..];
                    for entry in new_items {
                        if json {
                            println!("{}", serde_json::to_string(entry).unwrap());
                        } else {
                            let lvl_colored = match entry.level.as_str() {
                                "trace" => entry.level.dimmed(),
                                "debug" => entry.level.cyan(),
                                "info" => entry.level.green(),
                                "warn" => entry.level.yellow().bold(),
                                "error" => entry.level.red().bold(),
                                _ => entry.level.white(),
                            };
                            let sid_str = match &entry.session_id {
                                Some(s) => format!(" [{}]", s.dimmed()),
                                None => "".to_string(),
                            };
                            println!(
                                "{} [{:<5}]{} {}",
                                entry.timestamp.dimmed(),
                                lvl_colored,
                                sid_str,
                                entry.message
                            );
                        }
                    }
                    last_count = current.len();
                }
            }
        }
    });
}

async fn query_ipc_logs(
    level: Option<&str>,
    session: Option<&str>,
    limit: usize,
) -> Option<Vec<LogEntry>> {
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{}", crate::cmd::daemon::DAEMON_IPC_PORT))
            .await
            .ok()?;
    let req = serde_json::json!({
        "cmd": "logs",
        "level": level.unwrap_or("all"),
        "session": session.unwrap_or(""),
        "limit": limit
    });
    let _ = stream.write_all(req.to_string().as_bytes()).await;
    let _ = stream.write_all(b"\n").await;

    let mut resp_buf = Vec::new();
    let _ = stream.read_to_end(&mut resp_buf).await;
    let resp_str = String::from_utf8_lossy(&resp_buf);

    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&resp_str)
        && let Some(logs_arr) = val.get("logs")
        && let Ok(entries) = serde_json::from_value::<Vec<LogEntry>>(logs_arr.clone())
    {
        return Some(entries);
    }
    None
}
