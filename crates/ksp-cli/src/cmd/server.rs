//! `ksp server start|stop|status` — KSP server management.

use crate::ui;
use colored::Colorize;
use ksp_server::{ServerConfig, load_or_generate_cert, run_server};
use std::net::SocketAddr;

pub fn run_start(port: u16, host: &str, verbose: bool, json: bool) {
    if !json {
        ui::print_header("KSP Server");
        ui::kv("Host", host);
        ui::kv("Port", &port.to_string());
        ui::kv("Protocol", &format!("KSP v{}", ksp_core::CURRENT_VERSION));
        ui::kv("Cipher", "AES-256-GCM (preferred)");
        ui::kv("Compression", "zstd");
        ui::kv("Replay Window", "1024 packets");
        println!();
    }

    let bind_addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap_or_else(|_| {
        ui::failure(&format!("Invalid address: {}:{}", host, port));
        std::process::exit(1);
    });

    let level = if verbose { "debug" } else { "info" };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .try_init();

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        run_server_async(bind_addr, json).await;
    });
}

async fn run_server_async(bind_addr: SocketAddr, json: bool) {
    let cert_path = std::path::Path::new("certs/server.cert");
    let key_path = std::path::Path::new("certs/server.key");

    let (certificate, signing_key) = if cert_path.exists() && key_path.exists() {
        if !json {
            ui::success("Certificate loaded from certs/");
        }
        let cert_bytes = std::fs::read(cert_path).expect("Failed to read certificate");
        let key_bytes = std::fs::read(key_path).expect("Failed to read key");
        let cert = ksp_crypto::certificate::KspCertificate::deserialize(&cert_bytes)
            .expect("Invalid certificate");
        let key_arr: [u8; 32] = key_bytes.try_into().expect("Invalid key length");
        let key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
        (cert, key)
    } else {
        if !json {
            ui::info(
                "No certificate found in certs/ directory. Using server load_or_generate_cert()...",
            );
        }
        load_or_generate_cert().expect("Failed to load or generate server certificate")
    };

    let config = ServerConfig {
        bind_addr,
        capabilities: ksp_core::capability::default_capabilities(),
        certificate,
        signing_key,
        gateway_target: None,
        output_sink: None,
        auth_config: ksp_server::AuthConfig::from_env(),
    };

    if let Err(e) = run_server(config).await {
        if json {
            ui::json_output(&serde_json::json!({"status": "error", "message": e.to_string()}));
        } else {
            ui::failure(&format!("Server error: {}", e));
        }
    }
}

pub fn run_status(json: bool) {
    if !json {
        ui::print_header("KSP Server Status");
    }
    use std::io::{Read, Write};
    let ipc_running = match std::net::TcpStream::connect("127.0.0.1:9899") {
        Ok(mut s) => {
            let _ = s.write_all(b"{\"cmd\":\"status\"}\n");
            let mut buf = [0u8; 256];
            s.read(&mut buf).is_ok()
        }
        Err(_) => false,
    };
    let snap = crate::cmd::telemetry::TelemetrySnapshot::fetch_current();
    let is_running = ipc_running || snap.status == "running";

    if json {
        ui::json_output(&serde_json::json!({
            "status": if is_running { "running" } else { "stopped" },
            "daemon_ipc": ipc_running,
            "port": 9876,
        }));
    } else if is_running {
        ui::success("KSP server/daemon appears to be active in local state");
    } else {
        ui::info("No active KSP server daemon detected.");
        ui::info("Start one with: ksp server start");
    }
}

pub fn run_stop(json: bool) {
    use std::io::{Read, Write};
    if let Ok(mut s) = std::net::TcpStream::connect("127.0.0.1:9899") {
        let _ = s.write_all(b"{\"cmd\":\"stop\"}\n");
        let mut buf = [0u8; 256];
        let _ = s.read(&mut buf);
        let mut snap = crate::cmd::telemetry::TelemetrySnapshot::fetch_current();
        snap.status = "stopped".into();
        snap.save();
        if json {
            ui::json_output(
                &serde_json::json!({"status": "stopped", "message": "Signal sent to KSP daemon"}),
            );
        } else {
            ui::print_header("KSP Server Stop");
            ui::success("Termination signal sent to KSP background daemon.");
        }
    } else {
        if json {
            ui::json_output(
                &serde_json::json!({"status": "error", "message": "No active background KSP daemon found on IPC port 9899 to stop"}),
            );
        } else {
            ui::print_header("KSP Server Stop");
            ui::failure("No active background KSP daemon found on IPC port 9899 to stop.");
            ui::info(
                "If running interactively in foreground (`ksp server start`), use Ctrl+C in that terminal.",
            );
        }
        std::process::exit(1);
    }
}

pub fn run_restart(port: u16, host: &str, verbose: bool, json: bool) {
    use std::io::Write;
    if let Ok(mut s) = std::net::TcpStream::connect("127.0.0.1:9899") {
        let _ = s.write_all(b"{\"cmd\":\"stop\"}\n");
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    if !json {
        ui::header("KSP Server Restart");
        println!("  {} Starting KSP Server daemon...", "✔".green().bold());
    }
    run_start(port, host, verbose, json);
}

pub fn run_reload(json: bool) {
    use std::io::{Read, Write};
    if let Ok(mut s) = std::net::TcpStream::connect("127.0.0.1:9899") {
        let _ = s.write_all(b"{\"cmd\":\"reload\"}\n");
        let mut buf = [0u8; 256];
        if let Ok(n) = s.read(&mut buf) {
            let resp_str = String::from_utf8_lossy(&buf[..n]);
            if resp_str.contains("\"reloaded\"") {
                if json {
                    ui::json_output(
                        &serde_json::json!({"status": "reloaded", "message": "Configuration reloaded via daemon IPC"}),
                    );
                } else {
                    ui::header("KSP Server Hot-Reload");
                    ui::success("Reload command successfully processed by KSP daemon via IPC.");
                    println!();
                }
                return;
            }
        }
    }

    if json {
        ui::json_output(
            &serde_json::json!({"status": "error", "message": "Cannot reload: no active background daemon listening on IPC port 9899"}),
        );
    } else {
        ui::header("KSP Server Hot-Reload");
        ui::failure("Cannot reload: no active background daemon listening on IPC port 9899.");
    }
    std::process::exit(1);
}
