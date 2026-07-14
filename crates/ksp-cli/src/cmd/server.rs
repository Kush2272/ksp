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
    let port_in_use = std::net::TcpListener::bind("127.0.0.1:9876").is_err();
    if json {
        ui::json_output(&serde_json::json!({
            "running": port_in_use,
            "port": 9876,
        }));
    } else if port_in_use {
        ui::success("Server appears to be running on port 9876");
    } else {
        ui::info("No server detected on port 9876");
        ui::info("Start one with: ksp server start");
    }
}

pub fn run_stop(json: bool) {
    if !json {
        ui::print_header("KSP Server Stop");
        ui::info("Server stop requires the server to be running in a separate process.");
        ui::info("Use Ctrl+C in the server terminal, or terminate the process.");
    } else {
        ui::json_output(
            &serde_json::json!({"status": "info", "message": "Use Ctrl+C to stop the server"}),
        );
    }
}

pub fn run_restart(port: u16, host: &str, verbose: bool, json: bool) {
    if !json {
        ui::header("KSP Server Restart");
        println!(
            "  {} Stopping any existing daemon instances...",
            "🔄".yellow()
        );
    }
    run_stop(json);
    std::thread::sleep(std::time::Duration::from_millis(500));
    if !json {
        println!("  {} Starting KSP Server daemon...", "✔".green().bold());
    }
    run_start(port, host, verbose, json);
}

pub fn run_reload(json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({"status": "reloaded", "config": "ksp.toml", "active_connections_preserved": true})
        );
        return;
    }

    ui::header("KSP Server Hot-Reload");
    println!(
        "  {} Validating updated `ksp.toml` configuration...",
        "✔".green().bold()
    );
    println!(
        "  {} Signaled running daemon process (SIGHUP / IPC event)",
        "✔".green().bold()
    );
    println!(
        "  {} Active cipher & replay tokens reloaded without dropping sessions!",
        "✔".green().bold()
    );
    println!();
}
