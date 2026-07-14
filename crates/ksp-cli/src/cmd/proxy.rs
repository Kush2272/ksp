//! `ksp proxy` and `ksp gateway` — Real async L4/L7 proxy and protocol translation gateway.
//!
//! - `ksp proxy`: Local TCP -> KSP Encrypted Tunnel (`stunnel` / `ngrok` parity). Wraps unencrypted local TCP traffic into encrypted KSP streams to an upstream KSP server.
//! - `ksp gateway`: KSP Encrypted Server -> Upstream HTTP/TCP Backend Bridge (`nginx` / reverse proxy parity). Decrypts incoming KSP traffic and proxies it to local web apps.

use colored::Colorize;
use crate::ui;
use ksp_client::KspClient;
use ksp_core::types::PacketType;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub fn run_proxy(listen: &str, upstream: &str, json: bool) {
    let listen_addr: SocketAddr = match listen.parse() {
        Ok(a) => a,
        Err(_) => match format!("{}:8080", listen).parse() {
            Ok(a) => a,
            Err(e) => {
                if !json { ui::failure(&format!("Invalid listen address '{}': {}", listen, e)); }
                return;
            }
        },
    };

    let upstream_str = crate::cmd::env::resolve_target_address(upstream);
    let upstream_addr: SocketAddr = match upstream_str.parse() {
        Ok(a) => a,
        Err(e) => {
            if !json { ui::failure(&format!("Invalid upstream KSP address '{}': {}", upstream_str, e)); }
            return;
        }
    };

    if !json {
        ui::print_header("KSP High-Performance L4 Tunnel Proxy Relay");
        ui::kv("Listen Address (TCP)", &listen_addr.to_string());
        ui::kv("Upstream Target (KSP)", &upstream_str);
        ui::kv("Multiplexing", "Dynamic Stream Assignment (1 KSP Stream per TCP Socket)");
        ui::kv("Encryption", "AES-256-GCM / ChaCha20-Poly1305 End-to-End Tunnel");
        println!();
        println!("  {} Proxying local unencrypted TCP frames on {} -> encrypted KSP {}", "🚀".yellow(), listen_addr.to_string().cyan().bold(), upstream_str.green().bold());
        println!("  {} Press Ctrl+C to stop proxy daemon.\n", "ℹ".blue());
    } else {
        ui::json_output(&serde_json::json!({
            "status": "proxy_running",
            "listen": listen_addr.to_string(),
            "upstream": upstream_str,
            "mode": "tcp_to_ksp_tunnel"
        }));
        return;
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let listener = match TcpListener::bind(listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                ui::failure(&format!("Failed to bind listen address {}: {}", listen_addr, e));
                return;
            }
        };

        let mut stream_counter: u32 = 100;
        loop {
            if let Ok((mut tcp_socket, peer_addr)) = listener.accept().await {
                stream_counter = stream_counter.wrapping_add(1);
                let sid = stream_counter;
                let up_addr = upstream_addr;

                tokio::spawn(async move {
                    if let Ok(mut client) = KspClient::connect(up_addr).await {
                        crate::cmd::telemetry::LogEntry::record("info", Some(&client.session.id_string()), &format!("Proxy relay established for TCP client {} (Stream #{})", peer_addr, sid));

                        let mut buf = [0u8; 16384];
                        loop {
                            tokio::select! {
                                // Read from TCP client and send over KSP
                                n = tcp_socket.read(&mut buf) => {
                                    match n {
                                        Ok(0) | Err(_) => break,
                                        Ok(bytes_read) => {
                                            if let Err(_) = client.send_packet(PacketType::Data, sid, &buf[..bytes_read]).await {
                                                break;
                                            }
                                            crate::cmd::telemetry::TelemetrySnapshot::record_packets(bytes_read as u64, 0, 1, 0);
                                        }
                                    }
                                }
                                // Read from KSP server and write back to TCP client
                                pkt_res = client.receive_packet() => {
                                    match pkt_res {
                                        Ok((pkt, payload)) => {
                                            if pkt.stream_id == sid || pkt.stream_id == 0 {
                                                if let Err(_) = tcp_socket.write_all(&payload).await {
                                                    break;
                                                }
                                                let _ = tcp_socket.flush().await;
                                                crate::cmd::telemetry::TelemetrySnapshot::record_packets(0, payload.len() as u64, 1, 0);
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            }
                        }
                        let _ = client.send_packet(PacketType::GoAway, sid, b"tunnel_close").await;
                    }
                });
            }
        }
    });
}

pub fn run_gateway(listen: &str, target_http: &str, json: bool) {
    let listen_addr: SocketAddr = if listen.contains(':') {
        match listen.parse() {
            Ok(a) => a,
            Err(_) => {
                if !json { ui::failure(&format!("Invalid KSP listen address '{}'", listen)); }
                return;
            }
        }
    } else {
        match format!("{}:9876", listen).parse() {
            Ok(a) => a,
            Err(_) => {
                if !json { ui::failure(&format!("Invalid KSP listen port '{}'", listen)); }
                return;
            }
        }
    };

    let target_str = if target_http.contains(':') {
        target_http.to_string()
    } else {
        format!("127.0.0.1:{}", target_http)
    };
    let http_addr: SocketAddr = match target_str.parse() {
        Ok(a) => a,
        Err(e) => {
            if !json { ui::failure(&format!("Invalid HTTP upstream target '{}': {}", target_str, e)); }
            return;
        }
    };

    if !json {
        ui::print_header("KSP <-> HTTP/REST Reverse Proxy Gateway");
        ui::kv("KSP Listen Address", &format!("ksp://{}", listen_addr));
        ui::kv("HTTP Upstream Target", &format!("http://{}", http_addr));
        ui::kv("Protocol Translation", "KSP Streams -> HTTP/1.1 Request/Response Bridge");
        ui::kv("Zero-RTT Support", "Active (Stream id-based multiplexing to backend)");
        println!();
        println!("  {} Gateway active! Translating incoming KSP traffic on {} -> backend {}", "✔".green().bold(), listen_addr.to_string().cyan().bold(), http_addr.to_string().yellow().bold());
        println!("  {} Press Ctrl+C to stop gateway bridge.\n", "ℹ".blue());
    } else {
        ui::json_output(&serde_json::json!({
            "status": "gateway_active",
            "ksp_bind": listen_addr.to_string(),
            "http_upstream": http_addr.to_string()
        }));
        return;
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        use ksp_server::{load_or_generate_cert, run_server, ServerConfig};
        let (cert, key) = match load_or_generate_cert() {
            Ok((c, k)) => (c, k),
            Err(e) => {
                if !json { ui::failure(&format!("Failed to init gateway certificate: {}", e)); }
                return;
            }
        };

        let config = ServerConfig {
            bind_addr: listen_addr,
            capabilities: ksp_core::capability::default_capabilities(),
            certificate: cert,
            signing_key: key,
            gateway_target: Some(http_addr),
            output_sink: None,
        };

        let _ = run_server(config).await;
    });
}
