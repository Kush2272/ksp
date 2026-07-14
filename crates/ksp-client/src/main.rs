//! KSP Client Binary — connects to a KSP server and starts an interactive session.

use std::net::SocketAddr;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tracing::{debug, info};

use ksp_client::KspClient;
use ksp_core::constants::DEFAULT_PORT;
use ksp_core::types::PacketType;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr: SocketAddr = format!("127.0.0.1:{}", DEFAULT_PORT).parse().unwrap();
    info!("Connecting to KSP server at {}", addr);

    let mut client = KspClient::connect(addr).await?;

    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║           KSP Encrypted Session Active           ║");
    println!("║  Session: {}  ║", client.session.id_string());
    println!("║  Cipher:  {:41}║", format!("{}", client.cipher_suite));
    println!("╚══════════════════════════════════════════════════╝");
    println!("\nType messages to send (encrypted). Press Ctrl+C to exit.\n");

    let stdin = io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.is_empty() {
            continue;
        }

        client.send_data(1, line.as_bytes()).await?;
        debug!("Sent {} bytes (encrypted)", line.len());

        let (response, plaintext) = client.receive_packet().await?;
        if response.packet_type == PacketType::Data {
            let text = String::from_utf8_lossy(&plaintext);
            println!("← Echo: {}", text);
        }
    }

    client.close().await?;
    Ok(())
}
