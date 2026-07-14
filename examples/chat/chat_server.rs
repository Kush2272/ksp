//! Encrypted Multi-User KSP Chat Server Example
//!
//! Run with: `cargo run --example chat_server -- --port 9876`

use ksp_server::{KspServer, ServerConfig};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = "127.0.0.1:9876";
    println!("Starting KSP Chat Server on {}...", bind_addr);

    let config = ServerConfig {
        bind_address: bind_addr.parse()?,
        max_connections: 1024,
        ..Default::default()
    };

    let mut server = KspServer::bind(config).await?;
    println!("[OK] Chat server listening for secure X25519 handshakes.");

    let active_peers: Arc<Mutex<HashMap<u64, String>>> = Arc::new(Mutex::new(HashMap::new()));

    while let Some(mut session) = server.accept().await {
        let peers = Arc::clone(&active_peers);
        tokio::spawn(async move {
            let session_id = session.session_id();
            println!("[+] New peer connected! Session ID: {}", session_id);

            while let Ok((stream_id, payload)) = session.receive().await {
                if stream_id == 1 {
                    let msg = String::from_utf8_lossy(&payload);
                    println!("[Session {}] Chat broadcast: {}", session_id, msg);
                    // Broadcast logic across active peers would occur here
                }
            }
            
            println!("[-] Session {} disconnected.", session_id);
            peers.lock().await.remove(&session_id);
        });
    }

    Ok(())
}
