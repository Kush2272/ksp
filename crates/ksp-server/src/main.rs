//! KSP Server Binary — entry point for starting a standalone KSP server daemon.

use ksp_core::constants::DEFAULT_PORT;
use ksp_server::{load_or_generate_cert, run_server, ServerConfig};
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let (certificate, signing_key) = load_or_generate_cert()?;

    let config = ServerConfig {
        bind_addr: format!("0.0.0.0:{}", DEFAULT_PORT).parse().unwrap(),
        capabilities: ksp_core::capability::default_capabilities(),
        certificate,
        signing_key,
        gateway_target: None,
        output_sink: None,
    };

    info!("Starting KSP server on port {}", DEFAULT_PORT);
    run_server(config).await?;

    Ok(())
}
