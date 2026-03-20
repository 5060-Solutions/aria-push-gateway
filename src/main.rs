use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod auth;
mod config;
mod db;
mod handoff;
mod push;
mod server;
mod sip;

#[derive(Parser)]
#[command(name = "aria-gateway", about = "Aria SIP Push Gateway")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "gateway.toml")]
    config: String,

    /// Override listen address
    #[arg(long)]
    listen: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = config::GatewayConfig::load(&cli.config)?;

    let listen_addr = cli
        .listen
        .unwrap_or_else(|| config.server.listen.clone());

    tracing::info!("Aria Push Gateway v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Public URL: {}", config.server.public_url);

    // Initialize database
    let db = db::Database::connect(&config.database.url).await?;
    db.migrate().await?;
    tracing::info!("Database ready");

    // Initialize SIP proxy manager
    let sip_proxy = Arc::new(sip::SipProxyManager::new());

    // Initialize push notification clients
    let push_manager = Arc::new(push::PushManager::new(&config.push)?);

    // Initialize call handoff manager
    let handoff = Arc::new(handoff::HandoffManager::new());

    // Restore active device registrations from database
    let devices = db.list_active_devices().await?;
    tracing::info!("Restoring {} device registrations", devices.len());
    for device in devices {
        // Register push token so incoming calls can send notifications
        push_manager.register_device(device.clone()).await;

        if let Err(e) = sip_proxy
            .register_device(
                device.id.clone(),
                device.sip_config(),
                push_manager.clone(),
                handoff.clone(),
            )
            .await
        {
            tracing::warn!("Failed to restore registration for {}: {}", device.id, e);
        }
    }

    // Build and start HTTP server
    let app = server::build_router(
        db.clone(),
        sip_proxy.clone(),
        push_manager.clone(),
        handoff.clone(),
        config.auth.secret.clone(),
        config.auth.token_expiry_secs,
    );

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("Listening on {}", listen_addr);

    axum::serve(listener, app).await?;
    Ok(())
}
